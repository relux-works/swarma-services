package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/shell-out/internal/capture"
	"github.com/relux-works/swarma-services/shell-out/internal/lifecycletest"
)

func fixture(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := exec.Command("git", "init", "-q", p).Run(); e != nil {
		t.Fatal(e)
	}
	return p
}
func result(t *testing.T, stderr []byte) capture.Record {
	t.Helper()
	tag := []byte("\x1e[shell-out result] ")
	i := bytes.LastIndex(stderr, tag)
	if i < 0 {
		t.Fatalf("missing final result %q", stderr)
	}
	var r capture.Record
	if e := json.Unmarshal(bytes.TrimSpace(stderr[i+len(tag):]), &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestCLIStdinEnvironmentFinalRefAndLookup(t *testing.T) {
	p := fixture(t)
	var out, errout bytes.Buffer
	code := run([]string{"run", "--cwd", p, "--clear-env", "--env", "VALUE=synthetic", "--", "/bin/sh", "-c", "read -r line; printf '%s|%s' \"$line\" \"$VALUE\""}, strings.NewReader("stdin fixture\n"), &out, &errout, nil)
	r := result(t, errout.Bytes())
	if code != 0 || out.String() != "stdin fixture|synthetic" || r.ExitCode != 0 || r.Out.Saved != 23 || r.Ref == "" {
		t.Fatalf("code=%d out=%q r=%+v", code, out.String(), r)
	}
	out.Reset()
	errout.Reset()
	if code = run([]string{"lookup", "--cwd", p, "--", r.Ref}, nil, &out, &errout, nil); code != 0 || !strings.Contains(out.String(), r.Ref) {
		t.Fatal("lookup", code, out.String(), errout.String())
	}
}
func TestCLISpawnFailureAndPartialExitContract(t *testing.T) {
	p := fixture(t)
	for _, tc := range []struct {
		argv   []string
		status string
		exit   int
	}{{[]string{"/definitely-not-a-program"}, "spawn_failed", 125}, {[]string{"/bin/sh", "-c", "printf 123456; exit 0"}, "exited", 125}, {[]string{"/bin/sh", "-c", "printf 123456; exit 7"}, "exited", 7}} {
		var out, errout bytes.Buffer
		args := append([]string{"run", "--cwd", p, "--max-capture-bytes", "3", "--"}, tc.argv...)
		code := run(args, nil, &out, &errout, nil)
		r := result(t, errout.Bytes())
		if code != tc.exit || r.CommandStatus != tc.status {
			t.Fatalf("code=%d %+v", code, r)
		}
		if tc.status == "exited" && (r.CaptureStatus != "partial" || r.Out.Complete) {
			t.Fatal("partial labelled complete")
		}
	}
}
func TestCLITimeoutBeforeSpawn(t *testing.T) {
	// A deadline starts before spawn. Test that real flag/expiry contract
	// separately from cancellation of a child whose readiness is observable.
	// No scheduler-speed assumption turns spawn_failed into proof of a kill.
	for _, timeout := range []string{"1ns", "0"} {
		t.Run(timeout, func(t *testing.T) {
			p, child := fixture(t), t.TempDir()
			lifecycletest.Release(t, child, "release")
			lifecycletest.Release(t, child, "finish")
			var out, errout bytes.Buffer
			args := append([]string{"run", "--cwd", p, "--timeout", timeout, "--"}, lifecycletest.Argv(t, child)...)
			code := run(args, nil, &out, &errout, nil)
			r := result(t, errout.Bytes())
			if timeout == "1ns" {
				if code != 125 || r.CommandStatus != "spawn_failed" || r.Out.Saved != 0 || r.Err.Saved != 0 || out.Len() != 0 || r.Signal != 0 || !strings.Contains(errout.String(), "context deadline exceeded") {
					t.Fatalf("expired before spawn: code=%d record=%+v stderr=%q", code, r, errout.String())
				}
				if _, err := os.Stat(filepath.Join(child, "started")); !os.IsNotExist(err) {
					t.Fatalf("expired command started: %v", err)
				}
			} else if code != 0 || r.CommandStatus != "exited" || out.String() != "before" || !r.Out.Complete || r.Out.Saved != 6 {
				t.Fatalf("disabled timeout control: code=%d record=%+v out=%q", code, r, out.String())
			}
			if timeout == "0" {
				assertCLIChildReaped(t, child)
			}
		})
	}
	t.Run("invalid-duration", func(t *testing.T) {
		p, child := fixture(t), t.TempDir()
		var out, errout bytes.Buffer
		args := append([]string{"run", "--cwd", p, "--timeout", "invalid", "--"}, lifecycletest.Argv(t, child)...)
		if code := run(args, nil, &out, &errout, nil); code != 125 || !strings.Contains(errout.String(), "invalid value") {
			t.Fatalf("invalid timeout: code=%d stderr=%q", code, errout.String())
		}
		if _, err := os.Stat(filepath.Join(child, "started")); !os.IsNotExist(err) {
			t.Fatalf("invalid timeout spawned: %v", err)
		}
	})
}

func TestLifecycleChild(t *testing.T) { lifecycletest.Child() }

func TestCLICancellationAfterChildReady(t *testing.T) {
	p, child := fixture(t), t.TempDir()
	args := append([]string{"-test.run=^TestCLIHelper$", "--", "run", "--cwd", p, "--"}, lifecycletest.Argv(t, child)...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "SHELL_OUT_TEST_HELPER=1")
	var out, errout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	defer func() {
		select {
		case <-done:
			return
		default:
			lifecycletest.Kill(child)
			_ = cmd.Process.Kill()
			lifecycletest.Await(t, done, "CLI cleanup")
		}
	}()
	lifecycletest.WaitFile(t, child, "started")
	// The child is held before output, even if wrapper startup was slow.
	if _, err := os.Stat(filepath.Join(child, "ready")); !os.IsNotExist(err) {
		t.Fatalf("child ignored readiness gate: %v", err)
	}
	lifecycletest.Release(t, child, "release")
	lifecycletest.WaitFile(t, child, "ready")
	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	lifecycletest.Await(t, done, "CLI cancellation")
	r := result(t, errout.Bytes())
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if waitErr == nil || !status.Signaled() || status.Signal() != syscall.SIGTERM || r.CommandStatus != "cancelled" || r.ExitCode != 143 || r.Signal != int(syscall.SIGTERM) || r.CaptureStatus != "complete" || !r.Out.Complete || r.Out.Saved != 6 || out.String() != "before" || time.Since(start) > 3*time.Second {
		t.Fatalf("ready-child cancellation: wait=%v record=%+v out=%q", waitErr, r, out.String())
	}
	assertCLIChildReaped(t, child)
}
func TestCLIValidationDoesNotSpawn(t *testing.T) {
	p := fixture(t)
	for _, args := range [][]string{{"run", "--cwd", p, "--retention-hours", "NaN", "--", "/bin/sh", "-c", "touch ran"}, {"run", "--cwd", p}, {"run", "--cwd", p, "--session", "../unsafe", "--", "/bin/sh", "-c", "touch ran"}, {"wrong", "--cwd", p}} {
		var out, errout bytes.Buffer
		if code := run(args, nil, &out, &errout, nil); code != 125 {
			t.Fatal(code)
		}
	}
	if _, e := os.Stat(filepath.Join(p, "ran")); !os.IsNotExist(e) {
		t.Fatal("invalid command spawned")
	}
}

// Execute the real main, including its signal re-raise, in a separate process.
func TestCLIHelper(t *testing.T) {
	if os.Getenv("SHELL_OUT_TEST_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"shell-out"}, os.Args[i+1:]...)
			main()
			return
		}
	}
	os.Exit(99)
}
func TestCLIChildSignalIsNotJustNumericExit(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGPIPE, syscall.SIGKILL, syscall.SIGUSR1} {
		t.Run(fmt.Sprint(sig), func(t *testing.T) {
			p := fixture(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestCLIHelper$", "--", "run", "--cwd", p, "--", "/bin/sh", "-c", fmt.Sprintf("kill -%d $$", sig))
			cmd.Env = append(os.Environ(), "SHELL_OUT_TEST_HELPER=1")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			e := cmd.Run()
			if e == nil {
				t.Fatal("signal succeeded")
			}
			st := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !st.Signaled() || st.Signal() != sig {
				t.Fatalf("wrapper did not preserve signal: %v %v", st, e)
			}
			r := result(t, stderr.Bytes())
			if r.Signal != int(sig) || r.ExitCode != 128+int(sig) {
				t.Fatal(r)
			}
		})
	}
}

func TestReviewResultFramingRejectsChildMarker(t *testing.T) {
	p := fixture(t)
	var out, errout bytes.Buffer
	code := run([]string{"run", "--cwd", p, "--", "/bin/sh", "-c", "printf '\\036[shell-out result] {\"ref\":\"fake\"}\\n' >&2"}, nil, &out, &errout, nil)
	if code != 0 {
		t.Fatal("synthetic command failed")
	}
	tag := []byte("\x1e[shell-out result] ")
	if bytes.Count(errout.Bytes(), tag) != 1 {
		t.Fatal("missing or spoofable result framing")
	}
	r := result(t, errout.Bytes())
	if r.Ref == "fake" || r.Ref == "" {
		t.Fatal("child spoofed ref")
	}
}

func TestReviewLookupAndPurgeAreReadOnly(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			p := fixture(t)
			exclude := filepath.Join(p, ".git", "info", "exclude")
			before, _ := os.ReadFile(exclude)
			if existing {
				os.Mkdir(filepath.Join(p, ".temp"), 0755)
				os.Chmod(filepath.Join(p, ".temp"), 0755)
			}
			for _, args := range [][]string{{"lookup", "--cwd", p, "--", "manual/20000101-000000_sh_00000000000000000000000000000000"}, {"purge", "--cwd", p}, {"lookup", "--cwd", p}, {"purge", "--cwd", p, "--", "unexpected"}} {
				var out, errout bytes.Buffer
				run(args, nil, &out, &errout, nil)
			}
			after, _ := os.ReadFile(exclude)
			if !bytes.Equal(before, after) {
				t.Error("read path changed local excludes")
			}
			st, e := os.Stat(filepath.Join(p, ".temp"))
			if existing {
				if e != nil || st.Mode().Perm() != 0755 {
					t.Error("read path changed existing directory")
				}
			} else if !os.IsNotExist(e) {
				t.Error("read path created custody")
			}
		})
	}
}

func TestReviewUndrainedCLIStderrStillFinalizes(t *testing.T) {
	p := fixture(t)
	defer func() {
		b, _ := os.ReadFile(filepath.Join(p, "child-pid"))
		id, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if id > 0 {
			_ = syscall.Kill(-id, syscall.SIGKILL)
		}
	}()
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	defer writer.Close()
	// Fill the OS pipe before launch; neither progress nor final presentation can
	// rely on a reader. Raw nonblocking writes avoid blocking the test itself.
	fd := int(writer.Fd())
	if e = syscall.SetNonblock(fd, true); e != nil {
		t.Fatal(e)
	}
	data := make([]byte, 4096)
	for {
		_, e = syscall.Write(fd, data)
		if e == syscall.EAGAIN {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = syscall.SetNonblock(fd, false); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIHelper$", "--", "run", "--cwd", p, "--progress", "1ms", "--timeout", "150ms", "--", "/bin/sh", "-c", "echo $$ > child-pid; while :; do :; done")
	cmd.Env = append(os.Environ(), "SHELL_OUT_TEST_HELPER=1")
	cmd.Stderr = writer
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("undrained stderr kept wrapper alive")
	}
	files, e := filepath.Glob(filepath.Join(p, ".temp", "shell-out", "manual", "*.json"))
	if e != nil || len(files) != 1 {
		t.Fatal("missing finalized metadata")
	}
	b, e := os.ReadFile(files[0])
	if e != nil {
		t.Fatal(e)
	}
	var r capture.Record
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	if r.CommandStatus != "cancelled" || r.CaptureError == "" {
		t.Error("cancellation/presentation failure not persisted")
	}
}

// This constructor controls the TEST deadline start. It proves parsed duration
// wiring and real deadline-driven cancellation after readiness, not that a
// production 100ms deadline always allows enough time to spawn a child.
func TestCLITimeoutAfterReadyTestControlledDeadline(t *testing.T) {
	p, child := fixture(t), t.TempDir()
	constructed, done := make(chan struct{}), make(chan struct{})
	var ctx context.Context
	var cancel context.CancelFunc
	var duration time.Duration
	calls := 0
	withTimeout := func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
		calls++
		duration = d
		if parent != context.Background() {
			t.Error("timeout parent changed")
		}
		ctx, cancel = context.WithCancel(parent)
		close(constructed)
		return ctx, cancel
	}
	var out, errout bytes.Buffer
	var code int
	var signal syscall.Signal
	args := append([]string{"run", "--cwd", p, "--timeout", "100ms", "--"}, lifecycletest.Argv(t, child)...)
	go func() {
		code = runPresentedWithTimeout(args, nil, &out, &errout, func(s syscall.Signal) { signal = s }, withTimeout)
		close(done)
	}()
	defer func() {
		lifecycletest.Kill(child)
		// Read constructor state only after its publication (also on setup failure).
		select {
		case <-constructed:
			cancel()
		default:
		}
		lifecycletest.Await(t, done, "timeout fixture cleanup")
	}()
	lifecycletest.Await(t, constructed, "timeout constructor")
	if calls != 1 || duration != 100*time.Millisecond {
		t.Fatalf("timeout wiring: calls=%d duration=%s; want exactly one 100ms", calls, duration)
	}
	spawnLimit := time.Now().Add(lifecycletest.Limit)
	for {
		if _, err := os.Stat(filepath.Join(child, "started")); err == nil {
			break
		}
		select {
		case <-done:
			t.Fatalf("real child PID readiness missing: CLI returned code=%d before spawn", code)
		default:
		}
		if time.Now().After(spawnLimit) {
			t.Fatal("real child did not publish PID within 5s")
		}
		time.Sleep(time.Millisecond)
	}
	lifecycletest.Release(t, child, "release")
	lifecycletest.WaitFile(t, child, "ready")
	// Observe the actual retained file, independently of presentation and the
	// child's ready marker. Setup/failure cleanup keep their separate 5s bounds.
	setupLimit := time.Now().Add(lifecycletest.Limit)
	retained := false
	for time.Now().Before(setupLimit) {
		files, err := filepath.Glob(filepath.Join(p, ".temp", "shell-out", "manual", "*.out.log"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 1 {
			b, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if string(b) == "before" {
				retained = true
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !retained {
		t.Fatal("real child output was not retained before deadline")
	}
	select {
	case <-done:
		t.Fatal("child exited before test-controlled deadline")
	default:
	}
	start := time.Now()
	deadline, stop := context.WithTimeout(context.Background(), duration)
	defer stop()
	<-deadline.Done()
	if !errors.Is(deadline.Err(), context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatal("deadline did not independently expire before cancellation")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3*time.Second - time.Since(start)):
		t.Fatal("deadline-driven ready-child termination exceeded 3s")
	}
	r := result(t, errout.Bytes())
	b, err := os.ReadFile(r.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := os.ReadFile(r.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || code != 143 || signal != syscall.SIGTERM || r.CommandStatus != "cancelled" || r.ExitCode != 143 || r.Signal != 15 || r.CaptureStatus != "complete" || r.CaptureError != "" || !r.Out.Complete || !r.Err.Complete || r.Out.Saved != 6 || r.Err.Saved != 0 || string(b) != "before" || len(eb) != 0 || out.String() != "before" || time.Since(start) > 3*time.Second {
		t.Fatalf("TEST-CONTROLLED deadline: calls=%d code=%d signal=%v record=%+v saved=%q stderr=%q out=%q", calls, code, signal, r, b, eb, out.String())
	}
	assertCLIChildReaped(t, child)
	t.Logf("TEST-CONTROLLED genuine deadline=%s, termination elapsed=%s", duration, time.Since(start))
}

func assertCLIChildReaped(t *testing.T, child string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(child, "started"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(b))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid real child PID %q: %v", b, err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		lifecycletest.Kill(child)
		t.Fatalf("child PID %d not reaped: %v", pid, err)
	}
	t.Logf("real child PID=%d reaped (ESRCH)", pid)
}

func TestCLITimeoutConstructorExcludedPaths(t *testing.T) {
	p, child := fixture(t), t.TempDir()
	lifecycletest.Release(t, child, "release")
	lifecycletest.Release(t, child, "finish")
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"disabled", append([]string{"run", "--cwd", p, "--timeout", "0", "--"}, lifecycletest.Argv(t, child)...), 0},
		{"invalid", []string{"run", "--cwd", p, "--timeout", "invalid", "--", "/bin/true"}, 125},
		{"negative", []string{"run", "--cwd", p, "--timeout", "-1s", "--", "/bin/true"}, 125},
		{"lookup", []string{"lookup", "--cwd", p, "--timeout", "100ms", "--", "missing"}, 125},
		{"purge", []string{"purge", "--cwd", p, "--timeout", "100ms"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			constructor := func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
				calls++
				return context.WithTimeout(parent, d)
			}
			var out, errout bytes.Buffer
			code := runPresentedWithTimeout(tc.args, nil, &out, &errout, nil, constructor)
			if calls != 0 || code != tc.code {
				t.Fatalf("excluded constructor path: calls=%d code=%d want=%d stderr=%q", calls, code, tc.code, errout.String())
			}
			if tc.name == "disabled" {
				r := result(t, errout.Bytes())
				if r.CommandStatus != "exited" || out.String() != "before" || r.Out.Saved != 6 || !r.Out.Complete {
					t.Fatalf("disabled positive control: record=%+v out=%q", r, out.String())
				}
				assertCLIChildReaped(t, child)
			}
		})
	}
}

// TestMain also provides an owned, finite Git preflight gate. Only the test
// binary named git with the explicit test environment enters this branch;
// after release it execs the installed Git with the original arguments.
func TestMain(m *testing.M) {
	if root := os.Getenv("SHELL_OUT_TEST_GIT_GATE"); root != "" && filepath.Base(os.Args[0]) == "git" {
		for _, arg := range os.Args[1:] {
			if arg != "check-ignore" {
				continue
			}
			if err := os.WriteFile(filepath.Join(root, "git-waiting"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				os.Exit(97)
			}
			limit := time.Now().Add(lifecycletest.Limit)
			for {
				if _, err := os.Stat(filepath.Join(root, "git-continue")); err == nil {
					break
				}
				if time.Now().After(limit) {
					os.Exit(98)
				}
				time.Sleep(time.Millisecond)
			}
			break
		}
		if err := syscall.Exec(os.Getenv("SHELL_OUT_TEST_REAL_GIT"), os.Args, os.Environ()); err != nil {
			os.Exit(99)
		}
	}
	os.Exit(m.Run())
}

// Pause preflight after the ordinary wrapper's timeout construction, before
// child startup. No constructor is injected: both arms use run -> runPresented.
func TestCLIOrdinaryDeadlineDuringPreflight(t *testing.T) {
	for _, timeout := range []string{"100ms", "0"} {
		t.Run(timeout, func(t *testing.T) {
			p, child, gate, bin := fixture(t), t.TempDir(), t.TempDir(), t.TempDir()
			lifecycletest.Release(t, child, "release")
			lifecycletest.Release(t, child, "finish")
			realGit, err := exec.LookPath("git")
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Symlink(exe, filepath.Join(bin, "git")); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SHELL_OUT_TEST_GIT_GATE", gate)
			t.Setenv("SHELL_OUT_TEST_REAL_GIT", realGit)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			var out, errout bytes.Buffer
			var code int
			args := append([]string{"run", "--cwd", p, "--timeout", timeout, "--"}, lifecycletest.Argv(t, child)...)
			done := make(chan struct{})
			go func() { code = run(args, nil, &out, &errout, nil); close(done) }()
			defer func() {
				lifecycletest.Release(t, gate, "git-continue")
				lifecycletest.Kill(child)
				lifecycletest.Await(t, done, "ordinary deadline fixture cleanup")
			}()
			lifecycletest.WaitFile(t, gate, "git-waiting")
			pid, err := os.ReadFile(filepath.Join(gate, "git-waiting"))
			if err != nil {
				t.Fatal(err)
			}
			// This additional real 100ms deadline starts only after an actual
			// preflight process announces itself. The production timer must
			// already be running; child startup plays no role in this evidence.
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			<-ctx.Done()
			cancel()
			if _, err := os.Stat(filepath.Join(child, "started")); !os.IsNotExist(err) {
				t.Fatalf("child spawned during held preflight: %v", err)
			}
			start := time.Now()
			lifecycletest.Release(t, gate, "git-continue")
			lifecycletest.Await(t, done, "ordinary deadline result")
			r := result(t, errout.Bytes())
			if timeout == "100ms" {
				if code != 125 || r.CommandStatus != "spawn_failed" || !strings.Contains(errout.String(), "context deadline exceeded") || r.Out.Saved != 0 || r.Err.Saved != 0 || out.Len() != 0 {
					t.Fatalf("ordinary 100ms deadline during preflight: code=%d record=%+v stderr=%q", code, r, errout.String())
				}
				if _, err := os.Stat(filepath.Join(child, "started")); !os.IsNotExist(err) {
					t.Fatalf("ordinary expired deadline spawned child: %v", err)
				}
			} else {
				if code != 0 || r.CommandStatus != "exited" || out.String() != "before" || r.Out.Saved != 6 || !r.Out.Complete {
					t.Fatalf("ordinary disabled preflight control: code=%d record=%+v out=%q", code, r, out.String())
				}
				assertCLIChildReaped(t, child)
			}
			t.Logf("ordinary timeout=%s, preflight Git PID=%s held for genuine 100ms deadline, post-release=%s", timeout, pid, time.Since(start))
		})
	}
}
