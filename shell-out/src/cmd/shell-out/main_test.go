package main

import (
	"bytes"
	"encoding/json"
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
func TestCLITimeout(t *testing.T) {
	p := fixture(t)
	var out, errout bytes.Buffer
	start := time.Now()
	code := run([]string{"run", "--cwd", p, "--timeout", "100ms", "--", "/bin/sh", "-c", "printf before; sleep 10"}, nil, &out, &errout, nil)
	r := result(t, errout.Bytes())
	if code != 143 || r.CommandStatus != "cancelled" || time.Since(start) > 3*time.Second {
		t.Fatalf("code=%d %+v", code, r)
	}
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
