package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	tag := []byte("[shell-out result] ")
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
