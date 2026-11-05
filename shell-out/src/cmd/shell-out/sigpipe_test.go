package main

import (
	"context"
	"encoding/json"
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

// Exercise actual fd 1/2 in main: an error-returning mock writer or a pipe
// on another fd does not exercise Go's special standard-stream SIGPIPE path.
func TestCLIClosedPresentation(t *testing.T) {
	for _, phase := range []string{"frame", "stdout", "stderr", "progress"} {
		for _, outcome := range []struct {
			name   string
			script string
			code   int
			signal syscall.Signal
		}{
			{"zero", "exit 0", 0, 0},
			{"exit42", "exit 42", 42, 0},
			{"term", "kill -TERM $$", 143, syscall.SIGTERM},
			{"pipe", "kill -PIPE $$", 141, syscall.SIGPIPE},
		} {
			t.Run(phase+"/"+outcome.name, func(t *testing.T) {
				p := fixture(t)
				// Also bound cleanup if the wrapper regresses to dying mid-run.
				t.Cleanup(func() {
					b, _ := os.ReadFile(filepath.Join(p, "child-pid"))
					id, _ := strconv.Atoi(strings.TrimSpace(string(b)))
					if id > 0 {
						_ = syscall.Kill(-id, syscall.SIGKILL)
					}
				})
				reader, writer, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				reader.Close() // real EPIPE, not a full/undrained queue
				defer writer.Close()
				script := "echo $$ > child-pid; "
				switch phase {
				case "stdout":
					script += "printf synthetic; "
				case "stderr":
					script += "printf synthetic >&2; "
				case "progress":
					script += "sleep .15; printf survived > after-progress; "
				}
				script += outcome.script
				progress := "1h"
				if phase == "progress" {
					progress = "5ms"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIHelper$", "--", "run", "--cwd", p, "--progress", progress, "--", "/bin/sh", "-c", script)
				cmd.Env = append(os.Environ(), "SHELL_OUT_TEST_HELPER=1")
				if phase == "stdout" {
					cmd.Stdout = writer
				} else {
					cmd.Stderr = writer
				}
				_ = cmd.Run()
				if ctx.Err() != nil || cmd.ProcessState == nil {
					t.Fatal("closed presentation prevented bounded wrapper exit")
				}
				status := cmd.ProcessState.Sys().(syscall.WaitStatus)
				if outcome.signal != 0 {
					if !status.Signaled() || status.Signal() != outcome.signal {
						t.Fatalf("lost child signal: %v", status)
					}
				} else {
					want := outcome.code
					if want == 0 {
						want = 125
					}
					if cmd.ProcessState.ExitCode() != want {
						t.Fatalf("lost child exit: %v, want %d", status, want)
					}
				}
				files, e := filepath.Glob(filepath.Join(p, ".temp", "shell-out", "manual", "*.json"))
				if e != nil || len(files) != 1 {
					t.Fatal("missing retained outcome")
				}
				b, e := os.ReadFile(files[0])
				var r capture.Record
				if e != nil || json.Unmarshal(b, &r) != nil {
					t.Fatal("invalid retained outcome")
				}
				wantStatus := "exited"
				if outcome.signal != 0 {
					wantStatus = "signaled"
				}
				if r.CommandStatus != wantStatus || r.ExitCode != outcome.code || r.Signal != int(outcome.signal) || r.Finished.IsZero() || r.CaptureStatus != "complete" {
					t.Fatalf("incorrect retained child outcome: %+v", r)
				}
				// An empty final preview does not write to the fd. A frame-only
				// failure occurs after metadata finalization and is not a receipt.
				if phase != "frame" && !strings.Contains(r.CaptureError, "broken pipe") {
					t.Fatal("EPIPE not retained as a presentation failure", r.CaptureError)
				}
				if phase == "progress" {
					if b, _ := os.ReadFile(filepath.Join(p, "after-progress")); string(b) != "survived" {
						t.Fatal("presentation SIGPIPE was forwarded to the child")
					}
				}
			})
		}
	}
}
