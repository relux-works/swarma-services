package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/shell-out/internal/capture"
)

type rejectResult struct{ attempts int }

func (w *rejectResult) Write(b []byte) (int, error) {
	if bytes.HasPrefix(b, []byte("\n\x1e[shell-out result] ")) {
		w.attempts++
		return 0, errors.New("synthetic result-frame failure")
	}
	return len(b), nil
}

func TestResidualFinalFrameFailure(t *testing.T) {
	for _, tc := range []struct {
		script string
		code   int
		signal syscall.Signal
	}{{"exit 0", 125, 0}, {"exit 42", 42, 0}, {"kill -TERM $$", 143, syscall.SIGTERM}} {
		p := fixture(t)
		w := &rejectResult{}
		var signal syscall.Signal
		code := runPresented([]string{"run", "--cwd", p, "--", "/bin/sh", "-c", tc.script}, nil, io.Discard, w, func(s syscall.Signal) { signal = s })
		if code != tc.code || signal != tc.signal || w.attempts != 1 {
			t.Fatal("frame-only failure masked outcome or split result packet", code, signal, w.attempts)
		}
		files, e := filepath.Glob(filepath.Join(p, ".temp", "shell-out", "manual", "*.json"))
		if e != nil || len(files) != 1 {
			t.Fatal("missing retained execution outcome")
		}
		b, e := os.ReadFile(files[0])
		var r capture.Record
		if e != nil || json.Unmarshal(b, &r) != nil || r.CaptureStatus != "complete" || r.Signal != int(tc.signal) {
			t.Fatal("frame-only failure changed retained execution outcome")
		}
		wantCode := tc.code
		if tc.script == "exit 0" {
			wantCode = 0
		}
		if r.ExitCode != wantCode || r.Finished.IsZero() {
			t.Fatal("retained child outcome incorrect")
		}
	}
}

func TestResidualSaturatedOutcome(t *testing.T) {
	for _, outcome := range []string{"exit42", "signal", "zero"} {
		t.Run(outcome, func(t *testing.T) {
			p := fixture(t)
			reader, writer, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer reader.Close()
			defer writer.Close()
			fd := int(writer.Fd())
			if e = syscall.SetNonblock(fd, true); e != nil {
				t.Fatal(e)
			}
			for {
				_, e = syscall.Write(fd, make([]byte, 4096))
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
			script := "sleep .1; exit 0"
			if outcome == "exit42" {
				script = "trap 'exit 42' TERM; sleep .1; kill -TERM $$"
			} else if outcome == "signal" {
				script = "sleep .1; kill -TERM $$"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIHelper$", "--", "run", "--cwd", p, "--progress", "1ms", "--", "/bin/sh", "-c", script)
			cmd.Env = append(os.Environ(), "SHELL_OUT_TEST_HELPER=1")
			cmd.Stderr = writer
			_ = cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("saturated presentation kept wrapper alive")
			}
			status := cmd.ProcessState.Sys().(syscall.WaitStatus)
			wantExit := 42
			if outcome == "zero" {
				wantExit = 125
			}
			if outcome == "signal" {
				if !status.Signaled() || status.Signal() != syscall.SIGTERM {
					t.Fatal("saturated presentation masked child signal", status)
				}
			} else if cmd.ProcessState.ExitCode() != wantExit {
				t.Fatal("saturated presentation masked child exit", status)
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
			wantCode, wantSignal := 42, 0
			if outcome == "signal" {
				wantCode, wantSignal = 143, 15
			} else if outcome == "zero" {
				wantCode = 0
			}
			if r.ExitCode != wantCode || r.Signal != wantSignal || r.CaptureStatus != "complete" || r.CaptureError == "" || r.Finished.IsZero() {
				t.Fatal("original outcome/presentation failure not retained")
			}
		})
	}
}
