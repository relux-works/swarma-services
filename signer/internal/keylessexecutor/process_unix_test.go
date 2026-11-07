//go:build linux || darwin

package keylessexecutor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These self-process modes are explicitly OFFLINE SYNTHETIC controls. None
// invokes the pinned Darwin recipe or supplies a native admission.
func TestOfflineWorker(t *testing.T) {
	mode := os.Getenv("KEYLESS_OFFLINE_CONTROL")
	if mode == "" {
		return
	}
	switch mode {
	case "env":
		if os.Getenv("MUST_NOT_BE_INHERITED") != "" || len(os.Environ()) != 1 {
			os.Exit(23)
		}
		fmt.Print("OFFLINE SYNTHETIC CLOSED ENVIRONMENT\n")
	case "fail":
		os.Exit(29)
	case "finite-log":
		fmt.Print(strings.Repeat("F", 2048))
	case "flood":
		for {
			fmt.Print(strings.Repeat("F", 4096))
		}
	case "closed-pipe-hang":
		os.Stdout.Close()
		os.Stderr.Close()
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Second)
		}
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		for {
			time.Sleep(time.Second)
		}
	case "orphan":
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "-test.run=^TestOfflineWorker$")
		cmd.Env = []string{"KEYLESS_OFFLINE_CONTROL=ignore-term"}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e := cmd.Start(); e != nil {
			os.Exit(24)
		}
		fmt.Printf("CHILD_PID=%d\n", cmd.Process.Pid)
	case "verify":
		v, b, raw, data, _ := fixture(t)
		p, e := v.Prepare(b, raw, data)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := PlanInput(p)
		if e != nil || len(plan.Entries()) == 0 {
			t.Fatal(e)
		}
		fmt.Print("OFFLINE SYNTHETIC WORKER: REAL SELECTED SOURCE VERIFIED; NOT NATIVE\n")
	default:
		os.Exit(25)
	}
}

func TestFiniteWorkerSupervisor(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("MUST_NOT_BE_INHERITED", "offline-control-sentinel")
	for _, mode := range []string{"env", "fail", "flood", "ignore-term", "closed-pipe-hang", "orphan", "verify"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "verify" && os.Getenv("KEYVAULT_FIXTURES") == "" {
				t.Skip("public source/module fixture required")
			}
			env := []string{"KEYLESS_OFFLINE_CONTROL=" + mode}
			if mode == "verify" {
				env = append(env, "KEYVAULT_FIXTURES="+os.Getenv("KEYVAULT_FIXTURES"))
			}
			cwd, e := os.Getwd()
			if e != nil {
				t.Fatal(e)
			}
			limit := uint64(1 << 20)
			if mode == "flood" {
				limit = 1024
			}
			timeout := 5 * time.Second
			if mode == "verify" {
				// Instrumented ZIP/h1 verification is substantially slower under
				// the race detector. This is a source-control allowance only.
				timeout = 30 * time.Second
			}
			if mode == "ignore-term" || mode == "closed-pipe-hang" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			r, e := supervise(ctx, workerSpec{executable: exe, dir: cwd, argv: []string{"-test.run=^TestOfflineWorker$"}, env: env}, limit, 100*time.Millisecond)
			t.Logf("offline mode=%s UTC=%s..%s exit=%d bounded_log_bytes=%d err=%v", mode, r.Started.Format(time.RFC3339Nano), r.Ended.Format(time.RFC3339Nano), r.Exit, len(r.Log), e)
			switch mode {
			case "env":
				if e != nil || !strings.Contains(string(r.Log), "CLOSED ENVIRONMENT") {
					t.Fatalf("closed environment failed: %s %v", r.Log, e)
				}
			case "verify":
				if e != nil || !strings.Contains(string(r.Log), "REAL SELECTED SOURCE VERIFIED; NOT NATIVE") {
					t.Fatalf("synchronous verifier not run: %s %v", r.Log, e)
				}
			case "fail":
				if !errors.Is(e, ErrWorker) || r.Exit != 29 {
					t.Fatal("actual exit lost")
				}
			case "flood":
				if !errors.Is(e, ErrLimit) || len(r.Log) > int(limit) {
					t.Fatal("unbounded/truncated success")
				}
			case "ignore-term", "closed-pipe-hang":
				if !errors.Is(e, context.DeadlineExceeded) || r.Exit != -1 || r.Ended.Sub(r.Started) > time.Second {
					t.Fatalf("deadline/termination unbounded: %+v %v", r, e)
				}
			case "orphan":
				if e != nil {
					t.Fatal(e)
				}
				start := strings.Index(string(r.Log), "CHILD_PID=")
				if start < 0 {
					t.Fatalf("missing child PID: %q", r.Log)
				}
				token := strings.Fields(string(r.Log)[start+len("CHILD_PID="):])[0]
				pid, e := strconv.Atoi(token)
				if e != nil {
					t.Fatal(e)
				}
				until := time.Now().Add(time.Second)
				for syscall.Kill(pid, 0) == nil && time.Now().Before(until) {
					time.Sleep(5 * time.Millisecond)
				}
				if syscall.Kill(pid, 0) == nil {
					t.Fatalf("child still present after cleanup: %d", pid)
				}
			}
		})
	}
	t.Run("pre-cancelled-worker-does-not-start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r, e := supervise(ctx, workerSpec{executable: exe, dir: filepath.Dir(exe)}, 1, 100*time.Millisecond)
		if !errors.Is(e, context.Canceled) || !r.Started.IsZero() {
			t.Fatal("pre-cancelled worker started")
		}
	})
	t.Run("verification-deadline-starts-before-child", func(t *testing.T) {
		// The parent enforces the original budget even if synchronous verification
		// in its child has not returned; no abandoned verifier goroutine is created.
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		time.Sleep(time.Microsecond)
		r, e := supervise(ctx, workerSpec{executable: exe, dir: filepath.Dir(exe), argv: []string{"-test.run=^TestOfflineWorker$"}, env: []string{"KEYLESS_OFFLINE_CONTROL=verify"}}, 1024, 100*time.Millisecond)
		if !errors.Is(e, context.DeadlineExceeded) || !r.Started.IsZero() {
			t.Fatal("expired verification budget restarted")
		}
	})
}

func TestArtifactFIFORefusesWithoutBlocking(t *testing.T) {
	_, p := preparedFixture(t)
	parent := t.TempDir()
	r := &syntheticRunner{t: t, p: p, action: func(ctx context.Context, phase string, n int, s *state) ([]byte, error) {
		if phase == "graph" {
			return []byte(selectedGraph), nil
		}
		return nil, syscall.Mkfifo(filepath.Join(s.root, "out", "mac-keyvault"), 0600)
	}}
	start := time.Now()
	if _, e := newController().exercise(context.Background(), parent, p, r); !errors.Is(e, ErrWorker) {
		t.Fatalf("FIFO accepted: %v", e)
	}
	if time.Since(start) > time.Second {
		t.Fatal("FIFO blocked artifact open")
	}
	emptyParent(t, parent)
}

// terminalContext deterministically exposes either cancellation reason at a
// completion barrier, without relying on wall-clock races or repeated selects.
type terminalContext struct {
	context.Context
	reason error
}

func (c terminalContext) Err() error {
	if c.Context.Err() != nil {
		return c.reason
	}
	return nil
}

func TestTerminalCancellation(t *testing.T) {
	for _, route := range []string{"wait-first", "EOF-first"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			for _, at := range []string{"none", "wait", "accept", "drain"} {
				if route == "EOF-first" && at == "drain" {
					continue // EOF is already drained on this route.
				}
				t.Run(route+"/"+cause.Error()+"/"+at, func(t *testing.T) {
					testTerminalCompletion(t, route, at, "env", cause, nil)
				})
			}
		}
	}
	for _, route := range []string{"wait-first", "EOF-first"} {
		t.Run(route+"/nonzero-with-cancellation", func(t *testing.T) {
			testTerminalCompletion(t, route, "accept", "fail", context.Canceled, ErrWorker)
		})
	}
	t.Run("log-limit-with-cancellation", func(t *testing.T) {
		testTerminalCompletion(t, "wait-first", "accept", "finite-log", context.Canceled, ErrLimit)
	})
	t.Run("cleanup-budget-with-cancellation", func(t *testing.T) {
		testTerminalCompletion(t, "wait-first", "cleanup", "env", context.Canceled, ErrCleanup)
	})
}

func testTerminalCompletion(t *testing.T, route, at, mode string, cause, refusal error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := terminalContext{base, cause}
	release := make(chan struct{})
	logPublished := make(chan struct{})
	waitPublished := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	await := func(ch <-chan struct{}) {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-ch:
		case <-timer.C:
			panic("offline completion barrier exceeded two-second bound")
		}
	}
	var events []string // Only supervisor callbacks write this slice.
	observe := func(event string) {
		switch event {
		case "wait-ready":
			if route == "EOF-first" {
				await(release)
			}
			close(waitPublished)
			return
		case "logs-ready":
			if route == "wait-first" {
				await(release)
				if at == "drain" {
					cancel() // Cancellation is visible before drain can complete.
				}
			}
			close(logPublished)
			return
		}
		events = append(events, event)
		if event == at {
			cancel()
		}
		if route == "EOF-first" && event == "logs" {
			unblock()
		}
		if route == "wait-first" && event == "wait" && at != "drain" && at != "cleanup" {
			unblock()
		}
		if route == "wait-first" && event == "drain" && at == "drain" {
			unblock()
		}
		if at == "cleanup" {
			if event == "drain" {
				cancel()
			}
			if event == "accept" {
				unblock() // Withhold EOF publication until the shared budget expires.
			}
		}
	}
	limit := uint64(4096)
	if mode == "finite-log" {
		limit = 1024
	}
	const termination = 80 * time.Millisecond
	start := time.Now()
	r, err := supervise(ctx, workerSpec{
		executable: exe, dir: filepath.Dir(exe),
		argv: []string{"-test.run=^TestOfflineWorker$"},
		env:  []string{"KEYLESS_OFFLINE_CONTROL=" + mode}, completion: observe,
	}, limit, termination)
	elapsed := time.Since(start)
	await(logPublished)
	await(waitPublished)
	t.Logf("route=%s cancel_at=%s reason=%v events=%v UTC=%s..%s exit=%d signal=%q log_bytes=%d termination=%s elapsed=%s err=%v", route, at, cause, events, r.Started.Format(time.RFC3339Nano), r.Ended.Format(time.RFC3339Nano), r.Exit, r.Signal, len(r.Log), termination, elapsed, err)
	first := "wait"
	if route == "EOF-first" {
		first = "logs"
	}
	if len(events) == 0 || events[0] != first {
		t.Fatalf("terminal route was not forced: %v", events)
	}
	wantExit := 0
	if mode == "fail" {
		wantExit = 29
	}
	if r.Exit != wantExit || r.Signal != "" || r.Started.IsZero() || r.Ended.Before(r.Started) {
		t.Fatalf("actual child outcome lost: %+v", r)
	}
	if elapsed > 2*time.Second {
		t.Fatal("supervisor exceeded bounded control allowance")
	}
	if refusal != nil && !errors.Is(err, refusal) {
		t.Fatalf("independent refusal lost: want %v, got %v", refusal, err)
	}
	if mode == "finite-log" && len(r.Log) != 0 {
		t.Fatal("over-limit log retained")
	}
	if at == "none" {
		if err != nil || !strings.Contains(string(r.Log), "CLOSED ENVIRONMENT") {
			t.Fatalf("uncancelled neighbor refused: %v", err)
		}
		cancel() // Cancellation after committed success cannot change that result.
		if err != nil {
			t.Fatal("post-return cancellation changed success")
		}
	} else if !errors.Is(err, cause) {
		t.Fatalf("terminal cancellation lost: want %v, got %v", cause, err)
	}
}
