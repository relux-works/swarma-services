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
