package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/shell-out/internal/lifecycletest"
)

func TestLifecycleChild(t *testing.T) { lifecycletest.Child() }

// Acknowledge only an actual successful write to the retained stdout file.
type readyDestination struct {
	*os.File
	once  sync.Once
	ready chan struct{}
	bytes []byte
}

func (w *readyDestination) Write(b []byte) (int, error) {
	n, err := w.File.Write(b)
	w.bytes = append(w.bytes, b[:n]...)
	if err == nil && bytes.Equal(w.bytes, []byte("before")) {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

// Delay delivery at the caller-owned progress writer, without blocking the
// runtime's lifecycle loop. Access to its accumulated bytes is synchronized.
type lifecycleProgress struct {
	mu                         sync.Mutex
	buf                        bytes.Buffer
	once                       sync.Once
	entered, release, observed chan struct{}
}

func (w *lifecycleProgress) Write(b []byte) (int, error) {
	var deliveryErr error
	if bytes.Contains(b, []byte("capture running ref=")) {
		w.once.Do(func() {
			close(w.entered)
			select {
			case <-w.release:
			case <-time.After(lifecycletest.Limit):
				deliveryErr = errors.New("progress delivery gate expired")
			}
		})
	}
	if deliveryErr != nil {
		return 0, deliveryErr
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(b)
	if bytes.Contains(b, []byte("capture running ref=")) {
		select {
		case <-w.observed:
		default:
			close(w.observed)
		}
	}
	return n, err
}

func (w *lifecycleProgress) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func cancellationAfterProgress(t *testing.T, delayChild bool) {
	t.Helper()
	s, p := store(t)
	child := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	progress := &lifecycleProgress{entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan struct{})}
	var releaseOnce sync.Once
	releaseProgress := func() { releaseOnce.Do(func() { close(progress.release) }) }
	if delayChild {
		releaseProgress()
	} else {
		lifecycletest.Release(t, child, "release")
	}
	o := options(p, "")
	o.Argv = lifecycletest.Argv(t, child)
	o.ProgressInterval = 30 * time.Millisecond
	o.Stderr = progress
	retained, done := make(chan struct{}), make(chan struct{})
	var r Record
	var runErr error
	go func() {
		r, runErr = s.run(ctx, o, func(f *os.File) io.Writer {
			if strings.HasSuffix(f.Name(), ".out.log") {
				return &readyDestination{File: f, ready: retained}
			}
			return f
		})
		close(done)
	}()
	defer func() {
		releaseProgress()
		cancel()
		select {
		case <-done:
		default:
			lifecycletest.Kill(child)
			lifecycletest.Await(t, done, "capture cleanup")
		}
	}()
	lifecycletest.WaitFile(t, child, "started")
	lifecycletest.Await(t, progress.entered, "progress callback")
	if delayChild {
		select {
		case <-retained:
			t.Fatal("child output preceded its readiness release")
		default:
		}
		lifecycletest.Release(t, child, "release")
	}
	lifecycletest.Await(t, retained, "retained child output")
	if !delayChild {
		select {
		case <-progress.observed:
			t.Fatal("progress preceded its delivery release")
		default:
		}
		if ctx.Err() != nil {
			t.Fatal("cancelled before progress delivery")
		}
		releaseProgress()
	}
	lifecycletest.Await(t, progress.observed, "delivered progress")
	select {
	case <-done:
		t.Fatal("child exited before cancellation")
	default:
	}
	start := time.Now()
	cancel()
	lifecycletest.Await(t, done, "ready-child cancellation")
	a, b := logs(t, r)
	if runErr != nil || r.CommandStatus != "cancelled" || r.ExitCode != 143 || r.Signal != int(syscall.SIGTERM) || r.CaptureStatus != "complete" || !r.Out.Complete || !r.Err.Complete || r.Out.Saved != 6 || string(a) != "before" || len(b) != 0 || !strings.Contains(progress.String(), "capture running ref=") || time.Since(start) > 3*time.Second {
		t.Fatalf("cancellation: record=%+v error=%v stdout=%q stderr=%q progress=%q", r, runErr, a, b, progress.String())
	}
	pidBytes, err := os.ReadFile(filepath.Join(child, "started"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		lifecycletest.Kill(child)
		t.Fatalf("ready child not reaped: %v", err)
	}
}

func TestCancellationBeforeSpawnIsNotTermination(t *testing.T) {
	s, p := store(t)
	child := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := options(p, "")
	o.Argv = lifecycletest.Argv(t, child)
	r, err := s.Run(ctx, o)
	if !errors.Is(err, context.Canceled) || r.CommandStatus != "spawn_failed" || r.Out.Saved != 0 {
		t.Fatalf("before-spawn cancellation: %+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(child, "started")); !os.IsNotExist(err) {
		t.Fatal(fmt.Errorf("cancelled command started: %w", err))
	}
}
