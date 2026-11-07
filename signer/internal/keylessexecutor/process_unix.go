//go:build linux || darwin

package keylessexecutor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// workerSpec is internal. It is used only by the labelled offline controls.
// Process groups implement cancellation, not an admitted Mac containment
// boundary: a native domain must additionally contain escaped descendants and
// enforce aggregate CPU/RSS/process bounds around the entire worker.
type workerSpec struct {
	executable, dir string
	argv, env       []string
}
type workerResult struct {
	Log            []byte
	Exit           int
	Signal         string
	Started, Ended time.Time
}

// A malicious output must not block the controller in open(2), or follow a
// replacement symlink. Descriptor and pathname identity are checked afterwards.
func openArtifact(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// supervise contains synchronous verifier/planner work by placing the whole
// worker in a separate process. It does not use a goroutine timeout to pretend
// that uninterruptible in-process verification was stopped.
func supervise(ctx context.Context, s workerSpec, logBytes uint64, termination time.Duration) (result workerResult, err error) {
	result.Exit = -1
	if !filepath.IsAbs(s.executable) || !filepath.IsAbs(s.dir) || logBytes == 0 || logBytes > ProposedLimits().LogBytes || termination <= 0 || termination > ProposedLimits().Termination {
		return result, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	read, write, e := os.Pipe()
	if e != nil {
		return result, ErrWorker
	}
	defer read.Close()
	cmd := exec.Command(s.executable, s.argv...)
	cmd.Dir = s.dir
	// A nonnil, separately allocated empty slice prevents exec's nil=inherited
	// environment behavior. No shell or os.Environ is used.
	cmd.Env = make([]string, len(s.env))
	copy(cmd.Env, s.env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = write
	cmd.Stderr = write
	result.Started = time.Now().UTC()
	if e = cmd.Start(); e != nil {
		write.Close()
		result.Ended = time.Now().UTC()
		return result, ErrWorker
	}
	write.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	type logResult struct {
		b   []byte
		err error
	}
	logs := make(chan logResult, 1)
	// One extra byte detects truncation without retaining an unbounded stream.
	go func() { b, e := io.ReadAll(io.LimitReader(read, int64(logBytes)+1)); logs <- logResult{b, e} }()
	var b []byte
	var waitErr error
	waited := false
	logRead := false
	select {
	case waitErr = <-done:
		waited = true
	case lr := <-logs:
		b = lr.b
		logRead = true
		if lr.err != nil {
			err = ErrWorker
		} else if uint64(len(b)) > logBytes {
			err = ErrLimit
		} else {
			// EOF may precede exit. A worker can close its descriptors and then hang.
			select {
			case waitErr = <-done:
				waited = true
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	// One shared termination budget covers TERM, KILL, reaping and pipe drain.
	// Separate full timers for each operation would multiply the recipe bound.
	cleanupDeadline := time.Now().Add(termination)
	if !waited {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		timer := time.NewTimer(termination / 2)
		select {
		case waitErr = <-done:
			waited = true
		case <-timer.C:
		}
		timer.Stop()
	}
	// Always kill surviving children, including after apparent successful exit.
	// If a child escaped this process group the native backend remains unavailable;
	// these process-group controls alone must never be called native containment.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if !waited {
		_ = cmd.Process.Kill()
		timer := time.NewTimer(time.Until(cleanupDeadline))
		select {
		case waitErr = <-done:
			waited = true
		case <-timer.C:
			err = errors.Join(err, ErrCleanup)
		}
		timer.Stop()
	}
	if !logRead {
		timer := time.NewTimer(time.Until(cleanupDeadline))
		select {
		case lr := <-logs:
			b = lr.b
			logRead = true
			if lr.err != nil {
				err = errors.Join(err, ErrWorker)
			}
		case <-timer.C:
			err = errors.Join(err, ErrCleanup)
		}
		timer.Stop()
	}
	// A failed drain remains a refusal; close also releases the bounded reader.
	read.Close()
	result.Ended = time.Now().UTC()
	if waited {
		result.Exit = cmd.ProcessState.ExitCode()
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			result.Signal = status.Signal().String()
		}
	}
	if uint64(len(b)) > logBytes {
		err = errors.Join(err, ErrLimit)
		b = nil
	}
	result.Log = b
	if waitErr != nil {
		err = errors.Join(err, ErrWorker)
	}
	return result, err
}
