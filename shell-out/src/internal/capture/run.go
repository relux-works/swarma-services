package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Options struct {
	Argv             []string
	Cwd              string
	Env              []string  // nil inherits; non-nil is the exact environment, including empty.
	Stdin            io.Reader // nil is closed stdin; CLI explicitly passes os.Stdin.
	Session          string
	RetentionHours   float64
	MaxCaptureBytes  int64 // per stream
	ProgressInterval time.Duration
	Stdout, Stderr   io.Writer
	Signals          <-chan os.Signal
}

// Run starts only after all capture files are open. It does not authorize the
// original command or participate in a runtime's permission policy.
func (s *Store) Run(ctx context.Context, o Options) (Record, error) {
	return s.run(ctx, o, func(f *os.File) io.Writer { return f })
}

func (s *Store) run(ctx context.Context, o Options, destination func(*os.File) io.Writer) (Record, error) {
	if len(o.Argv) == 0 || o.MaxCaptureBytes <= 0 || o.RetentionHours <= 0 || o.RetentionHours > 8760 || math.IsNaN(o.RetentionHours) || math.IsInf(o.RetentionHours, 0) {
		return Record{}, errors.New("argv, positive capture limit and retention <=8760 hours required")
	}
	c, e := s.create(o.Session, o.Argv, o.RetentionHours)
	if e != nil {
		return Record{}, e
	}
	defer c.close()
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	out, errout := newStream(destination(c.out), o.MaxCaptureBytes), newStream(destination(c.err), o.MaxCaptureBytes)
	unstarted := func(problem error) (Record, error) {
		c.record.CommandStatus = "spawn_failed"
		c.record.CaptureStatus = "complete"
		c.record.Finished = time.Now().UTC()
		c.record.Out = out.snapshot()
		c.record.Err = errout.snapshot()
		if se := c.save(); se != nil {
			c.record.CaptureStatus = "partial"
			c.record.CaptureError = se.Error()
			return c.record, errors.Join(problem, se)
		}
		return c.record, problem
	}

	exe, resolveError := executable(o.Argv[0], o.Cwd, o.Env)
	cmd := exec.Command(exe, o.Argv[1:]...)
	cmd.Args = append([]string(nil), o.Argv...)
	cmd.Dir = o.Cwd
	cmd.Env = o.Env
	cmd.Stdin = o.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Explicit pipes decouple direct-child wait from inherited background FDs.
	ro, wo, e := os.Pipe()
	if e != nil {
		return unstarted(e)
	}
	defer ro.Close()
	defer wo.Close()
	re, we, e := os.Pipe()
	if e != nil {
		return unstarted(e)
	}
	defer re.Close()
	defer we.Close()
	cmd.Stdout = wo
	cmd.Stderr = we
	c.record.CommandStatus = "not_started"
	if resolveError != nil {
		e = resolveError
	} else if ctx.Err() != nil {
		e = ctx.Err()
	} else {
		e = cmd.Start()
	}
	if e != nil {
		return unstarted(e)
	}
	wo.Close()
	we.Close()
	drained := make(chan struct{}, 2)
	go func() { _, e := io.Copy(out, ro); out.fail(e); drained <- struct{}{} }()
	go func() { _, e := io.Copy(errout, re); errout.fail(e); drained <- struct{}{} }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	interval := o.ProgressInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var escalation <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	cancelled := false
	ctxDone := ctx.Done()
	signals := o.Signals
	cancel := func(sig syscall.Signal) {
		_ = syscall.Kill(-cmd.Process.Pid, sig)
		if !cancelled {
			cancelled = true
			timer = time.NewTimer(250 * time.Millisecond)
			escalation = timer.C
		}
	}
waitLoop:
	for {
		select {
		case e = <-waited:
			break waitLoop
		case <-ctxDone:
			ctxDone = nil
			cancel(syscall.SIGTERM)
		case sig, ok := <-signals:
			if !ok {
				signals = nil
			} else if n, ok := sig.(syscall.Signal); ok {
				cancel(n)
			}
		case <-escalation:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			escalation = nil
		case <-ticker.C:
			fmt.Fprintf(o.Stderr, "\n[capture running ref=%s stdout_bytes=%d stderr_bytes=%d]\n", c.record.Ref, out.snapshot().Observed, errout.snapshot().Observed)
			_, _ = o.Stderr.Write(out.preview(true))
			_, _ = o.Stderr.Write(errout.preview(true))
		}
	}
	// Background jobs are scoped to this invocation, not persistent session jobs.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	grace := time.NewTimer(100 * time.Millisecond)
	<-grace.C
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for n := 0; n < 2; {
		select {
		case <-drained:
			n++
		case <-deadline.C:
			out.fail(errors.New("pipe drain deadline; descendant may have escaped process group"))
			errout.fail(errors.New("pipe drain deadline; descendant may have escaped process group"))
			ro.Close()
			re.Close()
			for n < 2 {
				<-drained
				n++
			}
		}
	}
	out.fail(c.out.Sync())
	errout.fail(c.err.Sync())
	out.fail(c.out.Close())
	errout.fail(c.err.Close())
	c.out = nil
	c.err = nil
	c.record.ExitCode = cmd.ProcessState.ExitCode()
	c.record.CommandStatus = "exited"
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		c.record.Signal = int(status.Signal())
		c.record.ExitCode = 128 + c.record.Signal
		c.record.CommandStatus = "signaled"
	}
	if cancelled {
		c.record.CommandStatus = "cancelled"
	}
	c.record.Out = out.snapshot()
	c.record.Err = errout.snapshot()
	c.record.CaptureStatus = "complete"
	if !c.record.Out.Complete || !c.record.Err.Complete {
		c.record.CaptureStatus = "partial"
	}
	c.record.Finished = time.Now().UTC()
	// Retention is measured from completion; a long run cannot expire mid-run.
	c.record.Expires = c.record.Finished.Add(time.Duration(o.RetentionHours * float64(time.Hour)))
	if se := c.save(); se != nil {
		c.record.CaptureStatus = "partial"
		c.record.CaptureError = "metadata write failed: " + se.Error()
	}
	if _, pe := o.Stdout.Write(out.preview(false)); pe != nil {
		c.record.CaptureError = "presentation failed: " + pe.Error()
	}
	if _, pe := o.Stderr.Write(errout.preview(false)); pe != nil {
		c.record.CaptureError = "presentation failed: " + pe.Error()
	}
	if c.record.CaptureError != "" {
		if se := c.save(); se != nil {
			c.record.CaptureStatus = "partial"
			c.record.CaptureError += "; metadata update failed: " + se.Error()
		}
	}
	// A nonzero command exit is an outcome, not a capture API error.
	return c.record, nil
}

// Resolve against the explicit child PATH, not the wrapper's PATH. Relative
// PATH components are resolved against the requested command cwd.
func executable(name, cwd string, env []string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return name, nil
	}
	if env == nil {
		return exec.LookPath(name)
	}
	path := ""
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			path = strings.TrimPrefix(entry, "PATH=")
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(cwd, dir)
		}
		candidate, e := filepath.Abs(filepath.Join(dir, name))
		if e != nil {
			continue
		}
		st, e := os.Stat(candidate)
		if e == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
			return candidate, nil
		}
	}
	return name, errors.New("executable not found in explicit child PATH; pass an executable path or set PATH")
}
