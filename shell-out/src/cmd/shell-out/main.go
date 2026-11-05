package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-services/shell-out/internal/capture"
)

type envFlags []string

func (e *envFlags) String() string { return "NAME=value (repeatable)" }
func (e *envFlags) Set(s string) error {
	n, _, ok := strings.Cut(s, "=")
	if !ok || n == "" || strings.ContainsRune(s, 0) {
		return fmt.Errorf("env requires NAME=value")
	}
	*e = append(*e, s)
	return nil
}
func main() {
	var childSignal syscall.Signal
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, func(s syscall.Signal) { childSignal = s })
	if childSignal != 0 {
		// Exec resets caught signal handlers. Killing the Go runtime directly
		// would turn QUIT/ABRT into a runtime traceback and numeric exit 2.
		// The fixed POSIX helper receives only the numeric signal, no user text
		// or environment. Its PID is this wrapper's PID, and finalization is done.
		signal.Notify(make(chan os.Signal, 1), childSignal)
		_ = syscall.Exec("/bin/sh", []string{"sh", "-c", fmt.Sprintf("kill -%d $$; exit %d", childSignal, code)}, []string{})
	}
	os.Exit(code)
}
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, signaled func(syscall.Signal)) int {
	out, errout := capture.NewPresentation(stdout), capture.NewPresentation(stderr)
	defer out.Close()
	defer errout.Close()
	code := runPresented(args, stdin, out, errout, signaled)
	oe, ee := out.Flush(), errout.Flush()
	if (oe != nil || ee != nil) && code == 0 {
		return 125
	}
	return code
}
func runPresented(args []string, stdin io.Reader, stdout, stderr io.Writer, signaled func(syscall.Signal)) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: shell-out run|lookup|purge [options] -- argv...")
		return 125
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(stderr)
	cwd := f.String("cwd", ".", "command working directory / project for ref lookup")
	session := f.String("session", "manual", "non-secret session label: lowercase letters, digits, hyphens")
	retention := f.Float64("retention-hours", 24, "retention from completion in hours (0 < hours <= 8760)")
	limit := f.Int64("max-capture-bytes", 64<<20, "maximum saved bytes per stream; excess explicitly partial")
	progress := f.Duration("progress", 5*time.Second, "interval between bounded progress previews")
	timeout := f.Duration("timeout", 0, "command timeout (zero disables)")
	empty := f.Bool("clear-env", false, "start with empty environment")
	var env envFlags
	f.Var(&env, "env", "explicit environment override NAME=value (repeatable)")
	if e := f.Parse(args[1:]); e != nil {
		return 125
	}
	if math.IsNaN(*retention) || math.IsInf(*retention, 0) || *retention <= 0 || *retention > 8760 || *limit <= 0 || *timeout < 0 || *progress <= 0 {
		fmt.Fprintln(stderr, "invalid numeric option")
		return 125
	}
	if args[0] != "run" && args[0] != "lookup" && args[0] != "purge" {
		fmt.Fprintln(stderr, "unknown subcommand")
		return 125
	}
	if args[0] == "run" && len(f.Args()) == 0 {
		fmt.Fprintln(stderr, "run requires explicit argv; use -- bash -c SCRIPT for shell syntax")
		return 125
	}
	s, e := capture.OpenStore(*cwd)
	if e != nil {
		fmt.Fprintln(stderr, "capture not started:", e)
		return 125
	}
	defer s.Close()
	switch args[0] {
	case "lookup":
		if len(f.Args()) != 1 {
			fmt.Fprintln(stderr, "lookup requires session/ref")
			return 125
		}
		r, e := s.Lookup(f.Args()[0])
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 125
		}
		if e = json.NewEncoder(stdout).Encode(r); e != nil {
			return 125
		}
		return 0
	case "purge":
		if len(f.Args()) != 0 {
			return 125
		}
		n, e := s.Purge(time.Now())
		fmt.Fprintf(stdout, "purged %d expired captures\n", n)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 125
		}
		return 0
	}
	childEnv := os.Environ()
	if *empty {
		childEnv = []string{}
	}
	for _, v := range env {
		key, _, _ := strings.Cut(v, "=")
		next := make([]string, 0, len(childEnv)+1)
		for _, old := range childEnv {
			if !strings.HasPrefix(old, key+"=") {
				next = append(next, old)
			}
		}
		childEnv = append(next, v)
	}
	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	r, e := s.Run(ctx, capture.Options{Argv: f.Args(), Cwd: *cwd, Env: childEnv, Stdin: stdin, Session: *session, RetentionHours: *retention, MaxCaptureBytes: *limit, ProgressInterval: *progress, Stdout: stdout, Stderr: stderr, Signals: signals})
	if e != nil {
		fmt.Fprintln(stderr, "capture:", e)
	}
	// Every started attempt ends with a machine-readable ref, separate from output.
	if r.Ref != "" {
		fmt.Fprint(stderr, "\n\x1e[shell-out result] ")
		if je := json.NewEncoder(stderr).Encode(r); je != nil {
			return 125
		}
	}
	if r.Ref == "" || r.CommandStatus == "spawn_failed" {
		return 125
	}
	if r.Signal != 0 && signaled != nil {
		signaled(syscall.Signal(r.Signal))
	}
	if r.ExitCode != 0 {
		return r.ExitCode
	}
	if e != nil || r.CaptureStatus != "complete" || r.CaptureError != "" {
		return 125
	}
	return 0
}
