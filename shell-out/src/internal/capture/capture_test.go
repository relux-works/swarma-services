package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func project(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	var pe error
	p, pe = filepath.EvalSymlinks(p)
	if pe != nil {
		t.Fatal(pe)
	}
	c := exec.Command("git", "init", "-q", p)
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatalf("git init: %v %s", e, b)
	}
	return p
}
func store(t *testing.T) (*Store, string) {
	t.Helper()
	p := project(t)
	s, e := OpenStore(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.initialize(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}
func options(p, script string) Options {
	return Options{Argv: []string{"/bin/bash", "-c", script}, Cwd: p, Session: "test", RetentionHours: 1, MaxCaptureBytes: 1 << 20, ProgressInterval: time.Hour}
}
func runScript(t *testing.T, s *Store, p, script string) (Record, []byte, []byte) {
	t.Helper()
	var out, errout bytes.Buffer
	o := options(p, script)
	o.Stdout = &out
	o.Stderr = &errout
	r, e := s.Run(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	return r, out.Bytes(), errout.Bytes()
}
func logs(t *testing.T, r Record) ([]byte, []byte) {
	t.Helper()
	a, e := os.ReadFile(r.Stdout)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(r.Stderr)
	if e != nil {
		t.Fatal(e)
	}
	return a, b
}

func TestExactSmallStreamsStatusAndPrivateRef(t *testing.T) {
	s, p := store(t)
	r, a, b := runScript(t, s, p, "printf 'alpha\\nno-final-newline'; printf 'error\\n' >&2; exit 7")
	wantA, wantB := []byte("alpha\nno-final-newline"), []byte("error\n")
	if !bytes.Equal(a, wantA) || !bytes.Equal(b, wantB) {
		t.Fatalf("small preview changed: %q %q", a, b)
	}
	ca, cb := logs(t, r)
	if !bytes.Equal(ca, wantA) || !bytes.Equal(cb, wantB) || r.ExitCode != 7 || r.CaptureStatus != "complete" || r.Out.Observed != int64(len(ca)) || r.Out.Saved != r.Out.Observed {
		t.Fatalf("bad result: %+v", r)
	}
	for _, path := range []string{r.Stdout, r.Stderr, strings.TrimSuffix(r.Stdout, ".out.log") + ".json"} {
		st, e := os.Stat(path)
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("file mode %v %v", st, e)
		}
	}
	for _, path := range []string{filepath.Join(p, ".temp"), s.Path, filepath.Dir(r.Stdout)} {
		st, e := os.Stat(path)
		if e != nil || st.Mode().Perm() != 0700 {
			t.Fatalf("dir mode %v %v", st, e)
		}
	}
	if _, e := s.Lookup(r.Ref); e != nil {
		t.Fatal(e)
	}
	if _, e := git(p, "check-ignore", "-q", "--", r.Stdout); e != nil {
		t.Fatal("exact capture not ignored")
	}
	if _, e := os.Stat(filepath.Join(p, ".gitignore")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("tracked ignore created")
	}
}
func TestStdinArgvCwdEnvAndShellState(t *testing.T) {
	s, p := store(t)
	o := options(p, "read -r line; printf '%s|%s|%s' \"$line\" \"$VALUE\" \"$PWD\"")
	o.Env = []string{"VALUE=synthetic space"}
	o.Stdin = strings.NewReader("stdin 'literal'\n")
	r, e := s.Run(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := logs(t, r)
	if string(a) != "stdin 'literal'|synthetic space|"+p {
		t.Fatalf("%q", a)
	}
	o = options(p, "")
	o.Argv = []string{"/usr/bin/printf", "%s", "a 'quoted' $literal ; | value"}
	r, e = s.Run(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	a, _ = logs(t, r)
	if string(a) != o.Argv[2] {
		t.Fatalf("argv reinterpreted %q", a)
	}
	r, _, _ = runScript(t, s, p, "cat <<'SAFE'\n$literal 'quotes' ; &&\nSAFE\nmkdir child; cd child; export SESSION_VALUE=one; printf '%s|%s' \"$PWD\" \"$SESSION_VALUE\"")
	a, _ = logs(t, r)
	if string(a) != "$literal 'quotes' ; &&\n"+p+"/child|one" {
		t.Fatalf("heredoc/state %q", a)
	}
	r, _, _ = runScript(t, s, p, "printf '%s|%s' \"$PWD\" \"${SESSION_VALUE-unset}\"")
	a, _ = logs(t, r)
	if string(a) != p+"|unset" {
		t.Fatalf("subprocess state leaked %q", a)
	}
}
func TestPipelinePipefailAndSignal(t *testing.T) {
	s, p := store(t)
	for _, tc := range []struct {
		script string
		code   int
	}{{"false | cat", 0}, {"set -o pipefail; false | cat", 1}, {"exit 23", 23}, {"kill -TERM $$", 143}} {
		r, _, _ := runScript(t, s, p, tc.script)
		if r.ExitCode != tc.code {
			t.Fatalf("%s: %+v", tc.script, r)
		}
		if tc.code == 143 && r.Signal != 15 {
			t.Fatal(r)
		}
	}
}
func TestBoundedPreviewGiantLineControlsBinaryAndManyLines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		data   []byte
		binary bool
	}{{"giant", bytes.Repeat([]byte("x"), 100000), false}, {"lines", bytes.Repeat([]byte("x\n"), 10000), false}, {"control", bytes.Repeat([]byte("\x1b[31m\r\b"), 10000), false}, {"binary", []byte{'a', 0, 'b'}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			var disk bytes.Buffer
			s := newStream(&disk, 1<<20)
			for i := 0; i < len(tc.data); i += 997 {
				s.Write(tc.data[i:min(i+997, len(tc.data))])
			}
			p := s.preview(false)
			if len(p) > previewBytes+128 || bytes.Count(p, []byte{'\n'}) > previewLines+5 || bytes.ContainsAny(p, "\x1b\r\b\x00") {
				t.Fatalf("unsafe/unbounded preview bytes=%d lines=%d", len(p), bytes.Count(p, []byte{'\n'}))
			}
			if tc.binary && !bytes.Contains(p, []byte("binary output")) {
				t.Fatal("binary printed")
			}
			if !bytes.Equal(disk.Bytes(), tc.data) {
				t.Fatal("capture changed")
			}
		})
	}
}

type failWriter struct{ left int }

func (w *failWriter) Write(p []byte) (int, error) {
	n := min(w.left, len(p))
	w.left -= n
	if n < len(p) {
		return n, syscall.ENOSPC
	}
	return n, nil
}
func TestWriteFailureRetainsBoundedObservedAndCommandOutcome(t *testing.T) {
	s := newStream(&failWriter{left: 10}, 1<<20)
	data := bytes.Repeat([]byte("a"), 20000)
	n, e := s.Write(data)
	s.Write([]byte("tail"))
	st := s.snapshot()
	if n != len(data) || e != nil || st.Complete || st.Saved != 10 || st.Observed != 20004 || st.Error == "" || !bytes.Contains(s.preview(false), []byte("tail")) {
		t.Fatalf("partial capture %+v", st)
	}
	store, p := store(t)
	o := options(p, "printf 1234567890; exit 9")
	o.MaxCaptureBytes = 3
	r, e := store.Run(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := logs(t, r)
	if r.ExitCode != 9 || r.CaptureStatus != "partial" || r.Out.Complete || r.Out.Saved != 3 || r.Out.Observed != 10 || string(a) != "123" {
		t.Fatalf("partial outcome %+v %q", r, a)
	}
}
func TestCancellationProgressAndBackgroundLifecycle(t *testing.T) {
	t.Run("child-readiness-delayed", func(t *testing.T) { cancellationAfterProgress(t, true) })
	t.Run("progress-delayed", func(t *testing.T) { cancellationAfterProgress(t, false) })
	// Retain the existing background-job contract independently of foreground
	// readiness: returning from Run must not leave the background marker writer.
	s, p := store(t)
	r, _, _ := runScript(t, s, p, "(sleep 1; printf escaped > background-marker) & printf foreground")
	time.Sleep(1100 * time.Millisecond)
	if _, e := os.Stat(filepath.Join(p, "background-marker")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("background child survived")
	}
	a, _ := logs(t, r)
	if string(a) != "foreground" {
		t.Fatalf("%q", a)
	}
}
func TestForwardInterruptPreservesActualOutcome(t *testing.T) {
	s, p := store(t)
	signals := make(chan os.Signal, 1)
	o := options(p, "trap 'exit 42' INT; printf ready; while :; do :; done")
	o.Signals = signals
	ready := make(chan bool, 1)
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			files, _ := filepath.Glob(filepath.Join(s.Path, "test", "*.out.log"))
			for _, f := range files {
				b, _ := os.ReadFile(f)
				if bytes.Equal(b, []byte("ready")) {
					ready <- true
					signals <- syscall.SIGINT
					return
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		ready <- false
		signals <- syscall.SIGINT
	}()
	r, e := s.Run(context.Background(), o)
	if !<-ready || e != nil || r.ExitCode != 42 || r.CommandStatus != "cancelled" {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestTTYDifference(t *testing.T) {
	s, p := store(t)
	r, _, _ := runScript(t, s, p, "if test -t 1; then printf tty; else printf pipe; fi; if test -t 2; then exit 8; fi")
	a, _ := logs(t, r)
	if string(a) != "pipe" || r.ExitCode != 0 {
		t.Fatalf("TTY semantics %+v %q", r, a)
	}
}
func TestOpenFailureBeforeSpawnAndSymlinkRefusal(t *testing.T) {
	for _, component := range []string{".temp", ".temp/shell-out", ".temp/shell-out/test"} {
		t.Run(component, func(t *testing.T) {
			p := project(t)
			outside := t.TempDir()
			if e := os.MkdirAll(filepath.Dir(filepath.Join(p, component)), 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink(outside, filepath.Join(p, component)); e != nil {
				t.Fatal(e)
			}
			s, e := OpenStore(p)
			if e == nil {
				defer s.Close()
				_, e = s.Run(context.Background(), options(p, "touch ran"))
			}
			if e == nil {
				t.Fatal("symlink accepted")
			}
			if _, e = os.Stat(filepath.Join(p, "ran")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("spawn occurred")
			}
			items, _ := os.ReadDir(outside)
			if len(items) != 0 {
				t.Fatal("crossed custody")
			}
		})
	}
	s, p := store(t)
	if e := os.WriteFile(filepath.Join(s.Path, "test"), []byte("occupied"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Run(context.Background(), options(p, "touch ran")); e == nil {
		t.Fatal("open failure ignored")
	}
	if _, e := os.Stat(filepath.Join(p, "ran")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("spawn after open failure")
	}
}
func TestIgnoredTrackedAndNotIgnoredPair(t *testing.T) {
	p := project(t)
	dest := filepath.Join(p, ".temp", "shell-out", "test", "log")
	if e := ignoredDestination(p, dest); e == nil {
		t.Fatal("not-ignored destination accepted")
	}
	s, e := OpenStore(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Run(context.Background(), options(p, "true")); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e := ignoredDestination(p, dest); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(p, ".temp", "tracked"), []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	c := exec.Command("git", "-C", p, "add", "-f", ".temp/tracked")
	if e := c.Run(); e != nil {
		t.Fatal(e)
	}
	if s, e := OpenStore(p); e == nil {
		_, e = s.Run(context.Background(), options(p, "true"))
		s.Close()
		if e == nil {
			t.Fatal("tracked destination accepted")
		}
	}
	// A higher-priority project negation defeats info/exclude; tool must refuse.
	q := project(t)
	if e := os.WriteFile(filepath.Join(q, ".gitignore"), []byte("!.temp/\n!.temp/**\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if s, e := OpenStore(q); e == nil {
		_, e = s.Run(context.Background(), options(q, "true"))
		s.Close()
		if e == nil {
			t.Fatal("still not ignored accepted")
		}
	}
}
func TestPurgeRunningExpiredRefAndNonReuse(t *testing.T) {
	s, p := store(t)
	c, e := s.create("test", []string{"/bin/sh"}, 1)
	if e != nil {
		t.Fatal(e)
	}
	c.record.Expires = time.Now().Add(-time.Hour)
	if e = c.save(); e != nil {
		t.Fatal(e)
	}
	if n, e := s.Purge(time.Now()); e != nil || n != 0 {
		t.Fatalf("running removed %d %v", n, e)
	}
	c.record.CommandStatus = "exited"
	c.record.CaptureStatus = "complete"
	if e = c.save(); e != nil {
		t.Fatal(e)
	}
	ref := c.record.Ref
	path := c.record.Stdout
	c.close()
	if n, e := s.Purge(time.Now()); e != nil || n != 1 {
		t.Fatalf("purge %d %v", n, e)
	}
	if _, e := os.Stat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("expired capture retained")
	}
	if _, e := s.Lookup(ref); e == nil || !strings.Contains(e.Error(), "expired") {
		t.Fatalf("expired ref %v", e)
	}
	r, _, _ := runScript(t, s, p, "printf fresh")
	if r.Ref == ref {
		t.Fatal("ref reused")
	}
	if _, e := s.Lookup(ref); e == nil {
		t.Fatal("expired ref revived")
	}
	if n, e := s.Purge(time.Now()); e != nil || n != 0 {
		t.Fatalf("fresh removed %d %v", n, e)
	}
}
func TestPurgeNeverFollowsOutputSymlink(t *testing.T) {
	s, p := store(t)
	r, _, _ := runScript(t, s, p, "printf fixture")
	outside := filepath.Join(t.TempDir(), "keep")
	os.WriteFile(outside, []byte("synthetic keep"), 0600)
	os.Remove(r.Stdout)
	os.Symlink(outside, r.Stdout)
	if _, e := s.Purge(time.Now().Add(2 * time.Hour)); e == nil {
		t.Fatal("unsafe output purge accepted")
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "synthetic keep" {
		t.Fatal("outside changed")
	}
}
func TestConcurrentUniqueAndSecretFreeNames(t *testing.T) {
	s, p := store(t)
	done := make(chan Record, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			r, e := s.Run(context.Background(), options(p, "printf synthetic-secret-argument"))
			done <- r
			errs <- e
		}()
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		r := <-done
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
		if seen[r.Ref] || strings.Contains(r.Ref, "secret") {
			t.Fatal(r.Ref)
		}
		seen[r.Ref] = true
	}
	if slug([]string{"/private/path/secret-token-executable", "secret-argument"}) != "command" {
		t.Fatal("unsafe slug")
	}
}
func TestNonGitPrivateCacheAndInvalidRef(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("XDG fixture is Linux-specific; Darwin uses UserCacheDir")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	p := t.TempDir()
	s, e := OpenStore(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if !strings.HasPrefix(s.Path, cache+string(os.PathSeparator)) {
		t.Fatal(s.Path)
	}
	if _, e := s.Lookup("../../outside"); e == nil {
		t.Fatal("ref traversal accepted")
	}
}

// Keep platform branching local; no native shell assumptions enter production.

var _ io.Writer = (*stream)(nil)

func TestExplicitChildPATHAndNoImplicitFallback(t *testing.T) {
	s, p := store(t)
	bin := filepath.Join(p, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "fixture"), []byte("#!/bin/sh\nprintf child-path"), 0700)
	o := options(p, "")
	o.Argv = []string{"fixture"}
	o.Env = []string{"PATH=bin"}
	r, e := s.Run(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := logs(t, r)
	if string(a) != "child-path" {
		t.Fatalf("%q", a)
	}
	o.Env = []string{}
	r, e = s.Run(context.Background(), o)
	if e == nil || r.CommandStatus != "spawn_failed" {
		t.Fatalf("ambient PATH used %+v %v", r, e)
	}
}
func TestInvalidUTF8SplitUTF8AndLogicalLineBounds(t *testing.T) {
	s := newStream(io.Discard, 1<<20)
	s.Write([]byte{0xff, 0xfe})
	if !bytes.Contains(s.preview(false), []byte("binary output")) {
		t.Fatal("invalid UTF8 printed")
	}
	s = newStream(io.Discard, 1<<20)
	s.Write([]byte{0xe2})
	s.Write([]byte{0x82, 0xac})
	if string(s.preview(false)) != "€" {
		t.Fatal("split valid UTF8 misclassified")
	}
	s = newStream(io.Discard, 1<<20)
	s.Write(bytes.Repeat([]byte("a\n"), 40))
	s.Write([]byte("last"))
	if s.snapshot().Lines != 41 || bytes.Equal(s.preview(false), append(bytes.Repeat([]byte("a\n"), 40), []byte("last")...)) {
		t.Fatal("partial final line escaped line budget")
	}
	s = newStream(io.Discard, 1<<20)
	s.Write([]byte("safe\u009b31m\u202e"))
	if bytes.ContainsAny(s.preview(false), "\u009b\u202e") {
		t.Fatal("Unicode controls unescaped")
	}
}
func TestEscapedDescendantReportsPartial(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip("python3 required for setsid fixture")
	}
	s, p := store(t)
	o := options(p, "")
	o.Argv = []string{python, "-c", "import os,time; p=os.fork(); (os.setsid(),time.sleep(2.0),os._exit(0)) if p==0 else None"}
	r, e := s.Run(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	if r.ExitCode != 0 || r.CaptureStatus != "partial" || r.Out.Complete || r.Err.Complete {
		t.Fatalf("escaped inherited pipes called complete %+v", r)
	}
}
func TestPurgeRefusesHardlinkedMetadata(t *testing.T) {
	s, p := store(t)
	r, _, _ := runScript(t, s, p, "true")
	meta := strings.TrimSuffix(r.Stdout, ".out.log") + ".json"
	outside := filepath.Join(t.TempDir(), "linked")
	if e := os.Link(meta, outside); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(outside)
	if _, e := s.Purge(time.Now().Add(2 * time.Hour)); e == nil {
		t.Fatal("hardlinked metadata accepted")
	}
	after, _ := os.ReadFile(outside)
	if !bytes.Equal(before, after) {
		t.Fatal("outside metadata modified")
	}
}

type failingFile struct {
	dst       io.Writer
	remaining int
}

func (f *failingFile) Write(p []byte) (int, error) {
	n := min(len(p), f.remaining)
	written, e := f.dst.Write(p[:n])
	f.remaining -= written
	if e != nil {
		return written, e
	}
	if n < len(p) {
		return written, syscall.ENOSPC
	}
	return written, nil
}
func TestMidRunDiskFailureKeepsExitRefAndObservedTail(t *testing.T) {
	s, p := store(t)
	var out bytes.Buffer
	o := options(p, "printf '0123456789'; for ((i=0;i<100;i++)); do printf synthetic; done; printf THE-END; exit 19")
	o.Stdout = &out
	r, e := s.run(context.Background(), o, func(f *os.File) io.Writer { return &failingFile{dst: f, remaining: 10} })
	if e != nil {
		t.Fatal(e)
	}
	a, _ := logs(t, r)
	if r.ExitCode != 19 || r.CaptureStatus != "partial" || r.Out.Saved != 10 || r.Out.Observed != 917 || string(a) != "0123456789" || !strings.Contains(out.String(), "THE-END") || r.Out.Error == "" {
		t.Fatalf("disk failure lost outcome/preview %+v %q", r, out.String())
	}
	saved, e := s.Lookup(r.Ref)
	if e != nil || saved.CaptureStatus != "partial" || saved.ExitCode != 19 {
		t.Fatalf("partial metadata %+v %v", saved, e)
	}
}
func TestLookupRejectsMetadataPathRedirect(t *testing.T) {
	s, p := store(t)
	r, _, _ := runScript(t, s, p, "printf synthetic")
	cpath := strings.TrimSuffix(r.Stdout, ".out.log") + ".json"
	r.Stdout = "/unrelated/private/path"
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(cpath, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Lookup(r.Ref); e == nil {
		t.Fatal("metadata redirected ref")
	}
}
