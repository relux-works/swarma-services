package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReviewExcludeSymlinks(t *testing.T) {
	for _, component := range []string{"exclude", "info"} {
		t.Run(component, func(t *testing.T) {
			p := project(t)
			outside := t.TempDir()
			target := filepath.Join(outside, "exclude")
			os.WriteFile(target, []byte("KEEP\n"), 0600)
			info := filepath.Join(p, ".git", "info")
			if component == "info" {
				os.RemoveAll(info)
				os.Symlink(outside, info)
			} else {
				os.Remove(filepath.Join(info, "exclude"))
				os.Symlink(target, filepath.Join(info, "exclude"))
			}
			s, e := OpenStore(p)
			if e == nil {
				_, e = s.Run(context.Background(), options(p, "touch ran"))
				s.Close()
			}
			if e == nil {
				t.Error("unsafe exclude accepted")
			}
			b, _ := os.ReadFile(target)
			if string(b) != "KEEP\n" {
				t.Error("outside file changed")
			}
			if _, e := os.Stat(filepath.Join(p, "ran")); !errors.Is(e, os.ErrNotExist) {
				t.Error("spawn occurred")
			}
		})
	}
}

func TestReviewPurgeContinuesAfterTornMetadata(t *testing.T) {
	for _, kind := range []string{"empty", "torn", "symlink", "fifo", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			s, p := store(t)
			r, _, _ := runScript(t, s, p, "true")
			broken := filepath.Join(filepath.Dir(r.Stdout), "20000101-000000_sh_00000000000000000000000000000000.json")
			outside := filepath.Join(t.TempDir(), "keep")
			os.WriteFile(outside, []byte("KEEP"), 0600)
			var e error
			switch kind {
			case "empty":
				e = os.WriteFile(broken, nil, 0600)
			case "torn":
				e = os.WriteFile(broken, []byte("{\"ref\":"), 0600)
			case "symlink":
				e = os.Symlink(outside, broken)
			case "fifo":
				e = syscall.Mkfifo(broken, 0600)
			case "hardlink":
				e = os.Link(outside, broken)
			}
			if e != nil {
				t.Fatal(e)
			}
			n, e := s.Purge(time.Now().Add(2 * time.Hour))
			if n != 1 || e == nil {
				t.Fatalf("want reclamation and warning: n=%d warning=%v", n, e)
			}
			if _, e = os.Stat(r.Stdout); !errors.Is(e, os.ErrNotExist) {
				t.Error("valid expired log retained")
			}
			b, _ := os.ReadFile(outside)
			if string(b) != "KEEP" {
				t.Error("outside file changed")
			}
		})
	}
}

func TestReviewRefusalDoesNotMutate(t *testing.T) {
	for _, kind := range []string{"negation", "mode", "exact-negation", "metadata-temp-negation", "invalid-session"} {
		t.Run(kind, func(t *testing.T) {
			p := project(t)
			exclude := filepath.Join(p, ".git", "info", "exclude")
			before, _ := os.ReadFile(exclude)
			switch kind {
			case "negation":
				os.WriteFile(filepath.Join(p, ".gitignore"), []byte("!.temp/\n!.temp/**\n"), 0600)
			case "exact-negation":
				os.WriteFile(filepath.Join(p, ".gitignore"), []byte(".temp/shell-out/probe\n!.temp/shell-out/test/*\n"), 0600)
			case "metadata-temp-negation":
				os.WriteFile(filepath.Join(p, ".gitignore"), []byte("!.temp/shell-out/test/*.json.tmp-[a-f0-9]*\n"), 0600)
			case "mode":
				os.Mkdir(filepath.Join(p, ".temp"), 0770)
				os.Chmod(filepath.Join(p, ".temp"), 0770)
			}
			for i := 0; i < 2; i++ {
				s, e := OpenStore(p)
				if e == nil {
					o := options(p, "touch ran")
					if kind == "invalid-session" {
						o.Session = "../bad"
					}
					_, e = s.Run(context.Background(), o)
					s.Close()
				}
				if e == nil {
					t.Error("refusal expected")
				}
			}
			after, _ := os.ReadFile(exclude)
			if !bytes.Equal(before, after) {
				t.Error("exclude mutated on refusal")
			}
			st, e := os.Stat(filepath.Join(p, ".temp"))
			if kind == "mode" {
				if e != nil || st.Mode().Perm() != 0770 {
					t.Error("existing .temp mode changed")
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				t.Error("custody created on refusal")
			}
		})
	}
}

func TestReviewSmallTabsAndLatestProgress(t *testing.T) {
	s := newStream(io.Discard, 1<<20)
	s.Write([]byte("a\tb\n"))
	if string(s.preview(false)) != "a\tb\n" {
		t.Error("small tab bytes changed")
	}
	s = newStream(io.Discard, 1<<20)
	for i := 0; i < 200; i++ {
		fmt.Fprintf(s, "line-%03d\n", i)
	}
	b := s.preview(true)
	if !bytes.Contains(b, []byte("line-199")) || bytes.Contains(b, []byte("line-000")) {
		t.Error("progress does not show latest lines")
	}
}

func TestReviewBlockedPresentationCancellation(t *testing.T) {
	s, p := store(t)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	o := options(p, "printf child-stderr >&2; while :; do :; done")
	o.Stderr = writer
	o.ProgressInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan Record, 1)
	go func() { r, _ := s.Run(ctx, o); done <- r }()
	select {
	case r := <-done:
		if r.CommandStatus != "cancelled" {
			t.Error("deadline not honored")
		}
	case <-time.After(2 * time.Second):
		reader.Close()
		<-done
		t.Fatal("blocked presentation defeated deadline")
	}
}

func TestReviewDrainPerStream(t *testing.T) {
	python, e := executable("python3", "", nil)
	if e != nil {
		t.Skip("python3 fixture unavailable")
	}
	s, p := store(t)
	o := options(p, "")
	o.Argv = []string{python, "-c", "import os,time; p=os.fork(); (os.setsid(),os.close(1),time.sleep(1.8),os._exit(0)) if p==0 else None"}
	r, e := s.Run(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Out.Complete || r.Err.Complete || !strings.Contains(r.Err.Error, "drain deadline") {
		t.Error("drain status not specific to held stderr")
	}
}

func TestReviewAtomicMetadataReplacement(t *testing.T) {
	s, _ := store(t)
	c, e := s.create("test", []string{"/bin/sh"}, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer c.close()
	path := c.name + ".json"
	pinned, e := c.dir.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer pinned.Close()
	before, e := io.ReadAll(pinned)
	if e != nil {
		t.Fatal(e)
	}
	c.record.CommandStatus = "exited"
	if e = c.save(); e != nil {
		t.Fatal(e)
	}
	pinned.Seek(0, 0)
	old, _ := io.ReadAll(pinned)
	if !bytes.Equal(old, before) {
		t.Error("save modified published inode in place")
	}
	after, _ := c.dir.ReadFile(path)
	if bytes.Equal(after, before) {
		t.Error("new metadata not published")
	}
	// A failed atomic save must leave the previous published JSON byte-exact.
	dirPath := filepath.Dir(c.record.Stdout)
	os.Chmod(dirPath, 0500)
	defer os.Chmod(dirPath, 0700)
	c.record.CommandStatus = "cancelled"
	if e = c.save(); e == nil {
		t.Error("read-only directory did not fail atomic save")
	}
	final, _ := c.dir.ReadFile(path)
	if !bytes.Equal(final, after) {
		t.Error("failed save damaged published metadata")
	}
}

func TestReviewCreateFailureHelper(t *testing.T) {
	if os.Getenv("SHELL_OUT_CREATE_FAILURE_HELPER") != "1" {
		return
	}
	s, e := OpenStore(os.Getenv("SHELL_OUT_FIXTURE_PROJECT"))
	if e != nil {
		os.Exit(91)
	}
	defer s.Close()
	// Synthetic kernel write failure, isolated from the parent test process.
	signal.Ignore(syscall.SIGXFSZ)
	if e = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 1, Max: 1}); e != nil {
		os.Exit(92)
	}
	c, e := s.create("test", []string{"/bin/sh"}, 1)
	if c != nil {
		c.close()
	}
	if e == nil {
		os.Exit(93)
	}
	os.Exit(0)
}
func TestReviewCreateFailureCleansPartialFiles(t *testing.T) {
	s, p := store(t)
	os.Mkdir(filepath.Join(s.Path, "test"), 0700)
	// Ignore setup precedes the file-size limit so only record creation fails.
	if _, e := git(p, "config", "--local", "core.excludesFile", "/dev/null"); e != nil {
		t.Fatal(e)
	}
	exclude := filepath.Join(p, ".git", "info", "exclude")
	os.WriteFile(exclude, []byte("/.temp/\n"), 0600)
	cmd := exec.Command(os.Args[0], "-test.run=^TestReviewCreateFailureHelper$")
	cmd.Env = append(os.Environ(), "SHELL_OUT_CREATE_FAILURE_HELPER=1", "SHELL_OUT_FIXTURE_PROJECT="+p)
	if e := cmd.Run(); e != nil {
		t.Fatal("isolated create failure helper", e)
	}
	entries, e := os.ReadDir(filepath.Join(s.Path, "test"))
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 0 {
		t.Errorf("failed create left %d partial artifacts", len(entries))
	}
}

func TestReviewLegacyRecordRemainsReadableAndPurgeable(t *testing.T) {
	s, p := store(t)
	r, _, _ := runScript(t, s, p, "true")
	os.Remove(strings.TrimSuffix(r.Stdout, ".out.log") + ".lock")
	if _, e := s.Lookup(r.Ref); e != nil {
		t.Fatal("legacy lookup", e)
	}
	if n, e := s.Purge(time.Now().Add(2 * time.Hour)); e != nil || n != 1 {
		t.Fatal("legacy purge", n, e)
	}
}

func TestReviewLinkedWorktreeCommonExclude(t *testing.T) {
	p := project(t)
	cmd := exec.Command("git", "-C", p, "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "fixture")
	if e := cmd.Run(); e != nil {
		t.Fatal(e)
	}
	work := filepath.Join(t.TempDir(), "linked")
	if _, e := git(p, "worktree", "add", "--detach", work, "HEAD"); e != nil {
		t.Fatal(e)
	}
	s, e := OpenStore(work)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r, _, _ := runScript(t, s, work, "true")
	if _, e = s.Lookup(r.Ref); e != nil {
		t.Fatal(e)
	}
	exclude := filepath.Join(p, ".git", "info", "exclude")
	b, e := os.ReadFile(exclude)
	if e != nil || !bytes.Contains(b, []byte("/.temp/")) {
		t.Fatal("common exclude not used")
	}
	outside := filepath.Join(t.TempDir(), "keep")
	os.WriteFile(outside, []byte("KEEP"), 0600)
	os.Remove(exclude)
	os.Symlink(outside, exclude)
	if _, e = s.Run(context.Background(), options(work, "touch ran")); e == nil {
		t.Fatal("linked worktree exclude symlink accepted")
	}
	b, _ = os.ReadFile(outside)
	if string(b) != "KEEP" {
		t.Error("linked worktree escaped common custody")
	}
}
