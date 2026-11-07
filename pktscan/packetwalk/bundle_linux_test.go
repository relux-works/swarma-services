//go:build linux

package packetwalk

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type gitFixture struct {
	g   gitRepo
	dir string
	t   *testing.T
}

func newGitFixture(t *testing.T) *gitFixture {
	t.Helper()
	d := t.TempDir()
	home := filepath.Join(d, "home")
	repo := filepath.Join(d, "repo")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(repo, 0700); e != nil {
		t.Fatal(e)
	}
	l := DefaultLimits()
	l.Commands = 4096
	l.CommandBytes = 128 << 20
	w := &walker{ctx: context.Background(), l: l}
	f := &gitFixture{g: gitRepo{w: w, dir: repo, home: home, tool: "/usr/bin/git"}, dir: d, t: t}
	f.run("init", "--template=", ".")
	return f
}
func (f *gitFixture) run(args ...string) []byte {
	f.t.Helper()
	b, e := f.g.run(args...)
	if e != nil {
		f.t.Fatalf("synthetic fixture command %s: %v", args[0], e)
	}
	return b
}
func (f *gitFixture) commit(name string, b []byte) string {
	f.t.Helper()
	p := filepath.Join(f.g.dir, name)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		f.t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0600); e != nil {
		f.t.Fatal(e)
	}
	f.run("add", "--all")
	f.run("-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "synthetic change")
	return strings.TrimSpace(string(f.run("rev-parse", "HEAD")))
}
func (f *gitFixture) bundle(name string, revs ...string) []byte {
	f.t.Helper()
	p := filepath.Join(f.dir, name)
	f.run(append([]string{"bundle", "create", "--version=2", p}, revs...)...)
	b, e := os.ReadFile(p)
	if e != nil {
		f.t.Fatal(e)
	}
	return b
}
func bundleOpts(t *testing.T, s BundleScope) *BundleOptions {
	t.Helper()
	d := filepath.Join(t.TempDir(), "quarantine")
	if e := os.Mkdir(d, 0700); e != nil {
		t.Fatal(e)
	}
	return &BundleOptions{GitPath: "/usr/bin/git", TempDir: d, Resolve: func(context.Context, string) (BundleScope, error) { return s, nil }}
}

func TestBundleDeltaActualObjectsAndCleanup(t *testing.T) {
	f := newGitFixture(t)
	base := f.commit("old.txt", []byte("baseline-only marker\n"))
	baseBundle := f.bundle("base.bundle", "HEAD")
	current := f.commit("src/new.txt", []byte("current-only marker\n"))
	thin := f.bundle("thin.bundle", "HEAD", "^"+base)
	git := bundleOpts(t, BundleScope{Current: current, Base: base, BaseBundle: baseBundle})
	r, files, e := runPacket(t, "change.bundle", thin, Options{Limits: DefaultLimits(), Git: git})
	if e != nil {
		t.Fatal(e)
	}
	var content []byte
	for _, file := range files {
		content = append(content, file.Bytes...)
	}
	if !bytes.Contains(content, []byte("current-only marker")) || bytes.Contains(content, []byte("baseline-only marker")) {
		t.Fatal("incorrect actual delta object scope")
	}
	if !bytes.Contains(content, []byte("src/new.txt")) {
		t.Fatal("full tree paths not visited")
	}
	if r.Commands == 0 || r.Containers != 2 || r.Leaves == 0 {
		t.Fatalf("bundle was not inspected: %+v", r)
	}
	es, e := os.ReadDir(git.TempDir)
	if e != nil || len(es) != 0 {
		t.Fatal("quarantine retained")
	}
}

func TestBundleFullScopeAndNestedBlob(t *testing.T) {
	f := newGitFixture(t)
	nested := zipPacket(t, zipEntry{"note.txt", []byte("nested git marker"), 0})
	current := f.commit("packet.dat", nested)
	b := f.bundle("full.bundle", "HEAD")
	r, files, e := runPacket(t, "source.bundle", b, Options{Limits: DefaultLimits(), Git: bundleOpts(t, BundleScope{Current: current})})
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, file := range files {
		if bytes.Equal(file.Bytes, []byte("nested git marker")) {
			found = true
		}
	}
	if !found || r.Containers != 2 {
		t.Fatal("nested source blob not inspected")
	}
}

func TestBundleRefusalControls(t *testing.T) {
	f := newGitFixture(t)
	base := f.commit("base.txt", []byte("safe baseline"))
	baseline := f.bundle("base.bundle", "HEAD")
	current := f.commit("next.txt", []byte("safe change"))
	thin := f.bundle("thin.bundle", "HEAD", "^"+base)
	full := f.bundle("full.bundle", "HEAD")
	other := f.commit("unrelated.txt", []byte("later unrelated object"))
	extras := f.bundle("extras.bundle", "HEAD")
	for _, which := range []string{"missing-policy", "missing-prerequisites", "wrong-current", "extras", "commands", "output", "deadline", "truncated"} {
		t.Run(which, func(t *testing.T) {
			l := DefaultLimits()
			data := full
			s := BundleScope{Current: current}
			g := bundleOpts(t, s)
			switch which {
			case "missing-policy":
				g = nil
			case "missing-prerequisites":
				data = thin
			case "wrong-current":
				g = bundleOpts(t, BundleScope{Current: strings.Repeat("f", 40)})
			case "extras":
				data = extras
				_ = other
			case "commands":
				l.Commands = 1
			case "output":
				l.CommandBytes = 1
			case "deadline":
				l.Duration = time.Nanosecond
			case "truncated":
				data = full[:len(full)-8]
			}
			r, _, e := runPacket(t, "bad.bundle", data, Options{Limits: l, Git: g})
			if e == nil || r != (Report{}) {
				t.Fatalf("invalid bundle accepted: %+v %v", r, e)
			}
			if g != nil {
				es, er := os.ReadDir(g.TempDir)
				if er != nil || len(es) != 0 {
					t.Fatal("failure retained quarantine")
				}
			}
		})
	}
	// Correct adjacent baseline supplies actual prerequisite objects.
	if _, _, e := runPacket(t, "valid.bundle", thin, Options{Limits: DefaultLimits(), Git: bundleOpts(t, BundleScope{Current: current, Base: base, BaseBundle: baseline})}); e != nil {
		t.Fatal(e)
	}
}

func TestBundleBinaryAndGitLinksRefused(t *testing.T) {
	for _, which := range []string{"binary", "symlink", "submodule"} {
		t.Run(which, func(t *testing.T) {
			f := newGitFixture(t)
			f.commit("safe.txt", []byte("safe"))
			switch which {
			case "binary":
				f.commit("binary.dat", []byte{0, 1, 2})
			case "symlink":
				if e := os.Symlink("safe.txt", filepath.Join(f.g.dir, "link")); e != nil {
					t.Fatal(e)
				}
				f.commit("next.txt", []byte("safe"))
			case "submodule":
				id := strings.TrimSpace(string(f.run("rev-parse", "HEAD")))
				f.run("update-index", "--add", "--cacheinfo", "160000,"+id+",child")
				f.run("-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "synthetic gitlink")
			}
			id := strings.TrimSpace(string(f.run("rev-parse", "HEAD")))
			b := f.bundle("bad.bundle", "HEAD")
			if r, _, e := runPacket(t, "bad.bundle", b, Options{Limits: DefaultLimits(), Git: bundleOpts(t, BundleScope{Current: id})}); e == nil || r != (Report{}) {
				t.Fatal("unsupported object accepted")
			}
		})
	}
}

func TestGitToolEnvironmentAndProcessBounds(t *testing.T) {
	// A synthetic executable tests the runner boundary, never packet execution.
	d := t.TempDir()
	home := filepath.Join(d, "home")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	tool := filepath.Join(d, "inert-tool")
	script := "#!/bin/sh\ncase \"$HOME\" in */home) ;; *) exit 9;; esac\n[ -z \"${SSH_AUTH_SOCK+x}\" ] || exit 8\n[ -z \"${INHERIT_CANARY+x}\" ] || exit 7\n[ \"$GIT_CONFIG_GLOBAL\" = /dev/null ] || exit 6\nprintf safe\n"
	if e := os.WriteFile(tool, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("INHERIT_CANARY", "synthetic")
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent-synthetic-socket")
	w := &walker{ctx: context.Background(), l: DefaultLimits()}
	g := gitRepo{w: w, dir: d, home: home, tool: tool}
	if b, e := g.run("ignored"); e != nil || string(b) != "safe" {
		t.Fatalf("environment not inert: %v", e)
	}
	if e := os.WriteFile(tool, []byte("#!/bin/sh\nwhile :; do printf 'bounded-output'; done\n"), 0700); e != nil {
		t.Fatal(e)
	}
	w.l.CommandBytes = 32
	start := time.Now()
	if _, e := g.run("ignored"); e != ErrLimit {
		t.Fatal("output cap failed", e)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("output cancellation too slow")
	}
}
