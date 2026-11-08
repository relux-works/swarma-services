package gate

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Native commands are fixed executables with an explicit environment. No source
// repository config, refs, hooks, replace refs, alternates, or shell is imported.
type runner struct {
	ctx                     context.Context
	dir, home, tmp, authDir string
	commands, total         int
}
type capture struct {
	mu     sync.Mutex
	b      bytes.Buffer
	used   int
	bad    bool
	save   bool
	budget *outputBudget
}
type outputBudget struct {
	mu   sync.Mutex
	used int
}

func (w *capture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.used+len(p) > MaxCommand {
		w.bad = true
		return 0, refused
	}
	if w.budget != nil {
		w.budget.mu.Lock()
		if w.budget.used+len(p) > MaxOutput {
			w.budget.mu.Unlock()
			w.bad = true
			return 0, refused
		}
		w.budget.used += len(p)
		w.budget.mu.Unlock()
	}
	w.used += len(p)
	if w.save {
		return w.b.Write(p)
	}
	return len(p), nil
}
func (g *runner) git(args ...string) ([]byte, error) {
	g.commands++
	if g.commands > MaxCommands {
		return nil, refused
	}
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()
	prefix := []string{"--no-pager", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "core.pager=cat", "-c", "protocol.allow=never", "-c", "http.followRedirects=false", "-c", "credential.helper=", "--git-dir=" + g.dir}
	cmd := exec.CommandContext(ctx, "/usr/bin/git", append(prefix, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.Env = g.environment()
	cmd.Dir = g.tmp
	cmd.WaitDelay = time.Second
	budget := &outputBudget{used: g.total}
	out, diag := &capture{save: true, budget: budget}, &capture{budget: budget}
	cmd.Stdout = out
	cmd.Stderr = diag
	e := cmd.Run()
	g.total = budget.used
	if e != nil || out.bad || diag.bad || g.total > MaxOutput {
		return nil, refused
	}
	return out.b.Bytes(), nil
}

// HOME is always the fresh state directory, never the operator home.
func (g *runner) environment() []string {
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + g.tmp, "TMPDIR=" + g.tmp, "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_ATTR_NOSYSTEM=1"}
	if g.authDir != "" {
		env = append(env, "GH_CONFIG_DIR="+g.authDir, "GH_HOST=github.com", "GH_PROMPT_DISABLED=1")
	}
	return env
}

var looseRE = regexp.MustCompile(`^[0-9a-f]{2}/[0-9a-f]{38}$`)
var packRE = regexp.MustCompile(`^pack/pack-[0-9a-f]{40}\.(?:pack|idx|rev)$`)
var derivedPackRE = regexp.MustCompile(`^pack/(?:pack-[0-9a-f]{40}\.(?:bitmap|keep)|multi-pack-index(?:-[0-9a-f]{40}\.bitmap)?)$`)
var fanoutRE = regexp.MustCompile(`^[0-9a-f]{2}$`)

func (g *runner) snapshot(objects string) error {
	if !filepath.IsAbs(objects) || filepath.Clean(objects) != objects {
		return refused
	}
	i, e := os.Lstat(objects)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return refused
	}
	if _, e = g.git("init", "--bare", "--object-format=sha1", g.dir); e != nil {
		return refused
	}
	total, files := int64(0), 0
	return filepath.WalkDir(objects, func(name string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || g.ctx.Err() != nil {
			return refused
		}
		rel, e := filepath.Rel(objects, name)
		if e != nil {
			return refused
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if strings.Contains(rel, "/") || (rel != "pack" && rel != "info" && !fanoutRE.MatchString(rel)) {
				return refused
			}
			return os.MkdirAll(filepath.Join(g.dir, "objects", rel), 0700)
		}
		before, e := os.Lstat(name)
		if e != nil || !before.Mode().IsRegular() {
			return refused
		}
		files++
		if files > MaxObjectFiles {
			return refused
		}
		// Never read or copy these derived indexes/retention markers. The private
		// repository rebuilds its own view from copied objects. Links still refuse.
		if rel == "info/commit-graph" || rel == "info/packs" || derivedPackRE.MatchString(rel) {
			return nil
		}
		// Reject info/alternates, graft-like extensions and unknown storage.
		if !looseRE.MatchString(rel) && !packRE.MatchString(rel) {
			return refused
		}
		total += before.Size()
		if total > MaxObjects || files > MaxObjectFiles || before.Size() < 0 {
			return refused
		}
		f, e := os.Open(name)
		if e != nil {
			return refused
		}
		actual, e := f.Stat()
		if e != nil || !os.SameFile(before, actual) {
			f.Close()
			return refused
		}
		dest, e := os.OpenFile(filepath.Join(g.dir, "objects", rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			f.Close()
			return refused
		}
		n, copyErr := io.Copy(dest, io.LimitReader(f, before.Size()+1))
		closeErr := dest.Close()
		after, statErr := f.Stat()
		f.Close()
		if copyErr != nil || closeErr != nil || statErr != nil || n != before.Size() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return refused
		}
		return nil
	})
}
func (g *runner) object(kind, oid string, limit int) ([]byte, error) {
	if !oidRE.MatchString(oid) {
		return nil, refused
	}
	t, e := g.git("cat-file", "-t", oid)
	if e != nil || string(t) != kind+"\n" {
		return nil, refused
	}
	// cat-file output is separately bounded; malformed objects cannot become zero.
	b, e := g.git("cat-file", kind, oid)
	if e != nil || len(b) > limit {
		return nil, refused
	}
	// Native fsck has already bound inflated bytes to their object identities.
	return b, nil
}

// Inspect native object size/type metadata before fsck inflates the whole pool.
// The later integrity check must agree with this finite declared inventory.
func (g *runner) inventory() error {
	b, e := g.git("cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if e != nil || len(b) == 0 || b[len(b)-1] != '\n' {
		return refused
	}
	rows := bytes.Split(b[:len(b)-1], []byte{'\n'})
	if len(rows) > 65536 {
		return refused
	}
	total := int64(0)
	seen := map[string]bool{}
	for _, row := range rows {
		a := strings.Split(string(row), " ")
		if len(a) != 3 || !oidRE.MatchString(a[0]) || seen[a[0]] {
			return refused
		}
		seen[a[0]] = true
		n, e := strconv.ParseInt(a[2], 10, 64)
		if e != nil || n < 0 {
			return refused
		}
		limit := int64(MaxRecord)
		switch a[1] {
		case "blob":
			limit = MaxBlob
		case "commit", "tree", "tag":
		default:
			return refused
		}
		if n > limit || n > MaxObjects-total {
			return refused
		}
		total += n
	}
	return nil
}
