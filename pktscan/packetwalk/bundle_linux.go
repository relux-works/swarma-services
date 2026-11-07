//go:build linux

package packetwalk

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// BundleScope pins actual commit object IDs, never ref names. BaseBundle must be
// standalone and contain Base's complete closure. The current bundle may depend
// only on objects in that baseline. Empty Base selects full reachable scope.
// Every object physically imported must be reachable from Current or Base;
// unrelated packed objects are refused. Base-only objects are intentionally
// excluded from content classification, not declared safe by this component.
type BundleScope struct {
	Current, Base string
	BaseBundle    []byte
}

// BundleOptions is Linux-only. The host MUST place this component in a network-
// isolated sandbox with read-only trusted tools and source, private HOME/TMP,
// and no host home, sockets or keys. It does not itself establish that sandbox.
// GitPath must be an explicit absolute trusted Git executable; TempDir must be
// an absolute, private 0700 directory. No config/environment is inherited.
type BundleOptions struct {
	GitPath, TempDir string
	Resolve          func(context.Context, string) (BundleScope, error)
}

func objectID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// bundleHeader admits SHA-1 bundle v2 only. It bounds and scans the actual
// header, including advertised refs and prerequisite descriptions. v3/unknown
// capabilities are refused instead of guessing object-format semantics.
func (w *walker) bundleHeader(name string, b []byte, base bool) error {
	if !bytes.HasPrefix(b, []byte("# v2 git bundle\n")) {
		return ErrBundle
	}
	i := bytes.Index(b, []byte("\n\n"))
	if i < 0 || i > 1<<20 || i+2+12 > len(b) || string(b[i+2:i+6]) != "PACK" {
		return ErrBundle
	}
	lines := bytes.Split(b[len("# v2 git bundle\n"):i+1], []byte{'\n'})
	refs := 0
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if err := w.entry(); err != nil {
			return err
		}
		if len(line) > 4096 {
			return ErrLimit
		}
		if line[0] == '-' {
			if base || len(line) < 42 || !objectID(string(line[1:41])) || line[41] != ' ' {
				return ErrBundle
			}
		} else {
			if len(line) < 42 || !objectID(string(line[:40])) || line[40] != ' ' {
				return ErrBundle
			}
			refs++
		}
	}
	if refs == 0 {
		return ErrBundle
	}
	// Refuse pack counts beyond the shared entry budget before Git allocates.
	pack := b[i+2:]
	count := uint64(pack[8])<<24 | uint64(pack[9])<<16 | uint64(pack[10])<<8 | uint64(pack[11])
	if count > uint64(w.l.Entries-w.r.Entries) {
		return ErrLimit
	}
	if e := w.preflightPack(pack); e != nil {
		return e
	}
	if !base {
		return w.leaf(File{LogicalPath: name + "/.bundle/header", Bytes: b[:i+1], ObjectType: "bundle-header", Origin: GitMetadata})
	}
	return nil
}

type gitRepo struct {
	w               *walker
	dir, home, tool string
	hints           map[string]string
}

// boundedOutput cancels the entire process group as soon as output exceeds a
// bound. stderr is charged but never retained or exposed. stdout is bounded by
// both FileBytes and the invocation-wide CommandBytes allowance.
type boundedOutput struct {
	mu     sync.Mutex
	w      *walker
	buf    bytes.Buffer
	cancel context.CancelFunc
	over   bool
}
type outputSide struct {
	out    *boundedOutput
	stdout bool
}

func (s outputSide) Write(p []byte) (int, error) {
	o := s.out
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.over || int64(len(p)) > o.w.l.CommandBytes-o.w.r.CommandBytes ||
		s.stdout && int64(len(p)) > o.w.l.FileBytes-int64(o.buf.Len()) {
		o.over = true
		o.cancel()
		return 0, ErrLimit
	}
	o.w.r.CommandBytes += int64(len(p))
	if s.stdout {
		return o.buf.Write(p)
	}
	return len(p), nil
}

func (g gitRepo) run(args ...string) ([]byte, error) {
	w := g.w
	if err := w.check(); err != nil {
		return nil, err
	}
	w.r.Commands++
	if w.r.Commands > w.l.Commands {
		return nil, ErrLimit
	}
	ctx, cancel := context.WithCancel(w.ctx)
	defer cancel()
	global := []string{"--no-pager", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
		"-c", "core.attributesFile=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
		"-c", "protocol.file.allow=never", "-c", "gc.auto=0", "-c", "maintenance.auto=false"}
	cmd := exec.CommandContext(ctx, g.tool, append(global, args...)...)
	cmd.Dir = g.dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + g.home, "XDG_CONFIG_HOME=" + g.home,
		"TMPDIR=" + g.home, "LC_ALL=C", "LANG=C", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	out := &boundedOutput{w: w, cancel: cancel}
	cmd.Stdout, cmd.Stderr = outputSide{out, true}, outputSide{out, false}
	err := cmd.Run()
	if out.over || w.check() != nil {
		return nil, ErrLimit
	}
	if err != nil {
		return nil, ErrBundle
	}
	return out.buf.Bytes(), nil
}

func (w *walker) bundle(name string, b []byte, depth int) (err error) {
	o := w.git
	if o == nil || o.Resolve == nil || !filepath.IsAbs(o.GitPath) || !filepath.IsAbs(o.TempDir) {
		return ErrBundle
	}
	st, e := os.Lstat(o.TempDir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return ErrBundle
	}
	scope, e := o.Resolve(w.ctx, name)
	if e != nil || !objectID(scope.Current) || scope.Base != "" && !objectID(scope.Base) ||
		(scope.Base == "") != (len(scope.BaseBundle) == 0) {
		return ErrBundle
	}
	if e = w.bundleHeader(name, b, false); e != nil {
		return e
	}
	q, e := os.MkdirTemp(o.TempDir, "packetwalk-")
	if e != nil {
		return ErrBundle
	}
	defer func() {
		if os.RemoveAll(q) != nil {
			err = ErrCleanup
		}
	}()
	home, repo := filepath.Join(q, "home"), filepath.Join(q, "objects.git")
	if os.Mkdir(home, 0700) != nil || os.Mkdir(repo, 0700) != nil {
		return ErrBundle
	}
	g := gitRepo{w: w, dir: repo, home: home, tool: o.GitPath, hints: map[string]string{}}
	if _, e = g.run("init", "--bare", "--template=", "--object-format=sha1", "."); e != nil {
		return e
	}
	importBundle := func(file string, data []byte) error {
		p := filepath.Join(q, file)
		if os.WriteFile(p, data, 0600) != nil {
			return ErrBundle
		}
		if _, e := g.run("bundle", "verify", p); e != nil {
			return e
		}
		_, e := g.run("bundle", "unbundle", p)
		return e
	}
	baseSet := map[string]bool{}
	if scope.Base != "" {
		// Caller-supplied baseline bytes consume the same finite budgets.
		if int64(len(scope.BaseBundle)) > w.l.FileBytes {
			return ErrLimit
		}
		if e = charge(&w.r.CompressedBytes, int64(len(scope.BaseBundle)), w.l.CompressedBytes); e != nil {
			return e
		}
		if e = charge(&w.r.ExpandedBytes, int64(len(scope.BaseBundle)), w.l.ExpandedBytes); e != nil {
			return e
		}
		w.r.Files++
		w.r.Containers++
		if w.r.Files > w.l.Files || w.r.Containers > w.l.Containers {
			return ErrLimit
		}
		if e = w.bundleHeader(name+"/.baseline", scope.BaseBundle, true); e != nil {
			return e
		}
		if e = importBundle("base.bundle", scope.BaseBundle); e != nil {
			return e
		}
		if e = g.requireCommit(scope.Base); e != nil {
			return e
		}
		baseSet, e = g.reachable(scope.Base)
		if e != nil {
			return e
		}
		if e = g.scopeObjects(baseSet); e != nil {
			return e
		}
	}
	if e = importBundle("current.bundle", b); e != nil {
		return e
	}
	if e = g.requireCommit(scope.Current); e != nil {
		return e
	}
	current, e := g.reachable(scope.Current)
	if e != nil {
		return e
	}
	union := make(map[string]bool, len(current)+len(baseSet))
	for id := range current {
		union[id] = true
	}
	for id := range baseSet {
		union[id] = true
	}
	if e = g.scopeObjects(union); e != nil {
		return e
	}
	w.r.GitImportedObjects += len(union)
	w.r.GitBaseObjects += len(baseSet)
	for id := range current {
		if !baseSet[id] {
			w.r.GitDeltaObjects++
		}
	}
	// Check full paths at the current tip, including baseline-shared trees.
	if e = g.paths(name, scope.Current); e != nil {
		return e
	}
	ids := make([]string, 0, len(current))
	for id := range current {
		if !baseSet[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		typ, _, e := g.objectInfo(id)
		if e != nil {
			return e
		}
		if typ == "commit" && id != scope.Current {
			if e = g.paths(name, id); e != nil {
				return e
			}
		}
	}
	for _, id := range ids {
		if e = w.entry(); e != nil {
			return e
		}
		typ, size, e := g.objectInfo(id)
		if e != nil {
			return e
		}
		if size > w.l.FileBytes || size > w.l.ExpandedBytes-w.r.ExpandedBytes {
			return ErrLimit
		}
		data, e := g.run("cat-file", typ, id)
		if e != nil {
			return e
		}
		if int64(len(data)) != size {
			return ErrBundle
		}
		if e = charge(&w.r.ExpandedBytes, size, w.l.ExpandedBytes); e != nil {
			return e
		}
		logical := name + "/.bundle/objects/" + id
		if !safePath(logical) {
			return ErrBundle
		}
		switch typ {
		case "blob":
			// Blobs may themselves be nested packets; never count a raw bundle,
			// archive or binary as a zero-hit successful source file.
			hint := g.hints[id]
			if kind(logical, data) == "" && (hint == "json" || hint == "stream" || hint == "") {
				w.r.Files++
				if w.r.Files > w.l.Files {
					return ErrLimit
				}
				if e = w.leaf(File{LogicalPath: logical, Bytes: data, ObjectID: id, ObjectType: "blob", FormatHint: hint, Origin: GitBlobContent}); e != nil {
					return e
				}
			} else if hint == "json" || hint == "stream" {
				return ErrBundle
			} else if e = w.payload(logical+hint, data, depth, GitBlobContent); e != nil {
				return e
			}
		case "tree":
			text, e := w.tree(data)
			if e != nil {
				return e
			}
			if e = w.leaf(File{LogicalPath: logical, Bytes: text, ObjectID: id, ObjectType: typ, Origin: GitMetadata}); e != nil {
				return e
			}
		case "commit":

			if e = w.leaf(File{LogicalPath: logical, Bytes: data, ObjectID: id, ObjectType: typ, Origin: GitMetadata}); e != nil {
				return e
			}
		default:
			return ErrBundle
		}
	}
	return w.check()
}

func (g gitRepo) paths(name, commit string) error {
	b, e := g.run("ls-tree", "-r", "-t", "-z", "--full-tree", commit)
	if e != nil {
		return e
	}
	var text bytes.Buffer
	for len(b) != 0 {
		if e = g.w.entry(); e != nil {
			return e
		}
		z := bytes.IndexByte(b, 0)
		if z < 0 {
			return ErrBundle
		}
		record := b[:z]
		b = b[z+1:]
		tab := bytes.IndexByte(record, '\t')
		if tab < 0 {
			return ErrBundle
		}
		parts := strings.Split(string(record[:tab]), " ")
		path := string(record[tab+1:])
		if len(parts) != 3 || !objectID(parts[2]) || !safePath(path) ||
			!(parts[0] == "100644" && parts[1] == "blob" || parts[0] == "100755" && parts[1] == "blob" || parts[0] == "040000" && parts[1] == "tree") {
			return ErrBundle
		}
		if g.w.path(name+"/.bundle/source/"+path, parts[1] == "tree", GitSourcePath) != nil {
			return ErrVisit
		}
		if parts[1] == "blob" {
			hint := ""
			switch strings.ToLower(filepath.Ext(path)) {
			case ".json":
				hint = "json"
			case ".jsonl", ".ndjson":
				hint = "stream"
			case ".zip":
				hint = ".zip"
			case ".tar":
				hint = ".tar"
			case ".tgz", ".gz":
				hint = ".tgz"
			case ".bundle":
				hint = ".bundle"
			}
			if g.hints != nil && hint != "" {
				if previous := g.hints[parts[2]]; previous != "" && previous != hint {
					return ErrBundle
				}
				g.hints[parts[2]] = hint
			}
		}
		// Length-prefixed names preserve LF without forging another record.
		text.WriteString(parts[0] + " " + parts[1] + " " + parts[2] + " " + strconv.Itoa(len(path)) + ":" + path + "\n")
		if int64(text.Len()) > g.w.l.FileBytes {
			return ErrLimit
		}
	}
	if e = charge(&g.w.r.ExpandedBytes, int64(text.Len()), g.w.l.ExpandedBytes); e != nil {
		return e
	}
	return g.w.leaf(File{LogicalPath: name + "/.bundle/paths/" + commit, Bytes: text.Bytes(), ObjectID: commit, ObjectType: "paths", Origin: GitMetadata})
}

func (g gitRepo) requireCommit(id string) error {
	t, _, e := g.objectInfo(id)
	if e != nil {
		return e
	}
	if t != "commit" {
		return ErrBundle
	}
	return nil
}

func (g gitRepo) reachable(id string) (map[string]bool, error) {
	b, e := g.run("rev-list", "--objects", "--no-object-names", id, "--")
	if e != nil {
		return nil, e
	}
	set := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\n'}) {
		if !objectID(string(line)) {
			return nil, ErrBundle
		}
		set[string(line)] = true
		if len(set) > g.w.l.Entries {
			return nil, ErrLimit
		}
	}
	return set, nil
}

func (g gitRepo) scopeObjects(scope map[string]bool) error {
	b, e := g.run("cat-file", "--batch-all-objects", "--batch-check=%(objectname)", "--unordered")
	if e != nil {
		return e
	}
	n := 0
	for _, line := range bytes.Split(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\n'}) {
		if !objectID(string(line)) || !scope[string(line)] {
			return ErrBundle
		}
		n++
		if n > g.w.l.Entries {
			return ErrLimit
		}
	}
	if n != len(scope) {
		return ErrBundle
	}
	return nil
}

func (g gitRepo) objectInfo(id string) (string, int64, error) {
	b, e := g.run("cat-file", "-t", id)
	if e != nil {
		return "", 0, e
	}
	t := strings.TrimSuffix(string(b), "\n")
	if t != "commit" && t != "tree" && t != "blob" {
		return "", 0, ErrBundle
	}
	b, e = g.run("cat-file", "-s", id)
	if e != nil {
		return "", 0, e
	}
	n, e := strconv.ParseInt(strings.TrimSuffix(string(b), "\n"), 10, 64)
	if e != nil || n < 0 {
		return "", 0, ErrBundle
	}
	return t, n, nil
}

// tree decodes actual binary Git tree records into text for classification.
// Every entry is counted, and links/submodules/unsupported modes are refused.
// Names cannot contain separators: hierarchy is represented by tree object IDs.
func (w *walker) tree(b []byte) ([]byte, error) {
	var out bytes.Buffer
	seen := map[string]bool{}
	for len(b) != 0 {
		if e := w.entry(); e != nil {
			return nil, e
		}
		sp := bytes.IndexByte(b, ' ')
		z := bytes.IndexByte(b, 0)
		if sp < 1 || z <= sp || z+21 > len(b) {
			return nil, ErrBundle
		}
		mode, name := string(b[:sp]), string(b[sp+1:z])
		if (mode != "100644" && mode != "100755" && mode != "40000") ||
			!safePath(name) || strings.Contains(name, "/") || seen[name] {
			return nil, ErrBundle
		}
		seen[name] = true
		// Length-prefix the name so LF in a valid path cannot forge extra records.
		out.WriteString(mode + " " + strconv.Itoa(len(name)) + ":" + name + " " + hex.EncodeToString(b[z+1:z+21]) + "\n")
		if int64(out.Len()) > w.l.FileBytes {
			return nil, ErrLimit
		}
		b = b[z+21:]
	}
	if e := charge(&w.r.ExpandedBytes, int64(out.Len()), w.l.ExpandedBytes); e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}

var _ io.Writer = outputSide{}
