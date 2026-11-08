// Package tails inventories only explicitly selected local Git scopes. It never
// fetches or mutates repository state; cached ancestry is not online evidence.
package tails

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
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

const MaxBytes = 2 << 20
const MaxRepos = 64
const MaxRows = 4096

type paths []string

func (p *paths) String() string { return "" }
func (p *paths) Set(v string) error {
	if len(*p) >= MaxRepos {
		return errors.New("bound")
	}
	*p = append(*p, v)
	return nil
}

type Options struct {
	Repos, Roots               []string
	Metadata                   string
	ScopeKind                  string
	ChildTimeout, TotalTimeout time.Duration
}
type Failure struct {
	Stage        string `json:"stage"`
	Kind         string `json:"kind"`
	Exit         int    `json:"exit"`
	Milliseconds int64  `json:"milliseconds"`
}
type Worktree struct {
	PathHash       string `json:"path_sha256"`
	Head           string `json:"head,omitempty"`
	Detached       bool   `json:"detached"`
	Selected       bool   `json:"selected"`
	Dirty          *bool  `json:"tracked_dirty"`
	AnyDirty       *bool  `json:"dirty"`
	UntrackedCount *int   `json:"untracked_count"`
	Untracked      string `json:"untracked_coverage"`
}
type Ref struct {
	NameHash string `json:"ref_sha256"`
	OID      string `json:"oid"`
}
type Repository struct {
	ID              string     `json:"common_db_sha256"`
	Selected        []int      `json:"selected_inputs"`
	Worktrees       []Worktree `json:"worktrees"`
	Branches        []Ref      `json:"branches"`
	Absent          []string   `json:"commits_absent_from_cached_remote_ancestry"`
	Stash           *int       `json:"stash_count"`
	RemoteRefs      int        `json:"cached_remote_refs"`
	RemoteFreshness string     `json:"remote_freshness"`
	Coverage        string     `json:"coverage"`
	Reasons         []string   `json:"reasons"`
	Failures        []Failure  `json:"failures"`
	Race            bool       `json:"race_detected"`
}
type Pull struct {
	Repository string    `json:"repository"`
	Number     int       `json:"number"`
	CreatedAt  time.Time `json:"created_at"`
	AgeSeconds int64     `json:"age_seconds"`
	Ownership  string    `json:"ownership"`
}
type Counts struct {
	Repositories          int `json:"repositories"`
	Worktrees             int `json:"worktrees"`
	LocalBranches         int `json:"local_branches"`
	DetachedHeads         int `json:"detached_heads"`
	AbsentCachedCommits   int `json:"commits_absent_from_cached_remote_ancestry"`
	KnownStashEntries     int `json:"known_stash_entries"`
	DirtyTrackedWorktrees int `json:"dirty_tracked_worktrees"`
	DirtyWorktrees        int `json:"dirty_worktrees"`
	UnknownDirtyWorktrees int `json:"unknown_dirty_worktrees"`
	OpenPRs               int `json:"supplied_open_prs"`
}
type Selection struct {
	Index    int    `json:"index"`
	PathHash string `json:"path_sha256"`
}
type ChildResult struct {
	Stage        string    `json:"stage"`
	Started      time.Time `json:"started_at"`
	Milliseconds int64     `json:"milliseconds"`
	Exit         int       `json:"exit"`
	StdoutBytes  int       `json:"stdout_bytes"`
	StderrBytes  int       `json:"stderr_bytes"`
	Timeout      bool      `json:"timeout"`
	Truncated    bool      `json:"truncated"`
}
type Report struct {
	ScopeKind      string        `json:"scope_kind"`
	ScopeKindBasis string        `json:"scope_kind_basis"`
	Children       []ChildResult `json:"children"`
	Selections     []Selection   `json:"selections"`
	RootHashes     []string      `json:"root_sha256"`
	Counts         Counts        `json:"counts"`
	Version        int           `json:"version"`
	Started        time.Time     `json:"started_at"`
	Finished       time.Time     `json:"finished_at"`
	Repositories   []Repository  `json:"repositories"`
	Pulls          []Pull        `json:"open_prs"`
	PRCoverage     string        `json:"pr_coverage"`
	Scope          string        `json:"scope"`
	PRScope        []string      `json:"pr_scope"`
	PRObserved     *time.Time    `json:"pr_observed_at"`
	Complete       bool          `json:"complete"`
	Failures       []Failure     `json:"failures"`
	Commands       int           `json:"commands"`
	CommandBytes   int           `json:"command_bytes"`
}

// A single declaration covers the whole invocation. Repeated declarations refuse;
// scopes containing different kinds must be inventoried in separate invocations.
type scopeKindFlag struct {
	value string
	set   bool
}

func validScopeKind(s string) bool {
	return s == "unknown" || s == "unit-scratch" || s == "product"
}
func (k *scopeKindFlag) String() string { return k.value }
func (k *scopeKindFlag) Set(s string) error {
	if k.set || !validScopeKind(s) {
		return errors.New("invalid_scope_kind")
	}
	k.value, k.set = s, true
	return nil
}

func Run(args []string, w io.Writer) int {
	f := flag.NewFlagSet("tails", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var repos, roots paths
	var meta string
	kind := scopeKindFlag{value: "unknown"}
	f.Var(&kind, "scope-kind", "operator declaration for the entire selected scope: unknown|unit-scratch|product; mixed kinds require separate invocations")
	f.Var(&repos, "repo", "explicit checkout")
	f.Var(&roots, "root", "bounded work root")
	f.StringVar(&meta, "pr-metadata", "", "validated projected offline PR metadata")
	if f.Parse(args) != nil || f.NArg() != 0 || len(repos)+len(roots) == 0 {
		json.NewEncoder(w).Encode(map[string]string{"error": "explicit_valid_scope_required"})
		return 2
	}
	r := Scan(Options{Repos: repos, Roots: roots, Metadata: meta, ScopeKind: kind.value, ChildTimeout: 3 * time.Second, TotalTimeout: 90 * time.Second})
	if kind.set {
		r.ScopeKindBasis = "declared_by_operator"
	} else {
		r.ScopeKindBasis = "default_unknown"
	}
	if json.NewEncoder(w).Encode(r) != nil {
		return 1
	}
	if !r.Complete {
		return 1
	}
	return 0
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

var oidRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

func privateDir(p string) bool {
	st, e := os.Lstat(p)
	return e == nil && owned(st) && st.IsDir() && st.Mode().Perm() == 0700 && filepath.IsAbs(p) && filepath.Clean(p) == p && !sensitive(p) && safePath(p)
}
func owned(st os.FileInfo) bool {
	v, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(v.Uid) == os.Geteuid()
}
func sensitive(p string) bool {
	for _, s := range strings.Split(filepath.ToSlash(p), "/") {
		s = strings.ToLower(s)
		if strings.HasPrefix(s, ".env") || s == ".local" || s == "id_rsa" || s == "id_ed25519" || strings.HasSuffix(s, ".pem") || strings.HasSuffix(s, ".key") || s == ".ssh" || s == ".gnupg" || s == ".config" || s == ".cache" || s == ".aws" || s == ".azure" || s == ".kube" || s == ".temp" || s == "node_modules" || s == "vendor" || s == "credentials" || s == "cache" || s == "keychains" || s == ".git-credentials" || s == ".netrc" || s == ".npmrc" || s == ".pypirc" || s == ".env" || s == ".codex" || s == ".claude" || s == "secrets" || s == "keys" || s == "sessions" {
			return true
		}
	}
	return false
}

// Walk ancestry without following symlinks. Broad host/home roots are refused.
func safePath(p string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
		return false
	}
	for q := p; q != "/"; q = filepath.Dir(q) {
		st, e := os.Lstat(q)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}
func scopePath(p string) bool {
	if sensitive(p) || !safePath(p) {
		return false
	}
	if p == "/" || p == "/home" || p == "/Users" || p == "/tmp" || p == "/var" || p == os.Getenv("HOME") {
		return false
	}
	return true
}
func inside(p, root string) bool {
	rel, e := filepath.Rel(root, p)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func readSmall(p string) ([]byte, error) {
	st, e := os.Lstat(p)
	if e != nil || !st.Mode().IsRegular() || st.Size() > MaxBytes {
		return nil, errors.New("unsupported")
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !os.SameFile(st, a) {
		return nil, errors.New("race")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	z, ze := f.Stat()
	if e != nil || ze != nil || len(b) > MaxBytes || !os.SameFile(st, z) || st.Size() != z.Size() || !st.ModTime().Equal(z.ModTime()) {
		return nil, errors.New("race")
	}
	return b, nil
}

// Deliberately narrow config grammar. In particular includes, filters, external
// commands, alternate worktrees, promisor and custom object formats fail closed.
func configOK(p string) bool {
	b, e := readSmall(p)
	if e != nil {
		return false
	}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		if strings.ContainsAny(s, "\x00\r") || strings.HasSuffix(s, "\\") {
			return false
		}
		if strings.HasPrefix(s, "[") {
			if !strings.HasSuffix(s, "]") {
				return false
			}
			h := strings.TrimSpace(s[1 : len(s)-1])
			words := strings.Fields(h)
			if len(words) == 0 {
				return false
			}
			section = strings.ToLower(words[0])
			if section != "core" && section != "remote" && section != "branch" && section != "user" && section != "commit" && section != "gpg" && section != "init" && section != "extensions" {
				return false
			}
			continue
		}
		a := strings.SplitN(s, "=", 2)
		if len(a) != 2 {
			return false
		}
		key := strings.ToLower(strings.TrimSpace(a[0]))
		val := strings.TrimSpace(a[1])
		allowed := false
		switch section {
		case "core":
			switch key {
			case "repositoryformatversion", "filemode", "bare", "logallrefupdates", "ignorecase", "precomposeunicode":
				allowed = true
			case "fsmonitor", "hookspath":
				allowed = false
			}
		case "remote":
			allowed = key == "url" || key == "fetch" || key == "pushurl"
		case "branch":
			allowed = key == "remote" || key == "merge" || key == "pushremote"
		case "user":
			allowed = key == "name" || key == "email" || key == "signingkey"
		case "commit":
			allowed = key == "gpgsign"
		case "gpg":
			allowed = key == "format"
		case "init":
			allowed = key == "defaultbranch"
		case "extensions":
			allowed = key == "worktreeconfig" && val == "true"
		}
		if !allowed {
			return false
		}
	}
	return true
}

type limited struct {
	mu       sync.Mutex
	b        bytes.Buffer
	total    int
	overflow bool
	save     bool
}

func (b *limited) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total += len(p)
	if b.total > MaxBytes {
		b.overflow = true
		return 0, errors.New("bound")
	}
	if b.save {
		return b.b.Write(p)
	}
	return len(p), nil
}

type runner struct {
	ctx        context.Context
	timeout    time.Duration
	report     *Report
	executable string
	locations  map[string]location
}

func (r *runner) git(dir, stage string, args ...string) ([]byte, *Failure) {
	return r.gitInput(dir, stage, nil, args...)
}
func (r *runner) gitInput(dir, stage string, input []byte, args ...string) ([]byte, *Failure) {
	start := time.Now()
	if r.report.Commands >= 1024 || r.report.CommandBytes >= 16<<20 {
		return nil, &Failure{Stage: stage, Kind: "total_bound", Exit: -1}
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()
	prefix := []string{"--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null", "-c", "credential.helper=", "-c", "protocol.allow=never", "-c", "diff.external=", "-c", "core.quotePath=true", "-C", dir}
	if l, ok := r.locations[dir]; ok {
		prefix = append(prefix, "--git-dir="+l.gitdir, "--work-tree="+l.path)
	}
	exe := r.executable
	if exe == "" {
		exe = "/usr/bin/git"
	}
	cmd := exec.CommandContext(ctx, exe, append(prefix, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.Getenv("TMPDIR"), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_ATTR_NOSYSTEM=1", "GIT_PAGER=cat"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 250 * time.Millisecond
	out, diag := &limited{save: true}, &limited{}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = out
	cmd.Stderr = diag
	e := cmd.Run()
	actualExit := -1
	if cmd.ProcessState != nil {
		actualExit = cmd.ProcessState.ExitCode()
	}
	r.report.Children = append(r.report.Children, ChildResult{stage, start.UTC(), time.Since(start).Milliseconds(), actualExit, out.total, diag.total, ctx.Err() != nil, out.overflow || diag.overflow})
	if e != nil && stage == "untracked_ignored" && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 1 {
		e = nil
	}
	r.report.Commands++
	r.report.CommandBytes += out.total + diag.total
	if e != nil || out.overflow || diag.overflow || r.report.CommandBytes > 16<<20 {
		kind := "command_failed"
		if ctx.Err() != nil {
			kind = "timeout"
		}
		if out.overflow || diag.overflow {
			kind = "output_bound"
		}
		exit := -1
		if cmd.ProcessState != nil {
			exit = cmd.ProcessState.ExitCode()
		}
		return nil, &Failure{Stage: stage, Kind: kind, Exit: exit, Milliseconds: time.Since(start).Milliseconds()}
	}
	b := out.b.Bytes()
	if b == nil {
		b = []byte{}
	}
	return b, nil
}

type location struct {
	path, db, gitdir string
	input            int
}

func locate(ctx context.Context, p string, allowed []string) (location, error) {
	l := location{path: p}
	if !scopePath(p) {
		return l, errors.New("unsafe_path")
	}
	g := filepath.Join(p, ".git")
	st, e := os.Lstat(g)
	if e != nil {
		return l, e
	}
	if st.IsDir() {
		l.gitdir = g
		l.db = g
	} else {
		b, e := readSmall(g)
		if e != nil || !strings.HasPrefix(string(b), "gitdir: ") {
			return l, errors.New("gitdir")
		}
		s := strings.TrimSpace(strings.TrimPrefix(string(b), "gitdir: "))
		if !filepath.IsAbs(s) {
			s = filepath.Join(p, s)
		}
		l.gitdir = filepath.Clean(s)
		b, e = readSmall(filepath.Join(l.gitdir, "commondir"))
		if e != nil {
			return l, e
		}
		s = strings.TrimSpace(string(b))
		if !filepath.IsAbs(s) {
			s = filepath.Join(l.gitdir, s)
		}
		l.db = filepath.Clean(s)
	}
	for _, q := range []string{l.db, l.gitdir} {
		ok := inside(q, p)
		for _, a := range allowed {
			ok = ok || inside(q, a)
		}
		// A linked registry identifier is metadata, while its database and
		// any other physical target retain the source exclusions.
		registry := filepath.Dir(q) == filepath.Join(l.db, "worktrees") && metadataRefName(filepath.Base(q))
		if !ok || !safePath(q) || sensitive(l.db) || (!registry && sensitive(q)) {
			return l, errors.New("outside_scope")
		}
	}
	if !metadataTreeOK(ctx, l.db) || !metadataTreeOK(ctx, l.gitdir) {
		return l, errors.New("unsupported_storage")
	}
	if !configOK(filepath.Join(l.db, "config")) {
		return l, errors.New("unsupported_config")
	}
	for _, q := range []string{filepath.Join(l.gitdir, "config.worktree"), filepath.Join(l.db, "config.worktree")} {
		if _, e := os.Lstat(q); e == nil && !configOK(q) {
			return l, errors.New("unsupported_config")
		}
	}
	for _, q := range []string{filepath.Join(l.db, "objects/info/alternates"), filepath.Join(l.db, "objects/info/http-alternates"), filepath.Join(l.db, "info/grafts")} {
		if _, e := os.Lstat(q); !os.IsNotExist(e) {
			return l, errors.New("unsupported_storage")
		}
	}
	// Git control files and directories must not redirect native reads.
	for _, base := range []string{l.db, l.gitdir} {
		for _, n := range []string{"HEAD", "index", "packed-refs", "refs", "objects", "logs", "info"} {
			q := filepath.Join(base, n)
			if st, e := os.Lstat(q); e == nil && st.Mode()&os.ModeSymlink != 0 {
				return l, errors.New("symlink_control")
			}
		}
	}
	return l, nil
}

// Read a finite batch of directory names at a time rather than allocating an
// unbounded listing before applying the admission budget. SkipDir is honored
// before opening any excluded directory. Filesystem syscalls still need an outer
// process timeout when the selected filesystem itself can block.
func walkBounded(root string, maxEntries, maxDepth int, ctx context.Context, visit func(string, os.DirEntry, error) error) error {
	count := 0
	var walk func(string, int) error
	walk = func(p string, depth int) error {
		if ctx.Err() != nil || count >= maxEntries || depth > maxDepth {
			return errors.New("walk_bound")
		}
		count++
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		d := fs.FileInfoToDirEntry(st)
		e = visit(p, d, nil)
		if e == filepath.SkipDir {
			return nil
		}
		if e != nil {
			return e
		}
		if !d.IsDir() {
			return nil
		}
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		defer f.Close()
		actual, e := f.Stat()
		if e != nil || !os.SameFile(st, actual) {
			return errors.New("walk_race")
		}
		for {
			batch, re := f.ReadDir(64)
			for _, child := range batch {
				if e := walk(filepath.Join(p, child.Name()), depth+1); e != nil {
					return e
				}
			}
			if re == io.EOF {
				break
			}
			if re != nil {
				return re
			}
		}
		after, e := f.Stat()
		if e != nil || !os.SameFile(st, after) || !st.ModTime().Equal(after.ModTime()) {
			return errors.New("walk_race")
		}
		return nil
	}
	return walk(root, 0)
}

// Ref and reflog names are Git metadata, not source paths. Validate their
// structure without applying source exclusions to individual name components.
func metadataRefName(p string) bool {
	if p == "" || strings.Contains(p, "..") || strings.Contains(p, "@{") || strings.ContainsAny(p, " ~^:?*[\\") {
		return false
	}
	for _, c := range p {
		if c < 32 || c == 127 {
			return false
		}
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

// Preserve permissive non-name Git storage admission. Only structurally bounded
// ref, reflog and worktree registry names bypass source-sensitive exclusions.
func metadataPathOK(p string, dir bool) bool {
	parts := strings.Split(p, "/")
	if parts[0] == "worktrees" && len(parts) >= 2 && metadataRefName(parts[1]) {
		if len(parts) == 2 && dir {
			return true
		}
		if len(parts) > 2 {
			p = strings.Join(parts[2:], "/")
		}
	}
	for _, prefix := range []string{"refs/", "logs/refs/"} {
		if strings.HasPrefix(p, prefix) && metadataRefName(strings.TrimPrefix(p, prefix)) {
			return true
		}
	}
	// Non-name entries (including transient ref locks) keep the previous
	// permissive treatment, without any exemption from sensitive().
	return !sensitive(p)
}

func metadataConfigPath(p string) bool {
	if p == "config" || p == "config.worktree" {
		return true
	}
	parts := strings.Split(p, "/")
	return len(parts) == 3 && parts[0] == "worktrees" && metadataRefName(parts[1]) && parts[2] == "config.worktree"
}

// Native Git may read refs, object packs, worktree registry and ignore metadata.
// Refuse redirects/special files before invoking it. No file content is read here.
func metadataTreeOK(ctx context.Context, root string) bool {
	count := 0
	var storage int64
	e := walkBounded(root, 65536, 32, ctx, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		count++
		if count > 65536 {
			return errors.New("metadata_bound")
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "hooks" && d.IsDir() {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink")
		}
		if !d.IsDir() {
			st, e := d.Info()
			if e != nil {
				return e
			}
			storage += st.Size()
			if st.Size() > 64<<20 || storage > 256<<20 {
				return errors.New("storage_bound")
			}
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return errors.New("special")
		}
		if !metadataPathOK(filepath.ToSlash(rel), d.IsDir()) {
			return errors.New("metadata_path")
		}
		if metadataConfigPath(filepath.ToSlash(rel)) && !configOK(p) {
			return errors.New("config")
		}
		return nil
	})
	return e == nil
}

func issue(r *Repository, s string) {
	r.Coverage = "incomplete"
	for _, v := range r.Reasons {
		if v == s {
			return
		}
	}
	r.Reasons = append(r.Reasons, s)
}

// Enumerate only filesystem metadata in admitted source paths. Git classifies
// the finite candidate list against ignore rules via stdin; it performs no crawl.
func untracked(run *runner, path string, tracked, submodules map[string]bool) (int, bool, *Failure) {
	start := time.Now()
	candidates := []string{}
	excluded := false
	e := walkBounded(path, 4096, 32, run.ctx, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(path, p)
		if rel == "." {
			return nil
		}
		if rel == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if sensitive(rel) || submodules[rel] {
			excluded = true
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if _, e := os.Lstat(filepath.Join(p, ".git")); e == nil {
				excluded = true
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() && d.Type()&os.ModeSymlink == 0 {
			return errors.New("special_source")
		}
		if !tracked[rel] {
			if len(rel) > 4096 {
				return errors.New("path_bound")
			}
			candidates = append(candidates, rel)
		}
		return nil
	})
	if e != nil {
		kind := "bounded_or_unavailable"
		if e.Error() == "walk_race" {
			kind = "race_detected"
		}
		return 0, excluded, &Failure{Stage: "untracked_walk", Kind: kind, Exit: -1, Milliseconds: time.Since(start).Milliseconds()}
	}
	if len(candidates) == 0 {
		return 0, excluded, nil
	}
	input := []byte(strings.Join(candidates, "\x00") + "\x00")
	if len(input) > MaxBytes {
		return 0, excluded, &Failure{Stage: "untracked_walk", Kind: "output_bound", Exit: -1}
	}
	ignored, f := run.gitInput(path, "untracked_ignored", input, "check-ignore", "--stdin", "-z")
	if f != nil {
		return 0, excluded, f
	}
	valid := map[string]bool{}
	for _, p := range candidates {
		valid[p] = true
	}
	seen := map[string]bool{}
	if len(ignored) > 0 && ignored[len(ignored)-1] != 0 {
		return 0, excluded, &Failure{Stage: "untracked_ignored", Kind: "invalid_records", Exit: -1}
	}
	for _, p := range bytes.Split(ignored, []byte{0}) {
		if len(p) == 0 {
			continue
		}
		v := string(p)
		if !valid[v] || seen[v] {
			return 0, excluded, &Failure{Stage: "untracked_ignored", Kind: "invalid_records", Exit: -1}
		}
		seen[v] = true
	}
	return len(candidates) - len(seen), excluded, nil
}

func scanRepo(run *runner, locations []location, selected map[string]bool) Repository {
	l := locations[0]
	r := Repository{ID: hash(l.db), Coverage: "complete", RemoteFreshness: "unknown_cached_only", Branches: []Ref{}, Worktrees: []Worktree{}, Absent: []string{}, Reasons: []string{}, Failures: []Failure{}}
	for _, v := range locations {
		r.Selected = append(r.Selected, v.input)
	}
	git := func(stage string, args ...string) []byte {
		b, e := run.git(l.path, stage, args...)
		if e != nil {
			r.Failures = append(r.Failures, *e)
			issue(&r, stage)
			return nil
		}
		return b
	}
	for _, base := range []string{l.db, l.gitdir} {
		for _, name := range []string{"index.lock", "HEAD.lock", "packed-refs.lock", "config.lock"} {
			if _, e := os.Lstat(filepath.Join(base, name)); e == nil {
				r.Race = true
				issue(&r, "git_lock_observed")
			}
		}
	}
	before := git("refs_before", "for-each-ref", "--format=%(refname)%00%(objectname)", "refs/heads", "refs/remotes", "refs/stash")
	if before == nil {
		return r
	}
	if len(bytes.Split(before, []byte{'\n'})) > MaxRows {
		issue(&r, "ref_bound")
		return r
	}
	var heads, remotes []string
	for _, row := range bytes.Split(bytes.TrimSuffix(before, []byte{'\n'}), []byte{'\n'}) {
		if len(row) == 0 {
			continue
		}
		a := bytes.Split(row, []byte{0})
		if len(a) != 2 || !oidRE.Match(a[1]) {
			issue(&r, "invalid_refs")
			return r
		}
		name, oid := string(a[0]), string(a[1])
		if strings.HasPrefix(name, "refs/heads/") {
			r.Branches = append(r.Branches, Ref{hash(name), oid})
			heads = append(heads, oid)
		}
		if strings.HasPrefix(name, "refs/remotes/") {
			remotes = append(remotes, oid)
		}
	}
	r.RemoteRefs = len(remotes)
	if len(remotes) == 0 {
		issue(&r, "no_cached_remote_refs")
	}
	workBefore := git("worktrees_before", "worktree", "list", "--porcelain", "-z")
	records := bytes.Split(workBefore, []byte{0})
	if len(records) > MaxRows {
		issue(&r, "worktree_bound")
		return r
	}
	var wt *Worktree
	for _, field := range records {
		s := string(field)
		if strings.HasPrefix(s, "worktree ") {
			p := strings.TrimPrefix(s, "worktree ")
			r.Worktrees = append(r.Worktrees, Worktree{PathHash: hash(p), Selected: selected[p], Untracked: "not_scanned"})
			wt = &r.Worktrees[len(r.Worktrees)-1]
			if !selected[p] {
				issue(&r, "unselected_worktree")
			}
		} else if wt != nil && strings.HasPrefix(s, "HEAD ") {
			o := strings.TrimPrefix(s, "HEAD ")
			if oidRE.MatchString(o) && o != strings.Repeat("0", 40) {
				wt.Head = o
				heads = append(heads, o)
			} else {
				issue(&r, "unborn_or_invalid_head")
			}
		} else if wt != nil && s == "detached" {
			wt.Detached = true
		}
	}
	for _, v := range locations {
		// Index path metadata is checked before status can read tracked content.
		names, e := run.git(v.path, "tracked_paths", "ls-files", "--stage", "-z")
		if e != nil {
			r.Failures = append(r.Failures, *e)
			issue(&r, "tracked_paths")
			continue
		}
		unsafe := false
		tracked, submodules := map[string]bool{}, map[string]bool{}
		rows := bytes.Split(names, []byte{0})
		if len(rows) > MaxRows {
			issue(&r, "tracked_path_bound")
			continue
		}
		for _, row := range rows {
			if len(row) == 0 {
				continue
			}
			a := bytes.SplitN(row, []byte{'\t'}, 2)
			if len(a) != 2 {
				unsafe = true
				continue
			}
			mode := strings.Fields(string(a[0]))
			if len(mode) != 3 || !oidRE.MatchString(mode[1]) || (mode[0] != "100644" && mode[0] != "100755" && mode[0] != "120000" && mode[0] != "160000") {
				unsafe = true
				continue
			}
			p := string(a[1])
			if sensitive(p) || len(p) > 4096 || filepath.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") {
				unsafe = true
			}
			tracked[p] = true
			if bytes.HasPrefix(a[0], []byte("160000 ")) {
				submodules[p] = true
			}
		}

		if unsafe {
			issue(&r, "excluded_tracked_path")
			continue
		}
		head, e := run.git(v.path, "head_before", "rev-parse", "--verify", "HEAD")
		if e != nil {
			r.Failures = append(r.Failures, *e)
			issue(&r, "unborn_or_unavailable_head")
			continue
		}
		status, e := run.git(v.path, "tracked_status", "status", "--porcelain=v1", "-z", "--untracked-files=no", "--ignore-submodules=all")
		if e != nil {
			r.Failures = append(r.Failures, *e)
			issue(&r, "tracked_status")
			continue
		}
		dirty := len(status) > 0
		n, excluded, uf := untracked(run, v.path, tracked, submodules)
		if uf != nil {
			r.Failures = append(r.Failures, *uf)
			issue(&r, "untracked_unavailable")
			if uf.Kind == "race_detected" {
				r.Race = true
				issue(&r, "untracked_race")
			}
		}
		if excluded {
			issue(&r, "untracked_or_submodule_exclusions")
		}
		for i := range r.Worktrees {
			if r.Worktrees[i].PathHash == hash(v.path) {
				w := &r.Worktrees[i]
				w.Dirty = &dirty
				if uf == nil {
					w.UntrackedCount = &n
					w.Untracked = "complete_safe_scope"
					if excluded {
						w.Untracked = "partial_exclusions"
					}
				}
				anyDirty := dirty || uf == nil && n > 0
				if anyDirty || uf == nil && !excluded {
					w.AnyDirty = &anyDirty
				}
			}
		}
		statusAfter, se := run.git(v.path, "status_after", "status", "--porcelain=v1", "-z", "--untracked-files=no", "--ignore-submodules=all")
		if se != nil {
			r.Failures = append(r.Failures, *se)
			issue(&r, "status_after")
		} else if !bytes.Equal(status, statusAfter) {
			r.Race = true
			issue(&r, "status_race")
		}
		after, e := run.git(v.path, "head_after", "rev-parse", "--verify", "HEAD")
		if e != nil {
			r.Failures = append(r.Failures, *e)
			issue(&r, "head_after")
		}
		if !bytes.Equal(head, after) {
			r.Race = true
			issue(&r, "head_race")
		}
	}
	var stash []byte
	if bytes.Contains(before, []byte("refs/stash\x00")) {
		stash = git("stash_count", "reflog", "show", "--format=%H", "refs/stash")
	}
	if bytes.Contains(before, []byte("refs/stash\x00")) && len(stash) == 0 {
		issue(&r, "stash_reflog_unavailable")
	}
	if stash != nil && len(stash) > 0 {
		n := 0
		if len(stash) > 0 {
			n = len(bytes.Split(bytes.TrimSuffix(stash, []byte{'\n'}), []byte{'\n'}))
		}
		if n > MaxRows {
			issue(&r, "stash_bound")
		} else {
			r.Stash = &n
		}
	}
	// A missing stash ref is a known zero at the ref observation, not an
	// assumption derived from a failed reflog command.
	if !bytes.Contains(before, []byte("refs/stash\x00")) {
		n := 0
		r.Stash = &n
	}

	if len(heads) > 0 {
		args := []string{"rev-list", "--max-count=" + strconv.Itoa(MaxRows+1)}
		seen := map[string]bool{}
		for _, o := range heads {
			if !seen[o] {
				args = append(args, o)
				seen[o] = true
			}
		}
		if len(remotes) > 0 {
			args = append(args, "--not")
			for _, o := range remotes {
				args = append(args, o)
			}
		}
		args = append(args, "--")
		b := git("ancestry", args...)
		if b != nil {
			rows := bytes.Split(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\n'})
			if len(rows) > MaxRows {
				issue(&r, "commit_bound")
			} else {
				for _, o := range rows {
					if len(o) == 0 {
						continue
					}
					if !oidRE.Match(o) {
						issue(&r, "invalid_ancestry")
						break
					}
					r.Absent = append(r.Absent, string(o))
				}
			}
		}
	}
	if _, e := os.Lstat(filepath.Join(l.db, "shallow")); !os.IsNotExist(e) {
		issue(&r, "shallow_history")
	}
	after := git("refs_after", "for-each-ref", "--format=%(refname)%00%(objectname)", "refs/heads", "refs/remotes", "refs/stash")
	workAfter := git("worktrees_after", "worktree", "list", "--porcelain", "-z")
	if !bytes.Equal(before, after) || !bytes.Equal(workBefore, workAfter) {
		r.Race = true
		issue(&r, "refs_or_worktrees_race")
	}
	return r
}

func Scan(o Options) (r Report) {
	r = Report{Children: []ChildResult{}, Selections: []Selection{}, RootHashes: []string{}, Version: 1, Started: time.Now().UTC(), Repositories: []Repository{}, Pulls: []Pull{}, PRScope: []string{}, PRCoverage: "not_requested", Scope: "explicit_local_selection_cached_ancestry_only", Complete: true, Failures: []Failure{}}

	defer func() {
		r.Finished = time.Now().UTC()
		r.Counts.Repositories = len(r.Repositories)
		r.Counts.OpenPRs = len(r.Pulls)
		for _, repo := range r.Repositories {
			r.Counts.LocalBranches += len(repo.Branches)
			r.Counts.AbsentCachedCommits += len(repo.Absent)
			if repo.Stash != nil {
				r.Counts.KnownStashEntries += *repo.Stash
			}
			r.Counts.Worktrees += len(repo.Worktrees)
			for _, wt := range repo.Worktrees {
				if wt.Detached {
					r.Counts.DetachedHeads++
				}
				if wt.AnyDirty == nil {
					r.Counts.UnknownDirtyWorktrees++
				} else if *wt.AnyDirty {
					r.Counts.DirtyWorktrees++
				}
				if wt.Dirty != nil && *wt.Dirty {
					r.Counts.DirtyTrackedWorktrees++
				}
			}
		}
	}()
	fail := func(stage, kind string) {
		r.Failures = append(r.Failures, Failure{Stage: stage, Kind: kind, Exit: -1})
		r.Complete = false
	}
	r.ScopeKind = o.ScopeKind
	r.ScopeKindBasis = "declared_by_operator"
	if r.ScopeKind == "" {
		r.ScopeKind, r.ScopeKindBasis = "unknown", "default_unknown"
	}
	if !validScopeKind(r.ScopeKind) {
		r.ScopeKind, r.ScopeKindBasis = "unknown", "invalid_declaration"
		fail("classification", "invalid_scope_kind")
		return r
	}
	if !privateDir(os.Getenv("HOME")) || !privateDir(os.Getenv("TMPDIR")) || os.Getenv("HOME") == os.Getenv("TMPDIR") {
		fail("environment", "private_home_tmp_required")
		r.Finished = time.Now().UTC()
		return r
	}
	if o.ChildTimeout <= 0 || o.ChildTimeout > 3*time.Second {
		o.ChildTimeout = 3 * time.Second
	}
	if o.TotalTimeout <= 0 || o.TotalTimeout > 90*time.Second {
		o.TotalTimeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.TotalTimeout)
	defer cancel()
	run := &runner{ctx: ctx, timeout: o.ChildTimeout, report: &r, locations: map[string]location{}}
	all := append([]string{}, o.Repos...)
	roots := []string{}
	for _, root := range o.Roots {
		r.RootHashes = append(r.RootHashes, hash(root))
		if !scopePath(root) {
			fail("root", "unsafe_path")
			continue
		}
		roots = append(roots, root)
		visited := 0
		// Root plus two directory levels, with no hidden or excluded traversal.
		e := walkBounded(root, 4096, 3, ctx, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			visited++
			if visited > 4096 || ctx.Err() != nil {
				return errors.New("discovery_bound")
			}
			if !d.IsDir() {
				return nil
			}
			if p != root && (strings.HasPrefix(d.Name(), ".") || sensitive(d.Name())) {
				fail("discovery", "excluded_subtree")
				return filepath.SkipDir
			}
			if _, e := os.Lstat(filepath.Join(p, ".git")); e == nil {
				all = append(all, p)
				if len(all) > MaxRepos {
					return errors.New("repository_bound")
				}
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, p)
			if rel != "." && len(strings.Split(rel, string(filepath.Separator))) >= 2 {
				fail("discovery", "depth_limit")
				return filepath.SkipDir
			}
			return nil
		})
		if e != nil {
			fail("discovery", "bounded_or_unavailable")
		}
	}
	if len(all) == 0 || len(all) > MaxRepos {
		fail("selection", "empty_or_repository_bound")
		r.Finished = time.Now().UTC()
		return r
	}
	groups := map[string][]location{}
	order := []string{}
	selected := map[string]bool{}
	for i, p := range all {
		r.Selections = append(r.Selections, Selection{i, hash(p)})
		if selected[p] {
			continue
		}
		l, e := locate(ctx, p, roots)
		if e != nil {
			kind := "unavailable_repository"
			switch e.Error() {
			case "unsafe_path", "outside_scope", "unsupported_config", "unsupported_storage", "symlink_control", "gitdir":
				kind = e.Error()
			}
			fail("selection_"+strconv.Itoa(i), kind)
			continue
		}
		dbInfo, de := os.Stat(l.db)
		if de != nil {
			fail("selection_"+strconv.Itoa(i), "unavailable_database")
			continue
		}
		for _, known := range order {
			knownInfo, ke := os.Stat(known)
			if ke == nil && os.SameFile(dbInfo, knownInfo) {
				l.db = known
				break
			}
		}
		l.input = i
		run.locations[p] = l
		selected[p] = true
		if _, ok := groups[l.db]; !ok {
			order = append(order, l.db)
		}
		groups[l.db] = append(groups[l.db], l)
	}
	for _, db := range order {
		rr := scanRepo(run, groups[db], selected)
		if rr.Coverage != "complete" {
			r.Complete = false
		}
		r.Repositories = append(r.Repositories, rr)
	}
	if o.Metadata != "" {
		if e := metadata(o.Metadata, &r); e != nil {
			r.PRCoverage = "incomplete_invalid_metadata"
			fail("pr_metadata", "invalid_or_unavailable")
		}
	}
	if ctx.Err() != nil {
		fail("scan", "total_timeout")
	}
	r.Finished = time.Now().UTC()
	return r
}

// Metadata is an explicit, bounded offline contract. No author/title/body/URL or
// raw repository JSON is accepted. The producer must project before capture.
var credentialRE = regexp.MustCompile(`(?i)(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})`)

func credentialShape(s string) bool { return credentialRE.MatchString(s) }
func metadata(path string, r *Report) error {
	if sensitive(path) || !safePath(path) {
		return errors.New("path")
	}
	b, e := readSmall(path)
	if e != nil {
		return e
	}
	var m struct {
		Observed     time.Time `json:"observed_at"`
		Repositories []string  `json:"repositories"`
		Complete     bool      `json:"pagination_complete"`
		Pulls        []struct {
			Repository string    `json:"repository"`
			Number     int       `json:"number"`
			Created    time.Time `json:"created_at"`
		} `json:"open_prs"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return errors.New("json")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing")
	}
	if m.Observed.IsZero() || m.Observed.After(r.Started) || r.Started.Sub(m.Observed) > 24*time.Hour || len(m.Repositories) == 0 || len(m.Repositories) > MaxRepos || len(m.Pulls) > MaxRows {
		return errors.New("bounds")
	}
	re := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	scopes := map[string]bool{}
	for _, s := range m.Repositories {
		if !re.MatchString(s) || credentialShape(s) || scopes[s] {
			return errors.New("scope")
		}
		scopes[s] = true
	}
	seen := map[string]bool{}
	pulls := []Pull{}
	for _, p := range m.Pulls {
		id := fmt.Sprint(p.Repository, "/", p.Number)
		if !scopes[p.Repository] || p.Number <= 0 || p.Created.IsZero() || p.Created.After(m.Observed) || seen[id] {
			return errors.New("pull")
		}
		seen[id] = true
		pulls = append(pulls, Pull{p.Repository, p.Number, p.Created, int64(m.Observed.Sub(p.Created) / time.Second), "unknown"})
	}
	r.Pulls = pulls
	r.PRScope = m.Repositories
	r.PRObserved = &m.Observed
	r.PRCoverage = "supplied_metadata_declares_complete_at_observation"
	if !m.Complete {
		r.PRCoverage = "supplied_metadata_incomplete"
		r.Complete = false
	}
	return nil
}
