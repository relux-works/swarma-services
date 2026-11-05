// Package capture implements private, manual subprocess output capture.
package capture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var safe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var recordName = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}_[a-z0-9-]{1,32}_[a-f0-9]{32}$`)

func randomID() (string, error) {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}

// Only known executable basenames enter names. Arbitrary executable names may
// themselves contain secrets; they use the fixed fallback instead.
func slug(argv []string) string {
	if len(argv) > 0 {
		n := filepath.Base(argv[0])
		switch n {
		case "sh", "bash", "zsh", "fish", "git", "go", "rg", "grep", "sed", "tail", "head", "cat", "printf", "echo", "python3", "node", "make":
			return n
		}
	}
	return "command"
}

// descend rejects all symlinks, including ones that stay within the parent.
// Root handles keep subsequent access anchored across directory renames.
func descend(parent *os.Root, name string, create, private bool) (*os.Root, error) {
	if create {
		if e := parent.Mkdir(name, 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return nil, e
		}
	}
	st, e := parent.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("unsafe directory component %q", name)
	}
	r, e := parent.OpenRoot(name)
	if e != nil {
		return nil, e
	}
	actual, e := r.Stat(".")
	if e != nil || !os.SameFile(st, actual) {
		r.Close()
		return nil, errors.New("directory changed during open")
	}
	if private {
		if st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			r.Close()
			return nil, errors.New("private directory has another owner")
		}
		if st.Mode().Perm() != 0700 {
			r.Close()
			return nil, errors.New("existing private directory must have mode 0700")
		}
	}
	return r, nil
}

func absoluteRoot(path string) (*os.Root, error) { return walkAbsolute(path, false) }
func walkAbsolute(path string, create bool) (*os.Root, error) {
	path, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	r, e := os.OpenRoot("/")
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := descend(r, part, create, false)
		r.Close()
		if e != nil {
			return nil, e
		}
		r = next
	}
	return r, nil
}

const gitTimeout = 2 * time.Second

// Git can block opening repository-controlled FIFOs, including info/exclude.
// Bound every invocation, including its pipe drain, and cancel its process group.
func gitOutput(cwd string, stdin io.Reader, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, "git", append([]string{"-C", cwd}, args...)...)
	c.Stdin = stdin
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	c.WaitDelay = 150 * time.Millisecond
	b, e := c.Output()
	if ctx.Err() != nil {
		return b, fmt.Errorf("git deadline: %w", ctx.Err())
	}
	return b, e
}

func git(cwd string, args ...string) (string, error) {
	b, e := gitOutput(cwd, nil, args...)
	return strings.TrimSpace(string(b)), e
}

// ignoredDestination checks tracked contents as well as the exact destination.
func ignoredDestination(project, path string) error {
	tracked, e := git(project, "ls-files", "--", ".temp")
	if e != nil {
		return e
	}
	if tracked != "" {
		return errors.New("refuse tracked .temp contents")
	}
	if _, e = git(project, "check-ignore", "-q", "--", path); e != nil {
		return errors.New("refuse destination not ignored by git")
	}
	return nil
}

type Store struct {
	mu      sync.Mutex
	root    *os.Root
	Path    string
	project string
}

func (s *Store) Close() error {
	if s.root == nil {
		return nil
	}
	return s.root.Close()
}

// OpenStore discovers custody without changing the repository or cache. Only
// create initializes missing directories and local exclusions after preflight.
func OpenStore(cwd string) (*Store, error) {
	cwd, e := filepath.Abs(cwd)
	if e != nil {
		return nil, e
	}
	cwd, e = filepath.EvalSymlinks(cwd)
	if e != nil {
		return nil, e
	}
	anchor, e := absoluteRoot(cwd)
	if e != nil {
		return nil, e
	}
	anchor.Close()
	project, ge := git(cwd, "rev-parse", "--show-toplevel")
	var base string
	if ge == nil {
		base = filepath.Join(project, ".temp")
	} else {
		project = ""
		for p := cwd; ; p = filepath.Dir(p) {
			if _, e := os.Lstat(filepath.Join(p, ".git")); e == nil {
				return nil, errors.New("git worktree detection failed")
			}
			if filepath.Dir(p) == p {
				break
			}
		}
		base, e = os.UserCacheDir()
		if e != nil {
			return nil, e
		}
	}
	s := &Store{Path: filepath.Join(base, "shell-out"), project: project}
	// Opening an existing store is read-only, including its permissions.
	r, e := absoluteRoot(base)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	defer r.Close()
	if project != "" {
		st, e := r.Stat(".")
		if e != nil {
			return nil, e
		}
		if st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return nil, errors.New("existing .temp must be owned and mode 0700")
		}
	}
	s.root, e = descend(r, "shell-out", false, true)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	return s, nil
}

// excludeRoot anchors at the common gitdir, never Git's symlink-resolved
// info/exclude filename. This also handles linked worktrees' shared excludes.
func (s *Store) excludeRoot() (*os.Root, error) {
	common, e := git(s.project, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if e != nil {
		return nil, e
	}
	r, e := absoluteRoot(common)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	info, e := descend(r, "info", false, false)
	if e != nil {
		return nil, e
	}
	st, e := info.Lstat("exclude")
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		info.Close()
		return nil, e
	}
	if e == nil && !st.Mode().IsRegular() {
		info.Close()
		return nil, errors.New("unsafe info/exclude")
	}
	return info, nil
}

// canIgnore determines whether appending the fixed local exclusion can help.
// Per-directory .gitignore negations outrank info/exclude; refuse them before
// any write. Git's -z framing preserves spaces/newlines in source filenames.
func (s *Store) canIgnore(paths []string) (bool, error) {
	b, e := gitOutput(s.project, strings.NewReader(strings.Join(paths, "\x00")+"\x00"), "check-ignore", "-v", "-n", "-z", "--stdin")
	var ee *exec.ExitError
	if e != nil && (!errors.As(e, &ee) || ee.ExitCode() != 1) {
		return false, e
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) != 4*len(paths)+1 {
		return false, errors.New("invalid check-ignore response")
	}
	appendRule := false
	for i := 0; i < len(paths); i++ {
		source, pattern := parts[i*4], parts[i*4+2]
		if strings.HasPrefix(pattern, "!") && !filepath.IsAbs(source) {
			return false, errors.New("refuse destination negated by project ignore rules")
		}
		if source == "" || strings.HasPrefix(pattern, "!") {
			appendRule = true
		}
	}
	return appendRule, nil
}

func (s *Store) initialize() error {
	if s.root != nil {
		return nil
	}
	base := filepath.Dir(s.Path)
	var r *os.Root
	var e error
	if s.project != "" {
		parent, pe := absoluteRoot(s.project)
		if pe != nil {
			return pe
		}
		r, e = descend(parent, ".temp", true, true)
		parent.Close()
	} else {
		r, e = walkAbsolute(base, true)
	}
	if e != nil {
		return e
	}
	defer r.Close()
	s.root, e = descend(r, "shell-out", true, true)
	return e
}

// preflight checks existing custody and every exact destination before bootstrap.
func (s *Store) preflight(session, name, initialTemp string) error {
	if s.root != nil {
		r, e := descend(s.root, session, false, true)
		if e == nil {
			r.Close()
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if s.project == "" {
		return nil
	}
	tracked, e := git(s.project, "ls-files", "--", ".temp")
	if e != nil {
		return e
	}
	if tracked != "" {
		return errors.New("refuse tracked .temp contents")
	}
	paths := []string{}
	for _, suffix := range []string{".json", ".lock", ".out.log", ".err.log"} {
		paths = append(paths, filepath.Join(s.Path, session, name+suffix))
	}
	paths = append(paths, filepath.Join(s.Path, session, initialTemp))
	appendRule, e := s.canIgnore(paths)
	if e != nil {
		return e
	}
	if appendRule {
		er, e := s.excludeRoot()
		if e != nil {
			return e
		}
		defer er.Close()
		f, e := er.OpenFile("exclude", os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		if e = regularOwnedFile(f); e != nil {
			return e
		}
		if _, e = io.WriteString(f, "\n/.temp/\n"); e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
	}
	if need, e := s.canIgnore(paths); e != nil {
		return e
	} else if need {
		return errors.New("refuse destination not ignored by git")
	}
	return nil
}

type Record struct {
	Ref           string      `json:"ref"`
	Stdout        string      `json:"stdout_path"`
	Stderr        string      `json:"stderr_path"`
	ExitCode      int         `json:"exit_code"`
	Signal        int         `json:"signal,omitempty"`
	CommandStatus string      `json:"command_status"`
	CaptureStatus string      `json:"capture_status"`
	CaptureError  string      `json:"capture_error,omitempty"`
	Out           StreamStats `json:"stdout"`
	Err           StreamStats `json:"stderr"`
	Started       time.Time   `json:"started"`
	Finished      time.Time   `json:"finished"`
	Expires       time.Time   `json:"expires"`
}

type call struct {
	dir            *os.Root
	meta, out, err *os.File
	name           string
	record         Record
	project        string
	published      bool
	// Live runs reuse this exact preflighted name under the held directory.
	// Purge has no preflighted name and validates a fresh one before saving.
	tempName string
}

func (c *call) close() {
	if c.out != nil {
		c.out.Close()
	}
	if c.err != nil {
		c.err.Close()
	}
	if c.meta != nil {
		c.meta.Close()
	}
	if c.dir != nil {
		c.dir.Close()
	}
}
func exclusive(r *os.Root, name string) (*os.File, error) {
	f, e := r.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	if e = f.Chmod(0600); e != nil {
		f.Close()
		_ = r.Remove(name)
		return nil, e
	}
	return f, nil
}
func (s *Store) create(session string, argv []string, hours float64) (*call, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !safe.MatchString(session) {
		return nil, errors.New("invalid session label")
	}
	id, e := randomID()
	if e != nil {
		return nil, e
	}
	name := time.Now().UTC().Format("20060102-150405") + "_" + slug(argv) + "_" + id
	tempID, e := randomID()
	if e != nil {
		return nil, e
	}
	initialTemp := name + ".json.tmp-" + tempID
	if e = s.preflight(session, name, initialTemp); e != nil {
		return nil, e
	}
	if e = s.initialize(); e != nil {
		return nil, e
	}
	dir, e := descend(s.root, session, true, true)
	if e != nil {
		return nil, e
	}
	c := &call{dir: dir, name: name, project: s.project, tempName: initialTemp}
	created := []string{}
	ok := false
	defer func() {
		if !ok {
			if c.published {
				_ = dir.Remove(name + ".json")
			}
			for _, n := range created {
				_ = dir.Remove(n)
			}
			c.close()
		}
	}()
	for _, item := range []struct {
		suffix string
		file   **os.File
	}{{".lock", &c.meta}, {".out.log", &c.out}, {".err.log", &c.err}} {
		*item.file, e = exclusive(dir, name+item.suffix)
		if e != nil {
			return nil, e
		}
		created = append(created, name+item.suffix)
		if item.suffix == ".lock" {
			if e = syscall.Flock(int(c.meta.Fd()), syscall.LOCK_EX); e != nil {
				return nil, e
			}
		}
	}
	c.record = Record{Ref: session + "/" + name, Stdout: filepath.Join(s.Path, session, name+".out.log"), Stderr: filepath.Join(s.Path, session, name+".err.log"), ExitCode: -1, CommandStatus: "running", CaptureStatus: "running", Started: time.Now().UTC(), Expires: time.Now().UTC().Add(time.Duration(hours * float64(time.Hour)))}
	if e = c.save(); e != nil {
		return nil, e
	}
	ok = true
	return c, nil
}

// save never truncates published JSON. The stable .lock inode protects the
// record across atomic replacements; old records without .lock remain readable.
func (c *call) save() error {
	temp := c.tempName
	var e error
	if temp == "" {
		id, re := randomID()
		if re != nil {
			return re
		}
		temp = c.name + ".json.tmp-" + id
		if c.project != "" {
			if e = ignoredDestination(c.project, filepath.Join(filepath.Dir(c.record.Stdout), temp)); e != nil {
				return e
			}
		}
	}
	f, e := exclusive(c.dir, temp)
	if e != nil {
		return e
	}
	defer c.dir.Remove(temp)
	e = json.NewEncoder(f).Encode(c.record)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = c.dir.Rename(temp, c.name+".json"); e != nil {
		return e
	}
	c.published = true
	d, e := c.dir.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// lockRecord uses the new stable lock, or the metadata inode for legacy records.
// Neither lookup nor purge creates lock files.
func lockRecord(dir *os.Root, name string, mode int) (*os.File, error) {
	f, e := dir.OpenFile(name+".lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(e, os.ErrNotExist) {
		f, e = dir.OpenFile(name+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if e != nil {
		return nil, e
	}
	if e = privateFile(f); e == nil {
		e = syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func splitRef(ref string) (string, string, error) {
	p := strings.Split(ref, "/")
	if len(p) != 2 || !safe.MatchString(p[0]) || !recordName.MatchString(p[1]) {
		return "", "", errors.New("invalid ref")
	}
	return p[0], p[1], nil
}
func (s *Store) Lookup(ref string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return Record{}, errors.New("expired or unknown ref")
	}
	session, name, e := splitRef(ref)
	if e != nil {
		return Record{}, e
	}
	dir, e := descend(s.root, session, false, false)
	if e != nil {
		return Record{}, errors.New("expired or unknown ref")
	}
	defer dir.Close()
	lock, e := lockRecord(dir, name, syscall.LOCK_SH)
	if e != nil {
		return Record{}, fmt.Errorf("capture unavailable or running: %w", e)
	}
	defer lock.Close()
	f, e := dir.OpenFile(name+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return Record{}, errors.New("expired or unknown ref")
	}
	defer f.Close()
	if e = privateFile(f); e != nil {
		return Record{}, e
	}
	var r Record
	if e = json.NewDecoder(io.LimitReader(f, 65536)).Decode(&r); e != nil {
		return r, e
	}
	if r.Ref != ref || r.Stdout != filepath.Join(s.Path, session, name+".out.log") || r.Stderr != filepath.Join(s.Path, session, name+".err.log") {
		return r, errors.New("ref or path mismatch")
	}
	if r.CaptureStatus == "expired" || time.Now().After(r.Expires) {
		return r, errors.New("expired ref; purge removes retained files")
	}
	for _, path := range []string{name + ".out.log", name + ".err.log"} {
		f, e := dir.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return r, errors.New("missing or unsafe capture")
		}
		e = privateFile(f)
		f.Close()
		if e != nil {
			return r, e
		}
	}
	return r, nil
}

// Purge leaves metadata tombstones. It never recursively removes a directory or
// follows symlinks, and an OS lock protects every live run even after expiry.
func (s *Store) Purge(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return 0, nil
	}
	top, e := s.root.Open(".")
	if e != nil {
		return 0, e
	}
	entries, e := top.ReadDir(-1)
	top.Close()
	if e != nil {
		return 0, e
	}
	n := 0
	var warnings []error
	warn := func(ref string, e error) { warnings = append(warnings, fmt.Errorf("skipped %s: %w", ref, e)) }
	for _, entry := range entries {
		if !entry.IsDir() || !safe.MatchString(entry.Name()) {
			continue
		}
		dir, e := descend(s.root, entry.Name(), false, true)
		if e != nil {
			warn(entry.Name(), e)
			continue
		}
		d, e := dir.Open(".")
		if e != nil {
			warn(entry.Name(), e)
			dir.Close()
			continue
		}
		files, e := d.ReadDir(-1)
		d.Close()
		if e != nil {
			warn(entry.Name(), e)
			dir.Close()
			continue
		}
		for _, f := range files {
			name := strings.TrimSuffix(f.Name(), ".json")
			if name == f.Name() || !recordName.MatchString(name) {
				continue
			}
			ref := entry.Name() + "/" + name
			lock, e := lockRecord(dir, name, syscall.LOCK_EX)
			if errors.Is(e, syscall.EWOULDBLOCK) || errors.Is(e, syscall.EAGAIN) {
				continue
			}
			if e != nil {
				warn(ref, e)
				continue
			}
			// Scope each lock to one record, including all refusal paths.
			func() {
				defer lock.Close()
				meta, e := dir.OpenFile(f.Name(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
				if e != nil {
					warn(ref, e)
					return
				}
				if e = privateFile(meta); e != nil {
					meta.Close()
					warn(ref, e)
					return
				}
				var r Record
				e = json.NewDecoder(io.LimitReader(meta, 65536)).Decode(&r)
				meta.Close()
				if e != nil {
					warn(ref, errors.New("undecodable metadata; inspect manually"))
					return
				}
				if r.Ref != ref || r.Expires.IsZero() ||
					r.Stdout != filepath.Join(s.Path, entry.Name(), name+".out.log") ||
					r.Stderr != filepath.Join(s.Path, entry.Name(), name+".err.log") {
					warn(ref, errors.New("invalid metadata; inspect manually"))
					return
				}
				if r.CaptureStatus == "expired" || r.CommandStatus == "running" || r.CommandStatus == "not_started" || now.Before(r.Expires) {
					return
				}
				switch r.CommandStatus {
				case "exited", "signaled", "cancelled", "spawn_failed":
				default:
					warn(ref, errors.New("unknown command status; inspect manually"))
					return
				}
				// Validate both logs before deleting either one.
				for _, suffix := range []string{".out.log", ".err.log"} {
					log, e := dir.OpenFile(name+suffix, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
					if errors.Is(e, os.ErrNotExist) {
						continue
					}
					if e == nil {
						e = privateFile(log)
						log.Close()
					}
					if e != nil {
						warn(ref, e)
						return
					}
				}
				for _, suffix := range []string{".out.log", ".err.log"} {
					if e = dir.Remove(name + suffix); e != nil && !errors.Is(e, os.ErrNotExist) {
						warn(ref, e)
						return
					}
				}
				r.CaptureStatus = "expired"
				c := call{dir: dir, name: name, record: r, project: s.project}
				if e = c.save(); e != nil {
					warn(ref, e)
					return
				}
				n++
			}()
		}
		dir.Close()
	}
	return n, errors.Join(warnings...)
}

func privateFile(f *os.File) error {
	st, e := f.Stat()
	if e != nil {
		return e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || sys.Nlink != 1 || sys.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0600 {
		return errors.New("unsafe capture file")
	}
	return nil
}

func regularOwnedFile(f *os.File) error {
	st, e := f.Stat()
	if e != nil {
		return e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || sys.Nlink != 1 || sys.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe regular file")
	}
	return nil
}
