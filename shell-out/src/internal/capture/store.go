// Package capture implements private, manual subprocess output capture.
package capture

import (
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
		f, e := r.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			r.Close()
			return nil, e
		}
		e = f.Chmod(0700)
		f.Close()
		if e != nil {
			r.Close()
			return nil, e
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

func git(cwd string, args ...string) (string, error) {
	c := exec.Command("git", append([]string{"-C", cwd}, args...)...)
	b, e := c.Output()
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
	root    *os.Root
	Path    string
	project string
}

func (s *Store) Close() error { return s.root.Close() }

// OpenStore never changes tracked ignore files. The sole repository mutation is
// appending /.temp/ to the local info/exclude when required.
func OpenStore(cwd string) (*Store, error) {
	cwd, e := filepath.Abs(cwd)
	if e != nil {
		return nil, e
	}
	// Resolve the caller-selected anchor once (including macOS /var ->
	// /private/var). Custody directories below it are never symlink-resolved.
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
		root, e := absoluteRoot(project)
		if e != nil {
			return nil, e
		}
		defer root.Close()
		tracked, e := git(project, "ls-files", "--", ".temp")
		if e != nil {
			return nil, e
		}
		if tracked != "" {
			return nil, errors.New("refuse tracked .temp contents")
		}
		temp, e := descend(root, ".temp", true, true)
		if e != nil {
			return nil, e
		}
		temp.Close()
		probe := filepath.Join(project, ".temp", "shell-out", "probe")
		if _, e = git(project, "check-ignore", "-q", "--", probe); e != nil {
			exclude, e := git(project, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude")
			if e != nil {
				return nil, e
			}
			er, e := absoluteRoot(filepath.Dir(exclude))
			if e != nil {
				return nil, e
			}
			f, e := er.OpenFile(filepath.Base(exclude), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
			er.Close()
			if e != nil {
				return nil, e
			}
			if e = regularOwnedFile(f); e != nil {
				f.Close()
				return nil, e
			}
			_, we := io.WriteString(f, "\n/.temp/\n")
			ce := f.Close()
			if we != nil {
				return nil, we
			}
			if ce != nil {
				return nil, ce
			}
		}
		if e = ignoredDestination(project, probe); e != nil {
			return nil, e
		}
		base = filepath.Join(project, ".temp")
	} else {
		// A broken Git worktree is not silently treated as a non-Git directory.
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
		// Cache ancestors must already exist; create only our private custody root.
		cacheRoot, ce := walkAbsolute(base, true)
		if ce != nil {
			return nil, ce
		}
		cacheRoot.Close()
	}
	root, e := absoluteRoot(base)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	r, e := descend(root, "shell-out", true, true)
	if e != nil {
		return nil, e
	}
	return &Store{root: r, Path: filepath.Join(base, "shell-out"), project: project}, nil
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
		return nil, e
	}
	return f, nil
}
func (s *Store) create(session string, argv []string, hours float64) (*call, error) {
	if !safe.MatchString(session) {
		return nil, errors.New("invalid session label")
	}
	dir, e := descend(s.root, session, true, true)
	if e != nil {
		return nil, e
	}
	id, e := randomID()
	if e != nil {
		dir.Close()
		return nil, e
	}
	name := time.Now().UTC().Format("20060102-150405") + "_" + slug(argv) + "_" + id
	if s.project != "" {
		for _, suffix := range []string{".json", ".out.log", ".err.log"} {
			if e = ignoredDestination(s.project, filepath.Join(s.Path, session, name+suffix)); e != nil {
				dir.Close()
				return nil, e
			}
		}
	}
	c := &call{dir: dir, name: name}
	ok := false
	defer func() {
		if !ok {
			c.close()
		}
	}()
	c.meta, e = exclusive(dir, name+".json")
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(c.meta.Fd()), syscall.LOCK_EX); e != nil {
		return nil, e
	}
	c.out, e = exclusive(dir, name+".out.log")
	if e != nil {
		return nil, e
	}
	c.err, e = exclusive(dir, name+".err.log")
	if e != nil {
		return nil, e
	}
	c.record = Record{Ref: session + "/" + name, Stdout: filepath.Join(s.Path, session, name+".out.log"), Stderr: filepath.Join(s.Path, session, name+".err.log"), ExitCode: -1, CommandStatus: "running", CaptureStatus: "running", Started: time.Now().UTC(), Expires: time.Now().UTC().Add(time.Duration(hours * float64(time.Hour)))}
	if e = c.save(); e != nil {
		return nil, e
	}
	ok = true
	return c, nil
}
func (c *call) save() error {
	if _, e := c.meta.Seek(0, 0); e != nil {
		return e
	}
	if e := c.meta.Truncate(0); e != nil {
		return e
	}
	if e := json.NewEncoder(c.meta).Encode(c.record); e != nil {
		return e
	}
	return c.meta.Sync()
}
func splitRef(ref string) (string, string, error) {
	p := strings.Split(ref, "/")
	if len(p) != 2 || !safe.MatchString(p[0]) || !recordName.MatchString(p[1]) {
		return "", "", errors.New("invalid ref")
	}
	return p[0], p[1], nil
}
func (s *Store) Lookup(ref string) (Record, error) {
	session, name, e := splitRef(ref)
	if e != nil {
		return Record{}, e
	}
	dir, e := descend(s.root, session, false, false)
	if e != nil {
		return Record{}, errors.New("expired or unknown ref")
	}
	defer dir.Close()
	f, e := dir.OpenFile(name+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return Record{}, errors.New("expired or unknown ref")
	}
	defer f.Close()
	if e = privateFile(f); e != nil {
		return Record{}, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); e != nil {
		return Record{}, errors.New("capture running")
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
	for _, entry := range entries {
		if !entry.IsDir() || !safe.MatchString(entry.Name()) {
			continue
		}
		dir, e := descend(s.root, entry.Name(), false, false)
		if e != nil {
			return n, e
		}
		d, e := dir.Open(".")
		if e != nil {
			dir.Close()
			return n, e
		}
		files, e := d.ReadDir(-1)
		d.Close()
		if e != nil {
			dir.Close()
			return n, e
		}
		for _, f := range files {
			name := strings.TrimSuffix(f.Name(), ".json")
			if name == f.Name() || !recordName.MatchString(name) {
				continue
			}
			meta, e := dir.OpenFile(f.Name(), os.O_RDWR|syscall.O_NOFOLLOW, 0)
			if e != nil {
				dir.Close()
				return n, e
			}
			if e = privateFile(meta); e != nil {
				meta.Close()
				dir.Close()
				return n, e
			}
			if syscall.Flock(int(meta.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
				meta.Close()
				continue
			}
			var r Record
			e = json.NewDecoder(io.LimitReader(meta, 65536)).Decode(&r)
			if e == nil && r.Ref == entry.Name()+"/"+name && r.CaptureStatus != "expired" && r.CommandStatus != "running" && !now.Before(r.Expires) {
				for _, suffix := range []string{".out.log", ".err.log"} {
					st, se := dir.Lstat(name + suffix)
					if errors.Is(se, os.ErrNotExist) {
						continue
					}
					if se != nil || !st.Mode().IsRegular() {
						e = errors.New("unsafe purge entry")
						break
					}
					if se = dir.Remove(name + suffix); se != nil {
						e = se
						break
					}
				}
				if e == nil {
					r.CaptureStatus = "expired"
					c := call{meta: meta, record: r}
					e = c.save()
					n++
				}
			}
			meta.Close()
			if e != nil {
				dir.Close()
				return n, e
			}
		}
		dir.Close()
	}
	return n, nil
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
