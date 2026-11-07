package keylessexecutor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// state is controller-owned and never reused between builds. A native backend
// must expose root as /work in a new namespace, bind source/modules/tools read
// only, and expose only home/tmp/cache/out and the recorded auxiliary dirs as
// writable. Permission bits alone are not an isolation boundary for the owner.
type state struct {
	root   string
	ledger []Entry
}

func privateParent(parent string) error {
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return ErrState
	}
	// Refuse symlinks in every ancestor, including the supplied parent itself.
	for p := parent; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return ErrState
		}
		if p == parent && i.Mode().Perm() != 0700 {
			return ErrState
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

func materialize(ctx context.Context, parent string, p *Plan) (s *state, err error) {
	if p == nil || len(p.files) == 0 {
		return nil, ErrInput
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = privateParent(parent); err != nil {
		return nil, err
	}
	root, e := os.MkdirTemp(parent, "keyless-")
	if e != nil {
		return nil, ErrState
	}
	s = &state{root: root}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.cleanup())
			s = nil
		}
	}()
	for _, d := range []string{"source", "modules", "home", "tmp", "cache", "out"} {
		if e = os.Mkdir(filepath.Join(root, d), 0700); e != nil {
			return s, ErrState
		}
	}
	for _, f := range p.files {
		if err = ctx.Err(); err != nil {
			return s, err
		}
		if !validPath(f.Path) || sum(f.data) != f.SHA256 || uint64(len(f.data)) != f.Bytes {
			return s, ErrInput
		}
		target := filepath.Join(root, filepath.FromSlash(f.Path))
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return s, ErrState
		}
		out, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return s, ErrState
		}
		_, we := out.Write(f.data)
		ce := out.Close()
		if we != nil || ce != nil {
			return s, ErrState
		}
		mode := fs.FileMode(0444)
		if f.Executable {
			mode = 0555
		}
		if e = os.Chmod(target, mode); e != nil {
			return s, ErrState
		}
		s.ledger = append(s.ledger, f.Entry)
	}
	// Canonical content directories are read only. Cache download directories
	// carry auxiliary Go lock/stat state; their canonical files stay read only.
	for _, base := range []string{"source", "modules"} {
		e = filepath.WalkDir(filepath.Join(root, base), func(name string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				mode := fs.FileMode(0555)
				rel, _ := filepath.Rel(root, name)
				if rel == "modules" || strings.HasPrefix(filepath.ToSlash(rel), "modules/cache") {
					mode = 0700
				}
				return os.Chmod(name, mode)
			}
			return nil
		})
		if e != nil {
			return s, ErrState
		}
	}
	return s, nil
}

// writableAuxiliary is a mount plan, not a claim that chmod alone enforces it.
func (s *state) writableAuxiliary() []string {
	return []string{"/work/home", "/work/tmp", "/work/cache", "/work/out", "/work/modules/cache/download"}
}
func (s *state) cleanup() error {
	if s == nil || s.root == "" {
		return nil
	}
	// Only this task's unique state is made removable. Never follow a symlink.
	e := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return os.Chmod(p, 0700)
		}
		return nil
	})
	if e != nil {
		return ErrCleanup
	}
	if e = os.RemoveAll(s.root); e != nil {
		return ErrCleanup
	}
	if _, e = os.Lstat(s.root); !errors.Is(e, os.ErrNotExist) {
		return ErrCleanup
	}
	s.root = ""
	return nil
}
