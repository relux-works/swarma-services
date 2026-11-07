package sourceauthority

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ProtectedPolicySource is a Linux local-installation adapter. The custodian
// fixes an absolute path and expected file UID at construction. Ancestors may
// be owned by root or that UID, and must never be group/other writable. The
// file must be single-link regular, exactly 0600 and owned by that UID. Root
// ownership is not required when the installation custodian is an ordinary UID.
// Directory identities are pinned; replacing a directory requires reconstruction.
// The file may be atomically reinstalled; each Snapshot opens it afresh.
//
// No goroutine, retry, network, key, credential, environment or caller URL is
// used. Context is checked around every syscall and bounded read. Linux cannot
// interrupt an uninterruptible filesystem syscall: use a trusted local filesystem
// and an outer supervised process for a hard wall-clock containment boundary.
type ProtectedPolicySource struct {
	parts []string
	uid   uint32
	dirs  []syscall.Stat_t
}

func NewProtectedPolicySource(ctx context.Context, path string, uid uint32) (*ProtectedPolicySource, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return nil, unavailable("policy_path")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityBudget)
	defer cancel()
	s := &ProtectedPolicySource{parts: strings.Split(path[1:], "/"), uid: uid}
	f, dirs, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	if f.Close() != nil {
		return nil, unavailable("policy_storage")
	}
	s.dirs = dirs
	// Validate the initial file as well; no partially configured source escapes.
	if _, err := s.Snapshot(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func sameNode(a, b syscall.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func sameFile(a, b syscall.Stat_t) bool {
	return sameNode(a, b) && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (s *ProtectedPolicySource) directory(st syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFDIR && st.Mode&0022 == 0 && (st.Uid == 0 || st.Uid == s.uid)
}
func (s *ProtectedPolicySource) regular(st syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&07777 == 0600 && st.Uid == s.uid && st.Nlink == 1 && st.Size > 0 && st.Size <= MaxPolicyBytes
}
func policyContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return unavailable("policy_deadline")
	}
	return nil
}

// open walks from / using only directory descriptors and NOFOLLOW at every
// component. A second independent walk at completion detects namespace races.
func (s *ProtectedPolicySource) open(ctx context.Context) (*os.File, []syscall.Stat_t, error) {
	if s == nil || len(s.parts) == 0 {
		return nil, nil, unavailable("policy_configuration")
	}
	if err := policyContext(ctx); err != nil {
		return nil, nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, unavailable("policy_storage")
	}
	defer func() { syscall.Close(fd) }()
	var dirs []syscall.Stat_t
	for i := 0; i < len(s.parts); i++ {
		if err := policyContext(ctx); err != nil {
			return nil, nil, err
		}
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || !s.directory(st) {
			return nil, nil, unavailable("policy_directory")
		}
		if s.dirs != nil && (i >= len(s.dirs) || !sameNode(st, s.dirs[i])) {
			return nil, nil, unavailable("policy_directory_changed")
		}
		dirs = append(dirs, st)
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(s.parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(fd, s.parts[i], flags, 0)
		if err != nil {
			return nil, nil, unavailable("policy_storage")
		}
		if i == len(s.parts)-1 {
			f := os.NewFile(uintptr(next), "protected-policy")
			if err := policyContext(ctx); err != nil {
				f.Close()
				return nil, nil, err
			}
			return f, dirs, nil
		}
		syscall.Close(fd)
		fd = next
	}
	return nil, nil, unavailable("policy_storage")
}

func (s *ProtectedPolicySource) read(ctx context.Context, f *os.File) ([]byte, syscall.Stat_t, error) {
	var before, after syscall.Stat_t
	if err := policyContext(ctx); err != nil {
		return nil, before, err
	}
	if syscall.Fstat(int(f.Fd()), &before) != nil || !s.regular(before) {
		return nil, before, unavailable("policy_file")
	}
	raw := make([]byte, int(before.Size)+1)
	n := 0
	for n < len(raw) {
		if err := policyContext(ctx); err != nil {
			return nil, before, err
		}
		got, err := syscall.Read(int(f.Fd()), raw[n:])
		if err != nil {
			return nil, before, unavailable("policy_storage")
		}
		if got == 0 {
			break
		}
		n += got
	}
	if err := policyContext(ctx); err != nil {
		return nil, before, err
	}
	if syscall.Fstat(int(f.Fd()), &after) != nil || !s.regular(after) || !sameFile(before, after) || int64(n) != before.Size {
		return nil, before, unavailable("policy_changed")
	}
	return raw[:n], after, nil
}

// Snapshot makes two fresh, bounded descriptor reads, compares exact bytes and
// metadata, and verifies the current installed pathname still names that file.
// It refuses races rather than retrying into a new phase budget. An atomic
// reinstall wholly before a read is legitimate; a racing replacement refuses.
func (s *ProtectedPolicySource) Snapshot(ctx context.Context) (*PolicySnapshot, error) {
	if ctx == nil {
		return nil, unavailable("policy_deadline")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityBudget)
	defer cancel()
	f, _, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, st, err := s.read(ctx, f)
	if err != nil {
		return nil, err
	}
	g, _, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Close()
	second, st2, err := s.read(ctx, g)
	if err != nil {
		return nil, err
	}
	if !sameFile(st, st2) || !bytes.Equal(raw, second) {
		return nil, unavailable("policy_changed")
	}
	snap, err := policySnapshot(raw)
	if err != nil {
		return nil, err
	}
	// Decode work is inside the same absolute deadline; confirm namespace and
	// metadata again after parsing, without accepting a new installed generation.
	h, _, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	var final syscall.Stat_t
	if syscall.Fstat(int(h.Fd()), &final) != nil || !sameFile(st, final) || !s.regular(final) {
		return nil, unavailable("policy_changed")
	}
	if err := policyContext(ctx); err != nil {
		return nil, err
	}
	return snap, nil
}
