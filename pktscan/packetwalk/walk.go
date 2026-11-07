// Package packetwalk enumerates bounded packet contents without extracting or
// executing them. The CLI composes it with a separate bounded classifier.
package packetwalk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// Errors contain no input names, contents, tool diagnostics or wrapped errors.
var (
	ErrInput   = errors.New("packet input refused")
	ErrLimit   = errors.New("packet limit exceeded")
	ErrArchive = errors.New("packet archive refused")
	ErrBundle  = errors.New("packet bundle refused")
	ErrBinary  = errors.New("packet binary refused")
	ErrVisit   = errors.New("packet visitor refused")
	ErrChanged = errors.New("packet input changed")
	ErrCleanup = errors.New("packet cleanup failed")
)

// Limits are cumulative across the entire invocation, including nested
// containers, Git objects and optional baseline bundle bytes. Every field must
// be positive. Hard ceilings prevent configuration overflow/unbounded settings.
type Limits struct {
	Depth, Files, Entries, Containers, Commands                          int
	FileBytes, CompressedBytes, ExpandedBytes, StreamBytes, CommandBytes int64
	Duration                                                             time.Duration
}

func DefaultLimits() Limits {
	return Limits{Depth: 8, Files: 4096, Entries: 8192, Containers: 64,
		Commands: 256, FileBytes: 16 << 20, CompressedBytes: 64 << 20,
		ExpandedBytes: 128 << 20, StreamBytes: 128 << 20,
		CommandBytes: 64 << 20, Duration: 30 * time.Second}
}

// Valid reports whether every budget is positive and below its hard ceiling.
func (l Limits) Valid() bool { return l.valid() }

func (l Limits) valid() bool {
	return l.Depth > 0 && l.Depth <= 32 && l.Files > 0 && l.Files <= 65536 &&
		l.Entries > 0 && l.Entries <= 131072 && l.Containers > 0 && l.Containers <= 1024 &&
		l.Commands > 0 && l.Commands <= 65536 && l.FileBytes > 0 && l.FileBytes <= 256<<20 &&
		l.CompressedBytes > 0 && l.CompressedBytes <= 1<<30 &&
		l.ExpandedBytes > 0 && l.ExpandedBytes <= 1<<30 &&
		l.StreamBytes > 0 && l.StreamBytes <= 1<<30 &&
		l.CommandBytes > 0 && l.CommandBytes <= 1<<30 && l.Duration > 0 && l.Duration <= 5*time.Minute
}

// Origin is assigned by the walker, never inferred from a logical path. It
// survives recursive archive expansion of a Git blob.
type Origin uint8

const (
	PacketContent Origin = iota
	GitBlobContent
	GitMetadata
	ArchiveMetadata
	GitSourcePath
)

// File is a fully materialized text leaf. Bytes are read-only to the visitor and
// valid only during the call. LogicalPath uses archive/member namespaces. Git
// metadata leaves additionally set ObjectID and ObjectType. No binary leaf can
// succeed with zero content counts: binary data is explicitly refused.
type File struct {
	LogicalPath          string
	Bytes                []byte
	ObjectID, ObjectType string
	FormatHint           string
	Origin               Origin
}

// Visitor must scan the entire leaf (including paths and Git metadata), honor
// ctx, and return nil only on complete classification. It must stage all results:
// any later error invalidates every previous callback and the returned Report.
type Visitor func(context.Context, File) error

type Options struct {
	Limits Limits
	// Git is required only when a bundle is encountered. See BundleOptions.
	Git *BundleOptions
	// Exclude identities are caller-owned control files. ValidateControl audits
	// their complete bytes before they are omitted from ordinary counts.
	Exclude         []fs.FileInfo
	ValidateControl func(context.Context, File) error
	// Path visits every input/member path, including empty directories and containers.
	Path func(context.Context, string, bool, Origin) error
}

type Report struct {
	Files, Entries, Containers, Commands                      int
	CompressedBytes, ExpandedBytes, StreamBytes, CommandBytes int64
	// Object scopes are counted per quarantined bundle, not globally deduplicated.
	GitImportedObjects, GitBaseObjects, GitDeltaObjects int
	// Leaves includes only fully visited text leaves, never raw containers.
	Leaves int
}

type walker struct {
	ctx   context.Context
	l     Limits
	r     Report
	visit Visitor
	git   *BundleOptions
	opts  Options
}

// Walk reads a quiescent operator-owned root using os.Root and rejects links or
// special files. It writes nothing beneath root. Errors return a zero Report;
// callers must discard staged callback results. The root must contain only
// intended packet data; controls/caches should be outside it.
func Walk(ctx context.Context, root *os.Root, opts Options, visit Visitor) (Report, error) {
	if ctx == nil || root == nil || visit == nil || !opts.Limits.valid() {
		return Report{}, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Limits.Duration)
	defer cancel()
	w := &walker{ctx: ctx, l: opts.Limits, visit: visit, git: opts.Git, opts: opts}
	if err := w.directory(root, "."); err != nil {
		return Report{}, err
	}
	if err := w.check(); err != nil {
		return Report{}, err
	}
	return w.r, nil
}

func (w *walker) check() error {
	if w.ctx.Err() != nil {
		return ErrLimit
	}
	return nil
}

func (w *walker) entry() error {
	w.r.Entries++
	if w.r.Entries > w.l.Entries {
		return ErrLimit
	}
	return w.check()
}

func charge(used *int64, n, limit int64) error {
	if n < 0 || n > limit-*used {
		return ErrLimit
	}
	*used += n
	return nil
}

func safePath(name string) bool {
	if name == "" || len(name) > 4096 || !utf8.ValidString(name) ||
		strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 128 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

func same(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func (w *walker) directory(root *os.Root, name string) error {
	if err := w.check(); err != nil {
		return err
	}
	f, err := root.Open(name)
	if err != nil {
		return ErrInput
	}
	defer f.Close()
	for {
		// Read one record at a time; never allocate an unbounded directory list.
		es, e := f.ReadDir(1)
		if e != nil && e != io.EOF {
			return ErrInput
		}
		for _, de := range es {
			if err = w.entry(); err != nil {
				return err
			}
			n := de.Name()
			if name != "." {
				n = name + "/" + n
			}
			if !safePath(n) {
				return ErrInput
			}
			i, e := root.Lstat(n)
			if e != nil {
				return ErrInput
			}
			if w.path(n, i.IsDir(), PacketContent) != nil {
				return ErrVisit
			}
			if i.IsDir() {
				if err = w.directory(root, n); err != nil {
					return err
				}
				continue
			}
			if !i.Mode().IsRegular() {
				return ErrInput
			}
			if i.Size() < 0 || i.Size() > w.l.FileBytes {
				return ErrLimit
			}
			in, e := root.Open(n)
			if e != nil {
				return ErrInput
			}
			actual, se := in.Stat()
			if se != nil || !same(i, actual) {
				in.Close()
				return ErrChanged
			}
			b, re := w.read(in, i.Size())
			after, se := in.Stat()
			ce := in.Close()
			if re != nil {
				return re
			}
			if se != nil || ce != nil || !same(i, after) {
				return ErrChanged
			}
			excluded := false
			for _, control := range w.opts.Exclude {
				if control != nil && os.SameFile(i, control) {
					if !same(i, control) {
						return ErrChanged
					}
					excluded = true
				}
			}
			if excluded {
				if w.opts.ValidateControl == nil || w.opts.ValidateControl(w.ctx, File{LogicalPath: n, Bytes: b}) != nil {
					return ErrVisit
				}
				continue
			}
			if err = w.payload(n, b, 0, PacketContent); err != nil {
				return err
			}
		}
		if e == io.EOF {
			break
		}
	}
	return nil
}

type checkedReader struct {
	w *walker
	r io.Reader
}

func (r checkedReader) Read(p []byte) (int, error) {
	if e := r.w.check(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}

// read charges all materialized payloads, including repeatedly nested bytes.
func (w *walker) read(r io.Reader, size int64) ([]byte, error) {
	if size < 0 || size > w.l.FileBytes || size > w.l.ExpandedBytes-w.r.ExpandedBytes {
		return nil, ErrLimit
	}
	b, err := io.ReadAll(io.LimitReader(checkedReader{w, r}, size+1))
	if err != nil {
		if w.check() != nil {
			return nil, ErrLimit
		}
		return nil, ErrArchive
	}
	if int64(len(b)) != size {
		return nil, ErrArchive
	}
	if err = charge(&w.r.ExpandedBytes, int64(len(b)), w.l.ExpandedBytes); err != nil {
		return nil, err
	}
	return b, nil
}

func kind(name string, b []byte) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".bundle"), bytes.HasPrefix(b, []byte("# v2 git bundle")), bytes.HasPrefix(b, []byte("# v3 git bundle")):
		return "bundle"
	case strings.HasSuffix(n, ".zip"), bytes.HasPrefix(b, []byte("PK\x03\x04")), bytes.HasPrefix(b, []byte("PK\x05\x06")), bytes.HasPrefix(b, []byte("PK\x07\x08")):
		return "zip"
	case strings.HasSuffix(n, ".tar.gz"), strings.HasSuffix(n, ".tgz"), bytes.HasPrefix(b, []byte{0x1f, 0x8b}):
		return "tgz"
	case strings.HasSuffix(n, ".tar"), len(b) >= 262 && string(b[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

func (w *walker) payload(name string, b []byte, depth int, origin Origin) error {
	if !safePath(name) {
		return ErrArchive
	}
	w.r.Files++
	if w.r.Files > w.l.Files {
		return ErrLimit
	}
	if e := w.check(); e != nil {
		return e
	}
	k := kind(name, b)
	if k == "" {
		return w.leaf(File{LogicalPath: name, Bytes: b, Origin: origin})
	}
	if depth >= w.l.Depth {
		return ErrLimit
	}
	w.r.Containers++
	if w.r.Containers > w.l.Containers {
		return ErrLimit
	}
	if e := charge(&w.r.CompressedBytes, int64(len(b)), w.l.CompressedBytes); e != nil {
		return e
	}
	switch k {
	case "zip":
		return w.zip(name, b, depth+1, origin)
	case "tar", "tgz":
		return w.tar(name, b, depth+1, k == "tgz", origin)
	case "bundle":
		return w.bundle(name, b, depth+1)
	}
	return ErrArchive
}

func (w *walker) leaf(f File) error {
	if e := w.check(); e != nil {
		return e
	}
	if bytes.IndexByte(f.Bytes, 0) >= 0 || !utf8.Valid(f.Bytes) {
		return ErrBinary
	}
	if w.visit(w.ctx, f) != nil {
		return ErrVisit
	}
	if e := w.check(); e != nil {
		return e
	}
	w.r.Leaves++
	return nil
}

func (w *walker) path(name string, directory bool, origin Origin) error {
	if e := w.check(); e != nil {
		return e
	}
	if w.opts.Path != nil && w.opts.Path(w.ctx, name, directory, origin) != nil {
		return ErrVisit
	}
	return w.check()
}
