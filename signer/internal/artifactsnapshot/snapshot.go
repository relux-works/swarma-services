// Package artifactsnapshot verifies the two unsigned builder streams after an
// authenticated, job-bound success result. It establishes byte identity only;
// it neither authenticates that result nor authorizes building, signing or release.
package artifactsnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	MaxBytes     int64 = 256 << 20
	StreamBudget       = 60 * time.Second
)

var (
	ErrReceipt  = errors.New("artifact_receipt_invalid")
	ErrStorage  = errors.New("artifact_storage_unavailable")
	ErrStream   = errors.New("artifact_stream_invalid")
	ErrMismatch = errors.New("artifact_mismatch")
	ErrDeadline = errors.New("artifact_deadline_unavailable")
	ErrCleanup  = errors.New("artifact_cleanup_failed")
)

// Receipt contains only the already-decoded first/second byte identity fields.
// The enclosing result, job/nonce, logs and source/policy bindings must have been
// independently validated before Verify. These fields establish no authority.
type Receipt struct {
	SHA256 string
	Bytes  int64
}

// Snapshot owns an unlinked, read-only file. No path or writable descriptor is
// exposed. Close releases its storage; concurrent ReadAt calls are supported.
// It is an unsigned in-process snapshot, not durable native signing staging.
type Snapshot struct {
	mu      sync.RWMutex
	file    *os.File
	receipt Receipt
}

func (s *Snapshot) Receipt() Receipt { return s.receipt }

func (s *Snapshot) ReadAt(p []byte, offset int64) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.file == nil {
		return 0, os.ErrClosed
	}
	return s.file.ReadAt(p, offset)
}

func (s *Snapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// Verify consumes and closes conn, which must be an authenticated builder
// connection positioned immediately after the validated success-result frame.
// conn must implement working absolute deadlines and concurrent Close semantics.
// ctx must carry the ORIGINAL job deadline (at most 600s from job acceptance);
// this function does not start or renew that budget. Cancellation closes conn.
// Each artifact has its own absolute 60s read budget capped by the job deadline;
// the final EOF shares the second budget and never renews it.
//
// parent is installed, signer-owned private scratch storage, never builder input.
// It must be an absolute, non-symlink 0700 directory. Its ancestors and concurrent
// namespace custody belong to the trusted host adapter. This package creates
// only its own exclusive 0700 child and 0600 files, and removes that child before
// returning. It never opens a builder path. Refusal returns no snapshot. Cleanup
// failure is explicit so the caller can retain the operation gate for recovery.
func Verify(ctx context.Context, parent string, conn net.Conn, first, second Receipt) (snapshot *Snapshot, resultErr error) {
	if conn == nil {
		return nil, ErrStream
	}
	defer func() {
		// Registered before all cleanup defers: final Close and any running
		// cancellation callback must finish before the original job is reconciled.
		if ctx != nil && ctx.Err() != nil {
			resultErr = errors.Join(resultErr, ctx.Err(), context.Cause(ctx))
			if snapshot != nil {
				if err := snapshot.Close(); err != nil {
					resultErr = errors.Join(resultErr, ErrCleanup, err)
				}
				snapshot = nil
			}
		}
	}()
	cleanupFailed := func() {
		resultErr = errors.Join(resultErr, ErrCleanup)
		if snapshot != nil {
			_ = snapshot.Close()
			snapshot = nil
		}
	}
	defer func() {
		if err := conn.Close(); !benignCloseError(err) {
			resultErr = errors.Join(resultErr, err)
			cleanupFailed()
		}
	}()
	if ctx == nil {
		return nil, ErrDeadline
	}
	jobDeadline, ok := ctx.Deadline()
	if !ok {
		return nil, ErrDeadline
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if time.Until(jobDeadline) > 600*time.Second {
		return nil, ErrDeadline
	}
	var cancelCloseErr error
	cancelCloseDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		cancelCloseErr = conn.Close()
		close(cancelCloseDone)
	})
	defer func() {
		// AfterFunc's stop does not wait for a running callback. Join it before
		// the final Close: an already-closed result must not hide its first error.
		if !stop() {
			<-cancelCloseDone
			if err := cancelCloseErr; !benignCloseError(err) {
				resultErr = errors.Join(resultErr, err)
				cleanupFailed()
			}
		}
	}()
	if !valid(first) || !valid(second) {
		return nil, ErrReceipt
	}
	if first != second {
		return nil, ErrMismatch
	}
	parent = filepath.Clean(parent)
	st, err := os.Lstat(parent)
	if err != nil || !filepath.IsAbs(parent) || st.Mode() != os.ModeDir|0700 {
		return nil, ErrStorage
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, ErrStorage
	}
	dir, err := os.MkdirTemp(parent, "artifact-")
	if err != nil {
		return nil, ErrStorage
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			cleanupFailed()
		}
	}()

	a, err := receive(ctx, conn, dir, "first", first, jobDeadline)
	if err != nil {
		return nil, err
	}
	defer func() {
		if a != nil {
			if err := a.Close(); err != nil {
				cleanupFailed()
			}
		}
	}()
	b, err := receive(ctx, conn, dir, "second", second, jobDeadline)
	if err != nil {
		return nil, err
	}
	defer func() {
		if b != nil {
			if err := b.Close(); err != nil {
				cleanupFailed()
			}
		}
	}()
	// The second receive installed its deadline. Do not extend it for EOF.
	var extra [1]byte
	n, err := conn.Read(extra[:])
	if n != 0 || err != io.EOF {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrStream
	}
	if err := equal(ctx, a, b, first.Bytes); err != nil {
		return nil, err
	}
	err = b.Close()
	b = nil
	if err != nil {
		return nil, ErrCleanup
	}
	err = a.Close()
	a = nil
	if err != nil {
		return nil, ErrCleanup
	}
	// Reopen only the private copy read-only, then unlink both names before
	// publishing the handle. The builder never gets this directory or descriptor.
	f, err := os.Open(filepath.Join(dir, "first"))
	if err != nil {
		return nil, ErrStorage
	}
	if err := os.RemoveAll(dir); err != nil {
		_ = f.Close()
		return nil, ErrCleanup
	}
	if err := ctx.Err(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Snapshot{file: f, receipt: first}, nil
}

// A match in one branch does not make an entire joined error benign. Unwrap
// both ordinary wrappers and joins, requiring every cause to be already closed.
func benignCloseError(err error) bool {
	if err == nil {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		causes := e.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !benignCloseError(cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		if cause := e.Unwrap(); cause != nil {
			return benignCloseError(cause)
		}
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

func valid(r Receipt) bool {
	if r.Bytes < 1 || r.Bytes > MaxBytes || len(r.SHA256) != 64 {
		return false
	}
	for _, c := range r.SHA256 {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func receive(ctx context.Context, conn net.Conn, dir, name string, r Receipt, jobDeadline time.Time) (_ *os.File, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(StreamBudget)
	if jobDeadline.Before(deadline) {
		deadline = jobDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
			return nil, ErrStream
		}
		return nil, ErrDeadline
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	keep := false
	defer func() {
		if !keep {
			if err := f.Close(); err != nil {
				resultErr = errors.Join(resultErr, ErrCleanup)
			}
		}
	}()
	h := sha256.New()
	var buf [32 << 10]byte
	remaining := r.Bytes
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		size := int64(len(buf))
		if remaining < size {
			size = remaining
		}
		n, err := io.ReadFull(conn, buf[:size])
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrStream
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return nil, ErrStorage
		}
		_, _ = h.Write(buf[:n])
		remaining -= int64(n)
	}
	if hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		return nil, ErrMismatch
	}
	keep = true
	return f, nil
}

func equal(ctx context.Context, a, b io.ReaderAt, size int64) error {
	var left, right [32 << 10]byte
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int64(len(left))
		if size-offset < n {
			n = size - offset
		}
		if _, err := a.ReadAt(left[:n], offset); err != nil {
			return ErrStorage
		}
		if _, err := b.ReadAt(right[:n], offset); err != nil {
			return ErrStorage
		}
		if !bytes.Equal(left[:n], right[:n]) {
			return ErrMismatch
		}
		offset += n
	}
	return nil
}
