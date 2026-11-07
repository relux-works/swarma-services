package signingaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// MaxAuditBytes is the agreed audit+idempotency allocation. Smaller fixture
	// budgets are allowed; raising the policy allocation requires a policy change.
	MaxAuditBytes int64 = 2 << 30
	maxRecord           = 16384
	// Acceptance reserves bounded space for intent, outcome and a recovery seal.
	operationReserve int64 = 5 * (maxRecord + 4)
	journalName            = "0000000000000001.journal"
	sealName               = "0000000000000002.journal"
)

// Durability is an explicitly injected, qualified-by-the-host persistence profile.
// An error poisons the writer; no write/flush is retried in that instance.
// File must cover appended data/metadata; Directory must persist new entries.
// There is no claim that Sync alone survives arbitrary power/storage failures.
type Durability interface {
	Name() string
	File(*os.File) error
	Directory(*os.File) error
}

// LocalFSync is an explicitly selectable source-fixture profile. It calls real
// file/directory fsync and propagates errors. It is NOT Darwin F_FULLFSYNC or a
// qualified production durability profile.
type LocalFSync struct{}

func (LocalFSync) Name() string               { return "local-fsync-fixture-v1" }
func (LocalFSync) File(f *os.File) error      { return f.Sync() }
func (LocalFSync) Directory(f *os.File) error { return f.Sync() }

type Options struct {
	Durability Durability
	MaxBytes   int64
	// Checkpoint is obtained from independently retained custody, not this log.
	// Zero explicitly means no rollback anchor is available; that limit persists.
	Checkpoint Anchor
}

// The format is a bounded local proposal, not the client wire protocol. Every
// frame is uint32be length + exact canonical Go-JSON record bytes. Digest hashes
// domain + those bytes with Digest empty, including Sequence and Previous.
type record struct {
	Schema    int
	Sequence  uint64
	Previous  string
	Kind      string
	Operation Operation
	Digest    string
}

type header struct {
	Schema  int
	Profile string
	Budget  int64
}

// A seal is the entire second segment. It binds EVERY byte of the damaged first
// segment plus its last verified record. It deliberately grants no continuation.
type seal struct {
	Schema      int
	Predecessor string
	Bytes       int64
	SHA256      string
	Last        Anchor
}

type journal struct {
	root    *os.Root
	dir     *os.File
	file    *os.File
	durable Durability
	budget  int64
	size    int64
	last    Anchor
	torn    bool
	write   func([]byte) (int, error)
}

func openJournal(path string, opts Options, apply func(record) error) (_ *journal, err error) {
	if opts.Durability == nil || !boundedASCII(opts.Durability.Name(), 128) || opts.MaxBytes < operationReserve+1024 || opts.MaxBytes > MaxAuditBytes {
		return nil, ErrAudit
	}
	if opts.Checkpoint.Sequence == 0 && opts.Checkpoint.Digest != "" || opts.Checkpoint.Sequence > 0 && !hexValue(opts.Checkpoint.Digest, 64) {
		return nil, ErrAudit
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrAudit
	}
	before, err := os.Lstat(path)
	if err != nil || !privateInfo(before, true) {
		return nil, ErrAudit
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrAudit
	}
	j := &journal{root: root, durable: opts.Durability, budget: opts.MaxBytes}
	defer func() {
		if err != nil {
			err = errors.Join(err, j.close())
		}
	}()
	j.dir, err = root.Open(".")
	if err != nil {
		return nil, ErrAudit
	}
	actual, err := j.dir.Stat()
	if err != nil || !privateInfo(actual, true) || !os.SameFile(before, actual) {
		return nil, ErrAudit
	}
	if err = syscall.Flock(int(j.dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, ErrLocked
	}
	entries, err := j.dir.ReadDir(3)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrAudit
	}
	if len(entries) > 2 {
		return nil, ErrCorrupt
	}
	for _, entry := range entries {
		if entry.Name() != journalName && entry.Name() != sealName {
			return nil, ErrCorrupt
		}
	}
	_, err = root.Lstat(journalName)
	if errors.Is(err, os.ErrNotExist) {
		if len(entries) != 0 || opts.Checkpoint.Sequence != 0 {
			return nil, ErrCorrupt
		}
		j.file, err = root.OpenFile(journalName, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return nil, ErrAudit
		}
		b, _ := json.Marshal(header{1, opts.Durability.Name(), opts.MaxBytes})
		if err = writeFrame(j.file, b); err != nil {
			return nil, errors.Join(ErrAudit, err)
		}
		if err = j.durable.File(j.file); err != nil {
			return nil, errors.Join(ErrAudit, err)
		}
		if err = j.durable.Directory(j.dir); err != nil {
			return nil, errors.Join(ErrAudit, err)
		}
	} else if err != nil {
		return nil, ErrAudit
	} else {
		j.file, err = openPrivate(root, journalName, os.O_RDWR|os.O_APPEND)
		if err != nil {
			return nil, err
		}
	}
	info, err := j.file.Stat()
	if err != nil || !privateInfo(info, false) || info.Size() > opts.MaxBytes {
		return nil, ErrCorrupt
	}
	j.size = info.Size()
	if _, err = j.file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrAudit
	}
	b, partial, err := readFrame(j.file)
	if err != nil || partial {
		return nil, ErrCorrupt
	}
	var h header
	if !decodeExact(b, &h) || h != (header{1, opts.Durability.Name(), opts.MaxBytes}) {
		return nil, ErrCorrupt
	}
	checkpointSeen := opts.Checkpoint.Sequence == 0
	for {
		b, partial, err = readFrame(j.file)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrCorrupt
		}
		if partial {
			j.torn = true
			break
		}
		var r record
		if !decodeExact(b, &r) || r.Schema != 1 || r.Sequence == 0 || r.Sequence > 9223372036854775807 || r.Sequence != j.last.Sequence+1 || r.Previous != j.last.Digest || !hexValue(r.Digest, 64) || recordDigest(r) != r.Digest {
			return nil, ErrCorrupt
		}
		if err = apply(r); err != nil {
			return nil, err
		}
		j.last = Anchor{r.Sequence, r.Digest}
		if r.Sequence == opts.Checkpoint.Sequence {
			if r.Digest != opts.Checkpoint.Digest {
				return nil, ErrCorrupt
			}
			checkpointSeen = true
		}
	}
	if !checkpointSeen {
		return nil, ErrCorrupt
	}
	_, sealErr := root.Lstat(sealName)
	if j.torn {
		// Seal without discarding tail bytes. All effects stay disabled. A future
		// tail reconciliation needs a separately agreed, custodian-owned protocol.
		if err = j.sealTail(errors.Is(sealErr, os.ErrNotExist)); err != nil {
			return nil, err
		}
	} else if !errors.Is(sealErr, os.ErrNotExist) {
		return nil, ErrCorrupt
	}
	// A complete record observed after restart may have survived a failed flush.
	// Re-establish the selected boundary before permitting any effect or release.
	if err = j.durable.File(j.file); err != nil {
		return nil, errors.Join(ErrAudit, err)
	}
	if err = j.durable.Directory(j.dir); err != nil {
		return nil, errors.Join(ErrAudit, err)
	}
	j.write = j.file.Write
	return j, nil
}

func (j *journal) sealTail(create bool) (err error) {
	if _, err := j.file.Seek(0, io.SeekStart); err != nil {
		return ErrAudit
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(j.file, j.budget+1))
	if err != nil || n != j.size {
		return ErrCorrupt
	}
	want := seal{1, journalName, n, hex.EncodeToString(h.Sum(nil)), j.last}
	if !create {
		f, openErr := openPrivate(j.root, sealName, os.O_RDONLY)
		if openErr != nil {
			return openErr
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				err = errors.Join(ErrAudit, err, closeErr)
			}
		}()
		b, partial, readErr := readFrame(f)
		var got seal
		if readErr != nil || partial || !decodeExact(b, &got) || got != want {
			return ErrCorrupt
		}
		if _, _, readErr = readFrame(f); !errors.Is(readErr, io.EOF) {
			return ErrCorrupt
		}
		st, statErr := f.Stat()
		if statErr != nil || j.size > j.budget-st.Size() {
			return ErrAudit
		}
		j.size += st.Size()
		return nil
	}
	b, _ := json.Marshal(want)
	if j.size > j.budget-int64(len(b)+4) {
		return ErrAudit
	}
	f, err := j.root.OpenFile(sealName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrAudit
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(ErrAudit, err, closeErr)
		}
	}()
	if err = writeFrame(f, b); err != nil {
		return errors.Join(ErrAudit, err)
	}
	if err = j.durable.File(f); err != nil {
		return errors.Join(ErrAudit, err)
	}
	if err = j.durable.Directory(j.dir); err != nil {
		return errors.Join(ErrAudit, err)
	}
	j.size += int64(len(b) + 4)
	return nil
}

func (j *journal) canAccept() bool { return !j.torn && j.size <= j.budget-operationReserve }

func (j *journal) append(kind string, op Operation) (record, error) {
	if j.torn || j.last.Sequence >= 9223372036854775807 {
		return record{}, ErrAudit
	}
	op.Receipt = Anchor{}
	r := record{Schema: 1, Sequence: j.last.Sequence + 1, Previous: j.last.Digest, Kind: kind, Operation: op}
	r.Digest = recordDigest(r)
	b, err := json.Marshal(r)
	if err != nil || len(b) > maxRecord || j.size > j.budget-int64(len(b)+4) {
		return record{}, ErrAudit
	}
	frame := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(b)))
	copy(frame[4:], b)
	n, err := j.write(frame)
	if err != nil {
		return record{}, errors.Join(ErrAudit, err)
	}
	if n != len(frame) {
		return record{}, errors.Join(ErrAudit, io.ErrShortWrite)
	}
	// PRE_RELEASE_OUTCOME: writer state advances ONLY after actual durable flush.
	if err = j.durable.File(j.file); err != nil {
		return record{}, errors.Join(ErrAudit, err)
	}
	j.size += int64(len(frame))
	j.last = Anchor{r.Sequence, r.Digest}
	return r, nil
}

func (j *journal) close() error {
	var errs []error
	if j.file != nil {
		errs = append(errs, j.file.Close())
		j.file = nil
	}
	if j.dir != nil {
		errs = append(errs, j.dir.Close())
		j.dir = nil
	}
	if j.root != nil {
		errs = append(errs, j.root.Close())
		j.root = nil
	}
	return errors.Join(errs...)
}

func recordDigest(r record) string {
	r.Digest = ""
	b, _ := json.Marshal(r)
	h := sha256.New()
	_, _ = h.Write([]byte("swarma-signingaudit-record-v1\x00"))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func decodeExact(b []byte, v any) bool {
	if len(b) == 0 || len(b) > maxRecord {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return false
	}
	canonical, err := json.Marshal(v)
	// Canonical local writer format also rejects duplicate keys, null, aliases,
	// unknown fields and alternate spellings. This is NOT a wire admission rule.
	return err == nil && bytes.Equal(b, canonical)
}

func readFrame(r io.Reader) ([]byte, bool, error) {
	var head [4]byte
	n, err := io.ReadFull(r, head[:])
	if err != nil {
		if err == io.EOF && n == 0 {
			return nil, false, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return nil, true, nil
		}
		return nil, false, err
	}
	size := binary.BigEndian.Uint32(head[:])
	if size == 0 || size > maxRecord {
		return nil, false, ErrCorrupt
	}
	b := make([]byte, int(size))
	if _, err := io.ReadFull(r, b); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, true, nil
		}
		return nil, false, err
	}
	return b, false, nil
}

func writeFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > maxRecord {
		return ErrAudit
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if n, err := w.Write(h[:]); err != nil {
		return err
	} else if n != len(h) {
		return io.ErrShortWrite
	}
	if n, err := w.Write(b); err != nil {
		return err
	} else if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func openPrivate(root *os.Root, name string, flags int) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil || !privateInfo(before, false) {
		return nil, ErrCorrupt
	}
	f, err := root.OpenFile(name, flags|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrCorrupt
	}
	after, err := f.Stat()
	if err != nil || !privateInfo(after, false) || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, ErrCorrupt
	}
	return f, nil
}

func privateInfo(info os.FileInfo, dir bool) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	if dir {
		return info.IsDir() && info.Mode() == os.ModeDir|0700
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && st.Nlink == 1
}
