package signingaudit

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func journalBytes(t *testing.T, f *fixture) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func closeFixture(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.a.Close(); err != nil {
		t.Fatal(err)
	}
	f.a = nil
}
func replaceFixtureJournal(t *testing.T, f *fixture, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, journalName), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func frames(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	r := bytes.NewReader(b)
	for {
		v, partial, err := readFrame(r)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil || partial {
			t.Fatalf("fixture frame: %v partial=%v", err, partial)
		}
		out = append(out, v)
	}
}
func frameBytes(t *testing.T, parts [][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, part := range parts {
		if err := writeFrame(&out, part); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func TestJournalChainReceiptAndCheckpoint(t *testing.T) {
	f := newFixture(t)
	op := succeeded(t, f)
	parts := frames(t, journalBytes(t, f))
	if len(parts) != 4 {
		t.Fatalf("frames %d", len(parts))
	}
	var last Anchor
	for n, b := range parts[1:] {
		var r record
		if !decodeExact(b, &r) {
			t.Fatal("record decode")
		}
		if r.Sequence != uint64(n+1) || r.Previous != last.Digest || r.Digest != recordDigest(r) {
			t.Fatal("chain/sequence digest")
		}
		last = Anchor{r.Sequence, r.Digest}
	}
	if last != op.Receipt {
		t.Fatal("receipt not exact outcome record")
	}
	f.opts.Checkpoint = op.Receipt
	f.restart(t)
	got, err := f.a.Inspect(op.Request.Caller, op.Request.RequestID)
	if err != nil || got != op {
		t.Fatal("anchored replay")
	}
	closeFixture(t, f)
	// Coherent rollback to the genuine intent is detected by independently
	// retained outcome sequence/digest, not a fabricated chain mismatch.
	replaceFixtureJournal(t, f, frameBytes(t, parts[:3]))
	_, err = Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrCorrupt)
}

func TestWrongCheckpointAndPolicyProfileRefuse(t *testing.T) {
	f := newFixture(t)
	op := succeeded(t, f)
	closeFixture(t, f)
	f.opts.Checkpoint = Anchor{op.Receipt.Sequence, digest([]byte("wrong checkpoint"))}
	_, err := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrCorrupt)
	f.opts.Checkpoint = Anchor{}
	f.opts.MaxBytes++
	_, err = Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrCorrupt)
	// A failed open must release its lock and never modify the journal.
	f.opts.MaxBytes--
	f.reopen(t)
}

func TestCorruptJournalRefusesWithoutRewriting(t *testing.T) {
	cases := []string{"digest", "sequence", "previous", "transition", "duplicate-member", "unknown-member", "oversize-length", "zero-length", "unknown-file"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			succeeded(t, f)
			parts := frames(t, journalBytes(t, f))
			closeFixture(t, f)
			if name == "unknown-file" {
				if err := os.WriteFile(filepath.Join(f.dir, "foreign"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if name == "oversize-length" || name == "zero-length" {
				b := frameBytes(t, parts)
				var n [4]byte
				if name == "oversize-length" {
					binary.BigEndian.PutUint32(n[:], maxRecord+1)
				}
				b = append(b, n[:]...)
				replaceFixtureJournal(t, f, b)
			} else {
				var r record
				if !decodeExact(parts[2], &r) {
					t.Fatal("fixture decode")
				}
				switch name {
				case "digest":
					r.Digest = digest([]byte("wrong"))
				case "sequence":
					r.Sequence++
					r.Digest = recordDigest(r)
				case "previous":
					r.Previous = digest([]byte("wrong"))
					r.Digest = recordDigest(r)
				case "transition":
					r.Kind = "outcome"
					r.Digest = recordDigest(r)
				}
				b, _ := json.Marshal(r)
				if name == "duplicate-member" {
					b = append([]byte(`{"Schema":1,`), b[1:]...)
				}
				if name == "unknown-member" {
					b = append([]byte(`{"Extra":1,`), b[1:]...)
				}
				parts[2] = b
				replaceFixtureJournal(t, f, frameBytes(t, parts))
			}
			before := journalBytes(t, f)
			_, err := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
			wantErr(t, err, ErrCorrupt)
			if !bytes.Equal(before, journalBytes(t, f)) {
				t.Fatal("corruption repaired by rewrite")
			}
			if f.effects.signs.Load() != 1 || f.effects.releases.Load() != 0 {
				t.Fatal("corrupt replay had effects")
			}
		})
	}
}

func TestPartialTailPreservedSealedAndHeld(t *testing.T) {
	for _, tail := range [][]byte{{0, 0}, {0, 0, 0, 50, '{', '"'}} {
		t.Run(map[int]string{2: "header", 6: "body"}[len(tail)], func(t *testing.T) {
			f := newFixture(t)
			op := accepted(t, f)
			f.effects.signError = true
			_, err := f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrUncertain)
			closeFixture(t, f)
			before := append(journalBytes(t, f), tail...)
			replaceFixtureJournal(t, f, before)
			f.reopen(t)
			if !bytes.Equal(before, journalBytes(t, f)) {
				t.Fatal("torn bytes lost")
			}
			b, err := os.ReadFile(filepath.Join(f.dir, sealName))
			if err != nil {
				t.Fatal(err)
			}
			p := frames(t, b)
			var s seal
			if len(p) != 1 || !decodeExact(p[0], &s) || s.Bytes != int64(len(before)) || s.SHA256 != digest(before) || s.Last.Sequence != 2 {
				t.Fatal("seal does not bind full predecessor and last record")
			}
			_, err = f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrUncertain)
			_, err = f.a.Reconcile(context.Background(), op.ID, f.effects)
			wantErr(t, err, ErrUncertain)
			r := request()
			r.RequestID = "next"
			_, err = f.a.Accept(r, inputs())
			wantErr(t, err, ErrBusy)
			wantErr(t, f.a.Fetch(context.Background(), op.Request.Caller, op.ID), ErrUncertain)
			_, err = f.a.Inspect(op.Request.Caller, "unknown-after-tail")
			wantErr(t, err, ErrUncertain)
			f.restart(t)
			if !bytes.Equal(before, journalBytes(t, f)) {
				t.Fatal("reopen changed sealed predecessor")
			}
			closeFixture(t, f)
			before[len(before)-1] ^= 1
			replaceFixtureJournal(t, f, before)
			_, err = Open(f.dir, f.opts, f.trust, f.effects, f.effects)
			wantErr(t, err, ErrCorrupt)
		})
	}
}

func TestExclusiveWriterAndFilesystemCustody(t *testing.T) {
	f := newFixture(t)
	_, err := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrLocked)
	closeFixture(t, f)
	for _, mode := range []os.FileMode{0755, 0770, os.ModeSticky | 0700} {
		if err := os.Chmod(f.dir, mode); err != nil {
			t.Fatal(err)
		}
		_, err = Open(f.dir, f.opts, f.trust, f.effects, f.effects)
		wantErr(t, err, ErrAudit)
	}
	if err := os.Chmod(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "journal-link")
	if err := os.Symlink(f.dir, link); err != nil {
		t.Fatal(err)
	}
	_, err = Open(link, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrAudit)
	f.reopen(t)
}

func TestJournalSymlinkHardlinkAndPermissionsRefuse(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			succeeded(t, f)
			closeFixture(t, f)
			path := filepath.Join(f.dir, journalName)
			outside := filepath.Join(t.TempDir(), "copy")
			if kind == "permissions" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			} else if kind == "hardlink" {
				if err := os.Link(path, outside); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(path, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
			wantErr(t, err, ErrCorrupt)
		})
	}
}

func TestCreationReplayAndDirectoryFlushFailures(t *testing.T) {
	f := newFixture(t)
	op := succeeded(t, f)
	closeFixture(t, f)
	f.p.fail("outcome")
	_, err := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrAudit)
	f.p.fail("")
	f.p.mu.Lock()
	f.p.failDir = true
	f.p.mu.Unlock()
	_, err = Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrAudit)
	newDir := t.TempDir()
	_, err = Open(newDir, f.opts, f.trust, f.effects, f.effects)
	wantErr(t, err, ErrAudit)
	f.p.mu.Lock()
	f.p.failDir = false
	f.p.mu.Unlock()
	f.reopen(t)
	got, err := f.a.Inspect(op.Request.Caller, op.Request.RequestID)
	if err != nil || got != op {
		t.Fatal("replay after explicit repair lost history")
	}
}

func TestBoundedStorageRefusesBeforeNewEffects(t *testing.T) {
	f := newFixture(t)
	closeFixture(t, f)
	// New policy budget needs a new private fixture, never rewriting its header.
	f.dir = t.TempDir()
	f.effects.journal = f.dir
	f.opts.MaxBytes = operationReserve + 1024
	f.reopen(t)
	f.trust.deny.Store(true)
	count := 0
	for ; count < 100; count++ {
		r := request()
		r.RequestID = string(rune('A' + count))
		op, err := f.a.Accept(r, inputs())
		if err != nil {
			wantErr(t, err, ErrAudit)
			break
		}
		_, err = f.a.Run(context.Background(), op.ID)
		wantErr(t, err, ErrAuthority)
	}
	if count == 0 || count == 100 {
		t.Fatalf("capacity not reached within bounded fixture: %d", count)
	}
	before := journalBytes(t, f)
	if int64(len(before)) > f.opts.MaxBytes {
		t.Fatal("budget exceeded")
	}
	if f.effects.signs.Load() != 0 || f.effects.releases.Load() != 0 {
		t.Fatal("storage failure had effects")
	}
	f.restart(t)
	r := request()
	r.RequestID = "new"
	_, err := f.a.Accept(r, inputs())
	wantErr(t, err, ErrAudit)
	if !bytes.Equal(before, journalBytes(t, f)) {
		t.Fatal("automatic pruning occurred")
	}
}

func TestConfigurationAndInputBounds(t *testing.T) {
	f := newFixture(t)
	for _, opts := range []Options{{}, {Durability: LocalFSync{}, MaxBytes: MaxAuditBytes + 1}, {Durability: LocalFSync{}, MaxBytes: 1024}, {Durability: LocalFSync{}, MaxBytes: 1 << 20, Checkpoint: Anchor{Digest: digest(nil)}}} {
		_, err := Open(t.TempDir(), opts, f.trust, f.effects, f.effects)
		wantErr(t, err, ErrAudit)
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.RequestID = "bad\n" }, func(r *Request) { r.Caller = "" }, func(r *Request) { r.Commit = "BAD" }, func(r *Request) { r.ProductID = string(make([]byte, 129)) }} {
		r := request()
		mutate(&r)
		_, err := f.a.Accept(r, inputs())
		wantErr(t, err, ErrInvalid)
	}
	for _, mutate := range []func(*Inputs){func(i *Inputs) { i.UnsignedBytes = 0 }, func(i *Inputs) { i.UnsignedBytes = 268435457 }, func(i *Inputs) { i.Target = "linux/amd64" }, func(i *Inputs) { i.InputSHA256 = "bad" }} {
		in := inputs()
		mutate(&in)
		_, err := f.a.Accept(request(), in)
		wantErr(t, err, ErrInvalid)
	}
	if _, err := f.a.Accept(request(), inputs()); err != nil {
		t.Fatal("valid neighbor", err)
	}
}
