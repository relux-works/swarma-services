package signingaudit

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type closingFault struct{ LocalFSync }

func (closingFault) File(f *os.File) error {
	if err := f.Close(); err != nil {
		return err
	}
	return syscall.EIO
}

type closingSealFault struct{ LocalFSync }

func (closingSealFault) File(f *os.File) error {
	if filepath.Base(f.Name()) == sealName {
		return f.Close()
	}
	return f.Sync()
}

func TestSealCleanupFailurePreservesTailAndFailure(t *testing.T) {
	f := newFixture(t)
	accepted(t, f)
	closeFixture(t, f)
	tail := append(journalBytes(t, f), 0, 0)
	replaceFixtureJournal(t, f, tail)
	f.opts.Durability = closingSealFault{}
	_, err := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	if !errors.Is(err, ErrAudit) || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("seal close error lost: %v", err)
	}
	if string(journalBytes(t, f)) != string(tail) {
		t.Fatal("cleanup failure rewrote tail")
	}
	if f.effects.signs.Load() != 0 || f.effects.releases.Load() != 0 {
		t.Fatal("cleanup failure enabled effect")
	}
	f.opts.Durability = LocalFSync{}
	f.reopen(t)
	if !f.a.tailHold {
		t.Fatal("cleanup failure removed torn-tail hold")
	}
}

func TestOpenPreservesFlushAndCleanupErrorsAndReleasesLock(t *testing.T) {
	dir := t.TempDir()
	options := Options{Durability: closingFault{}, MaxBytes: 1 << 20}
	_, err := Open(dir, options, &fakeTrust{}, &fakeEffects{}, &fakeEffects{})
	if !errors.Is(err, ErrAudit) || !errors.Is(err, syscall.EIO) || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("lost actual failure: %v", err)
	}
	options.Durability = LocalFSync{}
	a, err := Open(dir, options, &fakeTrust{}, &fakeEffects{}, &fakeEffects{})
	if err != nil {
		t.Fatal("failed-open cleanup retained lock", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}
