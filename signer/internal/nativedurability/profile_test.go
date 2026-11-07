package nativedurability

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// These tests substitute observations and flushes, never native platform proof.
func TestStrictProfileChecksAndFailurePropagation(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	f, err := os.CreateTemp(t.TempDir(), "file-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	v := volume{device: 17, fsid: [2]int32{4, 2}, local: true, writable: true, filesystem: "apfs"}
	for _, tc := range []struct {
		name   string
		change func(*volume)
		want   error
	}{
		{"same-volume", func(*volume) {}, nil},
		{"other-device", func(v *volume) { v.device++ }, ErrVolume},
		{"other-fsid", func(v *volume) { v.fsid[0]++ }, ErrVolume},
		{"remote", func(v *volume) { v.local = false }, ErrVolume},
		{"readonly", func(v *volume) { v.writable = false }, ErrVolume},
		{"other-filesystem", func(v *volume) { v.filesystem = "hfs" }, ErrVolume},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := v
			tc.change(&observed)
			calls := 0
			p := &Profile{volume: v, inspect: func(*os.File) (volume, error) { return observed, nil }, fullSync: func(*os.File) error { calls++; return nil }}
			for _, operation := range []func() error{func() error { return p.File(f) }, func() error { return p.Directory(dir) }} {
				if err := operation(); !errors.Is(err, tc.want) {
					t.Fatalf("got %v want %v", err, tc.want)
				}
			}
			wantCalls := 0
			if tc.want == nil {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("unexpected flushes %d", calls)
			}
		})
	}
	for _, fault := range []error{syscall.EIO, syscall.EINVAL, syscall.ENOTSUP, syscall.EINTR} {
		calls := 0
		p := &Profile{volume: v, inspect: func(*os.File) (volume, error) { return v, nil }, fullSync: func(*os.File) error { calls++; return fault }}
		if !errors.Is(p.File(f), fault) || !errors.Is(p.Directory(dir), fault) || calls != 2 {
			t.Fatal("lost errno, retried or downgraded")
		}
	}
	p := &Profile{volume: v, inspect: func(*os.File) (volume, error) { return v, nil }, fullSync: func(*os.File) error { t.Fatal("invalid descriptor reached native call"); return nil }}
	for _, err := range []error{p.File(dir), p.Directory(f), p.File(nil), p.Directory(nil)} {
		if !errors.Is(err, ErrDescriptor) {
			t.Fatalf("descriptor accepted: %v", err)
		}
	}
	if !errors.Is((&Profile{}).File(f), ErrUnavailable) {
		t.Fatal("zero profile usable")
	}
	var absent *Profile
	if !errors.Is(absent.Directory(dir), ErrUnavailable) {
		t.Fatal("nil profile usable")
	}
}

func TestInspectionFailureDoesNotFlush(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "file-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p := &Profile{inspect: func(*os.File) (volume, error) { return volume{}, syscall.EIO }, fullSync: func(*os.File) error { t.Fatal("flushed after failed observation"); return nil }}
	if !errors.Is(p.File(f), syscall.EIO) {
		t.Fatal("inspection error lost")
	}
}
