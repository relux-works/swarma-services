//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package gate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type foreignOwnerInfo struct {
	os.FileInfo
	native any
}

func (i foreignOwnerInfo) Sys() any { return i.native }

func TestForeignOwnerInertStatSeam(t *testing.T) {
	file := t.TempDir() + "/control"
	write(t, file, []byte("neutral\n"))
	info, e := os.Lstat(file)
	if e != nil {
		t.Fatal("stat")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("unsupported native stat in qualified owner test")
	}
	foreign := *stat
	foreign.Uid++ // copied inert metadata; no chown or privileges.
	for _, private := range []bool{true, false} {
		if !safeControl(info, private) {
			t.Fatal("own-file neighbor refused")
		}
		if safeControl(foreignOwnerInfo{info, &foreign}, private) {
			t.Fatal("foreign owner admitted")
		}
		if safeControl(foreignOwnerInfo{info, nil}, private) {
			t.Fatal("unknown owner admitted")
		}
	}
}

func TestDirectoryOwnerInertStatSeam(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "owned")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal("fixture directory")
	}
	info, e := os.Lstat(dir)
	if e != nil || !privateDir(dir) || !ownedByEffectiveUID(info) {
		t.Fatal("own-directory neighbor refused")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("unsupported native stat in qualified owner test")
	}
	foreign := *stat
	foreign.Uid++ // inert copied metadata; no privileged filesystem change.
	if ownedByEffectiveUID(foreignOwnerInfo{info, &foreign}) ||
		ownedByEffectiveUID(foreignOwnerInfo{info, nil}) {
		t.Fatal("foreign or unknown directory owner admitted")
	}
	// This covers the owner helper with directory metadata, not privateDir's
	// wiring to it. A real foreign-owned directory requires an external fixture.
}
