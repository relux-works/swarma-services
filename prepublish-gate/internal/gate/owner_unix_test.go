//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package gate

import (
	"os"
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
