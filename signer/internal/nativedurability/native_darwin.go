//go:build darwin && cgo

package nativedurability

/*
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>

// Use the supported libc/SDK entrypoint, not a raw Darwin syscall number.
static int journal_fullsync(int fd) {
    if (fcntl(fd, F_FULLFSYNC, 0) == -1) return errno;
    return 0;
}
static int journal_local(unsigned int flags) { return (flags & MNT_LOCAL) != 0; }
static int journal_writable(unsigned int flags) { return (flags & MNT_RDONLY) == 0; }
*/
import "C"

import (
	"os"
	"syscall"
)

func nativeFullSync(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var callErr error
	err = raw.Control(func(fd uintptr) {
		if n := C.journal_fullsync(C.int(fd)); n != 0 {
			callErr = syscall.Errno(n)
		}
	})
	if err != nil {
		return err
	}
	return callErr
}

func nativeVolume(f *os.File) (v volume, err error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return v, err
	}
	var stat syscall.Stat_t
	var fs syscall.Statfs_t
	var callErr error
	err = raw.Control(func(fd uintptr) {
		if callErr = syscall.Fstat(int(fd), &stat); callErr != nil {
			return
		}
		callErr = syscall.Fstatfs(int(fd), &fs)
	})
	if err != nil {
		return v, err
	}
	if callErr != nil {
		return v, callErr
	}
	name := make([]byte, 0, len(fs.Fstypename))
	for _, b := range fs.Fstypename {
		if b == 0 {
			break
		}
		name = append(name, byte(b))
	}
	return volume{
		device: uint64(stat.Dev), fsid: fs.Fsid.Val,
		local:      C.journal_local(C.uint(fs.Flags)) != 0,
		writable:   C.journal_writable(C.uint(fs.Flags)) != 0,
		filesystem: string(name),
	}, nil
}
