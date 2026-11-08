//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package gate

import (
	"os"
	"syscall"
)

// Ownership is taken from the opened file's native stat record, never a name.
// This is POSIX mode admission; it does not prove ACL or ancestor safety.
func ownedByEffectiveUID(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}
