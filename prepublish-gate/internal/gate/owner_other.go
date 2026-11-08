//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package gate

import "os"

// No unqualified owner mapping: unsupported native stat representations refuse.
func ownedByEffectiveUID(info os.FileInfo) bool { return false }
