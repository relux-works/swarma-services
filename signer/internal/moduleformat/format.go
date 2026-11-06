// Package moduleformat contains the shared, pure module identity, checksum
// spelling and directory predicates. These predicates establish no authority.
package moduleformat

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/module"
)

// ValidIdentity preserves the pinned module.Check/CanonicalVersion grammar and
// the wire's decoded path/version byte bounds.
func ValidIdentity(p, v string) bool {
	return len(p) > 0 && len(p) <= 1024 && utf8.ValidString(p) && len(v) > 0 && len(v) <= 128 && module.CanonicalVersion(v) == v && module.Check(p, v) == nil
}

// ValidH1 requires the exact canonical standard-Base64 encoding of 32 bytes.
func ValidH1(s string) bool {
	if len(s) != 47 || !strings.HasPrefix(s, "h1:") {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s[3:])
	return err == nil && len(b) == sha256.Size && base64.StdEncoding.EncodeToString(b) == s[3:]
}

// Directory hashes decoded path UTF-8, one NUL byte, then decoded version ASCII.
// Callers validate identity and bounds before relying on this derived name.
func Directory(p, v string) string {
	h := sha256.Sum256([]byte(p + "\x00" + v))
	return "m/" + hex.EncodeToString(h[:])
}
