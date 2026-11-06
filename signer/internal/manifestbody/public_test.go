package manifestbody_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	mb "github.com/relux-works/swarma-services/signer/internal/manifestbody"
)

// A literal independent public-API fixture. Whitespace is legal BODY data and
// is included in the independently computed expected raw digest.
func publicFixture(n int) []byte {
	b := []byte(`{"version":1,"operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","transfer_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","commit":"cccccccccccccccccccccccccccccccccccccccc","tree":"dddddddddddddddddddddddddddddddddddddddd","policy_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","recipe_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","toolchain_sha256":"0000000000000000000000000000000000000000000000000000000000000000","entries":[{"root":"source","path":"go.mod","kind":"file","mode":"100644","size":0,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","link_target":""}],"module_receipt":{"source_go_mod_sha256":"1111111111111111111111111111111111111111111111111111111111111111","source_go_sum_sha256":"2222222222222222222222222222222222222222222222222222222222222222","modules":[]},"data_bytes":0}`)
	// Pad inside the top-level object, without reserializing any fields.
	return append(append(append([]byte(nil), b[:1]...), bytes.Repeat([]byte{' '}, n-len(b))...), b[1:]...)
}
func TestPublicActiveBodyLength(t *testing.T) {
	if mb.MaxOpcode34BodyBytes != 1048576 {
		t.Fatal("active_body_length: constant changed")
	}
	for _, n := range []int{17408, 1048576} {
		t.Run(fmt.Sprintf("valid_%d", n), func(t *testing.T) {
			b := publicFixture(n)
			v, e := mb.DecodeOpcode34BodyShape(b)
			if len(b) != n || e != nil || v == nil {
				t.Fatalf("active_body_length valid %d: %v", n, e)
			}
			h, ok := v.ComputedRawSHA256()
			if !ok || h != sha256.Sum256(b) {
				t.Fatal("actual raw hash")
			}
		})
	}
	b := publicFixture(1048577)
	v, e := mb.DecodeOpcode34BodyShape(b)
	var r *mb.BodyShapeRefusal
	if v != nil || !errors.As(e, &r) || r.Reason != mb.ReasonBodyTooLarge {
		t.Fatalf("active_body_length: oversize accepted or wrong refusal: %v", e)
	}
	// Length precedes malformed encoding/syntax; no caller-selected cap exists.
	b[0] = 0xff
	v, e = mb.DecodeOpcode34BodyShape(b)
	if v != nil || !errors.As(e, &r) || r.Reason != mb.ReasonBodyTooLarge {
		t.Fatal("length preflight precedence")
	}
}
