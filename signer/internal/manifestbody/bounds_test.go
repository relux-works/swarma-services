package manifestbody

import (
	"bytes"
	"fmt"
	"testing"
)

func padBody(t *testing.T, b []byte, n int) []byte {
	t.Helper()
	if n < len(b) {
		t.Fatal("fixture larger than selected boundary")
	}
	return append(append(append([]byte(nil), b[:1]...), bytes.Repeat([]byte{' '}, n-len(b))...), b[1:]...)
}

// WHITE-BOX INACTIVE-CANDIDATE: these calls do not exercise public admission,
// activate 4 MiB, or qualify initial-source headroom or native resource behavior.
func TestWhiteBoxInactiveCandidateCapacity(t *testing.T) {
	b := encoded(t, validManifest())
	v, e := decodeBody(padBody(t, b, 4194304), 4194304)
	if v == nil || e != nil {
		t.Fatalf("private exact bound: %v", e)
	}
	v, e = decodeBody(padBody(t, b, 4194305), 4194304)
	checkBad(t, v, e, ReasonBodyTooLarge)
	for _, n := range []int{4194304, 4194305} {
		bad(t, padBody(t, b, n), ReasonBodyTooLarge)
	}
}

// WHITE-BOX INACTIVE-CANDIDATE: count8192/8193 is unreachable under the public
// cap. Mutating only the count guard must fail the named 8193 assertion while
// count8192 still succeeds; public rejection of both is a separate assertion.
func TestWhiteBoxInactiveCandidateEntryCount(t *testing.T) {
	for _, n := range []int{8192, 8193} {
		t.Run(fmt.Sprintf("count_%d", n), func(t *testing.T) {
			m := validManifest()
			es := make([]any, 0, n)
			for i := 0; i < n; i++ {
				es = append(es, entry(fmt.Sprintf("f%04d", i)))
			}
			m["entries"] = es
			b := encoded(t, m)
			if len(b) <= MaxOpcode34BodyBytes || len(b) > 4194304 {
				t.Fatal("count pair not isolated in private seam")
			}
			v, e := decodeBody(b, 4194304)
			if n == 8192 {
				if v == nil || e != nil {
					t.Fatalf("entry_count valid8192: %v", e)
				}
			} else {
				checkBad(t, v, e, ReasonScalarBound)
			}
			bad(t, b, ReasonBodyTooLarge)
		})
	}
	m := validManifest()
	m["entries"] = []any{}
	bad(t, encoded(t, m), ReasonScalarBound)
}
func TestP13ModuleCount(t *testing.T) {
	for _, n := range []int{0, 512, 513} {
		m := validManifest()
		rs := make([]any, 0, n)
		for i := 0; i < n; i++ {
			rs = append(rs, record(fmt.Sprintf("example.com/m%03d", i), "v1.0.0"))
		}
		receipt(m)["modules"] = rs
		b := encoded(t, m)
		if len(b) > MaxOpcode34BodyBytes {
			t.Fatal("module count shadowed by raw cap")
		}
		if n <= 512 {
			good(t, b)
		} else {
			bad(t, b, ReasonScalarBound)
		}
	}
}
