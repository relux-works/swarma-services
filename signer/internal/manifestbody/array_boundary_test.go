package manifestbody

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func TestPublicModuleCountPunctuation(t *testing.T) {
	testArrayCountPunctuation(t, "modules", 512, DecodeOpcode34BodyShape)
}

// WHITE-BOX INACTIVE-CANDIDATE: these entry counts exceed the public raw cap.
// The private 4 MiB seam isolates count and punctuation, without activation.
func TestWhiteBoxInactiveCandidateEntryCountPunctuation(t *testing.T) {
	testArrayCountPunctuation(t, "entries", 8192, func(b []byte) (*UnqualifiedOpcode34Body, error) {
		return decodeBody(b, 4194304)
	})
}

func testArrayCountPunctuation(t *testing.T, field string, max int, decode func([]byte) (*UnqualifiedOpcode34Body, error)) {
	t.Helper()
	for _, n := range []int{max - 1, max, max + 1} {
		t.Run(fmt.Sprintf("count_%d", n), func(t *testing.T) {
			m := validManifest()
			items := make([]any, 0, n)
			for i := 0; i < n; i++ {
				if field == "modules" {
					items = append(items, record(fmt.Sprintf("example.com/m%03d", i), "v1.0.0"))
				} else {
					items = append(items, entry(fmt.Sprintf("f%04d", i)))
				}
			}
			if field == "modules" {
				receipt(m)[field] = items
			} else {
				m[field] = items
			}
			b := encoded(t, m)
			if field == "modules" && len(b) > MaxOpcode34BodyBytes {
				t.Fatal("public module count shadowed by raw cap")
			}
			if field == "entries" && (len(b) <= MaxOpcode34BodyBytes || len(b) > 4194304) {
				t.Fatal("entry count not isolated in inactive private seam")
			}
			t.Run("valid_json", func(t *testing.T) {
				v, e := decode(b)
				if n > max {
					checkBad(t, v, e, ReasonScalarBound)
				} else if v == nil || e != nil {
					t.Fatalf("valid count neighbor refused: %v", e)
				}
			})
			if n > max {
				return
			}
			array, e := json.Marshal(items)
			if e != nil {
				t.Fatal(e)
			}
			marker := append([]byte(`"`+field+`":`), array...)
			start := bytes.Index(b, marker)
			if start < 0 || bytes.Count(b, marker) != 1 {
				t.Fatal("array fixture selector not unique")
			}
			end := start + len(marker) - 1 // closing array bracket
			for _, tc := range []struct{ name, after string }{
				{"trailing_comma", ","},
				{"trailing_comma_whitespace", ", \t\r\n"},
				{"comma_eof", ","},
				{"comma_eof_whitespace", ", \t\r\n"},
				{"double_comma", ",,"},
				{"colon", ",:"},
				{"close_object", ",}"},
				{"invalid_token", ",@"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					raw := append(bytes.Clone(b[:end]), tc.after...)
					if tc.name != "comma_eof" && tc.name != "comma_eof_whitespace" {
						raw = append(raw, b[end:]...)
					}
					v, e := decode(raw)
					checkBad(t, v, e, ReasonJSONSyntax)
				})
			}
		})
	}
}
