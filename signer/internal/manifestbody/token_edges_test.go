package manifestbody

import (
	"fmt"
	"strings"
	"testing"
)

// Valid JSON fractions/exponents are wrong types; malformed forms are JSON syntax faults.
func TestWrongTypeNumberSyntax(t *testing.T) {
	base := string(encoded(t, validManifest()))
	t.Run("valid_body", func(t *testing.T) { good(t, []byte(base)) })
	for _, tc := range []struct {
		name, token string
		want        BodyShapeReason
	}{
		{"fraction", "0.5", ReasonValueType},
		{"negative_fraction", "-12.5", ReasonValueType},
		{"exponent", "1e2", ReasonValueType},
		{"positive_exponent", "1E+2", ReasonValueType},
		{"negative_exponent", "1e-2", ReasonValueType},
		{"fraction_exponent", "-0.5E+2", ReasonValueType},
		{"missing_fraction", "1.", ReasonJSONSyntax},
		{"missing_fraction_before_exponent", "1.e2", ReasonJSONSyntax},
		{"missing_exponent", "1e", ReasonJSONSyntax},
		{"missing_positive_exponent", "1e+", ReasonJSONSyntax},
		{"missing_negative_exponent", "1E-", ReasonJSONSyntax},
		{"fraction_suffix", "1.2x", ReasonJSONSyntax},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(base, `"operation_id":"`+strings.Repeat("a", 32)+`"`, `"operation_id":`+tc.token, 1)
			bad(t, []byte(raw), tc.want)
		})
	}
}

// A complete false literal is a wrong type; incomplete or suffixed literals are syntax faults.
func TestWrongTypeFalseLiteral(t *testing.T) {
	base := string(encoded(t, validManifest()))
	t.Run("valid_body", func(t *testing.T) { good(t, []byte(base)) })
	for _, tc := range []struct {
		token string
		want  BodyShapeReason
	}{
		{"false", ReasonValueType},
		{"fals", ReasonJSONSyntax},
		{"falsex", ReasonJSONSyntax},
	} {
		t.Run(tc.token, func(t *testing.T) {
			bad(t, []byte(strings.Replace(base, `"path":"go.mod"`, `"path":`+tc.token, 1)), tc.want)
		})
	}
}

// Complete escapes decode into valid paths; EOF within hex4 or just after a backslash is syntax.
func TestTruncatedStringEscapes(t *testing.T) {
	base := string(encoded(t, validManifest()))
	marker := `"path":"go.mod"`
	start := strings.Index(base, marker)
	if start < 0 || strings.Count(base, marker) != 1 {
		t.Fatal("path fixture selector not unique")
	}
	for _, tc := range []struct{ name, token, path string }{
		{"hex4", `"\u0061"`, "a"},
		{"surrogate_pair", `"\ud83d\ude00"`, "😀"},
		{"escaped_quote", `"quote\"name"`, `quote"name`},
	} {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			v := good(t, []byte(strings.Replace(base, marker, `"path":`+tc.token, 1)))
			if got := v.ManifestCopy().Entries[0].Path; got != tc.path {
				t.Fatalf("decoded path %q; want %q", got, tc.path)
			}
		})
	}
	for _, prefix := range []string{`\u`, `\ud83d\u`} {
		for n := 0; n < 4; n++ {
			t.Run(fmt.Sprintf("%s/hex_digits_%d", prefix, n), func(t *testing.T) {
				bad(t, []byte(base[:start]+`"path":"`+prefix+"0061"[:n]), ReasonJSONSyntax)
			})
		}
	}
	t.Run("backslash_eof", func(t *testing.T) {
		bad(t, []byte(base[:start]+`"path":"quote\`), ReasonJSONSyntax)
	})
}
