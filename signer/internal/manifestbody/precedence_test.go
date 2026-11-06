package manifestbody

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
)

func TestLexicalAndEncounterPrecedence(t *testing.T) {
	// The raw UTF-8 pre-pass precedes an earlier schema fault everywhere.
	for _, prefix := range []string{`{"unknown":0}`, `{"version":2}`, `{"version":1,"version":1}`} {
		b := append([]byte(prefix), 0xff)
		bad(t, b, ReasonJSONEncoding)
	}
	for _, b := range []string{
		`{"version":1,"\ud800":0}`, `{"version":1,"unknown\ud800":0}`,
	} {
		bad(t, []byte(b), ReasonJSONEncoding)
	}
	bad(t, []byte(`{"version":1,"unknown\q":0}`), ReasonJSONSyntax)
	// Unknown and duplicate decoded names are rejected without parsing values.
	bad(t, []byte(`{"version":1,"unknown":`+strings.Repeat("[", 2048)), ReasonMemberSet)
	bad(t, []byte(`{"version":1,"version":`+strings.Repeat("[", 2048)), ReasonDecodedDuplicateName)
	bad(t, []byte(`{"data_bytes":1073741825,"unknown":0}`), ReasonScalarBound)
	bad(t, []byte(`{"unknown":0,"data_bytes":1073741825}`), ReasonMemberSet)
	bad(t, []byte(`{"operation_id":"bad","unknown":0}`), ReasonIdentifierSyntax)
	// A nested decoded name is also inspected before its malformed value.
	bad(t, []byte(`{"module_receipt":{"source_go_mod_sha256":"`+strings.Repeat("0", 64)+`","\u0073ource_go_mod_sha256":`), ReasonDecodedDuplicateName)
	bad(t, []byte(`{"entries":[{"root":"source","unknown":`), ReasonMemberSet)
	bad(t, []byte(`{"module_receipt":{"modules":[{"path":"example.com/a","unknown":`), ReasonMemberSet)
}

// Entry and module arrays reject complete non-object elements as value types.
func TestArrayElementTypes(t *testing.T) {
	for _, value := range []any{nil, true, "text", uint64(1), []any{}} {
		m := validManifest()
		m["entries"] = []any{value}
		bad(t, encoded(t, m), ReasonValueType)
		m = validManifest()
		receipt(m)["modules"] = []any{value}
		bad(t, encoded(t, m), ReasonValueType)
	}
}

// Canonical integer accumulation admits MaxInt64 and refuses its immediate overflow neighbor.
func TestCanonicalIntegerAccumulator(t *testing.T) {
	p := parser{raw: []byte("9223372036854775807")}
	if got := p.number(); got != 9223372036854775807 || p.err != nil {
		t.Fatal("exact int64 accumulator boundary")
	}
	p = parser{raw: []byte("9223372036854775808")}
	p.number()
	if p.err == nil || p.err.Reason != ReasonScalarBound {
		t.Fatal("overflow classification")
	}
}

// Permitted name/order/whitespace encodings preserve fields while retaining distinct raw digests.
func TestRawEncodingVariations(t *testing.T) {
	base := encoded(t, validManifest())
	original := good(t, base)
	variants := [][]byte{
		[]byte(strings.Replace(string(base), `"version":1`, `"\u0076ersion":1`, 1)),
		[]byte(" \r\n\t" + string(base) + "\t"),
		// Move version to the beginning, preserving every required field.
		[]byte(`{"version":1,` + strings.TrimSuffix(string(base[1:]), `,"version":1}`) + `}`),
	}
	for _, b := range variants {
		v := good(t, b)
		if !reflect.DeepEqual(v.ManifestCopy(), original.ManifestCopy()) {
			t.Fatal("permitted encoding changed fields")
		}
		if bytes.Equal(b, base) {
			t.Fatal("variation not independent")
		}
		h, ok := v.ComputedRawSHA256()
		if !ok || h != sha256.Sum256(b) {
			t.Fatal("actual-byte binding")
		}
		old, _ := original.ComputedRawSHA256()
		if h == old || v.CompareExpectedRawSHA256Only(old) == nil {
			t.Fatal("substituted/reserialized hash")
		}
	}
	// Escaping a target changes its raw encoding, not its decoded size or SHA.
	m := validManifest()
	e := first(m)
	e["kind"] = "symlink"
	e["mode"] = "120000"
	e["link_target"] = "é"
	e["size"] = uint64(2)
	e["sha256"] = digest([]byte("é"))
	raw := string(encoded(t, m))
	good(t, []byte(strings.Replace(raw, `"link_target":"é"`, `"link_target":"\u00e9"`, 1)))
}
func TestDeferredSourceCorrespondenceAndEmptyFileSHA(t *testing.T) {
	// A zero-byte regular file's lexical SHA is intentionally not tightened to
	// SHA256(empty) in this unit. The later DATA verifier owns that comparison.
	m := validManifest()
	first(m)["path"] = "unrelated"
	good(t, encoded(t, m))
	// Receipt-to-source go.mod/go.sum mapping and content are future gates; a
	// body-positive result remains opaque UnqualifiedOpcode34Body throughout.
	receipt(m)["source_go_mod_sha256"] = strings.Repeat("f", 64)
	good(t, encoded(t, m))
}

// A focused causal-control target: unique input passes, and a semantically
// identical duplicate version is rejected solely by decoded-name detection.
func TestDecodedDuplicateGuard(t *testing.T) {
	b := encoded(t, validManifest())
	t.Run("valid_unique", func(t *testing.T) { good(t, b) })
	t.Run("duplicate_version", func(t *testing.T) {
		duplicate := append([]byte(`{"version":1,`), b[1:]...)
		bad(t, duplicate, ReasonDecodedDuplicateName)
	})
}

// A canonical integer followed by invalid object punctuation reports JSON syntax.
func TestBrokenPunctuationAfterCanonicalInteger(t *testing.T) {
	for _, raw := range []string{
		`{"version":1:2}`, `{"version":1{}`, `{"version":1[`, `{"version":1"extra":0}`,
		`{"version":1]`, `{"version":1 2}`,
	} {
		bad(t, []byte(raw), ReasonJSONSyntax)
	}
}
