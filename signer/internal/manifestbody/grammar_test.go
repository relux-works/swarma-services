package manifestbody

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// This exercises the decoder's shared-helper wiring against fixed documented
// expectations, not agreement with another implementation under test.
func TestP14P15FixedGrammarConsumer(t *testing.T) {
	b, e := os.ReadFile("../moduleformat/testdata/grammar.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Identities []struct {
			ID, Path, Version string
			Valid             bool `json:"expected_valid_identity"`
		} `json:"identity_cases"`
		H1 []struct {
			ID, Text string
			Valid    bool `json:"expected_valid_h1"`
		} `json:"h1_cases"`
		Directories []struct {
			Path, Version string
			Directory     string `json:"expected_directory"`
		} `json:"directory_cases"`
	}
	if e = json.Unmarshal(b, &corpus); e != nil {
		t.Fatal(e)
	}
	for _, r := range corpus.Identities {
		t.Run(r.ID, func(t *testing.T) {
			m := validManifest()
			receipt(m)["modules"] = []any{record(r.Path, r.Version)}
			if r.Valid {
				good(t, encoded(t, m))
			} else if len(r.Path) > 1024 || len(r.Version) > 128 {
				bad(t, encoded(t, m), ReasonScalarBound)
			} else {
				bad(t, encoded(t, m), ReasonReceiptShape)
			}
		})
	}
	for _, r := range corpus.H1 {
		for _, field := range []string{"go_mod_h1", "module_h1"} {
			t.Run(field+"_"+r.ID, func(t *testing.T) {
				m := validManifest()
				rec := withRecord(m)
				rec[field] = r.Text
				if r.Valid || field == "module_h1" && r.Text == "" {
					good(t, encoded(t, m))
				} else {
					bad(t, encoded(t, m), ReasonReceiptShape)
				}
			})
		}
	}
	for _, r := range corpus.Directories {
		m := validManifest()
		rec := record(r.Path, r.Version)
		rec["directory"] = r.Directory
		receipt(m)["modules"] = []any{rec}
		good(t, encoded(t, m))
	}
}
func TestP14P15RecordSemantics(t *testing.T) {
	for _, field := range []string{"path", "version", "directory"} {
		m := validManifest()
		r := withRecord(m)
		r[field] = ""
		bad(t, encoded(t, m), ReasonReceiptShape)
	}
	for _, dir := range []string{"m/" + strings.Repeat("0", 64), "M/" + strings.Repeat("0", 64), "m/" + strings.Repeat("A", 64), "m/short"} {
		m := validManifest()
		r := withRecord(m)
		r["directory"] = dir
		bad(t, encoded(t, m), ReasonReceiptShape)
	}
	m := validManifest()
	a := record("example.com/a", "v1.10.0")
	b := record("example.com/a", "v1.2.0")
	receipt(m)["modules"] = []any{a, b}
	good(t, encoded(t, m)) // byte order, not semver order
	receipt(m)["modules"] = []any{b, a}
	bad(t, encoded(t, m), ReasonModuleOrderOrDuplicate)
	receipt(m)["modules"] = []any{a, a}
	bad(t, encoded(t, m), ReasonModuleOrderOrDuplicate)
	// A distinct identity with a copied directory is multi-fault (derivation and
	// duplication), not an invented single-fault collision oracle.
	c := record("example.com/b", "v1.0.0")
	c["directory"] = a["directory"]
	receipt(m)["modules"] = []any{a, c}
	bad(t, encoded(t, m), ReasonReceiptShape)
	m = validManifest()
	r := withRecord(m)
	raw := string(encoded(t, m))
	dir := r["directory"].(string)
	good(t, []byte(strings.Replace(raw, dir, `\u006d\/`+dir[2:], 1)))
	good(t, []byte(strings.Replace(raw, `example.com/alpha`, `example.com\/\u0061lpha`, 1)))
	for _, field := range []string{"go_mod_h1", "module_h1"} {
		m = validManifest()
		r = withRecord(m)
		r[field] = nil
		bad(t, encoded(t, m), ReasonValueType)
		m = validManifest()
		r = withRecord(m)
		delete(r, field)
		bad(t, encoded(t, m), ReasonMemberSet)
	}
	for _, h := range []string{"h1:" + strings.Repeat("A", 42) + "==", "h1:" + strings.Repeat("A", 43) + "é", "h1:" + strings.Repeat("A", 21) + "\r" + strings.Repeat("A", 21) + "="} {
		m = validManifest()
		r = withRecord(m)
		r["go_mod_h1"] = h
		bad(t, encoded(t, m), ReasonReceiptShape)
	}
}
func TestReasonSetDiagnostics(t *testing.T) {
	reasons := []BodyShapeReason{ReasonBodyTooLarge, ReasonJSONEncoding, ReasonJSONSyntax, ReasonDecodedDuplicateName, ReasonMemberSet, ReasonValueType, ReasonIntegerSpelling, ReasonScalarBound, ReasonIdentifierSyntax, ReasonEntryShape, ReasonPathShape, ReasonEntryOrderOrDuplicate, ReasonModuleOrderOrDuplicate, ReasonReceiptShape, ReasonDeclaredBytesInconsistent, ReasonRawDigestMismatch, ReasonResultAbsent}
	expected := []string{"body_too_large", "json_encoding", "json_syntax", "decoded_duplicate_name", "member_set", "value_type", "integer_spelling", "scalar_bound", "identifier_syntax", "entry_shape", "path_shape", "entry_order_or_duplicate", "module_order_or_duplicate", "receipt_shape", "declared_bytes_inconsistent", "raw_digest_mismatch", "result_absent"}
	if len(reasons) != 17 {
		t.Fatal("closed reason set")
	}
	for i, r := range reasons {
		if string(r) != expected[i] || (&BodyShapeRefusal{r}).Error() != expected[i] {
			t.Fatal("reason spelling/diagnostic changed")
		}
	}
}
