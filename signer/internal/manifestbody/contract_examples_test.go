package manifestbody

import (
	"encoding/json"
	"os"
	"testing"
)

// The original declarative examples remain immutable. Only their concrete BODY
// entry shapes are exercised here. Their graph/DATA/source-authority outcomes
// remain later obligations, including the deliberately wrong regular-file hash
// and short/extra streams. No transport or native effect is exercised.
func TestOriginalContractEntryShapes(t *testing.T) {
	b, e := os.ReadFile("../../docs/examples/contract-cases-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases struct {
		Source []struct {
			Name    string
			Entry   object
			Entries []any
		} `json:"source_cases"`
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	expected := map[string]BodyShapeReason{
		"bounded_regular_source_data": "", "path_escape": ReasonPathShape,
		"absolute_path": ReasonPathShape, "backslash_path": ReasonPathShape,
		"special_file": ReasonEntryShape, "setuid_mode": ReasonEntryShape,
		"oversized_file": ReasonScalarBound, "hash_mismatch": "",
		"symlink_escape": "", "short_stream": "", "extra_stream": "",
		"unsupported_required_gitlink": ReasonEntryShape,
	}
	seen := 0
	for _, c := range cases.Source {
		want, ok := expected[c.Name]
		if !ok {
			continue
		}
		seen++
		t.Run(c.Name, func(t *testing.T) {
			m := validManifest()
			es := c.Entries
			if c.Entry != nil {
				es = []any{c.Entry}
			}
			if len(es) == 0 {
				t.Fatal("concrete original entry missing")
			}
			var total uint64
			for _, item := range es {
				entry := item.(map[string]any)
				if entry["kind"] == "file" {
					total += uint64(entry["size"].(float64))
				}
			}
			m["entries"] = es
			m["data_bytes"] = total
			if want == "" {
				good(t, encoded(t, m))
			} else {
				bad(t, encoded(t, m), want)
			}
		})
	}
	if seen != len(expected) {
		t.Fatal("required original concrete entry row absent")
	}
}
