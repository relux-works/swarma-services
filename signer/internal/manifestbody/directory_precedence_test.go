package manifestbody

import (
	"encoding/json"
	"strings"
	"testing"
)

// Decoded directory aliases retain derivation-before-duplicate and identity-order precedence.
func TestDecodedDirectoryPrecedence(t *testing.T) {
	alias := func(r object) json.RawMessage {
		raw := string(encoded(t, r))
		dir := r["directory"].(string)
		marker := `"directory":"` + dir + `"`
		if strings.Count(raw, marker) != 1 {
			t.Fatal("directory fixture selector not unique")
		}
		return json.RawMessage(strings.Replace(raw, marker, `"directory":"\u006d\/`+dir[2:]+`"`, 1))
	}
	t.Run("valid_distinct_decoded_directories", func(t *testing.T) {
		m := validManifest()
		a := record("example.com/a", "v1.0.0")
		b := record("example.com/b", "v1.0.0")
		receipt(m)["modules"] = []any{a, alias(b)}
		v := good(t, encoded(t, m))
		if got := v.ManifestCopy().ModuleReceipt.Modules[1].Directory; got != b["directory"] {
			t.Fatalf("decoded directory %q; want %q", got, b["directory"])
		}
	})
	t.Run("copied_decoded_directory_fails_derivation", func(t *testing.T) {
		m := validManifest()
		a := record("example.com/a", "v1.0.0")
		b := record("example.com/b", "v1.0.0")
		b["directory"] = a["directory"]
		receipt(m)["modules"] = []any{a, alias(b)}
		bad(t, encoded(t, m), ReasonReceiptShape)
	})
	t.Run("repeated_identity_fails_order_before_directory_lookup", func(t *testing.T) {
		m := validManifest()
		a := record("example.com/a", "v1.0.0")
		receipt(m)["modules"] = []any{a, alias(a)}
		bad(t, encoded(t, m), ReasonModuleOrderOrDuplicate)
	})
}
