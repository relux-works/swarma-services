package moduleinput_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	mi "github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

// Source-sum parsing is a real consumer of both shared grammar predicates.
// Empty supplied subsets still validate every original anchor line. Expected
// verdicts come from the separate fixed corpus, not predicate equivalence.
func TestSharedGrammarSourceSumConsumer(t *testing.T) {
	b, err := os.ReadFile("../moduleformat/testdata/grammar.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Identities []struct {
			ID, Path, Version string
			Valid             bool `json:"expected_valid_identity"`
		} `json:"identity_cases"`
		H1 []struct {
			ID, Text string
			Valid    bool `json:"expected_valid_h1"`
		} `json:"h1_cases"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	const good = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	check := func(t *testing.T, p, v, h string, valid bool) {
		t.Helper()
		in := mi.Input{GoMod: []byte("module example.com/source\n"), GoSum: []byte(p + " " + v + "/go.mod " + h + "\n")}
		bind(&in)
		if valid {
			accept(t, in)
		} else {
			refuse(t, in, mi.SourceSum)
		}
	}
	for _, r := range c.Identities {
		t.Run("identity_"+r.ID, func(t *testing.T) { check(t, r.Path, r.Version, good, r.Valid) })
	}
	for _, r := range c.H1 {
		t.Run("h1_"+r.ID, func(t *testing.T) { check(t, "example.com/alpha", "v1.0.0", r.Text, r.Valid) })
	}
}

// The literal is independently supplied for SHA256(decoded path + NUL + version),
// not emitted by moduleformat. Existing independent .mod anchors are unchanged.
func TestSharedDirectoryConsumer(t *testing.T) {
	const want = "m/cc9b3d5cc55385bb26c5cae18e78f1e5d964f7929d5bed0a13487408b88009da"
	in := fixture(vectors(t)[:1], false)
	if in.Records[0].Path != "example.com/alpha" || in.Records[0].Version != "v1.0.0" {
		t.Fatal("fixed standard-Go neighbor identity")
	}
	in.Records[0].Directory = want
	in.Files[0].Path = want + "/go.mod"
	accept(t, in)
	in.Records[0].Directory = "m/" + strings.Repeat("0", 64)
	refuse(t, in, mi.Identity)
}
