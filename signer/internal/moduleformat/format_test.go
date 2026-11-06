package moduleformat_test

import (
	"encoding/json"
	"os"
	"testing"

	mf "github.com/relux-works/swarma-services/signer/internal/moduleformat"
)

// Expected verdicts are fixed documented grammar/standard-Go records, never a
// call to module.Check or the predicate under test. See each corpus row's basis.
func TestFixedGrammar(t *testing.T) {
	b, err := os.ReadFile("testdata/grammar.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Identities []struct {
			ID, Path, Version, Basis string
			Valid                    bool `json:"expected_valid_identity"`
		} `json:"identity_cases"`
		H1 []struct {
			ID, Text, Basis string
			Valid           bool `json:"expected_valid_h1"`
		} `json:"h1_cases"`
		Directories []struct {
			Path, Version, Basis string
			Directory            string `json:"expected_directory"`
		} `json:"directory_cases"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Identities) != 17 || len(c.H1) != 7 || len(c.Directories) != 2 {
		t.Fatal("fixed corpus cardinality")
	}
	for _, r := range c.Identities {
		t.Run(r.ID, func(t *testing.T) {
			if r.Basis == "" {
				t.Fatal("missing independent basis")
			}
			if r.ID == "existing_actual_boundary" && (len(r.Path) != 1024 || len(r.Version) != 128) {
				t.Fatal("retained standard-Go boundary dimensions")
			}
			if got := mf.ValidIdentity(r.Path, r.Version); got != r.Valid {
				t.Fatalf("identity=%v want %v", got, r.Valid)
			}
		})
	}
	for _, r := range c.H1 {
		t.Run("h1_"+r.ID, func(t *testing.T) {
			if r.Basis == "" {
				t.Fatal("missing independent basis")
			}
			if got := mf.ValidH1(r.Text); got != r.Valid {
				t.Fatalf("h1=%v want %v", got, r.Valid)
			}
		})
	}
	for _, r := range c.Directories {
		if mf.Directory(r.Path, r.Version) != r.Directory {
			t.Fatal("directory hash domain")
		}
	}
}
