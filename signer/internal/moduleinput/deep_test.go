package moduleinput_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	mi "github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

func deepFixture(t *testing.T) mi.Input {
	t.Helper()
	b, e := os.ReadFile("testdata/deep-shared-go.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Path, Version, GoModH1, ModuleH1, GoMod string
		Count, Depth                            int
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if v.Count != mi.MaxFiles || v.Depth != 256 {
		t.Fatal("unexpected fixed workload")
	}
	files := map[string]string{"go.mod": v.GoMod}
	for i := 0; i < v.Count-1; i++ {
		files[fmt.Sprintf("%sf%04d.txt", strings.Repeat("a/", v.Depth), i)] = "x\n"
	}
	return fixture([]vector{{Path: v.Path, Version: v.Version, GoModH1: v.GoModH1, ModuleH1: v.ModuleH1, Files: files}}, true)
}

// TestDeepSharedAncestors admits the exact 8192-file, 256-shared-segment tree
// against separate standard-Go anchors, then checks alias/prefix refusals before
// checksum validation. Repeated calls test operation-local state. This exercises
// typed paths, not raw JSON or native filesystem equivalence.
func TestDeepSharedAncestors(t *testing.T) {
	base := deepFixture(t)
	v := accept(t, base)
	if len(v.Files()) != mi.MaxFiles {
		t.Fatal("shared path lost files")
	}
	for _, tc := range []struct {
		name   string
		change func(*mi.Input)
	}{
		{"ancestor_case_alias", func(in *mi.Input) { in.Files[0].Path = strings.Replace(in.Files[0].Path, "/a/", "/A/", 1) }},
		{"deep_ancestor_case_alias", func(in *mi.Input) {
			in.Files[0].Path = in.Records[0].Directory + "/" + strings.Repeat("a/", 255) + "A/other.txt"
		}},
		{"file_directory_prefix", func(in *mi.Input) {
			in.Files[0].Path = in.Records[0].Directory + "/" + strings.TrimSuffix(strings.Repeat("a/", 256), "/")
		}},
		{"duplicate_leaf", func(in *mi.Input) { in.Files[0].Path = in.Files[1].Path }},
	} {
		t.Run(tc.name, func(t *testing.T) { in := clone(base); tc.change(&in); sortFiles(&in); refuse(t, in, mi.Collision) })
	}
	// A rejection in another operation must not contaminate the genuine neighbor.
	accept(t, base)
}
