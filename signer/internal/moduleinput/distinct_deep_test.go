package moduleinput_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	mi "github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

// An independent standard-Go archive/download supplies both anchors for this
// 129-file distinct-branch tree. Aliases, duplicates, both prefix conflicts and
// layout failures have genuine successful full and metadata neighbors. Failure
// helpers require exact reason, no partial handle and no caller mutation.
func TestDistinctDeepSnapshotAndRefusals(t *testing.T) {
	b, err := os.ReadFile("testdata/distinct-deep-go.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Path, Version, GoModH1, ModuleH1, GoMod string
		Count, Depth                            int
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Count != 129 || v.Depth != 64 {
		t.Fatal("unexpected independent fixture dimensions")
	}
	files := map[string]string{"go.mod": v.GoMod}
	for i := 0; i < v.Count-1; i++ {
		files[fmt.Sprintf("d%04d/%sf.txt", i, strings.Repeat("a/", v.Depth))] = "x\n"
	}
	vec := vector{Path: v.Path, Version: v.Version, GoModH1: v.GoModH1, ModuleH1: v.ModuleH1, Files: files}
	base := fixture([]vector{vec}, true)
	snapshot := accept(t, base)
	if len(snapshot.Files()) != v.Count {
		t.Fatal("distinct deep snapshot lost files")
	}
	accept(t, fixture([]vector{vec}, false))
	for _, tc := range []struct {
		name   string
		change func(*mi.Input)
		reason mi.Reason
	}{
		{"shallow_alias", func(in *mi.Input) {
			in.Files[0].Path = strings.TrimSuffix(strings.Replace(in.Files[0].Path, "/d0000/", "/D0000/", 1), "f.txt") + "other.txt"
			in.Files = append(in.Files, base.Files[0])
		}, mi.Collision},
		{"deep_alias", func(in *mi.Input) {
			in.Files[0].Path = strings.TrimSuffix(strings.Replace(in.Files[0].Path, "/a/", "/A/", 1), "f.txt") + "other.txt"
			in.Files = append(in.Files, base.Files[0])
		}, mi.Collision},
		{"duplicate", func(in *mi.Input) { in.Files = append(in.Files, in.Files[0]) }, mi.Collision},
		{"file_as_directory", func(in *mi.Input) {
			in.Files = append(in.Files, mi.File{Path: in.Files[0].Path + "/child", Mode: "100644"})
		}, mi.Collision},
		{"directory_as_file", func(in *mi.Input) {
			in.Files = append(in.Files, mi.File{Path: strings.TrimSuffix(in.Files[0].Path, "/f.txt"), Mode: "100644"})
		}, mi.Collision},
		{"missing_go_mod", func(in *mi.Input) { in.Files = in.Files[:len(in.Files)-1] }, mi.Layout},
		{"metadata_with_extra", func(in *mi.Input) { in.Records[0].ModuleH1 = "" }, mi.Layout},
		{"mutated_content_original_h1", func(in *mi.Input) { in.Files[0].Bytes = append(in.Files[0].Bytes, 'x') }, mi.Checksum},
	} {
		t.Run(tc.name, func(t *testing.T) { in := clone(base); tc.change(&in); sortFiles(&in); refuse(t, in, tc.reason) })
	}
	// Independent operations and accessor copies retain the genuine snapshot.
	copy := snapshot.Files()
	copy[0].Bytes[0] ^= 1
	if string(snapshot.Files()[0].Bytes) != "x\n" {
		t.Fatal("snapshot accessor alias")
	}
	accept(t, base)
}
