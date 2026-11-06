package manifestbody

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	mi "github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

// These retained synthetic standard-Go fixtures carry independent actual .mod
// and full-module anchors. Neither decoder nor moduleinput supplies expectations.
type standardVector struct {
	Path, Version, GoModH1, ModuleH1 string
	Files                            map[string]string
	GeneratedGoMod                   string
}

func standardFixture(t *testing.T, full bool) mi.Input {
	t.Helper()
	b, e := os.ReadFile("../moduleinput/testdata/standard-go.json")
	if e != nil {
		t.Fatal(e)
	}
	var vs []standardVector
	if e = json.Unmarshal(b, &vs); e != nil || len(vs) == 0 {
		t.Fatalf("standard-Go vectors: %v", e)
	}
	v := vs[0]
	r := mi.Record{Path: v.Path, Version: v.Version, Directory: fixtureDirectory(v.Path, v.Version), GoModH1: v.GoModH1}
	in := mi.Input{GoMod: []byte("module example.com/source\n\ngo 1.24.0\n"), Records: []mi.Record{r}}
	in.GoSum = []byte(v.Path + " " + v.Version + "/go.mod " + v.GoModH1 + "\n")
	if full {
		in.Records[0].ModuleH1 = v.ModuleH1
		in.GoSum = append(in.GoSum, []byte(v.Path+" "+v.Version+" "+v.ModuleH1+"\n")...)
	}
	for name, content := range v.Files {
		if full || name == "go.mod" {
			in.Files = append(in.Files, mi.File{Path: r.Directory + "/" + name, Mode: "100644", Bytes: []byte(content)})
		}
	}
	if !full && v.GeneratedGoMod != "" {
		in.Files = append(in.Files, mi.File{Path: r.Directory + "/go.mod", Mode: "100644", Bytes: []byte(v.GeneratedGoMod)})
	}
	in.GoModSHA256 = digest(in.GoMod)
	in.GoSumSHA256 = digest(in.GoSum)
	sortModuleFiles(&in)
	return in
}
func sortModuleFiles(in *mi.Input) {
	sort.Slice(in.Files, func(i, j int) bool { return in.Files[i].Path < in.Files[j].Path })
}
func manifestForInput(in mi.Input) object {
	m := validManifest()
	rec := receipt(m)
	rec["source_go_mod_sha256"] = in.GoModSHA256
	rec["source_go_sum_sha256"] = in.GoSumSHA256
	rs := []any{}
	for _, r := range in.Records {
		rs = append(rs, object{"path": r.Path, "version": r.Version, "directory": r.Directory, "go_mod_h1": r.GoModH1, "module_h1": r.ModuleH1})
	}
	rec["modules"] = rs
	es := []any{}
	var total uint64
	add := func(root, path string, b []byte) {
		e := entry(path)
		e["root"] = root
		e["size"] = uint64(len(b))
		e["sha256"] = digest(b)
		total += uint64(len(b))
		es = append(es, e)
	}
	for _, f := range in.Files {
		add("modules", f.Path, f.Bytes)
	}
	add("source", "go.mod", in.GoMod)
	add("source", "go.sum", in.GoSum)
	m["entries"] = es
	m["data_bytes"] = total
	return m
}
func laterGood(t *testing.T, in mi.Input) {
	t.Helper()
	v, e := mi.Verify(in)
	if v == nil || e != nil || !v.IsVerified() {
		t.Fatalf("independent anchored valid neighbor: %v", e)
	}
}
func laterBad(t *testing.T, in mi.Input, want mi.Reason) {
	t.Helper()
	v, e := mi.Verify(in)
	var r *mi.InvalidError
	if v != nil || !errors.As(e, &r) || r.Reason != want {
		t.Fatalf("later want %s body=%v error=%v", want, v != nil, e)
	}
}

// R1: body positivity never admits a module layout. Each subcase keeps exact
// content/anchors, repairs path order and body sizes/hashes, and has a genuinely
// accepted metadata/full twin. Verify refuses Layout, not an earlier Path fault.
func TestDeferredModulesEntryLayout(t *testing.T) {
	for _, full := range []bool{false, true} {
		for _, fault := range []string{"uppercase_M", "no_rest", "unclaimed"} {
			t.Run(fault+map[bool]string{false: "_metadata", true: "_full"}[full], func(t *testing.T) {
				in := standardFixture(t, full)
				laterGood(t, in)
				good(t, encoded(t, manifestForInput(in)))
				dir := in.Records[0].Directory
				for i := range in.Files {
					if in.Files[i].Path == dir+"/go.mod" {
						switch fault {
						case "uppercase_M":
							in.Files[i].Path = "M/" + dir[2:] + "/go.mod"
						case "no_rest":
							in.Files[i].Path = dir
						case "unclaimed":
							other := strings.Repeat("0", 64)
							if other == dir[2:] {
								other = strings.Repeat("1", 64)
							}
							in.Files[i].Path = "m/" + other + "/go.mod"
						}
					}
				}
				sortModuleFiles(&in)
				good(t, encoded(t, manifestForInput(in)))
				laterBad(t, in, mi.Layout)
			})
		}
	}
}

// The colon case is deliberately distinct: it has correct m/hash/rest and record
// membership, passes body shape, and fails the existing CheckFilePath Path gate.
// These two full-tree h1 literals were independently evaluated from the
// documented Hash1 domain: SHA256 of sorted "<file SHA256 hex>  <module@version/name>\n"
// lines, then standard Base64. They are analytical fixture values, not a claim
// that a Go command admits a colon filename. The mandatory .mod anchor is the
// retained standard-Go alpha anchor. No predicate under test computes an oracle.
func TestDeferredModulesInteriorColonPath(t *testing.T) {
	for _, tc := range []struct {
		name, h1 string
		invalid  bool
	}{
		{"dir/ab", "h1:xFSItsksoyDf/XqHwrlpIA4KSxAG6XYfwyqzNQ3dH7g=", false},
		{"dir/a:b", "h1:4N68QFfKr6JvVAz9uz8JkcKDsCzfbXZsFioRVBg7Ag4=", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := standardFixture(t, false)
			r := &in.Records[0]
			r.ModuleH1 = tc.h1
			in.Files = append(in.Files, mi.File{Path: r.Directory + "/" + tc.name, Mode: "100644", Bytes: []byte("ordinary canonical content\n")})
			in.GoSum = append(in.GoSum, []byte(r.Path+" "+r.Version+" "+tc.h1+"\n")...)
			in.GoSumSHA256 = digest(in.GoSum)
			sortModuleFiles(&in)
			good(t, encoded(t, manifestForInput(in)))
			if tc.invalid {
				laterBad(t, in, mi.Path)
			} else {
				laterGood(t, in)
			}
		})
	}
}

// This is a typed original-anchor asymmetry only, not P23 native graph/closure
// execution. DATA/source correspondence and per-file SHA checks are future work.
func TestDeferredOriginalAnchor(t *testing.T) {
	in := standardFixture(t, false)
	laterGood(t, in)
	good(t, encoded(t, manifestForInput(in)))
	in.Records[0].GoModH1 = zeroH1
	good(t, encoded(t, manifestForInput(in)))
	laterBad(t, in, mi.Anchor)
}
