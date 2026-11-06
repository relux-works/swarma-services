package moduleinput_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	mi "github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

// The checksums in testdata/standard-go.json were emitted by the installed
// standard Go command's `go mod download -json` from independent synthetic
// proxy archives. The generator never imports this package. Expected sums are
// not computed by Verify or by a test helper that implements its algorithm.
type vector struct {
	Path, Version, GoModH1, ModuleH1 string
	Files                            map[string]string
	RepeatName                       string
	RepeatCount                      int
	GeneratedGoMod                   string
}

func vectors(t *testing.T) []vector {
	t.Helper()
	b, e := os.ReadFile("testdata/standard-go.json")
	if e != nil {
		t.Fatal(e)
	}
	var out []vector
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func hash(b []byte) string   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func dir(p, v string) string { return "m/" + hash([]byte(p+"\x00"+v)) }
func bind(in *mi.Input)      { in.GoModSHA256 = hash(in.GoMod); in.GoSumSHA256 = hash(in.GoSum) }
func fixture(vs []vector, full ...bool) mi.Input {
	in := mi.Input{GoMod: []byte("module example.com/source\n\ngo 1.24.0\n")}
	for i, v := range vs {
		isFull := i < len(full) && full[i]
		r := mi.Record{Path: v.Path, Version: v.Version, Directory: dir(v.Path, v.Version), GoModH1: v.GoModH1}
		in.GoSum = append(in.GoSum, []byte(v.Path+" "+v.Version+"/go.mod "+v.GoModH1+"\n")...)
		if isFull {
			r.ModuleH1 = v.ModuleH1
			in.GoSum = append(in.GoSum, []byte(v.Path+" "+v.Version+" "+v.ModuleH1+"\n")...)
		}
		in.Records = append(in.Records, r)
		for n, b := range v.Files {
			if isFull || n == "go.mod" {
				in.Files = append(in.Files, mi.File{Path: r.Directory + "/" + n, Mode: "100644", Bytes: []byte(b)})
			}
		}
		if isFull && v.RepeatCount > 0 {
			in.Files = append(in.Files, mi.File{Path: r.Directory + "/" + v.RepeatName, Mode: "100644", Bytes: bytes.Repeat([]byte{'x'}, v.RepeatCount)})
		}
		if !isFull && v.GeneratedGoMod != "" {
			in.Files = append(in.Files, mi.File{Path: r.Directory + "/go.mod", Mode: "100644", Bytes: []byte(v.GeneratedGoMod)})
		}
	}
	sort.Slice(in.Records, func(i, j int) bool {
		a, b := in.Records[i], in.Records[j]
		return a.Path < b.Path || a.Path == b.Path && a.Version < b.Version
	})
	sortFiles(&in)
	bind(&in)
	return in
}
func sortFiles(in *mi.Input) {
	sort.Slice(in.Files, func(i, j int) bool { return in.Files[i].Path < in.Files[j].Path })
}
func clone(in mi.Input) mi.Input {
	out := in
	out.GoMod = bytes.Clone(in.GoMod)
	out.GoSum = bytes.Clone(in.GoSum)
	out.Records = slices.Clone(in.Records)
	out.Files = slices.Clone(in.Files)
	for i := range out.Files {
		out.Files[i].Bytes = bytes.Clone(out.Files[i].Bytes)
	}
	return out
}
func accept(t *testing.T, in mi.Input) *mi.Verified {
	t.Helper()
	before := clone(in)
	v, e := mi.Verify(in)
	if e != nil || v == nil || !v.IsVerified() {
		t.Fatalf("valid neighbor refused: %v", e)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("successful call mutated caller")
	}
	return v
}
func refuse(t *testing.T, in mi.Input, reason mi.Reason) {
	t.Helper()
	before := clone(in)
	v, e := mi.Verify(in)
	if e == nil {
		t.Fatalf("UNEXPECTED ACCEPTANCE: intended %s guard; verified=%v", reason, v != nil)
	}
	if v != nil {
		t.Fatal("failure exposed a partial verified handle")
	}
	var ie *mi.InvalidError
	if !errors.Is(e, mi.ErrInputInvalid) || !errors.As(e, &ie) || ie.Reason != reason {
		t.Fatalf("wrong refusal: got %v, want %s", e, reason)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("failed call mutated caller")
	}
}
func addFile(in *mi.Input, name, mode string, b []byte) {
	in.Files = append(in.Files, mi.File{Path: in.Records[0].Directory + "/" + name, Mode: mode, Bytes: b})
	sortFiles(in)
}
func leaf(in *mi.Input) int {
	for i, f := range in.Files {
		if strings.HasSuffix(f.Path, "/a.go") {
			return i
		}
	}
	panic("missing leaf")
}

// These independent full/metadata examples preserve ordered snapshot content and hashes;
// empty-subset success does not certify omitted dependencies or graph closure.
func TestCanonicalFullAndMetadata(t *testing.T) {
	vs := vectors(t)
	for _, idx := range []int{0, 1, 2, 3, 4} {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_%s_full_%v", vs[idx].Path, vs[idx].Version, full), func(t *testing.T) {
				in := fixture(vs[idx:idx+1], full)
				v := accept(t, in)
				if !reflect.DeepEqual(v.Files(), in.Files) || !reflect.DeepEqual(v.Records(), in.Records) {
					t.Fatal("snapshot lost sequence/content")
				}
				for i, h := range v.FileSHA256s() {
					if h != hash(in.Files[i].Bytes) {
						t.Fatal("hash not of returned content")
					}
				}
			})
		}
	}
	// Distinct versions and module versus /go.mod keys are legitimate.
	accept(t, fixture(vs[:3], true, false, true))
	// Supplying no records is only verification of an empty subset.
	in := fixture(nil)
	accept(t, in)
}

// Source byte/pin mutations refuse at source binding, before sum interpretation;
// matching bytes alone do not establish acquisition authority.
func TestOriginalHashesBeforeSums(t *testing.T) {
	base := fixture(vectors(t)[:1], true)
	accept(t, base)
	for _, tc := range []struct {
		name   string
		mutate func(*mi.Input)
		reason mi.Reason
	}{
		{"go_mod_bytes", func(in *mi.Input) { in.GoMod[0] ^= 1 }, mi.SourceHash},
		{"go_sum_bytes", func(in *mi.Input) { in.GoSum[0] ^= 1 }, mi.SourceHash},
		{"go_mod_pin", func(in *mi.Input) { in.GoModSHA256 = strings.Repeat("0", 64) }, mi.SourceHash},
		{"go_sum_pin", func(in *mi.Input) { in.GoSumSHA256 = strings.ToUpper(in.GoSumSHA256) }, mi.SourceHash},
		{"malformed_unbound_sum", func(in *mi.Input) { in.GoSum = []byte("invalid") }, mi.SourceHash},
	} {
		t.Run(tc.name, func(t *testing.T) { in := clone(base); tc.mutate(&in); refuse(t, in, tc.reason) })
	}
}

// The fixed public-source bytes match their original SHA256 anchors and parse
// with an empty supplied subset; no dependency closure is exercised.
func TestOriginalPublicSourceAnchors(t *testing.T) {
	mod, e := os.ReadFile("testdata/original.mod")
	if e != nil {
		t.Fatal(e)
	}
	sum, e := os.ReadFile("testdata/original.sum")
	if e != nil {
		t.Fatal(e)
	}
	in := mi.Input{GoMod: mod, GoSum: sum, GoModSHA256: "2ac74c5ce215b31a56ab06bd813e5aab7dee7286734427a8b89a8dbd1ffd0c3c", GoSumSHA256: "8cad9e29334080f01724ac5b43cbc355e99dd52018a5de66617d96fdeb0ecbcc"}
	// This accepts only original-byte binding and source-sum validity with an
	// empty supplied subset. No closure or production success is inferred.
	accept(t, in)
}

// These rebound source-sum examples preserve identical duplicates and distinct
// keys, and reject malformed/conflicting keys including unused entries.
func TestOriginalSumFormatAndConflicts(t *testing.T) {
	vs := vectors(t)
	base := fixture(vs[:1], true)
	accept(t, base)
	first := strings.Split(string(base.GoSum), "\n")[0] + "\n"
	for _, extra := range []string{first, first + first, "\n\t\n", strings.ReplaceAll(first, " ", "\t"), strings.TrimSuffix(first, "\n")} {
		in := clone(base)
		in.GoSum = append(in.GoSum, []byte(extra)...)
		bind(&in)
		v := accept(t, in)
		_, s := v.Source()
		if !bytes.Equal(s, in.GoSum) {
			t.Fatal("source sums rewritten")
		}
	}
	unusedGood := vs[4].Path + " " + vs[4].Version + "/go.mod " + vs[4].GoModH1 + "\n"
	in := clone(base)
	in.GoSum = append(in.GoSum, []byte(unusedGood)...)
	bind(&in)
	accept(t, in)
	for _, tc := range []struct{ name, line string }{
		{"conflicting_same_key", strings.Replace(first, vs[0].GoModH1, vs[0].ModuleH1, 1)},
		{"conflicting_unused", unusedGood + strings.Replace(unusedGood, vs[4].GoModH1, vs[0].ModuleH1, 1)},
		{"wrong_fields", "example.com/a v1.0.0\n"},
		{"extra_fields", strings.TrimSpace(first) + " extra\n"},
		{"unsupported_hash", strings.Replace(first, "h1:", "h2:", 1)},
		{"invalid_base64", strings.Replace(first, vs[0].GoModH1, "h1:"+strings.Repeat("!", 43)+"=", 1)},
		{"invalid_utf8", "\xff\n"},
		{"invalid_path", "../bad v1.0.0 " + vs[0].GoModH1 + "\n"},
		{"invalid_version", "example.com/a latest " + vs[0].GoModH1 + "\n"},
		{"double_domain", "example.com/a v1.0.0/go.mod/go.mod " + vs[0].GoModH1 + "\n"},
		{"noncanonical_version", "example.com/a v1.0 " + vs[0].GoModH1 + "\n"},
		{"nul", strings.TrimSpace(first) + "\x00\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := clone(base)
			in.GoSum = append(in.GoSum, []byte(tc.line)...)
			bind(&in)
			refuse(t, in, mi.SourceSum)
		})
	}
}

// These full/metadata neighbors require the original go.mod anchor and the
// appropriate independent full-module domain; transport hashes confer no trust.
func TestMandatoryAnchorsAndDualDomains(t *testing.T) {
	vs := vectors(t)
	for _, full := range []bool{false, true} {
		base := fixture(vs[:1], full)
		accept(t, base)
		for _, tc := range []struct {
			name   string
			mutate func(*mi.Input)
			reason mi.Reason
		}{
			{"missing_go_mod_h1", func(in *mi.Input) { in.Records[0].GoModH1 = "" }, mi.Anchor},
			{"malformed_go_mod_h1", func(in *mi.Input) { in.Records[0].GoModH1 = "h1:bad" }, mi.Anchor},
			{"noncanonical_padding", func(in *mi.Input) { s := in.Records[0].GoModH1; in.Records[0].GoModH1 = s[:45] + "B=" }, mi.Anchor},
			{"missing_source_go_mod_anchor", func(in *mi.Input) {
				in.GoSum = []byte(strings.ReplaceAll(string(in.GoSum), strings.Split(string(in.GoSum), "\n")[0]+"\n", ""))
				bind(in)
			}, mi.Anchor},
			{"wrong_version_anchor", func(in *mi.Input) {
				in.GoSum = []byte(strings.ReplaceAll(string(in.GoSum), "v1.0.0", "v1.1.0"))
				bind(in)
			}, mi.Anchor},
			{"module_domain_substitution", func(in *mi.Input) { in.Records[0].GoModH1 = vs[0].ModuleH1 }, mi.Anchor},
			{"wrong_source_anchor", func(in *mi.Input) {
				in.GoSum = []byte(strings.ReplaceAll(string(in.GoSum), vs[0].GoModH1, vs[0].ModuleH1))
				in.Records[0].GoModH1 = vs[0].ModuleH1
				bind(in)
			}, mi.Checksum},
		} {
			t.Run(fmt.Sprintf("full_%v/%s", full, tc.name), func(t *testing.T) { in := clone(base); tc.mutate(&in); refuse(t, in, tc.reason) })
		}
	}
	base := fixture(vs[:1], true)
	accept(t, base)
	for _, tc := range []struct {
		name   string
		mutate func(*mi.Input)
		reason mi.Reason
	}{
		{"missing_module_anchor", func(in *mi.Input) {
			lines := strings.SplitAfter(string(in.GoSum), "\n")
			in.GoSum = []byte(lines[0])
			bind(in)
		}, mi.Anchor},
		{"go_mod_domain_for_full", func(in *mi.Input) { in.Records[0].ModuleH1 = vs[0].GoModH1 }, mi.Anchor},
		{"wrong_full_h1_despite_matching_receipt", func(in *mi.Input) {
			in.GoSum = []byte(strings.ReplaceAll(string(in.GoSum), vs[0].ModuleH1, vs[1].ModuleH1))
			in.Records[0].ModuleH1 = vs[1].ModuleH1
			bind(in)
		}, mi.Checksum},
	} {
		t.Run(tc.name, func(t *testing.T) { in := clone(base); tc.mutate(&in); refuse(t, in, tc.reason) })
	}
}

// Changing canonical content with self-consistent transport bytes still fails
// the original module h1; this does not establish graph or source authority.
func TestOriginalH1ContentMutation(t *testing.T) {
	base := fixture(vectors(t)[:1], true)
	accept(t, base)
	in := clone(base)
	in.Files[leaf(&in)].Bytes = append(in.Files[leaf(&in)].Bytes, 'x')
	// Any transport checksum of these changed bytes would be self-consistent;
	// it cannot change the original standard-Go module checksum.
	_ = hash(in.Files[leaf(&in)].Bytes)
	refuse(t, in, mi.Checksum)
}

// Replacing a valid root go.mod still affects the full-module domain; these
// legacy examples distinguish supported metadata from unsupported full layout.
func TestSameRootGoModInBothDomains(t *testing.T) {
	vs := vectors(t)
	base := fixture(vs[:1], true)
	accept(t, base)
	// Independently valid singleton go.mod bytes/domain, but the original full
	// module anchor is unchanged. The full checksum must include this same entry.
	in := clone(base)
	replacement := vs[4]
	for i, f := range in.Files {
		if strings.HasSuffix(f.Path, "/go.mod") {
			in.Files[i].Bytes = []byte(replacement.Files["go.mod"])
		}
	}
	in.GoSum = []byte(strings.ReplaceAll(string(in.GoSum), vs[0].GoModH1, replacement.GoModH1))
	in.Records[0].GoModH1 = replacement.GoModH1
	bind(&in)
	refuse(t, in, mi.Checksum)
	var legacy vector
	for _, v := range vs {
		if v.Path == "example.com/legacy" {
			legacy = v
		}
	}
	if legacy.GeneratedGoMod == "" {
		t.Fatal("missing independent legacy vector")
	}
	accept(t, fixture([]vector{legacy}, false))
	in = fixture([]vector{legacy}, true)
	refuse(t, in, mi.Layout)
	addFile(&in, "go.mod", "100644", []byte(legacy.GeneratedGoMod))
	refuse(t, in, mi.Checksum)
}

// Independent vectors admit exact path/identity and 64 MiB file bounds and
// reject exercised +1 lengths; this is supplied-subset accounting only.
func TestByteLengthBoundaries(t *testing.T) {
	vs := vectors(t)
	var pathBound, fileBound, identityBound vector
	for _, v := range vs {
		switch {
		case v.Path == "example.com/pathbound":
			pathBound = v
		case v.Path == "example.com/filebound":
			fileBound = v
		case len(v.Path) == mi.MaxPathBytes:
			identityBound = v
		}
	}
	in := fixture([]vector{pathBound}, true)
	accept(t, in)
	found := false
	for i, f := range in.Files {
		if len(f.Path) == mi.MaxPathBytes {
			found = true
			in.Files[i].Path += "x"
			break
		}
	}
	if !found {
		t.Fatal("no exact path bound")
	}
	sortFiles(&in)
	refuse(t, in, mi.Bounds)
	in = fixture([]vector{identityBound}, false)
	if len(in.Records[0].Version) != mi.MaxVersionBytes {
		t.Fatal("no exact version bound")
	}
	accept(t, in)
	if fileBound.RepeatCount != mi.MaxFileBytes {
		t.Fatal("missing standard-Go large-file vector")
	}
	in = fixture([]vector{fileBound}, true)
	accept(t, in)
	for i, f := range in.Files {
		if len(f.Bytes) == mi.MaxFileBytes {
			in.Files[i].Bytes = append(f.Bytes, 'x')
			break
		}
	}
	refuse(t, in, mi.Bounds)
}

// These full/metadata neighbors reject nonordinary modes and noncanonical
// layouts, while authenticated ordinary .info content remains legitimate.
func TestCanonicalLayoutAndModes(t *testing.T) {
	vs := vectors(t)
	for _, full := range []bool{false, true} {
		base := fixture(vs[:1], full)
		accept(t, base)
		for _, mode := range []string{"120000", "100755", "040000", "160000", "100600", "0644", ""} {
			t.Run(fmt.Sprintf("full_%v/mode_%s", full, mode), func(t *testing.T) { in := clone(base); in.Files[0].Mode = mode; refuse(t, in, mi.Mode) })
		}
		for _, tc := range []struct {
			name   string
			change func(*mi.Input)
			reason mi.Reason
		}{
			{"missing_go_mod", func(in *mi.Input) {
				for i, f := range in.Files {
					if strings.HasSuffix(f.Path, "/go.mod") {
						in.Files = append(in.Files[:i], in.Files[i+1:]...)
						break
					}
				}
			}, mi.Layout},
			{"go_mod_wrong_case", func(in *mi.Input) {
				for i, f := range in.Files {
					if strings.HasSuffix(f.Path, "/go.mod") {
						in.Files[i].Path = strings.TrimSuffix(f.Path, "go.mod") + "Go.Mod"
					}
				}
				sortFiles(in)
			}, mi.Layout},
			{"nested_go_mod", func(in *mi.Input) { addFile(in, "sub/go.mod", "100644", []byte("module nested\n")) }, mi.Layout},
			{"unclaimed_directory", func(in *mi.Input) { in.Files[0].Path = "m/" + strings.Repeat("0", 64) + "/go.mod"; sortFiles(in) }, mi.Layout},
			{"wrong_modules_prefix", func(in *mi.Input) {
				in.Files[0].Path = "n/" + strings.TrimPrefix(in.Files[0].Path, "m/")
				sortFiles(in)
			}, mi.Layout},
			{"empty_material", func(in *mi.Input) { in.Files = nil }, mi.Layout},
		} {
			t.Run(fmt.Sprintf("full_%v/%s", full, tc.name), func(t *testing.T) { in := clone(base); tc.change(&in); refuse(t, in, tc.reason) })
		}
	}
	metadata := fixture(vs[:1], false)
	accept(t, metadata)
	for _, n := range []string{"extra.txt", ".info", "sub/extra.txt"} {
		t.Run("metadata_extra_"+n, func(t *testing.T) {
			in := clone(metadata)
			addFile(&in, n, "100644", []byte("extra"))
			refuse(t, in, mi.Layout)
		})
	}
	full := fixture(vs[:1], true)
	accept(t, full) // includes authenticated ordinary .info content.
	in := clone(full)
	addFile(&in, ".info", "100644", []byte("auxiliary cache metadata"))
	refuse(t, in, mi.Checksum)
	in = clone(full)
	in.Files = append(in.Files[:leaf(&in)], in.Files[leaf(&in)+1:]...)
	refuse(t, in, mi.Checksum)
	// A synthesized root go.mod cannot authenticate a tree whose original
	// module-domain anchor is for a different canonical layout.
	in = clone(full)
	for i, f := range in.Files {
		if strings.HasSuffix(f.Path, "/go.mod") {
			in.Files[i].Bytes = []byte("module generated.invalid/replacement\n")
		}
	}
	refuse(t, in, mi.Checksum)
}

// Every supplied full/metadata neighbor is checked even without a later build
// consuming it; no native graph selection or compiled-content sufficiency is proved.
func TestEverySuppliedUnusedRecord(t *testing.T) {
	vs := vectors(t)
	for _, full := range []bool{false, true} {
		base := fixture([]vector{vs[0], vs[2]}, true, full)
		accept(t, base)
		t.Run(fmt.Sprintf("full_%v/unanchored_unused", full), func(t *testing.T) {
			in := clone(base)
			var lines []string
			for _, s := range strings.SplitAfter(string(in.GoSum), "\n") {
				if !strings.HasPrefix(s, vs[2].Path+" ") {
					lines = append(lines, s)
				}
			}
			in.GoSum = []byte(strings.Join(lines, ""))
			bind(&in)
			refuse(t, in, mi.Anchor)
		})
		t.Run(fmt.Sprintf("full_%v/corrupt_unused", full), func(t *testing.T) {
			in := clone(base)
			for i, f := range in.Files {
				if strings.HasPrefix(f.Path, dir(vs[2].Path, vs[2].Version)+"/") {
					in.Files[i].Bytes = append(in.Files[i].Bytes, 'x')
					break
				}
			}
			refuse(t, in, mi.Checksum)
		})
		t.Run(fmt.Sprintf("full_%v/malformed_unused", full), func(t *testing.T) { in := clone(base); in.Records[1].GoModH1 = ""; refuse(t, in, mi.Anchor) })
		t.Run(fmt.Sprintf("full_%v/extra_unused", full), func(t *testing.T) {
			in := clone(base)
			in.Files = append(in.Files, mi.File{Path: in.Records[1].Directory + "/other.txt", Mode: "100644", Bytes: []byte("extra")})
			sortFiles(&in)
			reason := mi.Layout
			if full {
				reason = mi.Checksum
			}
			refuse(t, in, reason)
		})
	}
}

// Ordered typed sequences retain detectable duplicates, order and identity
// defects; these assertions do not cover raw JSON duplicate members.
func TestOrderedSequencesIdentityAndDirectories(t *testing.T) {
	vs := vectors(t)
	base := fixture(vs[:3], true, true, true)
	accept(t, base)
	for _, tc := range []struct {
		name   string
		change func(*mi.Input)
		reason mi.Reason
	}{
		{"duplicate_record", func(in *mi.Input) {
			in.Records = append(in.Records[:1], append([]mi.Record{in.Records[0]}, in.Records[1:]...)...)
		}, mi.Collision},
		{"record_order", func(in *mi.Input) { in.Records[0], in.Records[1] = in.Records[1], in.Records[0] }, mi.Order},
		{"duplicate_directory", func(in *mi.Input) { in.Records[1].Directory = in.Records[0].Directory }, mi.Identity},
		{"directory_uppercase", func(in *mi.Input) { in.Records[0].Directory = strings.ToUpper(in.Records[0].Directory) }, mi.Identity},
		{"directory_wrong_hash", func(in *mi.Input) { in.Records[0].Directory = "m/" + strings.Repeat("0", 64) }, mi.Identity},
		{"bad_module_path", func(in *mi.Input) { in.Records[0].Path = "../escape" }, mi.Identity},
		{"bad_module_utf8", func(in *mi.Input) { in.Records[0].Path = "example.com/\xff" }, mi.Identity},
		{"major_mismatch", func(in *mi.Input) {
			in.Records[0].Version = "v2.0.0"
			in.Records[0].Directory = dir(in.Records[0].Path, in.Records[0].Version)
		}, mi.Identity},
		{"noncanonical_version", func(in *mi.Input) { in.Records[0].Version = "v1.0" }, mi.Identity},
		{"revision_not_version", func(in *mi.Input) { in.Records[0].Version = "main" }, mi.Identity},
		{"duplicate_decoded_file", func(in *mi.Input) {
			in.Files = append(in.Files[:1], append([]mi.File{in.Files[0]}, in.Files[1:]...)...)
		}, mi.Collision},
		{"file_order", func(in *mi.Input) { in.Files[0], in.Files[1] = in.Files[1], in.Files[0] }, mi.Order},
		{"unclaimed_modules", func(in *mi.Input) { in.Records = nil }, mi.Layout},
	} {
		t.Run(tc.name, func(t *testing.T) { in := clone(base); tc.change(&in); refuse(t, in, tc.reason) })
	}
}

// These decoded path examples reject traversal, aliases and file/directory
// conflicts under the portable predicate, without native filesystem qualification.
func TestDecodedPathsAndCollisions(t *testing.T) {
	base := fixture(vectors(t)[:1], true)
	accept(t, base)
	for _, p := range []string{"../escape", "/absolute", "C:/drive", "m//empty", "m/./dot", "m/../parent", "m/back\\slash", "m/nul\x00", "m/invalid\xff", "m/trailing/", "m/control\n", "m/CON", "m/x.", "m/e\u0301.txt", "."} {
		t.Run(fmt.Sprintf("path_%q", p), func(t *testing.T) { in := clone(base); in.Files[0].Path = p; sortFiles(&in); refuse(t, in, mi.Path) })
	}
	for _, pair := range [][2]string{{"Name.txt", "name.txt"}, {"Dir/a.txt", "dir/b.txt"}, {"node", "node/child"}, {"가.txt", "가.txt"}, {"Σ.txt", "ς.txt"}, {"K.txt", "K.txt"}} {
		t.Run(pair[0]+"_"+pair[1], func(t *testing.T) {
			in := clone(base)
			addFile(&in, pair[0], "100644", []byte("a"))
			addFile(&in, pair[1], "100644", []byte("b"))
			refuse(t, in, mi.Collision)
		})
	}
	// Go strings are already decoded: identical escape spellings are identical
	// input paths here. No raw JSON digest/framing claim is made.
	in := clone(base)
	duplicate := in.Files[0]
	in.Files = append(in.Files, duplicate)
	sortFiles(&in)
	refuse(t, in, mi.Collision)
}

// Independent fixtures admit exact record/file counts and reject count+1
// before copying; each bound is independent of whole-manifest byte accounting.
func TestExactCountsAndCountPlusOne(t *testing.T) {
	vs := vectors(t)
	var boundary []vector
	var many vector
	for _, v := range vs {
		if strings.HasPrefix(v.Path, "example.com/boundary/") {
			boundary = append(boundary, v)
		}
		if v.Path == "example.com/filecount" {
			many = v
		}
	}
	if len(boundary) != mi.MaxRecords || len(many.Files) != mi.MaxFiles {
		t.Fatal("independent boundary fixture is incomplete")
	}
	in := fixture(boundary)
	accept(t, in)
	tooMany := clone(in)
	tooMany.Records = append(tooMany.Records, tooMany.Records[len(tooMany.Records)-1])
	refuse(t, tooMany, mi.Bounds)
	in = fixture([]vector{many}, true)
	accept(t, in)
	tooMany = clone(in)
	tooMany.Files = append(tooMany.Files, mi.File{Path: in.Records[0].Directory + "/zz-extra", Mode: "100644"})
	refuse(t, tooMany, mi.Bounds)
	base := fixture(vs[:1], false)
	accept(t, base)
	for _, tc := range []struct {
		name   string
		change func(*mi.Input)
	}{
		{"path_bytes", func(in *mi.Input) { in.Files[0].Path = strings.Repeat("a", mi.MaxPathBytes+1) }},
		{"module_path_bytes", func(in *mi.Input) { in.Records[0].Path = strings.Repeat("a", mi.MaxPathBytes+1) }},
		{"version_bytes", func(in *mi.Input) { in.Records[0].Version = strings.Repeat("v", mi.MaxVersionBytes+1) }},
		{"directory_bytes", func(in *mi.Input) { in.Records[0].Directory = strings.Repeat("a", 67) }},
		{"h1_bytes", func(in *mi.Input) { in.Records[0].GoModH1 = strings.Repeat("a", 48) }},
		{"mode_bytes", func(in *mi.Input) { in.Files[0].Mode = "100644x" }},
	} {
		t.Run(tc.name, func(t *testing.T) { in := clone(base); tc.change(&in); refuse(t, in, mi.Bounds) })
	}
}

// Post-call input/accessor mutation preserves the verified snapshot and hashes;
// failures expose no handle. Unsynchronized caller mutation during Verify is excluded.
func TestImmutableSnapshotAndFailureState(t *testing.T) {
	in := fixture(vectors(t)[:1], true)
	original := clone(in)
	v := accept(t, in)
	oldFiles := v.Files()
	oldRecords := v.Records()
	oldHashes := v.FileSHA256s()
	modHash, sumHash := v.SourceHashes()
	in.GoMod[0] ^= 1
	in.GoSum[0] ^= 1
	for i := range in.Files {
		in.Files[i].Bytes[0] ^= 1
		in.Files[i].Path = "changed"
		in.Files[i].Mode = "100755"
	}
	in.Records[0].Path = "changed"
	in.Records = nil
	in.Files = nil
	m, s := v.Source()
	if !bytes.Equal(m, original.GoMod) || !bytes.Equal(s, original.GoSum) || !reflect.DeepEqual(v.Files(), oldFiles) || !reflect.DeepEqual(v.Records(), oldRecords) || !reflect.DeepEqual(v.FileSHA256s(), oldHashes) {
		t.Fatal("caller mutation changed verified snapshot")
	}
	if a, b := v.SourceHashes(); a != modHash || b != sumHash {
		t.Fatal("source hashes changed")
	}
	m[0] ^= 1
	s[0] ^= 1
	oldFiles[0].Bytes[0] ^= 1
	oldFiles[0].Path = "mutated accessor"
	oldRecords[0].Path = "mutated accessor"
	oldHashes[0] = "mutated accessor"
	m, s = v.Source()
	if !bytes.Equal(m, original.GoMod) || !bytes.Equal(s, original.GoSum) || !reflect.DeepEqual(v.Files(), original.Files) || !reflect.DeepEqual(v.Records(), original.Records) {
		t.Fatal("mutable accessor alias")
	}
	for i, h := range v.FileSHA256s() {
		if h != hash(v.Files()[i].Bytes) {
			t.Fatal("hash/content alias")
		}
	}
	// Concurrent access is safe after the call; concurrent input mutation during
	// Verify is deliberately outside the API contract.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				v.Files()
				v.Records()
				v.Source()
				v.FileSHA256s()
			}
		}()
	}
	wg.Wait()
	bad := clone(original)
	bad.Files[leaf(&bad)].Bytes[0] ^= 1
	refuse(t, bad, mi.Checksum)
	var zero mi.Verified
	var nilValue *mi.Verified
	for _, v := range []*mi.Verified{&zero, nilValue} {
		if v.IsVerified() || v.Files() != nil || v.Records() != nil || v.FileSHA256s() != nil {
			t.Fatal("zero handle appeared verified")
		}
		a, b := v.Source()
		x, y := v.SourceHashes()
		if a != nil || b != nil || x != "" || y != "" {
			t.Fatal("zero handle exposed data")
		}
	}
}

// A copied verified fixture can be written in owned temporary storage with
// explicit modes; this does not qualify product materialization or native isolation.
func TestFixtureScratchUsesOwnedTemp(t *testing.T) {
	// File-oriented consumers can obtain copies without ever writing the checkout.
	in := fixture(vectors(t)[:1], false)
	v := accept(t, in)
	f := v.Files()[0]
	p := filepath.Join(t.TempDir(), "go.mod")
	if e := os.WriteFile(p, f.Bytes, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(p)
	if e != nil || !bytes.Equal(got, f.Bytes) {
		t.Fatal("scratch content changed")
	}
	st, e := os.Stat(p)
	if e != nil || st.Mode().Perm() != 0644 {
		t.Fatal("fixture mode is not explicit")
	}
}
