package moduleinput

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Compare every step up to first refusal against the frozen accepted algorithm.
// Inputs are bounded; neither oracle nor candidate is reused after refusal.
// The fixed Unicode corpus uses valid module file-path segments, including
// precomposed characters whose NFD expansions contain combining marks.
func TestCollisionAcceptedDifferential(t *testing.T) {
	segments := []string{"a", "A", "b", "B", "é", "가", "가", "Σ", "ς", "σ", "K", "K", "ß", "ss", "İ", "i", "ǰ", "ΐ"}
	checks, sequences := 0, 0
	compare := func(paths []string) {
		t.Helper()
		var got collisionSet
		want := acceptedCollisionSet{folded: make(map[string]acceptedNode), exact: make(map[string]bool)}
		sequences++
		for _, p := range paths {
			if !validPath(p) {
				t.Fatalf("invalid differential fixture %q", p)
			}
			a, b := got.check(p), want.check(p)
			checks++
			if a != b {
				t.Fatalf("accepted differential mismatch for %q in %q: got %v want %v", p, paths, a, b)
			}
			if !a {
				break
			}
		}
	}
	for _, a := range segments {
		for _, b := range segments {
			for _, paths := range [][]string{
				{"m/" + a + "/one", "m/" + b + "/two"},
				{"m/" + a, "m/" + b + "/two"},
				{"m/" + a + "/one", "m/" + b},
				{"m/" + a + "/one", "m/" + b + "/one"},
			} {
				compare(paths)
			}
			p := "m/" + a + "/" + b + "/leaf"
			var keys []string
			for _, s := range strings.Split(p, "/") {
				keys = append(keys, fold(s))
			}
			if fold(p) != strings.Join(keys, "/") {
				t.Fatalf("segment normalization boundary mismatch: %q", p)
			}
		}
	}
	rng := rand.New(rand.NewSource(341))
	for i := 0; i < 2000; i++ {
		var paths []string
		for j := 0; j < 32; j++ {
			p := "m"
			for d := rng.Intn(12); d >= 0; d-- {
				p += "/" + segments[rng.Intn(len(segments))]
			}
			paths = append(paths, p+fmt.Sprintf("/f%d", j%7))
		}
		if i%3 == 0 {
			slices.Sort(paths)
		}
		compare(paths)
	}
	t.Logf("accepted collision differential: %d sequences, %d checks", sequences, checks)
}

// Distinct deep paths allocate one compact edge per distinct component, rather
// than retained full ancestor keys. Compare a smaller bound with the accepted
// checker, then exercise actual alias, duplicate and both prefix refusals.
func TestCollisionDistinctDeepBoundAndRefusals(t *testing.T) {
	const count, depth = 128, 64
	prefix := "m/" + strings.Repeat("0", 64) + "/"
	paths := make([]string, count)
	for i := range paths {
		paths[i] = fmt.Sprintf("%sd%04d/%sf.txt", prefix, i, strings.Repeat("a/", depth))
	}
	var seen collisionSet
	oracle := acceptedCollisionSet{folded: make(map[string]acceptedNode), exact: make(map[string]bool)}
	for _, p := range paths {
		if !validPath(p) || !seen.check(p) || !oracle.check(p) {
			t.Fatal("valid distinct deep neighbor refused")
		}
	}
	if want := 2 + count*(depth+2); len(seen.edges) != want || len(oracle.exact) != want {
		t.Fatalf("wrong actual ancestor count: trie=%d accepted=%d want=%d", len(seen.edges), len(oracle.exact), want)
	}
	if len(seen.segments) != count+4 || len(seen.folds) != count+4 {
		t.Fatalf("segments were not interned: exact=%d folded=%d", len(seen.segments), len(seen.folds))
	}
	for _, tc := range []struct{ name, bad string }{
		{"shallow_alias", strings.TrimSuffix(strings.Replace(paths[0], "/d0000/", "/D0000/", 1), "f.txt") + "other.txt"},
		{"deep_alias", strings.TrimSuffix(strings.Replace(paths[0], "/a/", "/A/", 1), "f.txt") + "other.txt"},
		{"duplicate", paths[0]},
		{"file_as_directory", paths[0] + "/child"},
		{"directory_as_file", strings.TrimSuffix(paths[0], "/f.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c collisionSet
			for _, p := range paths {
				if !c.check(p) {
					t.Fatal("valid distinct deep neighbor refused")
				}
			}
			if c.check(tc.bad) {
				t.Fatal("UNEXPECTED ACCEPTANCE: distinct deep collision")
			}
		})
	}
}

// A refusal permanently poisons the operation-local checker, including newly
// interned alias spellings. Verify discards it; a fresh call works.
func TestCollisionRefusalIsAbortOnly(t *testing.T) {
	var c collisionSet
	if !c.check("m/Dir/one") || !c.check("m/Dir/two") || c.check("m/dir/new/leaf") {
		t.Fatal("alias control failed")
	}
	edges, segments, folds := len(c.edges), len(c.segments), len(c.folds)
	if c.check("m/Other/valid") || c.check("m/dir/new/next") {
		t.Fatal("UNEXPECTED ACCEPTANCE: reused refused collision state")
	}
	if edges != len(c.edges) || segments != len(c.segments) || folds != len(c.folds) {
		t.Fatal("refused state mutated on reuse")
	}
	var fresh collisionSet
	if !fresh.check("m/Other/valid") {
		t.Fatal("fresh valid neighbor refused")
	}
}

// Full verification against the frozen accepted verify loop checks exact public
// reasons and encounter order, not just checker booleans. The independent fixed
// standard-Go vector supplies anchors. Deliberately invalid cases retain their
// actual first refusal; every attempt also checks caller-state preservation.
func TestVerifyAcceptedDifferential(t *testing.T) {
	var vs []struct {
		Path, Version, GoModH1, ModuleH1 string
		Files                            map[string]string
	}
	b, err := os.ReadFile("testdata/standard-go.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	v := vs[0]
	base := Input{GoMod: []byte("module example.com/source\n"), GoSum: []byte(v.Path + " " + v.Version + "/go.mod " + v.GoModH1 + "\n" + v.Path + " " + v.Version + " " + v.ModuleH1 + "\n")}
	base.GoModSHA256, base.GoSumSHA256 = sha(base.GoMod), sha(base.GoSum)
	r := Record{v.Path, v.Version, directory(v.Path, v.Version), v.GoModH1, v.ModuleH1}
	base.Records = []Record{r}
	for n, b := range v.Files {
		base.Files = append(base.Files, File{r.Directory + "/" + n, "100644", []byte(b)})
	}
	slices.SortFunc(base.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	rng := rand.New(rand.NewSource(196341))
	for i := 0; i < 600; i++ {
		s, err := copyBounded(base)
		if err != nil {
			t.Fatal(err)
		}
		in := s.input
		switch i % 12 {
		case 0: // genuine independent-anchor positive
		case 1:
			in.Files[0].Mode = "120000"
		case 2:
			in.Files[0].Path = "../bad"
		case 3:
			in.Files[0], in.Files[1] = in.Files[1], in.Files[0]
		case 4:
			in.Files[0].Path = in.Files[1].Path
		case 5:
			in.Files[0].Bytes = append(in.Files[0].Bytes, 'x')
		case 6:
			in.Files[0].Path = "m/" + strings.Repeat("0", 64) + "/file"
		case 7:
			in.GoModSHA256 = strings.Repeat("0", 64)
			in.Files[0].Mode = "100755"
		case 8:
			in.Files = append(in.Files, File{r.Directory + "/ASSETS/next", "100644", nil})
			slices.SortFunc(in.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
		case 9:
			in.Files = append(in.Files, File{r.Directory + "/assets", "100644", nil})
			slices.SortFunc(in.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
		case 10:
			in.Files[rng.Intn(len(in.Files))].Path += fmt.Sprintf("/%sfile", strings.Repeat("a/", rng.Intn(12)))
		case 11:
			in.Files[0].Mode = "100755"
			in.Files[0].Path = "../bad"
		}
		before, _ := copyBounded(in)
		wantSnapshot, _ := copyBounded(in)
		want := acceptedVerify(wantSnapshot)
		got, gotErr := Verify(in)
		var a, b *InvalidError
		ga, wa := errors.As(gotErr, &a), errors.As(want, &b)
		if (gotErr == nil) != (want == nil) || ga != wa || ga && a.Reason != b.Reason {
			t.Fatalf("case %d: got %v want %v", i, gotErr, want)
		}
		if !reflect.DeepEqual(in, before.input) {
			t.Fatal("caller mutation")
		}
		if want != nil && got != nil {
			t.Fatal("partial handle")
		}
		if want == nil && (got == nil || !reflect.DeepEqual(got.data, wantSnapshot)) {
			t.Fatal("snapshot differential")
		}
	}
	t.Log("accepted Verify differential: 600 cases, including 50 genuine positives")
}
