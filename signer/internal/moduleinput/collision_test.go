package moduleinput

import (
	"fmt"
	"strings"
	"testing"
)

// These direct checker assertions isolate portable ancestor equivalence from
// checksums/order. Legitimate siblings and distinct Unicode names must pass;
// case/decomposition aliases and file/directory conflicts must refuse. They do
// not qualify raw decoding, full case folding or native filesystem behavior.
func TestCollisionDeepAliasesAndNeighbors(t *testing.T) {
	prefix := "m/" + strings.Repeat("0", 64) + "/" + strings.Repeat("a/", 256)
	fresh := func() collisionSet { return collisionSet{folded: make(map[string]node), exact: make(map[string]bool)} }
	t.Run("legitimate_shared_siblings", func(t *testing.T) {
		seen := fresh()
		for i := 0; i < MaxFiles; i++ {
			if !seen.check(fmt.Sprintf("%sf%04d.txt", prefix, i)) {
				t.Fatal("legitimate neighbor refused")
			}
		}

	})
	for _, tc := range []struct{ name, first, neighbor, bad string }{
		{"case_ancestor", prefix + "Dir/one", prefix + "Dir/two", prefix + "dir/three"},
		{"deep_case_ancestor", prefix + "one", prefix + "two", strings.Replace(prefix, "/a/", "/A/", 1) + "three"},
		{"canonical_ancestor", prefix + "가/one", prefix + "가/two", prefix + "가/three"},
		{"simple_fold_ancestor", prefix + "Σ/one", prefix + "Σ/two", prefix + "ς/three"},
		{"file_then_directory", prefix + "node", prefix + "other", prefix + "node/child"},
		{"directory_then_file", prefix + "node/child", prefix + "node/other", prefix + "node"},
		{"duplicate_file", prefix + "one", prefix + "two", prefix + "one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := fresh()
			for _, p := range []string{tc.first, tc.neighbor, tc.bad} {
				if !validPath(p) {
					t.Fatal("invalid checker fixture")
				}
			}
			if !seen.check(tc.first) || !seen.check(tc.neighbor) {
				t.Fatal("legitimate neighbor refused")
			}
			if seen.check(tc.bad) {
				t.Fatal("UNEXPECTED ACCEPTANCE: intended ancestor collision guard")
			}
		})
	}
	t.Run("distinct_unicode_neighbors", func(t *testing.T) {
		seen := fresh()
		for _, p := range []string{prefix + "가/one", prefix + "각/two", prefix + "ß/three", prefix + "ss/four"} {
			if !validPath(p) || !seen.check(p) {
				t.Fatal("distinct Unicode neighbor refused")
			}
		}
	})
}
