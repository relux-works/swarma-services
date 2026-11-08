package tails

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Compare every regular file in the fixture, including refs/index/config/logs.
func fixtureSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			out[p] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScopeKindCLIJSONAndNoMutation(t *testing.T) {
	root, repo := fixture(t)
	git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
	write(t, filepath.Join(repo, "file"), "dirty fixture\n")
	before := fixtureSnapshot(t, root)
	for _, tc := range []struct {
		name, kind, basis string
		args              []string
	}{
		{"default", "unknown", "default_unknown", nil},
		{"unknown", "unknown", "declared_by_operator", []string{"--scope-kind", "unknown"}},
		{"scratch", "unit-scratch", "declared_by_operator", []string{"--scope-kind", "unit-scratch"}},
		{"product", "product", "declared_by_operator", []string{"--scope-kind", "product"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			args := append([]string{"--repo", repo}, tc.args...)
			if code := Run(args, &b); code != 0 {
				t.Fatalf("exit %d", code)
			}
			var r Report
			if err := json.Unmarshal(b.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			if r.ScopeKind != tc.kind || r.ScopeKindBasis != tc.basis || len(r.Repositories) != 1 || r.Counts.DirtyWorktrees != 1 {
				t.Fatal("classification or inventory contract mismatch")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(b.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if fields["scope_kind"] == nil || fields["scope_kind_basis"] == nil {
				t.Fatal("JSON schema fields missing")
			}
		})
	}
	if !reflect.DeepEqual(before, fixtureSnapshot(t, root)) {
		t.Fatal("inventory mutated fixture")
	}
}

func TestScopeKindInvalidAndMixedDeclarationsRefuse(t *testing.T) {
	for _, args := range [][]string{
		{"--scope-kind", "Product"}, {"--scope-kind", ""}, {"--scope-kind", "other"},
		{"--scope-kind", "unit-scratch", "--scope-kind", "product"},
		{"--scope-kind", "product", "--scope-kind", "product"},
	} {
		var b bytes.Buffer
		args = append([]string{"--root", "/nonexistent/one", "--root", "/nonexistent/two"}, args...)
		if code := Run(args, &b); code != 2 {
			t.Fatalf("invalid declaration exit %d", code)
		}
		var e map[string]string
		if json.Unmarshal(b.Bytes(), &e) != nil || e["error"] != "explicit_valid_scope_required" {
			t.Fatal("invalid CLI JSON")
		}
	}
	r := Scan(Options{ScopeKind: "other"})
	if r.Complete || r.Commands != 0 || len(r.Failures) != 1 || r.Failures[0].Kind != "invalid_scope_kind" || r.ScopeKind != "unknown" {
		t.Fatal("invalid programmatic declaration did not fail closed")
	}
}

func TestScopeKindMultipleRootsOneDeclaration(t *testing.T) {
	root1, repo1 := fixture(t)
	root2, repo2 := fixture(t)
	for _, repo := range []string{repo1, repo2} {
		git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
	}
	for _, kind := range []string{"unknown", "unit-scratch", "product"} {
		var b bytes.Buffer
		if code := Run([]string{"--root", root1, "--root", root2, "--scope-kind", kind}, &b); code != 0 {
			t.Fatalf("multi-root exit %d", code)
		}
		var r Report
		if json.Unmarshal(b.Bytes(), &r) != nil || r.ScopeKind != kind || r.ScopeKindBasis != "declared_by_operator" || len(r.RootHashes) != 2 || len(r.Repositories) != 2 {
			t.Fatal("one declaration must cover all selected roots")
		}
	}
	r := Scan(Options{Repos: []string{filepath.Join(root1, "repo")}})
	if r.ScopeKind != "unknown" || r.ScopeKindBasis != "default_unknown" {
		t.Fatal("Scan default inferred a kind")
	}
}
