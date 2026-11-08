package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Use real Git objects with distinct branch parents. No parent is discarded,
// and all fixture signatures use only the fresh test-local key.
func mergeFixture(f *fixture, parents int) string {
	f.t.Helper()
	args := []string{"-c", "gpg.format=ssh", "-c", "user.signingkey=" + f.key,
		"commit-tree", "-S", f.candidate + "^{tree}", "-p", f.candidate}
	for i := 1; i < parents; i++ {
		side := f.git("commit-tree", f.base+"^{tree}", "-p", f.base,
			"-m", fmt.Sprintf("distinct side %d", i))
		args = append(args, "-p", side)
	}
	return f.git(append(args, "-m", "unsupported candidate")...)
}

func checkMergeCLI(t *testing.T, c Config) (Report, int) {
	t.Helper()
	args := []string{"check", "--objects", c.Objects, "--base", c.Base,
		"--candidate", c.Candidate, "--patterns", c.Patterns,
		"--allowed-signers", c.Signers, "--principal", c.Principal}
	if c.ShallowBase {
		args = append(args, "--shallow-base")
	}
	var out bytes.Buffer
	code := Run(args, &out)
	var values map[string]int
	if json.Unmarshal(out.Bytes(), &values) != nil {
		t.Fatal("expected counts-only JSON")
	}
	if _, ok := values["unsupported_merge_errors"]; !ok {
		t.Fatal("named merge counter absent from CLI")
	}
	var r Report
	if json.Unmarshal(out.Bytes(), &r) != nil {
		t.Fatal("expected report")
	}
	return r, code
}

// TestUnsupportedMergeNamedCLI proves first-encounter merge refusal for two and
// three parents in both shallow-base modes, beside a completing, verified linear
// control. These bounded cases do not establish an exhaustive merge census.
func TestUnsupportedMergeNamedCLI(t *testing.T) {
	for _, parents := range []int{2, 3} {
		for _, shallow := range []bool{false, true} {
			t.Run(fmt.Sprintf("parents=%d/shallow=%t", parents, shallow), func(t *testing.T) {
				f := newFixture(t)
				c := f.config()
				c.ShallowBase = shallow
				// The nearby ordinary candidate still completes and verifies.
				r, code := checkMergeCLI(t, c)
				require(t, code == 0 && r.Completed == 1 && r.Signatures == 1 &&
					r.ScanErrors == 0 && r.UnsupportedMergeErrors == 0, r, code)
				c.Candidate = mergeFixture(f, parents)
				r, code = checkMergeCLI(t, c)
				require(t, code == 1 && r.Completed == 0 && r.ScanErrors == 1 &&
					r.UnsupportedMergeErrors == 1 && r.PoolLimitErrors == 0 &&
					r.SignatureErrors == 0 && r.Signatures == 0 && r.Commits == 0 &&
					r.PrivateHits == 0 && r.PublishedRefs == 0, r, code)
			})
		}
	}
}

// TestUnsupportedMergeBehindLinearCandidate proves that the parser reaches and
// labels a merge immediately behind a signed linear tip in default mode. It does
// not test every depth or the history bound, or count merges beyond the first refusal.
func TestUnsupportedMergeBehindLinearCandidate(t *testing.T) {
	f := newFixture(t)
	merge := mergeFixture(f, 2)
	c := f.config()
	c.Candidate = f.git("-c", "gpg.format=ssh", "-c", "user.signingkey="+f.key,
		"commit-tree", "-S", f.candidate+"^{tree}", "-p", merge, "-m", "linear tip")
	r, code := checkMergeCLI(t, c)
	require(t, code == 1 && r.ScanErrors == 1 && r.UnsupportedMergeErrors == 1 &&
		r.Completed == 0 && r.PublishedRefs == 0, r, code)
}

// TestUnsupportedMergeDoesNotRelabelOtherFailures pins zero merge counts for
// object/policy I/O, missing/malformed parents, an unrelated root, and a completing
// private-hit control. Parent defects can refuse at native fsck before parsing;
// these first-encounter cases are not exhaustive precedence or merge coverage.
func TestUnsupportedMergeDoesNotRelabelOtherFailures(t *testing.T) {
	for _, kind := range []string{"objects-io", "policy-io", "missing-parent", "malformed-parent", "root", "private-hit"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			c := f.config()
			switch kind {
			case "objects-io":
				c.Candidate = mergeFixture(f, 2)
				c.Objects = filepath.Join(f.dir, "missing-objects")
			case "policy-io":
				c.Candidate = mergeFixture(f, 2)
				c.Patterns = filepath.Join(f.dir, "missing-policy")
			case "missing-parent", "malformed-parent":
				// In particular, malformed-parent refuses at strict fsck, before history.
				parent := strings.Repeat("f", 40)
				if kind == "malformed-parent" {
					parent = "not-an-object-id"
				}
				raw := "tree " + f.git("rev-parse", f.candidate+"^{tree}") +
					"\nparent " + f.candidate + "\nparent " + parent +
					"\nauthor Fixture <fixture@example.test> 0 +0000" +
					"\ncommitter Fixture <fixture@example.test> 0 +0000\n\nincomplete candidate\n"
				name := filepath.Join(f.dir, "raw-commit")
				write(t, name, []byte(raw))
				c.Candidate = f.git("hash-object", "--literally", "-t", "commit", "-w", name)
			case "root":
				c.Candidate = f.git("commit-tree", f.base+"^{tree}", "-m", "unrelated root")
			case "private-hit":
				write(t, filepath.Join(f.repo, "data.txt"), []byte("base\nSYNTHETIC_PRIVATE_MARKER\n"))
				c.Candidate = f.commit("ordinary candidate with finding", true)
			}
			r, code := checkMergeCLI(t, c)
			require(t, code == 1 && r.UnsupportedMergeErrors == 0 && r.PublishedRefs == 0, r, code)
			if kind == "private-hit" {
				require(t, r.Completed == 1 && r.ScanErrors == 0 && r.PrivateHits == 1, r, code)
			} else {
				require(t, r.Completed == 0 && r.ScanErrors == 1 && r.PrivateHits == 0, r, code)
			}
		})
	}
}

// TestUnsupportedMergeDuplicateSignaturePrecedence proves that a complete,
// reachable two-parent record with two syntactically accepted inert gpgsig headers
// passes native strict fsck but retains the generic malformed-record refusal in
// both shallow-base modes. Its one-header merge neighbour keeps the named refusal.
// A local publication plan also leaves its destination unchanged; cryptographic
// verification and an exhaustive malformed-record census are not claimed.
func TestUnsupportedMergeDuplicateSignaturePrecedence(t *testing.T) {
	for _, shallow := range []bool{false, true} {
		t.Run(fmt.Sprintf("shallow=%t", shallow), func(t *testing.T) {
			d := t.TempDir()
			f := &fixture{t: t, dir: d, repo: d,
				patterns: filepath.Join(d, "patterns"), signers: filepath.Join(d, "allowed")}
			f.git("init", "--initial-branch=main")
			write(t, f.patterns, []byte("L:SYNTHETIC_PRIVATE_MARKER\n"))
			// Fixed public wire-format data only; no private key or signing agent.
			write(t, f.signers, []byte("fixture@example.test ssh-ed25519 "+
				"AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))
			tree := f.git("mktree")
			f.base = f.git("commit-tree", tree, "-m", "trusted root")
			left := f.git("commit-tree", tree, "-p", f.base, "-m", "left branch")
			right := f.git("commit-tree", tree, "-p", f.base, "-m", "right branch")
			destination := f.destination()
			const signature = "gpgsig -----BEGIN SSH SIGNATURE-----\n AAE=\n -----END SSH SIGNATURE-----\n"
			for _, count := range []int{1, 2} {
				t.Run(fmt.Sprintf("gpgsig=%d", count), func(t *testing.T) {
					raw := "tree " + tree + "\nparent " + left + "\nparent " + right +
						"\nauthor Fixture <fixture@example.test> 0 +0000" +
						"\ncommitter Fixture <fixture@example.test> 0 +0000\n" +
						strings.Repeat(signature, count) + "\ninert merge\n"
					name := filepath.Join(d, "raw-merge")
					write(t, name, []byte(raw))
					candidate := f.git("hash-object", "-t", "commit", "-w", name)
					f.git("update-ref", "refs/heads/main", candidate)
					if f.git("rev-list", "--parents", "-n", "1", "main") != candidate+" "+left+" "+right {
						t.Fatal("fixture must be reachable with both distinct parents")
					}
					// Native integrity/closure must succeed independently of the gate.
					f.git("fsck", "--strict", "--no-reflogs", "--no-dangling", f.base, candidate)
					c := f.config()
					c.Candidate, c.ShallowBase = candidate, shallow
					assertRefusal := func(r Report, code int) {
						t.Helper()
						wantMerge := 2 - count
						require(t, code == 1 && r.ScanErrors == 1 && r.UnsupportedMergeErrors == wantMerge &&
							r.Completed == 0 && r.PublishedRefs == 0 && r.PoolLimitErrors == 0 &&
							r.HomeAdmissionErrors == 0 && r.TmpdirAdmissionErrors == 0 &&
							r.SignatureErrors == 0 && r.Signatures == 0 && r.Commits == 0, r, code)
					}
					assertRefusal(checkMergeCLI(t, c))
					publication := f.pub(destination, "refs/heads/release=absent")
					publication.Candidate, publication.ShallowBase = candidate, shallow
					assertRefusal(run(publication))
					refs := command(t, d, "/usr/bin/git", "--git-dir="+destination,
						"for-each-ref", "--format=%(refname) %(objectname)")
					if refs != "refs/heads/main "+f.base {
						t.Fatal("refusal changed the local destination")
					}
					// A direct parser probe rules out a refusal at admission or inventory.
					g := &runner{ctx: context.Background(), dir: filepath.Join(d, ".git"),
						home: os.Getenv("HOME"), tmp: d}
					_, err := history(g, f.base, candidate)
					want := refused
					if count == 1 {
						want = unsupportedMergeFailure
					}
					if err != want {
						t.Fatal("fixture did not reach the intended parser refusal")
					}
				})
			}
		})
	}
}
