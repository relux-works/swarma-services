package sourceauthority

import (
	"bytes"
	"strings"
	"testing"
)

// Claim: SHA-256 and SHA-512 SSHSIG verification preserves exact signed payload bytes including multiline headers.
func TestSignatureAlgorithmsAndExactPayload(t *testing.T) {
	for _, algorithm := range []string{"sha256", "sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			f := validFixture(t)
			_, private, public := fixtureKey(t)
			f.p.OwnerKeys[0].PublicKey = public
			f.p.OwnerKeys[0].Fingerprint = fixtureFingerprint(public)
			// Include Unicode, a multiline header and gpgsig-looking message text;
			// only the actual header may be removed from the signature domain.
			unsigned := bytes.Replace(f.unsigned, []byte("\n\n"), []byte("\nencoding UTF-8\nextra continuation-header\n line-two\n\n"), 1)
			unsigned = append(unsigned, []byte("café\n\ngpgsig message text, not a header\n")...)
			raw := fixtureSign(t, unsigned, private, public, algorithm)
			f.s.observation.Commit = raw
			f.rebindHead(fixtureOID(raw))
			parsed, err := parseCommit(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(parsed.unsigned, unsigned) {
				t.Fatal("unsigned payload was normalized")
			}
			qualifyFixture(t, f)
		})
	}
}

// Claim: Real parent paths preserve exact-head landing while same-tree substitution and invalid paths refuse.
func TestLandingAncestryPositiveAndNegative(t *testing.T) {
	t.Run("nonrewriting_ancestor", func(t *testing.T) {
		f := validFixture(t)
		descendant := []byte("tree " + strings.Repeat("3", 40) + "\nparent " + f.r.Commit + "\nauthor Fixture <fixture@example.invalid> 1740000000 +0000\ncommitter Fixture <fixture@example.invalid> 1740000000 +0000\n\nLater commit.\n")
		f.s.observation.Repository.DefaultHead = fixtureOID(descendant)
		f.s.observation.LandingPath = [][]byte{descendant}
		q := qualifyFixture(t, f)
		s, _ := q.Summary()
		if s.Relationship != "ancestor" {
			t.Fatal("ancestor relationship lost")
		}
	})
	t.Run("merge_second_parent_preserves_exact_head", func(t *testing.T) {
		f := validFixture(t)
		merge := []byte("tree " + strings.Repeat("3", 40) + "\nparent " + strings.Repeat("4", 40) + "\nparent " + f.r.Commit + "\nauthor Fixture <fixture@example.invalid> 1740000000 +0000\ncommitter Fixture <fixture@example.invalid> 1740000000 +0000\n\nMerge.\n")
		f.s.observation.Repository.DefaultHead = fixtureOID(merge)
		f.s.observation.LandingPath = [][]byte{merge}
		qualifyFixture(t, f)
	})
	t.Run("same_tree_is_not_exact_landing", func(t *testing.T) {
		f := validFixture(t)
		other := bytes.Clone(f.unsigned)
		other = append(other, 'x')
		f.s.observation.Repository.DefaultHead = fixtureOID(other)
		f.s.observation.LandingPath = [][]byte{other}
		assertRefusal(t, f, ErrRejected, "unlanded_commit")
	})
	t.Run("substituted_ancestry_object", func(t *testing.T) {
		f := validFixture(t)
		other := bytes.Clone(f.unsigned)
		f.s.observation.Repository.DefaultHead = strings.Repeat("f", 40)
		f.s.observation.LandingPath = [][]byte{other}
		assertRefusal(t, f, ErrRejected, "landing_path")
	})
	t.Run("ancestry_path_not_for_equal_head", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.LandingPath = [][]byte{f.unsigned}
		assertRefusal(t, f, ErrRejected, "landing_path")
	})
}

// Claim: Malformed commit headers and signature armor refuse at both boundaries.
func TestRawCommitAndSignatureRefusals(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*fixture)
		predicate string
	}{
		{"missing_header_separator", func(f *fixture) {
			f.s.observation.Commit = []byte("not a Git commit")
			f.rebindHead(fixtureOID(f.s.observation.Commit))
		}, "commit_shape"},
		{"tree_not_sha1", func(f *fixture) {
			f.s.observation.Commit = bytes.Replace(f.s.observation.Commit, []byte(strings.Repeat("1", 40)), []byte(strings.Repeat("G", 40)), 1)
			f.rebindHead(fixtureOID(f.s.observation.Commit))
		}, "commit_shape"},
		{"duplicate_tree", func(f *fixture) {
			f.s.observation.Commit = append([]byte("tree "+strings.Repeat("1", 40)+"\n"), f.s.observation.Commit...)
			f.rebindHead(fixtureOID(f.s.observation.Commit))
		}, "commit_shape"},
		{"wrong_armor", func(f *fixture) {
			f.s.observation.Commit = bytes.ReplaceAll(f.s.observation.Commit, []byte("SSH SIGNATURE"), []byte("PGP SIGNATURE"))
			f.rebindHead(fixtureOID(f.s.observation.Commit))
		}, "commit_signature"},
		{"extra_signature_header", func(f *fixture) {
			f.s.observation.Commit = bytes.Replace(f.s.observation.Commit, []byte("\n\n"), []byte("\ngpgsig invalid\n\n"), 1)
			f.rebindHead(fixtureOID(f.s.observation.Commit))
		}, "commit_signature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { f := validFixture(t); tt.mutate(f); assertRefusal(t, f, ErrRejected, tt.predicate) })
	}
}

// Claim: Finite profile bounds and complete key fingerprints are mandatory before qualification.
func TestImplementationResourceBounds(t *testing.T) {
	t.Run("commit_capacity", func(t *testing.T) {
		f := validFixture(t)
		f.p.Profile.CommitBytes = len(f.s.observation.Commit) - 1
		assertRefusal(t, f, ErrUnavailable, "profile_capacity")
	})
	t.Run("check_inventory_capacity", func(t *testing.T) {
		f := validFixture(t)
		f.p.Profile.CheckRecords = 1
		assertRefusal(t, f, ErrUnavailable, "profile_capacity")
	})
	t.Run("unqualified_profile", func(t *testing.T) {
		f := validFixture(t)
		f.p.Profile = Profile{}
		if _, err := New(f.p, f.s, f.c); err == nil {
			t.Fatal("absent finite profile accepted")
		}
	})
	t.Run("key_fingerprint_is_not_a_prefix", func(t *testing.T) {
		f := validFixture(t)
		f.p.OwnerKeys[0].Fingerprint = f.p.OwnerKeys[0].Fingerprint[:12]
		if _, err := New(f.p, f.s, f.c); err == nil {
			t.Fatal("partial key pin accepted")
		}
	})
}
