package sourceauthority

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func labGitHubMembership(f *fixture) GitHubPRMembership {
	return GitHubPRMembership{Producer: GitHubMember{ID: 101, Login: "lab-producer", Member: f.p.ProducerSender}, Reviewers: []GitHubMember{{ID: 202, Login: "lab-reviewer", Member: f.p.ReviewerSenders[0]}}}
}
func labGitHubObservation(f *fixture, m GitHubPRMembership) {
	o := &f.s.observation
	v := o.Lookup.Scopes[0].Events[0]
	o.GitHub = &GitHubHandoff{Repository: o.PR.Repository, Head: o.PR.Head, Base: o.PR.Base, Number: o.PR.Number, Producer: m.Producer, Reviewer: m.Reviewers[0], Verdicts: GitHubVerdictInventory{Coverage: Complete, Records: []GitHubStoredVerdict{{Reference: "lab-stored-verdict-1", Body: v.Body, State: "intact", Reviewer: m.Reviewers[0], StoredAt: v.ServerAt}}}}
	o.Producer = ProducerHandoff{}
	o.Lookup = Lookup{}
	o.Reviews.Records[0].AccountID = m.Reviewers[0].ID
	o.Reviews.Records[0].AccountLogin = m.Reviewers[0].Login
	f.p.MatrixOrigin = ""
	f.p.Scopes = nil
}

// Numeric identities and verdict references here are deterministic laboratory
// values. No platform account, installed mapping or real COMMENT is claimed.
func TestGitHubPRCoreBothPhases(t *testing.T) {
	f := validFixture(t)
	m := labGitHubMembership(f)
	labGitHubObservation(f, m)
	a, err := NewGitHubPR(f.p, m, f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	m.Reviewers[0].ID = 303 // installed constructor must own its membership
	if _, err = a.BeforeBuild(context.Background(), f.r); err != nil {
		t.Fatal(err)
	}
	f.r.Nonce = strings.Repeat("d", 64)
	if _, err = a.BeforeSign(context.Background(), f.r); err != nil {
		t.Fatal(err)
	}
	if len(f.s.queries) != 2 || f.s.queries[0].Phase != Prebuild || f.s.queries[1].Phase != Presign || f.s.queries[0].Nonce == f.s.queries[1].Nonce {
		t.Fatal("phase reads did not bind independently")
	}
	if _, err = New(f.p, f.s, f.c); err == nil {
		t.Fatal("legacy route accepted absent Matrix policy")
	}
}
func TestGitHubPRCoreRefusals(t *testing.T) {
	tests := []struct {
		name      string
		change    func(*fixture)
		predicate string
	}{
		{"missing_handoff", func(f *fixture) { f.s.observation.GitHub = nil }, "github_handoff"},
		{"invented_matrix_origin", func(f *fixture) { f.s.observation.Producer.Origin = "invented.invalid" }, "github_handoff"},
		{"wrong_base", func(f *fixture) { f.s.observation.GitHub.Base = strings.Repeat("3", 40) }, "github_handoff"},
		{"missing_review", func(f *fixture) { f.s.observation.Reviews.Records = nil }, "review_missing"},
		{"self_review", func(f *fixture) {
			h := f.s.observation.GitHub
			h.Reviewer = h.Producer
			f.s.observation.Reviews.Records[0].AccountID = h.Producer.ID
			f.s.observation.Reviews.Records[0].AccountLogin = h.Producer.Login
		}, "reviewer_identity_or_integrity"},
		{"unmapped_account", func(f *fixture) { f.s.observation.Reviews.Records[0].AccountID = 999 }, "reviewer_identity_or_integrity"},
		{"changed_head", func(f *fixture) { f.s.observation.PR.Head = strings.Repeat("3", 40) }, "pull_request"},
		{"changed_review_head", func(f *fixture) { f.s.observation.Reviews.Records[0].Head = strings.Repeat("3", 40) }, "review_withdrawal_or_binding"},
		{"native_approval", func(f *fixture) { f.s.observation.Reviews.Records[0].Kind = "APPROVED" }, "review_withdrawal_or_binding"},
		{"ordinary_comment", func(f *fixture) { f.s.observation.Reviews.Records[0].Body = "Looks good" }, "platform_format"},
		{"absent_stored_verdict", func(f *fixture) { f.s.observation.GitHub.Verdicts.Records = nil }, "github_verdict_uniqueness"},
		{"stored_body_changed", func(f *fixture) { f.s.observation.GitHub.Verdicts.Records[0].Body += "\n" }, "github_verdict_uniqueness"},
		{"stored_producer", func(f *fixture) {
			f.s.observation.GitHub.Verdicts.Records[0].Reviewer = f.s.observation.GitHub.Producer
		}, "github_stored_verdict"},
		{"incomplete_stored_inventory", func(f *fixture) { f.s.observation.GitHub.Verdicts.Coverage = Partial }, "github_verdict_coverage"},
		{"ambiguous_stored_body", func(f *fixture) {
			v := f.s.observation.GitHub.Verdicts.Records[0]
			v.Reference = "lab-stored-verdict-2"
			f.s.observation.GitHub.Verdicts.Records = append(f.s.observation.GitHub.Verdicts.Records, v)
		}, "github_verdict_uniqueness"},
		{"ambiguous_unallowed_sender", func(f *fixture) {
			v := f.s.observation.GitHub.Verdicts.Records[0]
			v.Reference = "lab-stored-verdict-2"
			v.Reviewer = GitHubMember{ID: 303, Login: "lab-other", Member: "unallowed-member"}
			f.s.observation.GitHub.Verdicts.Records = append(f.s.observation.GitHub.Verdicts.Records, v)
		}, "github_verdict_uniqueness"},
		{"unsigned_commit", func(f *fixture) { f.s.observation.Commit = f.unsigned; f.r.Commit = fixtureOID(f.unsigned) }, "unsigned_commit"},
		{"unadopted_key", func(f *fixture) {
			_, _, pub := fixtureKey(t)
			f.p.OwnerKeys[0].PublicKey = pub
			f.p.OwnerKeys[0].Fingerprint = fixtureFingerprint(pub)
		}, "owner_key"},
		{"changed_policy", func(f *fixture) { f.s.observation.PolicySHA256 = strings.Repeat("e", 64) }, "policy_revoked_or_changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, phase := range []Phase{Prebuild, Presign} {
				f := validFixture(t)
				m := labGitHubMembership(f)
				labGitHubObservation(f, m)
				tt.change(f)
				a, err := NewGitHubPR(f.p, m, f.s, f.c)
				if err != nil {
					t.Fatal(err)
				}
				_, err = a.qualify(context.Background(), f.r, phase)
				var r *Refusal
				if !errors.As(err, &r) || r.Predicate() != tt.predicate {
					t.Fatalf("phase %s: got %v, want %s", phase, err, tt.predicate)
				}
			}
		})
	}
}
func TestGitHubPRMembershipRequiresExistingIndependentMember(t *testing.T) {
	for _, change := range []func(*GitHubPRMembership){
		func(m *GitHubPRMembership) { m.Reviewers[0].ID = m.Producer.ID },
		func(m *GitHubPRMembership) { m.Reviewers[0].Login = strings.ToUpper(m.Producer.Login) },
		func(m *GitHubPRMembership) { m.Reviewers[0].Member = "unconfigured-member" },
		func(m *GitHubPRMembership) { m.Producer.Member = "unconfigured-producer" },
		func(m *GitHubPRMembership) { m.Reviewers = nil },
	} {
		f := validFixture(t)
		m := labGitHubMembership(f)
		change(&m)
		if _, err := NewGitHubPR(f.p, m, f.s, f.c); err == nil {
			t.Fatal("unadmitted/self membership accepted")
		}
	}
}
func TestGitHubPRLegacyCannotSelectNewRoute(t *testing.T) {
	f := validFixture(t)
	m := labGitHubMembership(f)
	a := f.authority(t)
	labGitHubObservation(f, m)
	if _, err := a.BeforeBuild(context.Background(), f.r); err == nil {
		t.Fatal("observation changed installed route")
	}
}
