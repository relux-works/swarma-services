package sourceauthority

import (
	"context"
	"crypto/ed25519"
	"strconv"
	"testing"
	"time"
)

func TestSharedPublisherAccountCorrelation(t *testing.T) {
	p := GitHubMember{ID: 1, Login: "publisher"}
	for _, tc := range []struct {
		name      string
		reviewers []GitHubMember
		valid     bool
	}{
		{"distinct", []GitHubMember{{ID: 2, Login: "reviewer"}}, true},
		{"shared-exact-pair", []GitHubMember{p}, true},
		{"shared-and-distinct", []GitHubMember{p, {ID: 2, Login: "reviewer"}}, true},
		{"producer-id-wrong-login", []GitHubMember{{ID: 1, Login: "reviewer"}}, false},
		{"producer-login-wrong-id", []GitHubMember{{ID: 2, Login: "publisher"}}, false},
		{"case-alias-wrong-id", []GitHubMember{{ID: 2, Login: "Publisher"}}, false},
		{"case-alias-same-id", []GitHubMember{{ID: 1, Login: "Publisher"}}, false},
		{"duplicate-reviewer", []GitHubMember{p, p}, false},
		{"reviewer-id-alias", []GitHubMember{{ID: 2, Login: "reviewer"}, {ID: 2, Login: "other"}}, false},
		{"reviewer-login-alias", []GitHubMember{{ID: 2, Login: "reviewer"}, {ID: 3, Login: "Reviewer"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := GitHubPRMembership{Producer: p, Reviewers: tc.reviewers}
			if got := validGitHubMembers(m); got != tc.valid {
				t.Fatalf("membership valid=%v want=%v", got, tc.valid)
			}
			r := PlatformReview{AccountID: tc.reviewers[0].ID, AccountLogin: tc.reviewers[0].Login}
			if _, ok := githubReviewerAccount(m, r); ok != tc.valid {
				t.Fatal("selection differs from constructor validation")
			}
			if tc.valid {
				r.AccountID = 9
				if _, ok := githubReviewerAccount(m, r); ok {
					t.Fatal("unmapped numeric account accepted")
				}
				r.AccountID = tc.reviewers[0].ID
				r.AccountLogin = "wrong"
				if _, ok := githubReviewerAccount(m, r); ok {
					t.Fatal("wrong login accepted")
				}
			}
		})
	}
}

// The shared account carries genuine independently generated native role keys.
// Both phase admissions and their final fixed-query GraphQL reads must pass.
func TestSharedPublisherProtectedBoundaries(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(strconv.FormatBool(shared), func(t *testing.T) {
			f := newProviderLabPostingMode(t, shared)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			a, e := NewWithPolicySource(ctx, f.l.installed, f.l.digest, f.l.source, f.l.clock)
			if e != nil {
				t.Fatal(e)
			}
			var original string
			for _, phase := range []Phase{Prebuild, Presign} {
				q, e := a.qualify(ctx, f.l.request, phase)
				if e != nil {
					t.Fatal("phase", phase, e)
				}
				if original != "" && q.summary.PlatformReviewID != original {
					t.Fatal("original selector changed")
				}
				original = q.summary.PlatformReviewID
				if e = q.checkFinalEffectContext(ctx); e != nil {
					t.Fatal("final", phase, e)
				}
			}
			if f.graphReads.Load() != 4 {
				t.Fatal("missing admission/final original reads", f.graphReads.Load())
			}
		})
	}
}

func TestSharedPublisherFinalRefusals(t *testing.T) {
	for _, fault := range []string{"wrong-id", "wrong-login", "original-id", "body", "edited", "stale-generation", "revoked", "unmapped-account"} {
		t.Run(fault, func(t *testing.T) {
			f := newProviderLabPostingMode(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			a, e := NewWithPolicySource(ctx, f.l.installed, f.l.digest, f.l.source, f.l.clock)
			if e != nil {
				t.Fatal(e)
			}
			q, e := a.BeforeSign(ctx, f.l.request)
			if e != nil {
				t.Fatal("paired admission", e)
			}
			f.mu.Lock()
			n := graphNode(f.l.proof)
			switch fault {
			case "wrong-id":
				mutateGraph(n, "author.databaseId", uint64(9), false)
			case "wrong-login":
				mutateGraph(n, "author.login", "other", false)
			case "original-id":
				n["fullDatabaseId"] = "1702"
			case "body":
				n["body"] = f.l.proof.body + "\n"
			case "edited":
				n["lastEditedAt"] = "2026-11-07T01:00:00Z"
			case "stale-generation":
				f.afterGraph = func() { f.current.mu.Lock(); defer f.current.mu.Unlock(); f.current.value.Generation = "next" }
			case "revoked":
				f.current.mu.Lock()
				f.current.value.State = PolicyState("revoked")
				f.current.mu.Unlock()
			case "unmapped-account":
				f.current.mu.Lock()
				f.current.value.Members.Reviewers[0] = GitHubMember{ID: 9, Login: "other"}
				f.current.mu.Unlock()
			}
			f.graph = graphBytes(n)
			f.mu.Unlock()
			if e = q.checkFinalEffectContext(ctx); e == nil {
				t.Fatal("refused fact reached final effect")
			}
			if f.connector.active.Load() != 0 || f.l.source.transport.busy.Load() {
				t.Fatal("unjoined refusal")
			}
		})
	}
}

// Native policy expresses a role-wide key pool and separate account pins, not
// a per-person key/account map. One publisher entry supports each of 1..4 pins,
// one cryptographically authenticated original at a time. It adds no quorum.
func TestSharedPublisherSigningPoolAndOriginalUniqueness(t *testing.T) {
	l := newReviewLab(t)
	publisher := GitHubMember{ID: 1, Login: "publisher"}
	m := GitHubPRMembership{Producer: publisher, Reviewers: []GitHubMember{publisher}}
	keys := []ed25519.PrivateKey{l.reviewer}
	for count := 1; count <= 4; count++ {
		if count > 1 {
			_, sk, pub := fixtureKey(t)
			keys = append(keys, sk)
			l.p.ReviewerKeys = append(l.p.ReviewerKeys, OwnerKey{GitHubRepository, fixtureFingerprint(pub), pub})
		}
		for i, pin := range l.p.ReviewerKeys {
			v := l.verdict(l.b)
			r := originalLabRecord(t, l)
			r.AccountID = publisher.ID
			r.AccountLogin = publisher.Login
			r.Body = string(labComment(l.b, v, labSSHSIG(t, v, keys[i], pin.PublicKey, ReviewNamespace, "sha512")))
			o := Observation{PR: PullRequest{Repository: l.b.Repository, BaseBranch: l.b.BaseBranch, Head: l.b.Head, Base: l.b.Base, Number: l.b.PR}, Reviews: ReviewInventory{Coverage: Complete, SelectedID: r.ID, Records: []PlatformReview{r}}}
			if _, _, e := bindSourceGitHubReview(o, l.p, m); e != nil {
				t.Fatal("pool pin", count, i, e)
			}
			// Exact repeated pages deduplicate; they never count as two reviews.
			o.Reviews.Records = append(o.Reviews.Records, r)
			if _, _, e := bindSourceGitHubReview(o, l.p, m); e != nil {
				t.Fatal("identical page dedup", e)
			}
			r.ID = "1702"
			o.Reviews.Records = append(o.Reviews.Records, r)
			if _, _, e := bindSourceGitHubReview(o, l.p, m); e == nil {
				t.Fatal("copied signed original counted twice")
			}
			// A second genuinely signed original under another pin is still ambiguous.
			other := l.b
			other.ReviewID++
			r.Body = string(labComment(other, l.verdict(other), labSSHSIG(t, l.verdict(other), keys[(i+1)%count], l.p.ReviewerKeys[(i+1)%count].PublicKey, ReviewNamespace, "sha512")))
			o.Reviews.Records = []PlatformReview{o.Reviews.Records[0], r}
			if _, _, e := bindSourceGitHubReview(o, l.p, m); e == nil {
				t.Fatal("multiple authenticated originals accepted")
			}
			o.Reviews.Records = o.Reviews.Records[:1]
			r = o.Reviews.Records[0]
			for _, bad := range []string{"producer-signature", "unmapped-key", "duplicate-pin", "producer-pin", "wrong-account-id", "wrong-account-login"} {
				p := copyPolicy(l.p)
				badRecord := r
				switch bad {
				case "producer-signature":
					badRecord.Body = string(labComment(l.b, v, labSSHSIG(t, v, l.producer, l.p.OwnerKeys[0].PublicKey, ReviewNamespace, "sha512")))
				case "unmapped-key":
					_, sk, pub := fixtureKey(t)
					badRecord.Body = string(labComment(l.b, v, labSSHSIG(t, v, sk, pub, ReviewNamespace, "sha512")))
				case "duplicate-pin":
					p.ReviewerKeys = append(p.ReviewerKeys[:1], p.ReviewerKeys[0])
				case "producer-pin":
					p.ReviewerKeys = []OwnerKey{p.OwnerKeys[0]}
				case "wrong-account-id":
					badRecord.AccountID = 9
				case "wrong-account-login":
					badRecord.AccountLogin = "other"
				}
				o.Reviews.Records = []PlatformReview{badRecord}
				if _, _, e := bindSourceGitHubReview(o, p, m); e == nil {
					t.Fatal("role/account refusal", bad)
				}
			}
		}
	}
}
