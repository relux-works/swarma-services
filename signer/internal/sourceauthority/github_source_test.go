package sourceauthority

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// These dependencies exist ONLY in the test binary. They use synthetic original
// signed bytes and explicit laboratory evidence, never installed policy or live
// provider data. No production implementation is implied by their success.
type githubLabSupport struct {
	f                                               *fixture
	policyReads, gitReads, checkReads, verdictReads int
	policyChange                                    func(int, *githubPolicySnapshot)
	gitChange                                       func(int, *githubGitSnapshot)
	checkChange                                     func(int, *githubCheckSnapshot)
	verdictChange                                   func(int, *githubVerdictSelection)
}

func (d *githubLabSupport) readCurrent(context.Context) (githubPolicySnapshot, error) {
	d.policyReads++
	r := githubPolicySnapshot{Digest: d.f.p.SHA256, Generation: "lab-policy-generation-1", State: Current, Members: labGitHubMembership(d.f)}
	if d.policyChange != nil {
		d.policyChange(d.policyReads, &r)
	}
	return r, nil
}
func (d *githubLabSupport) readGit(context.Context, Query) (githubGitSnapshot, error) {
	d.gitReads++
	o := d.f.s.observation
	r := githubGitSnapshot{Repository: o.Repository, Commit: o.Commit, LandingPath: o.LandingPath}
	if d.gitChange != nil {
		d.gitChange(d.gitReads, &r)
	}
	return r, nil
}
func (d *githubLabSupport) readChecks(context.Context, Query) (githubCheckSnapshot, error) {
	d.checkReads++
	o := d.f.s.observation
	r := githubCheckSnapshot{Policy: o.CheckPolicy, Inventory: o.Checks}
	if d.checkChange != nil {
		d.checkChange(d.checkReads, &r)
	}
	return r, nil
}
func (d *githubLabSupport) readVerdict(context.Context, Query, PullRequest, []PlatformReview) (githubVerdictSelection, error) {
	d.verdictReads++
	r := githubVerdictSelection{ReviewID: "1701", Verdicts: d.f.s.observation.GitHub.Verdicts}
	r.Verdicts.Records = append([]GitHubStoredVerdict(nil), r.Verdicts.Records...)
	if d.verdictChange != nil {
		d.verdictChange(d.verdictReads, &r)
	}
	return r, nil
}

type githubLab struct {
	f       *fixture
	m       GitHubPRMembership
	d       *githubLabSupport
	s       *githubPRSource
	pr      map[string]any
	reviews []map[string]any
	reads   int
	mutate  func(int, *githubLab)
	mu      sync.Mutex
}

func newGitHubLab(t *testing.T) *githubLab {
	t.Helper()
	f := validFixture(t)
	m := labGitHubMembership(f)
	labGitHubObservation(f, m)
	l := &githubLab{f: f, m: m}
	l.d = &githubLabSupport{f: f}
	l.pr = map[string]any{"number": 17, "state": "closed", "draft": false, "merged": true, "user": map[string]any{"id": m.Producer.ID, "login": m.Producer.Login, "type": "User"}, "head": map[string]any{"sha": f.r.Commit}, "base": map[string]any{"sha": f.s.observation.PR.Base, "ref": "main", "repo": map[string]any{"full_name": f.p.RepositoryName, "html_url": f.p.CanonicalRepository, "private": false}}}
	r := f.s.observation.Reviews.Records[0]
	l.reviews = []map[string]any{{"id": 1701, "commit_id": r.Head, "state": "COMMENTED", "body": r.Body, "submitted_at": time.Unix(r.SubmittedAt, 0).UTC(), "user": map[string]any{"id": m.Reviewers[0].ID, "login": m.Reviewers[0].Login, "type": "User"}}}
	s, err := newGitHubPRSource(githubPRInstallation{policy: f.p, members: m, number: 17, clock: f.c, policies: l.d, git: l.d, checks: l.d, verdicts: l.d})
	if err != nil {
		t.Fatal(err)
	}
	l.s = s
	root := "/repos/" + f.p.RepositoryName + "/pulls/17"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.reads++
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" {
			t.Error("non-anonymous or unexpected request")
		}
		if l.mutate != nil {
			l.mutate(l.reads, l)
		}
		var v any
		switch r.URL.Path {
		case root:
			v = l.pr
		case root + "/reviews":
			v = l.reviews
		default:
			w.WriteHeader(404)
			return
		}
		body, err := json.Marshal(v)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	// The alternate origin and public test CA are private test assembly only.
	s.transport, err = newSourceAcquisition(acquisitionInstallation{provider: "lab-github-pr", origin: server.URL, roots: roots, limits: s.transport.limits, endpoints: map[string]acquisitionEndpoint{"pr": {path: root, kind: metadataResponse}, "reviews": {path: root + "/reviews", kind: metadataResponse}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func (l *githubLab) authority(t *testing.T) *Authority {
	t.Helper()
	a, err := NewGitHubPR(l.f.p, l.m, l.s, l.f.c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestGitHubPRSourceOfflineLabBothPhases(t *testing.T) {
	l := newGitHubLab(t)
	a := l.authority(t)
	b, err := a.BeforeBuild(context.Background(), l.f.r)
	if err != nil {
		t.Fatal(err)
	}
	summary, ok := b.Summary()
	if !ok || summary.PlatformReviewID != "1701" || summary.PR != 17 {
		t.Fatal("summary lost acquired PR/review binding")
	}
	l.f.r.Nonce = strings.Repeat("f", 64)
	s, err := a.BeforeSign(context.Background(), l.f.r)
	if err != nil {
		t.Fatal(err)
	}
	summary, ok = s.Summary()
	if !ok || summary.Binding.Phase != Presign || summary.Binding.Nonce != l.f.r.Nonce {
		t.Fatal("sign phase binding")
	}
	if l.reads != 8 || l.d.policyReads != 4 || l.d.gitReads != 4 || l.d.checkReads != 4 || l.d.verdictReads != 4 {
		t.Fatalf("phase refresh not complete: remote %d policy %d git %d checks %d verdict %d", l.reads, l.d.policyReads, l.d.gitReads, l.d.checkReads, l.d.verdictReads)
	}
}
func TestGitHubPRSourceRefusesSnapshotChanges(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*githubLab)
	}{
		{"pr_changed_during_read", func(l *githubLab) {
			l.mutate = func(n int, l *githubLab) {
				if n == 3 {
					l.pr["base"].(map[string]any)["sha"] = strings.Repeat("4", 40)
				}
			}
		}},
		{"review_changed_during_read", func(l *githubLab) {
			l.mutate = func(n int, l *githubLab) {
				if n == 4 {
					l.reviews[0]["body"] = "changed"
				}
			}
		}},
		{"policy_revoked", func(l *githubLab) {
			l.d.policyChange = func(n int, p *githubPolicySnapshot) {
				if n == 2 {
					p.State = Revoked
				}
			}
		}},
		{"policy_generation_changed", func(l *githubLab) {
			l.d.policyChange = func(n int, p *githubPolicySnapshot) {
				if n == 2 {
					p.Generation = "lab-policy-generation-2"
				}
			}
		}},
		{"member_admission_revoked", func(l *githubLab) {
			l.d.policyChange = func(n int, p *githubPolicySnapshot) {
				if n == 2 {
					p.Members.Reviewers = nil
				}
			}
		}},
		{"default_head_changed", func(l *githubLab) {
			l.d.gitChange = func(n int, g *githubGitSnapshot) {
				if n == 2 {
					g.Repository.DefaultHead = strings.Repeat("4", 40)
				}
			}
		}},
		{"checks_changed", func(l *githubLab) {
			l.d.checkChange = func(n int, c *githubCheckSnapshot) {
				if n == 2 {
					c.Policy.Ref = "changed-policy"
				}
			}
		}},
		{"verdict_changed", func(l *githubLab) {
			l.d.verdictChange = func(n int, v *githubVerdictSelection) {
				if n == 2 {
					v.Verdicts.Records[0].State = "redacted"
				}
			}
		}},
		{"absolute_budget", func(l *githubLab) {
			l.d.policyChange = func(n int, p *githubPolicySnapshot) {
				if n == 2 {
					l.f.c.advance(AuthorityBudget)
				}
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, phase := range []Phase{Prebuild, Presign} {
				l := newGitHubLab(t)
				tt.setup(l)
				if q, err := l.authority(t).qualify(context.Background(), l.f.r, phase); err == nil || q != nil {
					t.Fatalf("phase %s accepted changed snapshot", phase)
				}
			}
		})
	}
}
func TestGitHubPRSourceRefusesNativeControls(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*githubLab)
	}{
		{"self_review", func(l *githubLab) {
			l.reviews[0]["user"] = map[string]any{"id": l.m.Producer.ID, "login": l.m.Producer.Login, "type": "User"}
		}},
		{"missing_review", func(l *githubLab) { l.reviews = []map[string]any{} }},
		{"changed_head", func(l *githubLab) { l.pr["head"].(map[string]any)["sha"] = strings.Repeat("4", 40) }},
		{"wrong_target_branch", func(l *githubLab) { l.pr["base"].(map[string]any)["ref"] = "other" }},
		{"wrong_original_base", func(l *githubLab) { l.pr["base"].(map[string]any)["sha"] = strings.Repeat("4", 40) }},
		{"draft", func(l *githubLab) { l.pr["draft"] = true }},
		{"unmerged", func(l *githubLab) { l.pr["merged"] = false }},
		{"unresolved_blocking_review", func(l *githubLab) {
			r := map[string]any{}
			for k, v := range l.reviews[0] {
				r[k] = v
			}
			r["id"] = 1702
			r["state"] = "CHANGES_REQUESTED"
			l.reviews = append(l.reviews, r)
		}},
		{"ambiguous_page_coverage", func(l *githubLab) {
			r := l.reviews[0]
			for len(l.reviews) < 30 {
				l.reviews = append(l.reviews, r)
			}
		}},
		{"dismissed", func(l *githubLab) { l.reviews[0]["state"] = "DISMISSED" }},
		{"generic_native_approval", func(l *githubLab) { l.reviews[0]["state"] = "APPROVED" }},
		{"missing_stored_verdict", func(l *githubLab) { l.f.s.observation.GitHub.Verdicts.Records = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newGitHubLab(t)
			tt.setup(l)
			if q, err := l.authority(t).BeforeBuild(context.Background(), l.f.r); err == nil || q != nil {
				t.Fatal("invalid native evidence accepted")
			}
		})
	}
}
func TestGitHubPRSourcePresignRereadsReview(t *testing.T) {
	l := newGitHubLab(t)
	a := l.authority(t)
	if _, err := a.BeforeBuild(context.Background(), l.f.r); err != nil {
		t.Fatal(err)
	}
	l.mutate = func(n int, l *githubLab) {
		if n == 5 {
			l.reviews[0]["state"] = "DISMISSED"
		}
	}
	l.f.r.Nonce = strings.Repeat("e", 64)
	if q, err := a.BeforeSign(context.Background(), l.f.r); err == nil || q != nil {
		t.Fatal("build success reused at signing")
	}
}
func TestGitHubPRSourceMissingProductionDependencies(t *testing.T) {
	l := newGitHubLab(t)
	c := githubPRInstallation{policy: l.f.p, members: l.m, number: 17, clock: l.f.c, policies: l.d, git: l.d, checks: l.d, verdicts: l.d}
	c.verdicts = nil
	if _, err := newGitHubPRSource(c); err == nil {
		t.Fatal("absent production verdict mapping accepted")
	}
	c.verdicts = l.d
	c.policies = nil
	if _, err := newGitHubPRSource(c); err == nil {
		t.Fatal("absent protected policy loader accepted")
	}
}
func TestGitHubPRSourceCancellationAndGate(t *testing.T) {
	l := newGitHubLab(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.authority(t).BeforeBuild(ctx, l.f.r); err == nil {
		t.Fatal("cancellation accepted")
	}
	l.s.busy.Store(true)
	defer l.s.busy.Store(false)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if o, err := l.s.Read(ctx, Query{Request: l.f.r, Phase: Prebuild}); err == nil || o.Binding != (Query{}) {
		t.Fatal("busy instance returned evidence")
	}
}
func TestGitHubPRJSONRefusesAmbiguousBytes(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"id":1,"\u0069d":2}`), []byte(`{"user":{"id":1,"id":2}}`), []byte(`{"ID":1}`),
		[]byte(`{"body":"\ud800"}`), []byte(`{"body":"\udc00"}`), []byte(`{"body":"\ud800x"}`), []byte("{\"body\":\"\xff\"}"),
		[]byte(`{} {}`), []byte(strings.Repeat("[", 66) + strings.Repeat("]", 66)),
	}
	for i, raw := range cases {
		var out any
		if err := strictGitHubJSON(raw, &out); err == nil {
			t.Fatalf("invalid JSON case %d accepted", i)
		}
	}
	for _, raw := range []string{`{"body":"\ud83d\ude00"}`, `{"body":"literal \\ud800"}`, `{"body":"valid escaped quote: \""}`} {
		var out any
		if err := strictGitHubJSON([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
	}
	var reviews []nativeGitHubReview
	raw := []byte("[" + strings.Repeat("{},", 29) + "{}]")
	if err := strictGitHubJSON(raw, &reviews); err == nil || len(reviews) != 0 {
		t.Fatal("oversized review page decoded before capacity refusal")
	}
}
func TestGitHubPRCorePreservesUnsignedAndUnadoptedOnSource(t *testing.T) {
	for _, name := range []string{"unsigned", "unadopted"} {
		t.Run(name, func(t *testing.T) {
			l := newGitHubLab(t)
			if name == "unsigned" {
				l.f.s.observation.Commit = l.f.unsigned
				l.f.r.Commit = fixtureOID(l.f.unsigned)
				l.f.s.observation.Repository.DefaultHead = l.f.r.Commit
				l.pr["head"].(map[string]any)["sha"] = l.f.r.Commit
				// Keep every native review/head binding valid for the negative signed object.
				head := l.f.r.Commit
				base := l.f.s.observation.PR.Base
				v := "ACCEPT: independent source review of " + l.f.p.RepositoryName + " PR #17.\nPR " + l.f.p.CanonicalRepository + "/pull/17\nExact head " + head + ", base " + base + ".\n"
				l.f.s.observation.GitHub.Verdicts.Records[0].Body = v
				l.reviews[0]["commit_id"] = head
				l.reviews[0]["body"] = "Independent source review: **ACCEPT** for exact head `" + head + "` (base `" + base + "`).\nVerdict record digest: sha256:" + bodyHash(v) + "\n"
				l.f.s.observation.Checks.Head = head
				for i := range l.f.s.observation.Checks.Records {
					l.f.s.observation.Checks.Records[i].Head = head
				}
			} else {
				_, _, pub := fixtureKey(t)
				l.f.p.OwnerKeys[0].PublicKey = pub
				l.f.p.OwnerKeys[0].Fingerprint = fixtureFingerprint(pub)
			}
			_, err := l.authority(t).BeforeBuild(context.Background(), l.f.r)
			var r *Refusal
			if !errors.As(err, &r) {
				t.Fatalf("missing refusal: %v", err)
			}
			want := "unsigned_commit"
			if name == "unadopted" {
				want = "owner_key"
			}
			if r.Predicate() != want {
				t.Fatalf("got %v, want %s", err, want)
			}
		})
	}
}
