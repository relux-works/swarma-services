package sourceauthority

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

// Synthetic signed controls only. No live provider, reviewer key or mutation.
func graphLab(t *testing.T) (reviewLab, githubReviewProof, map[string]any) {
	l := newReviewLab(t)
	p := githubReviewProof{binding: l.b, account: GitHubMember{ID: 2, Login: "reviewer"}, body: string(l.signed(t)), nodeID: "PRR_lab"}
	return l, p, graphNode(p)
}
func graphNode(p githubReviewProof) map[string]any {
	b := p.binding
	return map[string]any{"__typename": "PullRequestReview", "id": p.nodeID, "fullDatabaseId": strconv.FormatUint(b.ReviewID, 10), "state": "COMMENTED", "body": p.body, "lastEditedAt": nil, "includesCreatedEdit": false, "isMinimized": false, "submittedAt": "2026-11-07T00:00:00Z", "commit": map[string]any{"oid": b.Head}, "author": map[string]any{"login": p.account.Login, "databaseId": p.account.ID}, "pullRequest": map[string]any{"number": b.PR, "headRefOid": b.Head, "baseRefOid": b.Base, "baseRefName": b.BaseBranch, "repository": map[string]any{"nameWithOwner": "relux-works/swarma-keyvault", "url": b.Repository}}, "userContentEdits": map[string]any{"totalCount": 0, "nodes": []any{}, "pageInfo": map[string]any{"hasNextPage": false, "hasPreviousPage": false, "startCursor": nil, "endCursor": nil}}}
}
func graphBytes(n any) []byte {
	raw, _ := json.Marshal(map[string]any{"data": map[string]any{"node": n}})
	return raw
}
func mutateGraph(n map[string]any, path string, v any, missing bool) {
	parts := strings.Split(path, ".")
	for _, k := range parts[:len(parts)-1] {
		n = n[k].(map[string]any)
	}
	k := parts[len(parts)-1]
	if missing {
		delete(n, k)
	} else {
		n[k] = v
	}
}
func TestGraphQLNeverEditedPairedPredicates(t *testing.T) {
	bad := map[string]any{"__typename": "Issue", "id": "copy", "fullDatabaseId": "1702", "state": "DISMISSED", "body": "changed", "lastEditedAt": "2026-11-07T01:00:00Z", "includesCreatedEdit": true, "isMinimized": true, "submittedAt": nil, "commit.oid": strings.Repeat("3", 40), "author.login": "producer", "author.databaseId": 9, "pullRequest.number": 18, "pullRequest.headRefOid": strings.Repeat("3", 40), "pullRequest.baseRefOid": strings.Repeat("3", 40), "pullRequest.baseRefName": "other", "pullRequest.repository.nameWithOwner": "other/repo", "pullRequest.repository.url": "https://github.com/other/repo", "userContentEdits.totalCount": 1, "userContentEdits.nodes": []any{map[string]any{"editedAt": nil, "deletedAt": nil}}, "userContentEdits.pageInfo.hasNextPage": true, "userContentEdits.pageInfo.hasPreviousPage": true, "userContentEdits.pageInfo.startCursor": "cursor", "userContentEdits.pageInfo.endCursor": "cursor"}
	for path, value := range bad {
		for _, missing := range []bool{false, true} {
			t.Run(path+"/missing="+strconv.FormatBool(missing), func(t *testing.T) {
				l, p, n := graphLab(t)
				if err := verifyGraphQLOriginal(graphBytes(n), l.p, p); err != nil {
					t.Fatal("signed control", err)
				}
				mutateGraph(n, path, value, missing)
				if err := verifyGraphQLOriginal(graphBytes(n), l.p, p); err == nil {
					t.Fatal("predicate accepted")
				}
				if err := verifyGraphQLOriginal(graphBytes(graphNode(p)), l.p, p); err != nil {
					t.Fatal("restored independent control", err)
				}
			})
		}
	}
	for _, state := range []string{"PENDING", "APPROVED", "CHANGES_REQUESTED", "DELETED"} {
		l, p, n := graphLab(t)
		n["state"] = state
		if verifyGraphQLOriginal(graphBytes(n), l.p, p) == nil {
			t.Fatal(state)
		}
	}
	for _, raw := range [][]byte{[]byte(`{"data":null}`), []byte(`{"data":{"node":null}}`), []byte(`{"data":{}}`), []byte(`{"data":{"node":null},"errors":[{}]}`), []byte(`{"data":{"node":null},"data":{}}`), []byte(`{`)} {
		l, p, _ := graphLab(t)
		if verifyGraphQLOriginal(raw, l.p, p) == nil {
			t.Fatal("partial accepted")
		}
	}
	l, p, n := graphLab(t)
	raw := graphBytes(n)
	var e map[string]any
	json.Unmarshal(raw, &e)
	e["errors"] = []any{map[string]any{"message": "redacted"}}
	raw, _ = json.Marshal(e)
	if verifyGraphQLOriginal(raw, l.p, p) == nil {
		t.Fatal("partial data with error")
	}
	for _, key := range []string{"State", "sTaTe", "includescreatededit", "LastEditedAt"} {
		l, p, n := graphLab(t)
		n[key] = nil
		if verifyGraphQLOriginal(graphBytes(n), l.p, p) == nil {
			t.Fatal("field alias accepted")
		}
	}
	for _, path := range []string{"includesCreatedEdit", "isMinimized", "userContentEdits.totalCount", "userContentEdits.pageInfo.hasNextPage", "userContentEdits.pageInfo.hasPreviousPage", "commit", "author", "pullRequest", "pullRequest.repository", "userContentEdits", "userContentEdits.pageInfo"} {
		t.Run("explicit-null/"+path, func(t *testing.T) {
			l, p, n := graphLab(t)
			if verifyGraphQLOriginal(graphBytes(n), l.p, p) != nil {
				t.Fatal("valid control")
			}
			mutateGraph(n, path, nil, false)
			if verifyGraphQLOriginal(graphBytes(n), l.p, p) == nil {
				t.Fatal("explicit null accepted")
			}
		})
	}
}

type labInstalledPolicy struct{ raw []byte }

func (l *labInstalledPolicy) Snapshot(ctx context.Context) (*PolicySnapshot, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return policySnapshotForRoute(l.raw, GitHubPRPolicyRoute)
}
func TestGraphQLProtectedConstructorAndPolicyReread(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(strconv.FormatBool(changed), func(t *testing.T) {
			a, r, g, _ := labGitHubAuthority(t)
			raw, err := EncodePolicyForRoute(a.policy, GitHubPRPolicyRoute)
			if err != nil {
				t.Fatal(err)
			}
			installed := &labInstalledPolicy{raw: raw}
			snapshot, err := installed.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			s := a.github
			s.policy = snapshot.PolicyCopy()
			policy := s.policies.(labPolicyReader)
			policy.snapshot.Digest = s.policy.SHA256
			s.policies = policy
			r.PolicySHA256 = s.policy.SHA256
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			protected, err := NewWithPolicySource(ctx, installed, s.policy.SHA256, s, a.clock)
			if err != nil {
				t.Fatal("protected constructor", err)
			}
			q, err := protected.BeforeSign(ctx, r)
			if err != nil {
				t.Fatal("protected admission", err)
			}
			if changed {
				installed.raw = append(append([]byte(nil), raw...), '\n')
			}
			before := g.calls
			err = q.checkFinalEffectContext(ctx)
			if changed {
				if err == nil || g.calls != before {
					t.Fatal("changed installed policy reached provider/effect")
				}
			} else if err != nil || g.calls != before+1 {
				t.Fatal("protected final control", err)
			}
		})
	}
}

type labGraphReader struct {
	raw       []byte
	err       error
	calls     int
	deadline  time.Time
	deadlines []time.Time
}

func (g *labGraphReader) readReview(ctx context.Context, r githubGraphQLRequest) ([]byte, error) {
	g.calls++
	d, ok := ctx.Deadline()
	if !ok || r.Query != githubOriginalReviewQuery || r.NodeID != "PRR_lab" || r.Responses != 1 || r.BodyLimit != MaxReviewCommentBytes+16384 || r.HeaderLimit != acquisitionHeaderMax {
		return nil, errors.New("lab request")
	}
	g.deadline = d
	g.deadlines = append(g.deadlines, d)
	return append([]byte(nil), g.raw...), g.err
}

type labPolicyReader struct{ snapshot githubPolicySnapshot }

func (l labPolicyReader) readCurrent(context.Context) (githubPolicySnapshot, error) {
	return l.snapshot, nil
}

type labGitReader struct{ snapshot githubGitSnapshot }

func (l labGitReader) readGit(context.Context, Query) (githubGitSnapshot, error) {
	return l.snapshot, nil
}

type labCheckReader struct{ snapshot githubCheckSnapshot }

func (l labCheckReader) readChecks(context.Context, Query) (githubCheckSnapshot, error) {
	return l.snapshot, nil
}

func labGitHubAuthority(t *testing.T) (*Authority, Request, *labGraphReader, githubReviewProof) {
	t.Helper()
	l := newReviewLab(t)
	f := validFixture(t)
	commit := fixtureSign(t, f.unsigned, l.producer, l.p.OwnerKeys[0].PublicKey, "sha512")
	l.b.Head = fixtureOID(commit)
	proof := githubReviewProof{binding: l.b, account: GitHubMember{ID: 2, Login: "reviewer"}, body: string(l.signed(t)), nodeID: "PRR_lab"}
	g := &labGraphReader{raw: graphBytes(graphNode(proof))}
	m := GitHubPRMembership{Producer: GitHubMember{ID: 1, Login: "producer"}, Reviewers: []GitHubMember{proof.account}}
	c := githubPRInstallation{policy: l.p, members: m, number: l.b.PR, clock: f.c, graphql: g, policies: labPolicyReader{githubPolicySnapshot{Digest: l.p.SHA256, Generation: "lab", State: Current, Members: m}}, git: labGitReader{githubGitSnapshot{Repository: RepositoryRecord{Canonical: l.b.Repository, DefaultBranch: "main", DefaultHead: l.b.Head}, Commit: commit}}, checks: labCheckReader{githubCheckSnapshot{Policy: CheckPolicy{Repository: l.b.Repository, Ref: "lab", State: "no_required"}, Inventory: CheckInventory{Repository: l.b.Repository, Head: l.b.Head, Coverage: Complete}}}}
	s, err := newGitHubPRSource(c)
	if err != nil {
		t.Fatal(err)
	}
	nativePR := map[string]any{"number": l.b.PR, "state": "closed", "draft": false, "merged": true, "user": map[string]any{"id": 1, "login": "producer", "type": "User"}, "head": map[string]any{"sha": l.b.Head, "repo": map[string]any{"full_name": "fork/source", "html_url": "https://github.com/fork/source"}}, "base": map[string]any{"ref": "main", "sha": l.b.Base, "repo": map[string]any{"full_name": l.p.RepositoryName, "html_url": l.b.Repository, "private": false}}}
	nativeReviews := []any{map[string]any{"id": l.b.ReviewID, "node_id": proof.nodeID, "commit_id": l.b.Head, "state": "COMMENTED", "body": proof.body, "submitted_at": "2026-11-07T00:00:00Z", "user": map[string]any{"id": 2, "login": "reviewer", "type": "User"}}}
	transport, _ := acquisitionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reviews" {
			json.NewEncoder(w).Encode(nativeReviews)
		} else {
			json.NewEncoder(w).Encode(nativePR)
		}
	}, acquisitionLimits{acquisitionHeaderMax, acquisitionBodyMax, acquisitionCommitMax, acquisitionAggregateMax, acquisitionResponsesMax})
	root := strings.TrimSuffix(transport.endpoints["metadata"].url, "/body")
	transport.endpoints = map[string]installedEndpoint{"pr": {url: root + "/pr", kind: metadataResponse}, "reviews": {url: root + "/reviews", kind: metadataResponse}}
	s.transport = transport
	a, err := NewGitHubPR(l.p, s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	return a, Request{OperationID: strings.Repeat("a", 32), Nonce: strings.Repeat("b", 64), Product: l.p.Product, Repository: l.p.Alias, Commit: l.b.Head, PolicySHA256: l.p.SHA256}, g, proof
}
func TestGraphQLActualAdmissionAndFinalEffectReread(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, failure := range []string{"none", "edit", "dismissal", "minimize", "deletion", "error", "missing_false", "partial_page", "copy", "body", "cancel", "expiry"} {
			t.Run(string(phase)+"/"+failure, func(t *testing.T) {
				a, r, g, p := labGitHubAuthority(t)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				q, err := a.qualify(ctx, r, phase)
				if err != nil || g.calls != 1 {
					t.Fatalf("actual admission: %v reads=%d", err, g.calls)
				}
				n := graphNode(p)
				switch failure {
				case "edit":
					n["lastEditedAt"] = "2026-11-07T01:00:00Z"
				case "dismissal":
					n["state"] = "DISMISSED"
				case "minimize":
					n["isMinimized"] = true
				case "deletion":
					n = nil
				case "error":
					g.err = errors.New("synthetic read error")
				case "missing_false":
					delete(n, "includesCreatedEdit")
				case "partial_page":
					mutateGraph(n, "userContentEdits.pageInfo.hasNextPage", true, false)
				case "copy":
					n["fullDatabaseId"] = "1702"
				case "body":
					n["body"] = p.body + "\n"
				case "cancel":
					cancel()
				case "expiry":
					q.originalDeadline = time.Now().Add(-time.Second)
				}
				g.raw = graphBytes(n)
				effects := 0
				if err = q.checkFinalEffectContext(ctx); err == nil {
					effects++
				}
				if failure == "none" {
					if err != nil || effects != 1 || g.calls != 2 {
						t.Fatalf("final control %v reads=%d", err, g.calls)
					}
					if g.deadlines[1].After(g.deadlines[0]) {
						t.Fatal("final read widened admission deadline")
					}
				} else if err == nil || effects != 0 {
					t.Fatal("revoked effect reached")
				}
			})
		}
	}
}

func graphEffectRaw(t *testing.T, raw []byte, a *Authority, r Request) []byte {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["operation_id"] = r.OperationID
	fields["commit"] = r.Commit
	fields["policy_sha256"] = a.policy.SHA256
	result, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestGraphQLRevocationAtActualEffectBoundary(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, revoked := range []bool{false, true} {
			t.Run(string(phase)+"/revoked="+strconv.FormatBool(revoked), func(t *testing.T) {
				a, req, g, p := labGitHubAuthority(t)
				e, _, raw := newEffectFixture(t)
				runner, err := newEffectRunner(a, e.policy, effectBuilder{e}, effectSigner{e}, e)
				if err != nil {
					t.Fatal(err)
				}
				e.auditChange = func(r EffectRecord) error {
					if revoked && r.Authority.Binding.Phase == phase {
						n := graphNode(p)
						n["lastEditedAt"] = "2026-11-07T01:00:00Z"
						g.raw = graphBytes(n)
					}
					return nil
				}
				err = runner.Run(effectContext(t), effectBody(t, graphEffectRaw(t, raw, a, req)))
				if !revoked {
					if err != nil || e.buildCalls != 1 || e.signCalls != 1 || g.calls != 4 {
						t.Fatalf("valid runner: %v build=%d sign=%d reads=%d", err, e.buildCalls, e.signCalls, g.calls)
					}
				} else {
					if err == nil || e.signCalls != 0 || phase == Prebuild && e.buildCalls != 0 {
						t.Fatal("revoked effect entered")
					}
				}
				assertSnapshotClosed(t, e)
			})
		}
	}
}
func TestGraphQLRevocationAtAuditedBackendEntry(t *testing.T) {
	for _, point := range []string{"intent-sign", "peer-sign", "peer-verify", "peer-release", "peer-recover"} {
		for _, revoked := range []bool{false, true} {
			t.Run(point+"/revoked="+strconv.FormatBool(revoked), func(t *testing.T) {
				fixture := newAuditAdapterFixture(t)
				authority, request, g, p := labGitHubAuthority(t)
				fixture.runner.authority = authority
				fixture.signer.authority = authority
				fixture.raw = graphEffectRaw(t, fixture.raw, authority, request)
				fixture.e.f.r = request
				isSign := point == "intent-sign" || point == "peer-sign"
				if !isSign {
					if point == "peer-recover" {
						fixture.backend.signErr = errAuditFixture
					}
					err := fixture.run(t)
					if (err != nil) != (point == "peer-recover") {
						t.Fatal("setup", err)
					}
					fixture.backend.signErr = nil
				}
				revoke := func() {
					if revoked {
						n := graphNode(p)
						n["isMinimized"] = true
						g.raw = graphBytes(n)
					}
				}
				if point == "intent-sign" {
					fixture.profile.hook = func(kind string) {
						if kind == "intent" {
							revoke()
						}
					}
				} else {
					fetch := 0
					fixture.trust.change = func(phase signingaudit.Phase, _ signingaudit.Operation) error {
						if phase == signingaudit.Fetch {
							fetch++
						}
						if point == "peer-sign" && phase == signingaudit.Presign || point == "peer-verify" && fetch == 1 || point == "peer-release" && fetch == 2 || point == "peer-recover" && phase == signingaudit.Recovery {
							fixture.backend.peerHook = func() { fixture.backend.peerHook = nil; revoke() }
						}
						return nil
					}
				}
				beforeSign, beforeVerify, beforeRelease, beforeRecover := fixture.backend.signs, fixture.backend.verifies, fixture.backend.releases, fixture.backend.reconciles
				var err error
				if isSign {
					err = fixture.run(t)
				} else if point == "peer-recover" {
					_, err = fixture.signer.Reconcile(fixture.id())
				} else {
					err = fixture.signer.Fetch(fixture.id())
				}
				entered := fixture.backend.signs - beforeSign
				switch point {
				case "peer-verify":
					entered = fixture.backend.verifies - beforeVerify
				case "peer-release":
					entered = fixture.backend.releases - beforeRelease
				case "peer-recover":
					entered = fixture.backend.reconciles - beforeRecover
				}
				if revoked {
					if err == nil || entered != 0 {
						t.Fatalf("revoked backend entered=%d err=%v", entered, err)
					}
				} else if err != nil || entered != 1 {
					t.Fatalf("valid backend entered=%d err=%v", entered, err)
				}
			})
		}
	}
}
