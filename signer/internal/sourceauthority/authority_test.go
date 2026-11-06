package sourceauthority

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func assertRefusal(t *testing.T, f *fixture, code error, predicate string) {
	t.Helper()
	a := f.authority(t)
	// The simulated downstream effect is reachable only after qualification;
	// this asserts the intended guard, not a nonexistent native signer run.
	for _, boundary := range []func(context.Context, Request) (*Qualification, error){a.BeforeBuild, a.BeforeSign} {
		effects := 0
		q, err := boundary(context.Background(), f.r)
		if err == nil {
			effects++
		}
		var refusal *Refusal
		if q != nil || !errors.Is(err, code) || !errors.As(err, &refusal) || refusal.Predicate() != predicate || effects != 0 {
			t.Fatalf("expected %s: %s and no downstream effect, got qualification=%v err=%v effects=%d", code, predicate, q != nil, err, effects)
		}
	}
}

// Claim: Both boundaries refresh exact-source authority and expose a bound summary without private provenance.
func TestValidBoundaryQualification(t *testing.T) {
	f := validFixture(t)
	a := f.authority(t)
	build, err := a.BeforeBuild(context.Background(), f.r)
	if err != nil {
		t.Fatal(err)
	}
	if err := build.CheckFreshness(); err != nil {
		t.Fatal(err)
	}
	request := f.r
	request.Nonce = strings.Repeat("e", 64)
	sign, err := a.BeforeSign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	s, present := sign.Summary()
	if !present || s.Binding.Request != request || s.Binding.Phase != Presign || s.Tree != strings.Repeat("1", 40) || s.OwnerFingerprint != f.p.OwnerKeys[0].Fingerprint || s.DefaultHead != request.Commit || s.Relationship != "equal" || s.Verdict != "ACCEPT" || s.CheckVerdict != "required_passed" || s.VerdictBodySHA256 != bodyHash(f.s.observation.Lookup.Scopes[0].Events[0].Body) {
		t.Fatalf("incorrect exact-source summary: %+v", s)
	}
	if len(f.s.queries) != 2 || f.s.queries[0].Phase != Prebuild || f.s.queries[1].Phase != Presign || f.s.queries[0].Nonce == f.s.queries[1].Nonce {
		t.Fatal("both boundaries must independently refresh")
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{f.p.ProducerSender, f.p.ReviewerSenders[0], f.p.Scopes[0], "$verdict", "$producer", "Non-blocking notes"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("private provenance leaked into summary")
		}
	}
}

// Claim: Wrong source, owner, landing, policy or response bindings refuse at both boundaries without downstream effects.
func TestAuthorityRefusals(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*testing.T, *fixture)
		code      error
		predicate string
	}{
		{"foreign_repository_owner_key", func(t *testing.T, f *fixture) {
			f.p.OwnerKeys[0].Repository = "https://github.com/fixture-owner/other-repository"
		}, ErrRejected, "owner_key"},
		{"wrong_owner", func(t *testing.T, f *fixture) {
			_, _, public := fixtureKey(t)
			f.p.OwnerKeys[0].PublicKey = public
			f.p.OwnerKeys[0].Fingerprint = fixtureFingerprint(public)
		}, ErrRejected, "owner_key"},
		{"unsigned", func(t *testing.T, f *fixture) {
			f.s.observation.Commit = f.unsigned
			f.rebindHead(fixtureOID(f.unsigned))
		}, ErrRejected, "unsigned_commit"},
		{"altered_signed_payload", func(t *testing.T, f *fixture) {
			f.s.observation.Commit = append(f.s.observation.Commit, 'x')
			f.rebindHead(fixtureOID(f.s.observation.Commit))
		}, ErrRejected, "commit_signature"},
		{"wrong_exact_commit", func(t *testing.T, f *fixture) { f.r.Commit = strings.Repeat("f", 40) }, ErrRejected, "commit_identity"},
		{"uppercase_sha1", func(t *testing.T, f *fixture) { f.r.Commit = strings.ToUpper(f.r.Commit) }, ErrRejected, "request_binding"},
		{"short_sha1", func(t *testing.T, f *fixture) { f.r.Commit = f.r.Commit[:39] }, ErrRejected, "request_binding"},
		{"sha256_object_format", func(t *testing.T, f *fixture) { f.r.Commit = strings.Repeat("f", 64) }, ErrRejected, "request_binding"},
		{"caller_product", func(t *testing.T, f *fixture) { f.r.Product = "caller-selected" }, ErrRejected, "request_binding"},
		{"caller_repository", func(t *testing.T, f *fixture) { f.r.Repository = "https://github.com/fixture-owner/elsewhere" }, ErrRejected, "request_binding"},
		{"caller_policy", func(t *testing.T, f *fixture) { f.r.PolicySHA256 = strings.Repeat("f", 64) }, ErrRejected, "request_binding"},
		{"configured_repository_mismatch", func(t *testing.T, f *fixture) { f.s.observation.Repository.Canonical += "-other" }, ErrRejected, "repository_default_branch"},
		{"wrong_default_branch", func(t *testing.T, f *fixture) { f.s.observation.Repository.DefaultBranch = "producer-branch" }, ErrRejected, "repository_default_branch"},
		{"unlanded", func(t *testing.T, f *fixture) { f.s.observation.Repository.DefaultHead = strings.Repeat("f", 40) }, ErrRejected, "unlanded_commit"},
		{"wrong_pr_head", func(t *testing.T, f *fixture) { f.s.observation.PR.Head = strings.Repeat("f", 40) }, ErrRejected, "pull_request"},
		{"draft", func(t *testing.T, f *fixture) { f.s.observation.PR.State = "draft" }, ErrRejected, "pull_request"},
		{"accepted_but_open", func(t *testing.T, f *fixture) { f.s.observation.PR.State = "open" }, ErrRejected, "pull_request"},
		{"wrong_pr_repository", func(t *testing.T, f *fixture) { f.s.observation.PR.Repository += "-other" }, ErrRejected, "pull_request"},
		{"wrong_producer", func(t *testing.T, f *fixture) { f.s.observation.Producer.Sender = f.p.ReviewerSenders[0] }, ErrRejected, "producer_handoff"},
		{"producer_head", func(t *testing.T, f *fixture) { f.s.observation.Producer.Head = strings.Repeat("f", 40) }, ErrRejected, "producer_handoff"},
		{"producer_origin", func(t *testing.T, f *fixture) { f.s.observation.Producer.Origin = "untrusted.invalid" }, ErrRejected, "producer_handoff"},
		{"changed_local_policy", func(t *testing.T, f *fixture) { f.s.observation.PolicySHA256 = strings.Repeat("f", 64) }, ErrRejected, "policy_revoked_or_changed"},
		{"revoked", func(t *testing.T, f *fixture) { f.s.observation.PolicyState = Revoked }, ErrRejected, "policy_revoked_or_changed"},
		{"unknown_policy_state", func(t *testing.T, f *fixture) { f.s.observation.PolicyState = "unknown" }, ErrUnavailable, "policy_state"},
		{"unavailable_provider", func(t *testing.T, f *fixture) { f.s.err = errors.New("PRIVATE_PROVIDER_PAYLOAD_MUST_NOT_ESCAPE") }, ErrUnavailable, "source_read"},
		{"replayed_nonce", func(t *testing.T, f *fixture) {
			f.s.change = func(_ context.Context, _ Query, o *Observation) { o.Binding.Nonce = strings.Repeat("0", 64) }
		}, ErrRejected, "response_binding"},
		{"replayed_phase", func(t *testing.T, f *fixture) {
			f.s.change = func(_ context.Context, q Query, o *Observation) {
				if q.Phase == Prebuild {
					o.Binding.Phase = Presign
				} else {
					o.Binding.Phase = Prebuild
				}
			}
		}, ErrRejected, "response_binding"},
		{"replayed_operation", func(t *testing.T, f *fixture) {
			f.s.change = func(_ context.Context, _ Query, o *Observation) { o.Binding.OperationID = strings.Repeat("0", 32) }
		}, ErrRejected, "response_binding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { f := validFixture(t); tt.mutate(t, f); assertRefusal(t, f, tt.code, tt.predicate) })
	}
}

// Claim: Unknown clocks, stale/future/overlong leases and exhausted phase budgets refuse at both boundaries.
func TestLeaseRefusals(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*fixture)
		predicate string
	}{
		{"expired", func(f *fixture) { f.s.observation.ExpiresAt = f.s.observation.ObservedAt }, "lease_clock"},
		{"stale", func(f *fixture) {
			f.s.observation.ObservedAt -= 301
			f.s.observation.ExpiresAt = f.s.observation.ObservedAt + 300
		}, "lease_clock"},
		{"future_observation", func(f *fixture) { f.s.observation.ObservedAt++; f.s.observation.ExpiresAt++ }, "lease_clock"},
		{"lease_too_long", func(f *fixture) { f.s.observation.ExpiresAt++ }, "lease_clock"},
		{"negative_time", func(f *fixture) { f.s.observation.ObservedAt = -1 }, "lease_clock"},
		{"clock_unknown", func(f *fixture) { f.c.err = errors.New("unknown clock") }, "clock"},
		{"lookup_budget_exhausted", func(f *fixture) {
			f.s.change = func(_ context.Context, _ Query, _ *Observation) { f.c.advance(30 * time.Second) }
		}, "authority_budget"},
		{"clock_restart", func(f *fixture) {
			f.s.change = func(_ context.Context, _ Query, _ *Observation) { f.c.r.Epoch += "-restarted" }
		}, "clock"},
		{"clock_backward", func(f *fixture) {
			f.s.change = func(_ context.Context, _ Query, _ *Observation) { f.c.r.Wall = f.c.r.Wall.Add(-time.Second) }
		}, "clock"},
		{"monotonic_backward", func(f *fixture) {
			f.s.change = func(_ context.Context, _ Query, _ *Observation) { f.c.r.Monotonic -= time.Nanosecond }
		}, "clock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFixture(t)
			tt.mutate(f)
			assertRefusal(t, f, ErrUnavailable, tt.predicate)
		})
	}
}

// Claim: Lease endpoints, fractional time, epoch changes and monotonic expiry cannot extend qualification.
func TestLeaseMonotonicCapAndBoundaries(t *testing.T) {
	t.Run("exact_300_second_lease", func(t *testing.T) {
		f := validFixture(t)
		q := qualifyFixture(t, f)
		f.c.advance(299 * time.Second)
		if err := q.CheckFreshness(); err != nil {
			t.Fatal(err)
		}
		f.c.advance(time.Second)
		if !errors.Is(q.CheckFreshness(), ErrUnavailable) {
			t.Fatal("expired lease accepted")
		}
	})
	t.Run("backward_wall_cannot_extend", func(t *testing.T) {
		f := validFixture(t)
		q := qualifyFixture(t, f)
		f.c.r.Monotonic += 300 * time.Second
		if !errors.Is(q.CheckFreshness(), ErrUnavailable) {
			t.Fatal("monotonic expiry bypassed")
		}
	})
	t.Run("clock_epoch_invalidates", func(t *testing.T) {
		f := validFixture(t)
		q := qualifyFixture(t, f)
		f.c.r.Epoch += "-restart"
		if !errors.Is(q.CheckFreshness(), ErrUnavailable) {
			t.Fatal("restarted lease accepted")
		}
	})
	t.Run("expires_while_verifying", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.ExpiresAt = f.s.observation.ObservedAt + 1
		f.c.onRead = func(c *fixtureClock) {
			if c.reads == 3 {
				c.r.Wall = c.r.Wall.Add(time.Second)
				c.r.Monotonic += time.Second
			}
		}
		assertRefusal(t, f, ErrUnavailable, "lease_clock")
	})
	t.Run("fractional_clock_does_not_round_lease_up", func(t *testing.T) {
		f := validFixture(t)
		f.c.r.Wall = f.c.r.Wall.Add(900 * time.Millisecond)
		f.s.observation.ExpiresAt = f.s.observation.ObservedAt + 1
		q := qualifyFixture(t, f)
		f.c.r.Monotonic += 100 * time.Millisecond
		if !errors.Is(q.CheckFreshness(), ErrUnavailable) {
			t.Fatal("fractional lease extended")
		}
	})
}

// Claim: Presign refresh refuses withdrawn review, failed checks, revocation or unavailable evidence after build success.
func TestFreshPresignReadCannotReuseBuildSuccess(t *testing.T) {
	for _, changed := range []string{"review_withdrawn", "check_failure", "policy_revoked", "unavailable"} {
		t.Run(changed, func(t *testing.T) {
			f := validFixture(t)
			a := f.authority(t)
			if _, err := a.BeforeBuild(context.Background(), f.r); err != nil {
				t.Fatal(err)
			}
			switch changed {
			case "review_withdrawn":
				f.s.observation.Reviews.Records[0].State = "dismissed"
			case "check_failure":
				f.s.observation.Checks.Records[0].Result = "failure"
			case "policy_revoked":
				f.s.observation.PolicyState = Revoked
			case "unavailable":
				f.s.err = errors.New("offline")
			}
			r := f.r
			r.Nonce = strings.Repeat("e", 64)
			q, err := a.BeforeSign(context.Background(), r)
			if q != nil || err == nil || len(f.s.queries) != 2 || f.s.queries[1].Phase != Presign {
				t.Fatal("build qualification bypassed current presign read")
			}
		})
	}
}

// Claim: Policy and summary copies resist mutation while zero qualifications and absent configuration refuse.
func TestConfiguredCopiesAndAbsentValues(t *testing.T) {
	f := validFixture(t)
	a := f.authority(t)
	f.p.OwnerKeys[0].PublicKey[0] ^= 1
	f.p.Scopes[0] = "!caller:elsewhere"
	f.p.ReviewerSenders[0] = "@producer:fixture.invalid"
	q, err := a.BeforeBuild(context.Background(), f.r)
	if err != nil {
		t.Fatal("mutable input policy changed authority:", err)
	}
	before, _ := q.Summary()
	f.s.observation.Commit[0] ^= 1
	f.s.observation.Lookup.Scopes[0].Events[0].Body = "mutated"
	after, _ := q.Summary()
	if before != after {
		t.Fatal("mutable source changed qualification")
	}
	var absent Qualification
	if _, ok := absent.Summary(); ok {
		t.Fatal("zero qualification present")
	}
	if !errors.Is(absent.CheckFreshness(), ErrUnavailable) {
		t.Fatal("zero qualification fresh")
	}
	if _, err := New(Policy{}, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing configuration accepted")
	}
}

// Claim: Source reads receive an absolute deadline, canceled reads do not run and provider diagnostics stay sanitized.
func TestAuthorityBudgetAndSanitizedErrors(t *testing.T) {
	f := validFixture(t)
	f.s.change = func(ctx context.Context, _ Query, _ *Observation) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > AuthorityBudget {
			t.Fatal("missing absolute authority budget")
		}
	}
	qualifyFixture(t, f)
	f.s.err = errors.New("secret provider payload /private/path")
	_, err := f.authority(t).BeforeSign(context.Background(), f.r)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/private") {
		t.Fatal("unsanitized provider error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(f.s.queries)
	_, err = f.authority(t).BeforeBuild(ctx, f.r)
	if !errors.Is(err, ErrUnavailable) || len(f.s.queries) != before {
		t.Fatal("cancelled phase called source")
	}
}
