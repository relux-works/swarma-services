package sourceauthority

import (
	"strings"
	"testing"
	"time"
)

// Claim: Unbound, withdrawn, contradictory or nonindependent review evidence refuses at both boundaries.
func TestReviewRefusals(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*fixture)
		predicate string
	}{
		{"comment_alone", func(f *fixture) {
			f.s.observation.Reviews.Records[0].Body = strings.Split(f.s.observation.Reviews.Records[0].Body, "\n")[0]
		}, "platform_digest"},
		{"historical_no_digest", func(f *fixture) {
			f.s.observation.Reviews.Records[0].Body = strings.Split(f.s.observation.Reviews.Records[0].Body, "\n")[0] + "\nHistorical ACCEPT without forward digest."
		}, "platform_digest"},
		{"wrong_platform_head", func(f *fixture) { f.s.observation.Reviews.Records[0].Head = strings.Repeat("f", 40) }, "review_withdrawal_or_binding"},
		{"wrong_platform_base", func(f *fixture) { f.s.observation.Reviews.Records[0].Base = strings.Repeat("f", 40) }, "review_withdrawal_or_binding"},
		{"wrong_platform_pr", func(f *fixture) { f.s.observation.Reviews.Records[0].PR++ }, "review_inventory"},
		{"review_withdrawn", func(f *fixture) { f.s.observation.Reviews.Records[0].State = "dismissed" }, "review_withdrawal_or_binding"},
		{"approval_without_configured_comment_evidence", func(f *fixture) { f.s.observation.Reviews.Records[0].Kind = "APPROVED" }, "review_withdrawal_or_binding"},
		{"review_missing", func(f *fixture) { f.s.observation.Reviews.Records = nil }, "review_missing"},
		{"review_blocked_now", func(f *fixture) {
			r := f.s.observation.Reviews.Records[0]
			r.ID = "blocking-current-review"
			r.Kind = "CHANGES_REQUESTED"
			f.s.observation.Reviews.Records = append(f.s.observation.Reviews.Records, r)
		}, "review_withdrawal_or_blocking"},
		{"digest_twice", func(f *fixture) {
			b := f.s.observation.Reviews.Records[0].Body
			f.s.observation.Reviews.Records[0].Body = b + strings.Split(b, "\n")[2] + "\n"
		}, "platform_digest"},
		{"digest_uppercase", func(f *fixture) {
			b := f.s.observation.Reviews.Records[0].Body
			at := strings.Index(b, "sha256:")
			f.s.observation.Reviews.Records[0].Body = b[:at+7] + strings.ToUpper(b[at+7:])
		}, "platform_digest"},
		{"platform_quoted", func(f *fixture) {
			f.s.observation.Reviews.Records[0].Body = "> " + f.s.observation.Reviews.Records[0].Body
		}, "platform_format"},
		{"platform_fenced", func(f *fixture) {
			f.s.observation.Reviews.Records[0].Body = "```\n" + f.s.observation.Reviews.Records[0].Body + "```\n"
		}, "platform_format"},
		{"platform_unrelated_accept", func(f *fixture) {
			f.s.observation.Reviews.Records[0].Body = "An unrelated sentence: ACCEPT\n" + f.s.observation.Reviews.Records[0].Body
		}, "platform_format"},
		{"platform_wrong_text_head", func(f *fixture) {
			f.s.observation.Reviews.Records[0].Body = strings.Replace(f.s.observation.Reviews.Records[0].Body, f.r.Commit, strings.Repeat("f", 40), 1)
		}, "platform_format"},
		{"body_changed_without_rebinding", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Events[0].Body += "\n" }, "lookup_uniqueness"},
		{"zero_match", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Events = nil }, "lookup_uniqueness"},
		{"multiple_matches", func(f *fixture) {
			e := f.s.observation.Lookup.Scopes[0].Events[0]
			e.ID = "$another-verdict"
			f.s.observation.Lookup.Scopes[0].Events = append(f.s.observation.Lookup.Scopes[0].Events, e)
		}, "lookup_uniqueness"},
		{"producer_is_reviewer", func(f *fixture) {
			f.p.ReviewerSenders = append(f.p.ReviewerSenders, f.p.ProducerSender)
			f.s.observation.Lookup.Scopes[0].Events[0].Sender = f.p.ProducerSender
		}, "reviewer_identity_or_integrity"},
		{"wrong_authenticated_reviewer", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Events[0].Sender = "@unadmitted:fixture.invalid" }, "reviewer_identity_or_integrity"},
		{"display_name_is_not_sender", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Events[0].Sender = "reviewer" }, "reviewer_identity_or_integrity"},
		{"redacted_event", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Events[0].State = "redacted" }, "reviewer_identity_or_integrity"},
		{"stored_accept_quoted", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body = "> " + f.s.observation.Lookup.Scopes[0].Events[0].Body
			f.rebindDigest()
		}, "verdict_format"},
		{"stored_accept_fenced", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body = "```\n" + f.s.observation.Lookup.Scopes[0].Events[0].Body + "```\n"
			f.rebindDigest()
		}, "verdict_format"},
		{"stored_wrong_pr", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body = strings.Replace(f.s.observation.Lookup.Scopes[0].Events[0].Body, "/pull/17", "/pull/18", 1)
			f.rebindDigest()
		}, "verdict_binding"},
		{"stored_wrong_head", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body = strings.Replace(f.s.observation.Lookup.Scopes[0].Events[0].Body, f.r.Commit, strings.Repeat("f", 40), 1)
			f.rebindDigest()
		}, "verdict_binding"},
		{"stored_wrong_base", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body = strings.Replace(f.s.observation.Lookup.Scopes[0].Events[0].Body, f.s.observation.PR.Base, strings.Repeat("f", 40), 1)
			f.rebindDigest()
		}, "verdict_binding"},
		{"stored_duplicate_pr", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body += "PR " + f.p.CanonicalRepository + "/pull/17\n"
			f.rebindDigest()
		}, "verdict_format"},
		{"stored_reject", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body += "REJECT: current candidate\n"
			f.rebindDigest()
		}, "review_blocking"},
		{"stored_changes_requested", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body += "CHANGES_REQUESTED: fix the source\n"
			f.rebindDigest()
		}, "review_blocking"},
		{"stored_blocking", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].Body += "Blocking: unresolved finding\n"
			f.rebindDigest()
		}, "review_blocking"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFixture(t)
			tt.mutate(f)
			code := ErrRejected
			if tt.predicate == "review_inventory" {
				code = ErrUnavailable
			}
			assertRefusal(t, f, code, tt.predicate)
		})
	}
}

// Claim: Incomplete, misbound, ambiguous or over-budget verdict lookup refuses at both boundaries.
func TestLookupRefusals(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*fixture)
		code      error
		predicate string
	}{
		{"partial_scope", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Coverage = Partial }, ErrUnavailable, "lookup_frontier_coverage"},
		{"unknown_scope_frontier", func(f *fixture) { f.s.observation.Lookup.Scopes[0].FrontierSHA256 = "" }, ErrUnavailable, "lookup_frontier_coverage"},
		{"zero_pages_unknown_read", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Pages = 0 }, ErrUnavailable, "lookup_frontier_coverage"},
		{"missing_scope", func(f *fixture) { f.p.Scopes = append(f.p.Scopes, "!second:fixture.invalid") }, ErrUnavailable, "lookup_scope_coverage"},
		{"unconfigured_scope", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Scope = "!unknown:fixture.invalid" }, ErrRejected, "lookup_scope_binding"},
		{"wrong_origin", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Origin = "forged.invalid" }, ErrRejected, "lookup_scope_binding"},
		{"page_budget", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Pages = MaxPages + 1 }, ErrUnavailable, "lookup_capacity"},
		{"event_budget", func(f *fixture) {
			e := f.s.observation.Lookup.Scopes[0].Events[0]
			events := make([]Event, MaxEvents+1)
			for i := range events {
				events[i] = e
			}
			f.s.observation.Lookup.Scopes[0].Events = events
		}, ErrUnavailable, "lookup_capacity"},
		{"decoded_body_budget", func(f *fixture) {
			e := f.s.observation.Lookup.Scopes[0].Events[0]
			e.ID = "$large-unmatched"
			e.Body = strings.Repeat("x", MaxBodyBytes)
			f.s.observation.Lookup.Scopes[0].Events = append(f.s.observation.Lookup.Scopes[0].Events, e)
		}, ErrUnavailable, "lookup_capacity"},
		{"conflicting_event_replay", func(f *fixture) {
			e := f.s.observation.Lookup.Scopes[0].Events[0]
			e.Body += "changed"
			f.s.observation.Lookup.Scopes[0].Events = append(f.s.observation.Lookup.Scopes[0].Events, e)
		}, ErrUnavailable, "lookup_event_integrity"},
		{"before_24h_window", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].ServerAt = f.s.observation.Lookup.WindowStart - 1
		}, ErrUnavailable, "lookup_event"},
		{"after_300s_window", func(f *fixture) {
			f.s.observation.Lookup.Scopes[0].Events[0].ServerAt = f.s.observation.Lookup.WindowEnd + 1
		}, ErrUnavailable, "lookup_event"},
		{"future_event_not_at_frontier", func(f *fixture) { f.s.observation.Lookup.Scopes[0].Events[0].ServerAt = f.s.observation.ObservedAt + 1 }, ErrUnavailable, "lookup_event"},
		{"wrong_window_start", func(f *fixture) { f.s.observation.Lookup.WindowStart++ }, ErrRejected, "lookup_window"},
		{"wrong_window_end", func(f *fixture) { f.s.observation.Lookup.WindowEnd-- }, ErrRejected, "lookup_window"},
		{"stale_lookup_observation", func(f *fixture) { f.s.observation.Lookup.ObservedAt-- }, ErrRejected, "lookup_window"},
		{"partial_current_review_inventory", func(f *fixture) { f.s.observation.Reviews.Coverage = Partial }, ErrUnavailable, "review_coverage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { f := validFixture(t); tt.mutate(f); assertRefusal(t, f, tt.code, tt.predicate) })
	}
}

// Claim: Exact digest spellings, complete bounded frontiers and quoted history preserve valid build qualification.
func TestReviewAndLookupPositiveNeighbors(t *testing.T) {
	t.Run("backticked_neutral_digest", func(t *testing.T) {
		f := validFixture(t)
		b := f.s.observation.Reviews.Records[0].Body
		value := strings.Split(strings.Split(b, "sha256:")[1], "\n")[0]
		f.s.observation.Reviews.Records[0].Body = strings.Replace(b, "sha256:"+value, "`sha256:"+value+"`", 1)
		qualifyFixture(t, f)
	})
	t.Run("identical_pagination_replay_is_one_event", func(t *testing.T) {
		f := validFixture(t)
		e := f.s.observation.Lookup.Scopes[0].Events[0]
		f.s.observation.Lookup.Scopes[0].Events = append(f.s.observation.Lookup.Scopes[0].Events, e)
		qualifyFixture(t, f)
	})
	t.Run("complete_multiple_scopes", func(t *testing.T) {
		f := validFixture(t)
		f.p.Scopes = append(f.p.Scopes, "!second:fixture.invalid")
		scope := f.s.observation.Lookup.Scopes[0]
		scope.Scope = f.p.Scopes[1]
		scope.Events = nil
		f.s.observation.Lookup.Scopes = append(f.s.observation.Lookup.Scopes, scope)
		qualifyFixture(t, f)
	})
	t.Run("24h_inclusive_start", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.Lookup.Scopes[0].Events[0].ServerAt = f.s.observation.Lookup.WindowStart
		qualifyFixture(t, f)
	})
	t.Run("300s_inclusive_end_at_later_frontier", func(t *testing.T) {
		f := validFixture(t)
		o := &f.s.observation
		o.Lookup.Scopes[0].Events[0].ServerAt = o.Lookup.WindowEnd
		delta := o.Lookup.WindowEnd - o.ObservedAt
		f.c.advance(time.Duration(delta) * time.Second)
		o.ObservedAt += delta
		o.ExpiresAt += delta
		o.Lookup.ObservedAt = o.ObservedAt
		qualifyFixture(t, f)
	})
	t.Run("256_pages", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.Lookup.Scopes[0].Pages = MaxPages
		qualifyFixture(t, f)
	})
	t.Run("16384_read_events_with_replays", func(t *testing.T) {
		f := validFixture(t)
		e := f.s.observation.Lookup.Scopes[0].Events[0]
		events := make([]Event, MaxEvents)
		for i := range events {
			events[i] = e
		}
		f.s.observation.Lookup.Scopes[0].Events = events
		qualifyFixture(t, f)
	})
	t.Run("16MiB_decoded_body_total", func(t *testing.T) {
		f := validFixture(t)
		scope := &f.s.observation.Lookup.Scopes[0]
		e := scope.Events[0]
		e.ID = "$large-unmatched"
		e.Body = strings.Repeat("x", MaxBodyBytes-len(e.Body))
		scope.Events = append(scope.Events, e)
		qualifyFixture(t, f)
	})
	t.Run("raw_unicode_and_trailing_newline_hashed", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.Lookup.Scopes[0].Events[0].Body += "Non-blocking note: café e\u0301.\n"
		f.rebindDigest()
		qualifyFixture(t, f)
	})
	t.Run("quoted_historical_text_is_not_authoritative", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.Lookup.Scopes[0].Events[0].Body += "> PR https://example.invalid/wrong\n> Exact head quoted.\n```\nREJECT: quoted source example\n```\n"
		f.rebindDigest()
		qualifyFixture(t, f)
	})
}
