package sourceauthority

import (
	"strings"
	"testing"
)

// Claim: Incomplete or inconsistent check evidence and unsuccessful required identities refuse at both boundaries.
func TestChecksRefusals(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*fixture)
		code      error
		predicate string
	}{
		{"unknown_empty_policy_not_no_required", func(f *fixture) {
			f.s.observation.CheckPolicy.State = "unknown"
			f.s.observation.CheckPolicy.Required = nil
			f.s.observation.Checks.Records = nil
		}, ErrUnavailable, "checks_coverage_or_policy"},
		{"403_inventory_is_unknown", func(f *fixture) {
			f.s.observation.CheckPolicy.State = "no_required"
			f.s.observation.CheckPolicy.Required = nil
			f.s.observation.Checks.Records = nil
			f.s.observation.Checks.Coverage = Unknown
		}, ErrUnavailable, "checks_coverage_or_policy"},
		{"partial_green_inventory", func(f *fixture) { f.s.observation.Checks.Coverage = Partial }, ErrUnavailable, "checks_coverage_or_policy"},
		{"green_inventory_unknown_rules", func(f *fixture) { f.s.observation.CheckPolicy.State = "unknown" }, ErrUnavailable, "checks_coverage_or_policy"},
		{"one_required_check_missing", func(f *fixture) { f.s.observation.Checks.Records = f.s.observation.Checks.Records[:1] }, ErrRejected, "required_check"},
		{"no_required_check_present", func(f *fixture) { f.s.observation.Checks.Records = nil }, ErrRejected, "required_check"},
		{"failure", func(f *fixture) { f.s.observation.Checks.Records[0].Result = "failure" }, ErrRejected, "required_check"},
		{"pending", func(f *fixture) { f.s.observation.Checks.Records[0].State = "in_progress" }, ErrRejected, "required_check"},
		{"neutral_not_success", func(f *fixture) { f.s.observation.Checks.Records[0].Result = "neutral" }, ErrRejected, "required_check"},
		{"skipped_not_success", func(f *fixture) { f.s.observation.Checks.Records[0].Result = "skipped" }, ErrRejected, "required_check"},
		{"wrong_application_cannot_spoof_context", func(f *fixture) { f.s.observation.Checks.Records[0].Identity.Application = "different-bot" }, ErrRejected, "required_check"},
		{"wrong_head", func(f *fixture) { f.s.observation.Checks.Records[0].Head = strings.Repeat("f", 40) }, ErrRejected, "check_record_binding"},
		{"wrong_inventory_head", func(f *fixture) { f.s.observation.Checks.Head = strings.Repeat("f", 40) }, ErrRejected, "checks_binding"},
		{"wrong_policy_repository", func(f *fixture) { f.s.observation.CheckPolicy.Repository += "-other" }, ErrRejected, "checks_binding"},
		{"wrong_record_repository", func(f *fixture) { f.s.observation.Checks.Records[0].Repository += "-other" }, ErrRejected, "check_record_binding"},
		{"ambiguous_same_context_application", func(f *fixture) {
			r := f.s.observation.Checks.Records[0]
			r.ID = "another-attempt"
			f.s.observation.Checks.Records = append(f.s.observation.Checks.Records, r)
		}, ErrUnavailable, "ambiguous_check_inventory"},
		{"duplicate_required_identity", func(f *fixture) {
			f.s.observation.CheckPolicy.Required = append(f.s.observation.CheckPolicy.Required, f.s.observation.CheckPolicy.Required[0])
		}, ErrUnavailable, "check_policy_inconsistent"},
		{"required_empty_not_no_required", func(f *fixture) { f.s.observation.CheckPolicy.Required = nil; f.s.observation.Checks.Records = nil }, ErrUnavailable, "check_policy_inconsistent"},
		{"no_required_but_required_list_present", func(f *fixture) {
			f.s.observation.CheckPolicy.State = "no_required"
			f.s.observation.Checks.Records = nil
		}, ErrUnavailable, "check_policy_inconsistent"},
		{"no_required_nonempty_has_no_projection_variant", func(f *fixture) {
			f.s.observation.CheckPolicy.State = "no_required"
			f.s.observation.CheckPolicy.Required = nil
		}, ErrUnavailable, "no_required_nonempty_inventory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { f := validFixture(t); tt.mutate(f); assertRefusal(t, f, tt.code, tt.predicate) })
	}
}

// Claim: Known no-required policy with complete empty inventory has its distinct successful summary.
func TestCompleteNoRequiredChecksPositiveControl(t *testing.T) {
	f := validFixture(t)
	f.s.observation.CheckPolicy.State = "no_required"
	f.s.observation.CheckPolicy.Required = nil
	f.s.observation.Checks.Records = nil
	q := qualifyFixture(t, f)
	s, ok := q.Summary()
	if !ok || s.CheckVerdict != "no_required_and_none_present" {
		t.Fatal("complete empty inventory not distinguished")
	}
}

// Claim: A failed optional check does not invalidate successful exact required checks.
func TestOnlyRequiredChecksMustSucceed(t *testing.T) {
	f := validFixture(t)
	r := f.s.observation.Checks.Records[0]
	r.ID = "optional"
	r.Identity = CheckIdentity{"optional", "other-app"}
	r.Result = "failure"
	f.s.observation.Checks.Records = append(f.s.observation.Checks.Records, r)
	qualifyFixture(t, f)
}
