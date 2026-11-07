package sourceauthority

import (
	"strings"
	"unicode/utf8"
)

// GitHubMember is protected installation data, never request evidence. ID is the
// immutable numeric provider account ID. Member is an EXISTING configured member;
// a login, display name or commit author never admits membership.
type GitHubMember struct {
	ID            uint64
	Login, Member string
}
type GitHubPRMembership struct {
	Producer  GitHubMember
	Reviewers []GitHubMember
}

// GitHubHandoff is distinct from ProducerHandoff: no Matrix origin/event is
// synthesized. Source binds these fields to the current native PR and to its
// separately authenticated stored verdict. These are private adapter data, not
// an envelope or a new wire record.
type GitHubHandoff struct {
	Repository, Head, Base string
	Number                 uint64
	Producer               GitHubMember
	Reviewer               GitHubMember
	Verdicts               GitHubVerdictInventory
}

type GitHubVerdictInventory struct {
	Coverage Coverage
	Records  []GitHubStoredVerdict
}

// GitHubStoredVerdict retains the existing stored-verdict grammar and exact body
// hash. A production store/provenance mapping is a required, unresolved source
// dependency. A COMMENT header alone cannot produce this record.
type GitHubStoredVerdict struct {
	Reference, Body, State string
	Reviewer               GitHubMember
	StoredAt               int64
}

func validGitHubMember(m GitHubMember) bool {
	if m.ID == 0 || m.ID > 9223372036854775807 || !text(m.Member, 255) || len(m.Login) == 0 || len(m.Login) > 39 {
		return false
	}
	for i, c := range m.Login {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' && i > 0 && i < len(m.Login)-1) {
			return false
		}
	}
	return true
}
func validGitHubMembership(p Policy, m GitHubPRMembership) bool {
	if !validGitHubMember(m.Producer) || m.Producer.Member != p.ProducerSender || len(m.Reviewers) == 0 || len(m.Reviewers) > MaxEvents {
		return false
	}
	seenID := map[uint64]bool{m.Producer.ID: true}
	seenLogin := map[string]bool{strings.ToLower(m.Producer.Login): true}
	seenMember := map[string]bool{m.Producer.Member: true}
	for _, r := range m.Reviewers {
		if !validGitHubMember(r) || !contains(p.ReviewerSenders, r.Member) || seenID[r.ID] || seenLogin[strings.ToLower(r.Login)] || seenMember[r.Member] {
			return false
		}
		seenID[r.ID] = true
		seenLogin[strings.ToLower(r.Login)] = true
		seenMember[r.Member] = true
	}
	return true
}

// NewGitHubPR constructs the explicit PR route using protected installation
// membership. It does not install policy or qualify a provider implementation.
// Legacy New retains its original Matrix requirements. Neither route can be
// selected or downgraded by a Request or by returned evidence.
func NewGitHubPR(policy Policy, membership GitHubPRMembership, source Source, clock Clock) (*Authority, error) {
	if source == nil || clock == nil || !validPRPolicy(policy) || !validGitHubMembership(policy, membership) {
		return nil, unavailable("configuration")
	}
	p := copyPolicy(policy)
	m := membership
	m.Reviewers = append([]GitHubMember(nil), membership.Reviewers...)
	return &Authority{policy: p, source: source, clock: clock, github: &m}, nil
}

func verifyGitHubHandoff(o Observation, p Policy, m GitHubPRMembership) error {
	h := o.GitHub
	if h == nil || o.Producer != (ProducerHandoff{}) || len(o.Lookup.Scopes) != 0 || o.Lookup.WindowStart != 0 || o.Lookup.WindowEnd != 0 || o.Lookup.ObservedAt != 0 {
		return rejected("github_handoff")
	}
	if h.Repository != p.CanonicalRepository || h.Head != o.PR.Head || h.Base != o.PR.Base || h.Number != o.PR.Number || h.Producer != m.Producer {
		return rejected("github_handoff")
	}
	return nil
}

func verifyGitHubReview(o Observation, p Policy, m GitHubPRMembership) (PlatformReview, string, error) {
	r, err := selectedPlatformReview(o, p)
	if err != nil {
		return r, "", err
	}
	digest, err := platformDigest(r, o.PR.Head, o.PR.Base)
	if err != nil {
		return r, "", err
	}
	h := o.GitHub
	admitted := false
	for _, member := range m.Reviewers {
		if h.Reviewer == member {
			admitted = true
		}
	}
	if !admitted || h.Reviewer.ID == h.Producer.ID || strings.EqualFold(h.Reviewer.Login, h.Producer.Login) || h.Reviewer.Member == h.Producer.Member || r.AccountID != h.Reviewer.ID || r.AccountLogin != h.Reviewer.Login {
		return r, "", rejected("reviewer_identity_or_integrity")
	}
	if h.Verdicts.Coverage != Complete {
		return r, "", unavailable("github_verdict_coverage")
	}
	var v GitHubStoredVerdict
	matches := 0
	seen := map[string]GitHubStoredVerdict{}
	for _, record := range h.Verdicts.Records {
		if !text(record.Reference, 512) || !validGitHubMember(record.Reviewer) || !utf8.ValidString(record.Body) || record.StoredAt < r.SubmittedAt-86400 || record.StoredAt > r.SubmittedAt+300 || record.StoredAt > o.ObservedAt {
			return r, "", unavailable("github_verdict_inventory")
		}
		if previous, exists := seen[record.Reference]; exists {
			if previous != record {
				return r, "", unavailable("github_verdict_integrity")
			}
			continue
		}
		seen[record.Reference] = record
		// Count every digest match BEFORE sender filtering, as on the legacy
		// route. An unallowed sender cannot hide an ambiguous matching body.
		if bodyHash(record.Body) == digest {
			matches++
			v = record
		}
	}
	if matches != 1 {
		return r, "", rejected("github_verdict_uniqueness")
	}
	if v.State != "intact" || v.Reviewer != h.Reviewer {
		return r, "", rejected("github_stored_verdict")
	}
	if err := verdictBody(v.Body, p, o.PR); err != nil {
		return r, "", err
	}
	return r, digest, nil
}

// Compile-time assertion for the concrete acquisition/normalization adapter.
var _ Source = (*githubPRSource)(nil)
