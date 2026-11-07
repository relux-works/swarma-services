package sourceauthority

import "reflect"

// Historical adapter membership metadata is not reviewer authority. GitHub
// logins, account IDs and publishing permissions cannot replace ReviewerKeys.
type GitHubMember struct {
	ID            uint64
	Login, Member string
}
type GitHubPRMembership struct {
	Producer  GitHubMember
	Reviewers []GitHubMember
}
type GitHubHandoff struct {
	Repository, Head, Base string
	Number                 uint64
	Producer, Reviewer     GitHubMember
	Verdicts               GitHubVerdictInventory
}
type GitHubVerdictInventory struct {
	Coverage Coverage
	Records  []GitHubStoredVerdict
}
type GitHubStoredVerdict struct {
	Reference, Body, State string
	Reviewer               GitHubMember
	StoredAt               int64
}

// NewGitHubPR binds the explicit native route to the protected GraphQL source.
// A generic caller-supplied Source cannot assert original-review integrity.
func NewGitHubPR(policy Policy, source Source, clock Clock) (*Authority, error) {
	if source == nil || clock == nil || ValidateGitHubPolicy(policy) != nil {
		return nil, unavailable("configuration")
	}
	s, ok := source.(*githubPRSource)
	if !ok || s == nil || s.graphql == nil || !reflect.DeepEqual(copyPolicy(s.policy), copyPolicy(policy)) {
		return nil, unavailable("github_provider_configuration")
	}
	return &Authority{policy: copyPolicy(policy), source: s, clock: clock, github: s}, nil
}

func verifyGitHubHandoff(o Observation, p Policy, _ GitHubPRMembership) error {
	h := o.GitHub
	if h == nil || o.Producer != (ProducerHandoff{}) || len(o.Lookup.Scopes) != 0 || o.Lookup.WindowStart != 0 || o.Lookup.WindowEnd != 0 || o.Lookup.ObservedAt != 0 {
		return rejected("github_handoff")
	}
	if ValidateGitHubPolicy(p) != nil || h.Repository != p.CanonicalRepository || o.PR.Repository != h.Repository || h.Head != o.PR.Head || h.Base != o.PR.Base || !lowerHex(h.Head, 40) || !lowerHex(h.Base, 40) || h.Number == 0 || h.Number > 9223372036854775807 || h.Number != o.PR.Number || o.PR.BaseBranch != p.DefaultBranch || !githubCanonicalRepository(o.PR.HeadRepository) || o.PR.State != "merged" {
		return rejected("github_provenance")
	}
	return nil
}
func githubCanonicalRepository(s string) bool {
	const prefix = "https://github.com/"
	return len(s) > len(prefix) && s[:len(prefix)] == prefix && githubRepoName(s[len(prefix):])
}

// NewForRoute fixes route at construction; neither policy bytes nor request
// evidence can select it. Unknown routes refuse and Matrix remains the default
// only for the existing New constructor.
func NewForRoute(p Policy, route PolicyRoute, source Source, clock Clock) (*Authority, error) {
	switch route {
	case MatrixPolicyRoute:
		return New(p, source, clock)
	case GitHubPRPolicyRoute:
		return NewGitHubPR(p, source, clock)
	default:
		return nil, unavailable("policy_route")
	}
}
