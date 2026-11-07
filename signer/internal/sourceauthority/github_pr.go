package sourceauthority

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

// NewGitHubPR validates the complete native configuration and refuses the
// missing source-owned history capability. There is deliberately no caller flag,
// journal or invented history-provider interface that can enable this route.
func NewGitHubPR(policy Policy, source Source, clock Clock) (*Authority, error) {
	if source == nil || clock == nil || ValidateGitHubPolicy(policy) != nil {
		return nil, unavailable("configuration")
	}
	return nil, unavailable("github_original_history_unqualified")
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
