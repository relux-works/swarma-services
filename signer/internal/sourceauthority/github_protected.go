package sourceauthority

import (
	"context"
	"encoding/json"
	"reflect"
)

// GitHubInstallationAuth is an opaque service-owned capability. There is no
// credential discovery or public minting API. Its issuer/visibility attestation
// is a custodian qualification gap; an empty capability always refuses.
type GitHubInstallationAuth struct {
	repository string
	header     string
	qualified  bool
}

func (GitHubInstallationAuth) String() string { return "GitHub installation authentication (opaque)" }
func (GitHubInstallationAuth) GoString() string {
	return "GitHub installation authentication (opaque)"
}

// QualifiedGitHubConnector can only be issued by reviewed installation code.
// Its implementation must join all work before returning, including failures.
// No issuer is shipped yet: numeric destination provenance and currentness
// must be qualified independently. Request clients cannot mint this capability.
type QualifiedGitHubConnector struct {
	owned     acquisitionConnector
	qualified bool
}

// CurrentGitHubMembership is a trusted currentness port, not request evidence.
// Implementations must bound collections BEFORE returning, obey the original
// context, and authenticate generation, revocation and exact member relations.
// A concrete custodian-backed implementation is not shipped in this unit.
type CurrentGitHubMembership interface {
	CurrentGitHubMembers(context.Context) (GitHubCurrentMembers, error)
}
type GitHubCurrentMembers struct {
	Generation string
	State      PolicyState
	Members    GitHubPRMembership
}

// OriginalGitHubObjects must acquire exact raw signed Git objects and real
// bounded parent ancestry, default-head state and repository identity. Metadata
// synthesis is not an implementation. All bytes must be bounded before return.
type OriginalGitHubObjects interface {
	ReadOriginalGitHubObjects(context.Context, Query) (GitHubOriginalObjects, error)
}
type GitHubOriginalObjects struct {
	Repository  RepositoryRecord
	Commit      []byte
	LandingPath [][]byte
}

// EffectiveGitHubChecks must authenticate the complete effective rule/app and
// latest-attempt inventory. Hidden/unknown/partial visibility must return error,
// never Complete or no_required. Custodian composition remains unimplemented.
type EffectiveGitHubChecks interface {
	ReadEffectiveGitHubChecks(context.Context, Query) (GitHubEffectiveChecks, error)
}
type GitHubEffectiveChecks struct {
	Policy    CheckPolicy
	Inventory CheckInventory
}

// ProtectedGitHubPRInstallation is bound once by the service composition root.
// It accepts no request-selected URL, client, query, header, roots or auth bytes.
// Public construction refuses absent qualified auth/connector/currentness ports.
type ProtectedGitHubPRInstallation struct {
	Installed      PolicySource
	AcceptedSHA256 string
	Number         uint64
	Clock          Clock
	Membership     CurrentGitHubMembership
	Objects        OriginalGitHubObjects
	Checks         EffectiveGitHubChecks
	Authentication *GitHubInstallationAuth
	Connector      *QualifiedGitHubConnector
}

type protectedGitHubPolicy struct {
	installed PolicySource
	digest    string
	members   CurrentGitHubMembership
}

func (r protectedGitHubPolicy) readCurrent(ctx context.Context) (githubPolicySnapshot, error) {
	s, err := r.installed.Snapshot(ctx)
	if err != nil || s == nil || s.route != GitHubPRPolicyRoute || s.SHA256() != r.digest || ctx.Err() != nil {
		return githubPolicySnapshot{}, unavailable("github_policy")
	}
	m, err := r.members.CurrentGitHubMembers(acquisitionContext{ctx})
	if err != nil || ctx.Err() != nil || !text(m.Generation, 256) || m.State != Current || !validGitHubMembers(m.Members) {
		return githubPolicySnapshot{}, unavailable("github_membership")
	}
	m.Members.Reviewers = append([]GitHubMember(nil), m.Members.Reviewers...)
	return githubPolicySnapshot{Digest: s.SHA256(), Generation: m.Generation, State: m.State, Members: m.Members}, nil
}

type protectedGitHubObjects struct{ reader OriginalGitHubObjects }

func (r protectedGitHubObjects) readGit(ctx context.Context, q Query) (githubGitSnapshot, error) {
	v, e := r.reader.ReadOriginalGitHubObjects(acquisitionContext{ctx}, q)
	return githubGitSnapshot{Repository: v.Repository, Commit: v.Commit, LandingPath: v.LandingPath}, e
}

type protectedGitHubChecks struct{ reader EffectiveGitHubChecks }

func (r protectedGitHubChecks) readChecks(ctx context.Context, q Query) (githubCheckSnapshot, error) {
	v, e := r.reader.ReadEffectiveGitHubChecks(acquisitionContext{ctx}, q)
	return githubCheckSnapshot{Policy: v.Policy, Inventory: v.Inventory}, e
}

func OpenProtectedGitHubPRSource(ctx context.Context, c ProtectedGitHubPRInstallation) (Source, error) {
	if ctx == nil || c.Installed == nil || !lowerHex(c.AcceptedSHA256, 64) || c.Clock == nil || c.Membership == nil || c.Objects == nil || c.Checks == nil || c.Authentication == nil || !c.Authentication.qualified || c.Connector == nil || !c.Connector.qualified || c.Connector.owned == nil {
		return nil, unavailable("github_installation_unqualified")
	}
	ctx, cancel := context.WithTimeout(acquisitionContext{ctx}, AuthorityBudget)
	defer cancel()
	snap, err := c.Installed.Snapshot(ctx)
	if err != nil || snap == nil || snap.route != GitHubPRPolicyRoute || snap.SHA256() != c.AcceptedSHA256 {
		return nil, unavailable("github_policy")
	}
	p := snap.PolicyCopy()
	if c.Authentication.repository != p.CanonicalRepository || !validGitHubAuthorization(c.Authentication.header) {
		return nil, unavailable("github_auth_qualification")
	}
	policies := protectedGitHubPolicy{c.Installed, c.AcceptedSHA256, c.Membership}
	current, err := policies.readCurrent(ctx)
	if err != nil {
		return nil, err
	}
	s, err := newGitHubPRSource(githubPRInstallation{policy: p, members: current.Members, number: c.Number, clock: c.Clock, policies: policies, git: protectedGitHubObjects{c.Objects}, checks: protectedGitHubChecks{c.Checks}, graphql: &githubGraphQLTransport{}})
	if err != nil {
		return nil, err
	}
	s.transport.connector = c.Connector.owned
	auth := *c.Authentication
	s.transport.auth = &auth
	s.transport.endpoints["graphql"] = installedEndpoint{"https://api.github.com/graphql", metadataResponse}
	s.graphql = &githubGraphQLTransport{source: s.transport}
	end, err := policies.readCurrent(ctx)
	if err != nil || !reflect.DeepEqual(current, end) || acquisitionExpired(ctx) {
		return nil, unavailable("github_installation_changed")
	}
	return s, nil
}

func validGitHubAuthorization(s string) bool {
	if len(s) < 8 || len(s) > 4096 || s[:7] != "Bearer " {
		return false
	}
	for _, b := range s[7:] {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

type githubGraphQLTransport struct{ source *sourceAcquisition }

func (g *githubGraphQLTransport) readReview(ctx context.Context, r githubGraphQLRequest) ([]byte, error) {
	if g == nil || g.source == nil {
		return nil, unavailable("github_graphql_configuration")
	}
	p, err := g.source.begin(ctx, acquisitionAggregateMax, acquisitionResponsesMax)
	if err != nil {
		return nil, err
	}
	defer p.close()
	return g.readPhase(p, r)
}
func (g *githubGraphQLTransport) readPhase(p *acquisitionPhase, r githubGraphQLRequest) ([]byte, error) {
	if r.Query != githubOriginalReviewQuery || !ascii(r.NodeID, 256) || r.Responses != 1 || r.BodyLimit <= 0 || r.BodyLimit > MaxReviewCommentBytes+16384 || r.HeaderLimit <= acquisitionParserFixed || r.HeaderLimit > acquisitionHeaderMax {
		return nil, unavailable("github_graphql_configuration")
	}
	// Before encoding reserve the exact JSON string expansion for the node and
	// a conservative bound for the fixed query and object punctuation.
	encodedNode := 0
	for _, b := range r.NodeID {
		switch b {
		case '<', '>', '&':
			encodedNode += 6
		case '\\', '"':
			encodedNode += 2
		default:
			encodedNode++
		}
	}
	if encodedNode+2*len(githubOriginalReviewQuery)+64 > 2048 {
		return nil, unavailable("github_graphql_configuration")
	}
	// Fixed-shape encoding only; the original discovered node is the sole variable.
	body, err := json.Marshal(struct {
		Query     string `json:"query"`
		Variables struct {
			ID string `json:"id"`
		} `json:"variables"`
	}{githubOriginalReviewQuery, struct {
		ID string `json:"id"`
	}{r.NodeID}})
	if err != nil || len(body) > 2048 {
		return nil, unavailable("github_graphql_configuration")
	}
	out, err := p.acquireRequest("graphql", int64(r.BodyLimit), int64(r.HeaderLimit), body)
	return out.body, err
}
