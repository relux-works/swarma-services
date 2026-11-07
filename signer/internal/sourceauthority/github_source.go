package sourceauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// These source-owned component seams deliberately do not implement the pending
// policy loader, Git object acquisition or effective check-visibility work.
// Implementations must authenticate current state, bound work BEFORE returning,
// honor ctx, and transfer owned bytes. They are protected installation, not
// request callbacks. No exported constructor accepts caller evidence.
type githubPolicySnapshot struct {
	Digest, Generation string
	State              PolicyState
	// Admission of the exact account/member relation must be acquired with
	// current policy, not inferred from a historical constructor argument.
	Members GitHubPRMembership
}
type githubPolicyReader interface {
	readCurrent(context.Context) (githubPolicySnapshot, error)
}
type githubGitSnapshot struct {
	Repository  RepositoryRecord
	Commit      []byte
	LandingPath [][]byte
}
type githubGitReader interface {
	readGit(context.Context, Query) (githubGitSnapshot, error)
}
type githubCheckSnapshot struct {
	Policy    CheckPolicy
	Inventory CheckInventory
}
type githubCheckReader interface {
	readChecks(context.Context, Query) (githubCheckSnapshot, error)
}
type githubVerdictSelection struct {
	ReviewID string
	Verdicts GitHubVerdictInventory
}
type githubPRSource struct {
	policy    Policy
	members   GitHubPRMembership
	number    uint64
	transport *sourceAcquisition
	clock     Clock
	policies  githubPolicyReader
	git       githubGitReader
	checks    githubCheckReader
	graphql   githubGraphQLReader
	busy      atomic.Bool
	graphBusy atomic.Bool
}

type githubPRInstallation struct {
	policy   Policy
	members  GitHubPRMembership
	number   uint64
	clock    Clock
	policies githubPolicyReader
	git      githubGitReader
	checks   githubCheckReader
	graphql  githubGraphQLReader
}

// Production endpoints are fixed to the canonical public GitHub API. The only
// alternate origin/roots are unexported test assembly of the existing transport.
// This constructor does not install anything or assert policy admission.
// The GraphQL seam is mandatory. REST never asserts edit/withdrawal integrity.
func newGitHubPRSource(c githubPRInstallation) (*githubPRSource, error) {
	if ValidateGitHubPolicy(c.policy) != nil || c.number == 0 || c.number > 9223372036854775807 || c.clock == nil || c.policies == nil || c.git == nil || c.checks == nil || c.graphql == nil || !validGitHubMembers(c.members) {
		return nil, unavailable("github_configuration")
	}
	root := "/repos/" + c.policy.RepositoryName + "/pulls/" + strconv.FormatUint(c.number, 10)
	a, err := newSourceAcquisition(acquisitionInstallation{provider: "github-anonymous-pr", origin: "https://api.github.com", limits: acquisitionLimits{header: acquisitionHeaderMax, metadata: acquisitionBodyMax, commit: acquisitionCommitMax, aggregate: acquisitionAggregateMax, responses: acquisitionResponsesMax}, endpoints: map[string]acquisitionEndpoint{"pr": {path: root, kind: metadataResponse}, "reviews": {path: root + "/reviews", kind: metadataResponse}}})
	if err != nil {
		return nil, err
	}
	m := c.members
	m.Reviewers = append([]GitHubMember(nil), m.Reviewers...)
	return &githubPRSource{policy: copyPolicy(c.policy), members: m, number: c.number, transport: a, clock: c.clock, policies: c.policies, git: c.git, checks: c.checks, graphql: c.graphql}, nil
}

func githubRepoName(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._", c)) {
				return false
			}
		}
	}
	return true
}

type nativeGitHubUser struct {
	ID    uint64 `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}
type nativeGitHubPR struct {
	Number uint64           `json:"number"`
	State  string           `json:"state"`
	Draft  *bool            `json:"draft"`
	Merged *bool            `json:"merged"`
	User   nativeGitHubUser `json:"user"`
	Head   struct {
		SHA  string `json:"sha"`
		Repo struct {
			FullName string `json:"full_name"`
			HTMLURL  string `json:"html_url"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo struct {
			FullName string `json:"full_name"`
			HTMLURL  string `json:"html_url"`
			Private  *bool  `json:"private"`
		} `json:"repo"`
	} `json:"base"`
}
type nativeGitHubReview struct {
	ID        uint64           `json:"id"`
	NodeID    string           `json:"node_id"`
	Commit    string           `json:"commit_id"`
	State     string           `json:"state"`
	Body      string           `json:"body"`
	Submitted time.Time        `json:"submitted_at"`
	User      nativeGitHubUser `json:"user"`
}

// readNative does not follow pagination or invent completeness. The GitHub
// endpoint's default page size is 30: a full page (even exactly 30 total) refuses.
// This conservative subset awaits transport pagination composition. The entire
// current inventory is re-read byte-for-byte before any successful transfer.
func (s *githubPRSource) readNative(p *acquisitionPhase) (PullRequest, GitHubMember, []PlatformReview, []byte, []byte, error) {
	var pr PullRequest
	var producer GitHubMember
	a, err := p.acquire("pr", acquisitionBodyMax, acquisitionHeaderMax)
	if err != nil {
		return pr, producer, nil, nil, nil, err
	}
	b, err := p.acquire("reviews", acquisitionBodyMax, acquisitionHeaderMax)
	if err != nil {
		return pr, producer, nil, nil, nil, err
	}
	var n nativeGitHubPR
	if err := strictGitHubJSON(a.body, &n); err != nil {
		return pr, producer, nil, nil, nil, err
	}
	if n.Number != s.number || n.State != "closed" || n.Draft == nil || *n.Draft || n.Merged == nil || !*n.Merged || !lowerHex(n.Head.SHA, 40) || !lowerHex(n.Base.SHA, 40) || n.Base.Ref != s.policy.DefaultBranch || n.Base.Repo.FullName != s.policy.RepositoryName || n.Base.Repo.HTMLURL != s.policy.CanonicalRepository || n.Base.Repo.Private == nil || *n.Base.Repo.Private || !githubRepoName(n.Head.Repo.FullName) || n.Head.Repo.HTMLURL != "https://github.com/"+n.Head.Repo.FullName {
		return pr, producer, nil, nil, nil, rejected("github_pull_request")
	}
	producer = s.members.Producer
	if n.User.ID != producer.ID || n.User.Login != producer.Login || n.User.Type != "User" && n.User.Type != "Bot" {
		return pr, producer, nil, nil, nil, rejected("github_producer")
	}
	pr = PullRequest{Repository: s.policy.CanonicalRepository, Head: n.Head.SHA, Base: n.Base.SHA, Number: n.Number, State: "merged", BaseBranch: n.Base.Ref, HeadRepository: n.Head.Repo.HTMLURL}
	var native []nativeGitHubReview
	if err := strictGitHubJSON(b.body, &native); err != nil {
		return pr, producer, nil, nil, nil, err
	}
	if bytes.Equal(bytes.TrimSpace(b.body), []byte("null")) || len(native) >= 30 || len(native) > s.policy.Profile.PlatformReviews {
		return pr, producer, nil, nil, nil, unavailable("github_review_coverage")
	}
	records := make([]PlatformReview, 0, len(native))
	seen := map[uint64]bool{}
	bodyBytes := 0
	for _, r := range native {
		if r.ID == 0 || r.ID > 9223372036854775807 || seen[r.ID] || !lowerHex(r.Commit, 40) || r.Submitted.IsZero() || r.User.ID == 0 || !ascii(r.User.Login, 39) || r.User.Type != "User" && r.User.Type != "Bot" || len(r.Body) > MaxBodyBytes-bodyBytes {
			return pr, producer, nil, nil, nil, unavailable("github_review_inventory")
		}
		seen[r.ID] = true
		bodyBytes += len(r.Body)
		kind, state := "", "active"
		switch r.State {
		case "COMMENTED":
			kind = "COMMENT"
		case "CHANGES_REQUESTED":
			kind = "CHANGES_REQUESTED"
		case "APPROVED":
			kind = "APPROVED"
		case "DISMISSED":
			kind = "COMMENT"
			state = "dismissed"
		default:
			return pr, producer, nil, nil, nil, unavailable("github_review_state")
		}
		// Base is correlated here only. platformDigest and the ORIGINAL stored
		// verdict independently bind the historical base before core acceptance.
		records = append(records, PlatformReview{Repository: pr.Repository, ID: strconv.FormatUint(r.ID, 10), Head: r.Commit, Base: pr.Base, PR: pr.Number, Kind: kind, State: state, Body: r.Body, SubmittedAt: r.Submitted.Unix(), AccountID: r.User.ID, AccountLogin: r.User.Login, NodeID: r.NodeID})
	}
	return pr, producer, records, a.body, b.body, nil
}

func (s *githubPRSource) Read(ctx context.Context, q Query) (out Observation, err error) {
	if s == nil || ctx == nil || !validRequest(q.Request, s.policy) || q.Phase != Prebuild && q.Phase != Presign {
		return out, rejected("request_binding")
	}
	if !s.busy.CompareAndSwap(false, true) {
		return out, unavailable("github_busy")
	}
	defer s.busy.Store(false)
	// An Authority supplies this absolute deadline. Direct calls cannot start an
	// unbounded acquisition or reset the enclosing phase's budget.
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > AuthorityBudget {
		return out, unavailable("authority_budget")
	}
	start, err := s.clock.Read()
	if err != nil || !validReading(start) {
		return out, unavailable("clock")
	}
	policy, err := s.policies.readCurrent(ctx)
	if err != nil || policy.Digest != s.policy.SHA256 || policy.State != Current || !text(policy.Generation, 256) || !reflect.DeepEqual(policy.Members, s.members) {
		return out, unavailable("github_policy")
	}
	policy.Members.Reviewers = append([]GitHubMember(nil), policy.Members.Reviewers...)
	phase, err := s.transport.begin(ctx, acquisitionAggregateMax, acquisitionResponsesMax)
	if err != nil {
		return out, err
	}
	defer phase.close()
	pr, producer, reviews, prBytes, reviewBytes, err := s.readNative(phase)
	if err != nil {
		return out, err
	}
	if pr.Head != q.Commit {
		return out, rejected("github_changed_head")
	}
	git, err := s.git.readGit(ctx, q)
	if err != nil {
		return out, unavailable("github_git")
	}
	if err := bounded(Observation{Commit: git.Commit, LandingPath: git.LandingPath}, s.policy.Profile); err != nil {
		return out, err
	}
	git = ownGitHubGit(git)
	checks, err := s.checks.readChecks(ctx, q)
	if err != nil {
		return out, unavailable("github_checks")
	}
	if len(checks.Policy.Required) > s.policy.Profile.CheckRecords || len(checks.Inventory.Records) > s.policy.Profile.CheckRecords {
		return out, unavailable("profile_capacity")
	}
	checks.Policy.Required = append([]CheckIdentity(nil), checks.Policy.Required...)
	checks.Inventory.Records = append([]CheckRecord(nil), checks.Inventory.Records...)
	inv := ReviewInventory{Coverage: Complete, Records: reviews}
	binding := GitHubReviewBinding{Repository: pr.Repository, BaseBranch: pr.BaseBranch, Head: pr.Head, Base: pr.Base, PR: pr.Number}
	selected, _, err := BindGitHubReviewInventory(s.policy, binding, inv)
	if err != nil {
		return out, err
	}
	selection := githubVerdictSelection{ReviewID: selected.ID}
	var reviewer GitHubMember
	for _, m := range s.members.Reviewers {
		if m.ID == selected.AccountID && m.Login == selected.AccountLogin {
			reviewer = m
		}
	}
	if reviewer.ID == 0 {
		return out, rejected("github_reviewer_account")
	}
	id, _ := strconv.ParseUint(selected.ID, 10, 63)
	binding.ReviewID = id
	proof := githubReviewProof{binding: binding, account: reviewer, body: selected.Body, nodeID: selected.NodeID}
	if err := s.readOriginal(ctx, proof); err != nil {
		return out, err
	}
	o := Observation{Binding: q, ObservedAt: start.Wall.Unix(), ExpiresAt: start.Wall.Unix() + 300, PolicySHA256: policy.Digest, PolicyState: policy.State, Repository: git.Repository, Commit: git.Commit, LandingPath: git.LandingPath, PR: pr, GitHub: &GitHubHandoff{Repository: pr.Repository, Head: pr.Head, Base: pr.Base, Number: pr.Number, Producer: producer, Reviewer: reviewer, Verdicts: selection.Verdicts}, Reviews: ReviewInventory{Coverage: Complete, SelectedID: selection.ReviewID, Records: reviews}, CheckPolicy: checks.Policy, Checks: checks.Inventory}
	if err := bounded(o, s.policy.Profile); err != nil {
		return out, err
	}
	if err := verifyGitHubHandoff(o, s.policy, s.members); err != nil {
		return out, err
	}
	if _, _, err := bindSourceGitHubReview(o, s.policy, s.members); err != nil {
		return out, err
	}
	if _, err := verifyChecks(o, s.policy); err != nil {
		return out, err
	}
	// Current metadata, reviews, default head, rules/attempts and installed policy
	// are acquired AGAIN, not assumed stable from an earlier successful phase.
	_, _, _, prEnd, reviewEnd, err := s.readNative(phase)
	if err != nil {
		return out, err
	}
	gitEnd, err := s.git.readGit(ctx, q)
	if err != nil || !reflect.DeepEqual(git, gitEnd) {
		return out, unavailable("github_git_changed")
	}
	checkEnd, err := s.checks.readChecks(ctx, q)
	if err != nil || !reflect.DeepEqual(checks, checkEnd) {
		return out, unavailable("github_checks_changed")
	}
	policyEnd, err := s.policies.readCurrent(ctx)
	if err != nil || !reflect.DeepEqual(policyEnd, policy) {
		return out, unavailable("github_policy_changed")
	}
	final, err := s.clock.Read()
	if err != nil || !validReading(final) || final.Epoch != start.Epoch || final.Monotonic < start.end() || final.Wall.Before(start.Wall) || final.end()-start.Monotonic >= AuthorityBudget || final.wallEnd().Unix() >= o.ExpiresAt || ctx.Err() != nil {
		return out, unavailable("authority_budget")
	}
	if !bytes.Equal(prBytes, prEnd) || !bytes.Equal(reviewBytes, reviewEnd) {
		return out, rejected("github_snapshot_changed")
	}
	o.githubProof = &proof
	return o, nil
}

// All JSON is bounded by the transport before parsing. Check encoding, decoded
// duplicate names and depth before typed decoding; never accept replacement
// decoding or a second JSON value. Native extension fields remain supported.
func strictGitHubJSON(raw []byte, out any) error {
	if !validGitHubJSONStrings(raw) {
		return unavailable("github_json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	rootLimit := MaxEvents
	if _, ok := out.(*[]nativeGitHubReview); ok {
		rootLimit = 29
	}
	if err := walkGitHubJSON(d, 0, rootLimit); err != nil {
		return err
	}
	if _, err := d.Token(); err == nil {
		return unavailable("github_json")
	} else if err != io.EOF {
		return unavailable("github_json")
	}
	if json.Unmarshal(raw, out) != nil {
		return unavailable("github_json")
	}
	return nil
}
func walkGitHubJSON(d *json.Decoder, depth, rootLimit int) error {
	return walkProviderJSON(d, depth, rootLimit, false)
}
func walkProviderJSON(d *json.Decoder, depth, rootLimit int, graphql bool) error {
	if depth > 64 {
		return unavailable("github_json_depth")
	}
	t, err := d.Token()
	if err != nil {
		return unavailable("github_json")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			if len(seen) >= MaxEvents {
				return unavailable("github_json_capacity")
			}
			k, err := d.Token()
			if err != nil {
				return unavailable("github_json")
			}
			key, ok := k.(string)
			if !ok || seen[key] || !graphql && strings.ToLower(key) != key || graphql && !graphQLField(key) {
				return unavailable("github_json_duplicate")
			}
			seen[key] = true
			if err := walkProviderJSON(d, depth+1, rootLimit, graphql); err != nil {
				return err
			}
		}
		t, err = d.Token()
		if err != nil || t != json.Delim('}') {
			return unavailable("github_json")
		}
	case '[':
		count, limit := 0, MaxEvents
		if depth == 0 {
			limit = rootLimit
		}
		for d.More() {
			if count >= limit {
				return unavailable("github_json_capacity")
			}
			count++
			if err := walkProviderJSON(d, depth+1, rootLimit, graphql); err != nil {
				return err
			}
		}
		t, err = d.Token()
		if err != nil || t != json.Delim(']') {
			return unavailable("github_json")
		}
	default:
		return unavailable("github_json")
	}
	return nil
}

func ownGitHubGit(g githubGitSnapshot) githubGitSnapshot {
	g.Commit = bytes.Clone(g.Commit)
	g.LandingPath = append([][]byte(nil), g.LandingPath...)
	for i := range g.LandingPath {
		g.LandingPath[i] = bytes.Clone(g.LandingPath[i])
	}
	return g
}
