package sourceauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
type githubVerdictReader interface {
	// Must establish UNIQUE original verdict provenance/integrity and selection
	// for the exact PR and current complete native review inventory. Its production
	// store and account/member admission are unresolved, never fixture defaults.
	readVerdict(context.Context, Query, PullRequest, []PlatformReview) (githubVerdictSelection, error)
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
	verdicts  githubVerdictReader
	busy      atomic.Bool
}

type githubPRInstallation struct {
	policy   Policy
	members  GitHubPRMembership
	number   uint64
	clock    Clock
	policies githubPolicyReader
	git      githubGitReader
	checks   githubCheckReader
	verdicts githubVerdictReader
}

// Production endpoints are fixed to the canonical public GitHub API. The only
// alternate origin/roots are unexported test assembly of the existing transport.
// This constructor does not install anything or assert policy admission.
// newGitHubPRSource cannot admit the sealed REST-only adapter. No history
// capability is asserted by configured callbacks or repeated current snapshots.
func newGitHubPRSource(c githubPRInstallation) (*githubPRSource, error) {
	if ValidateGitHubPolicy(c.policy) != nil || c.number == 0 || c.number > 9223372036854775807 || c.clock == nil || c.policies == nil || c.git == nil || c.checks == nil || c.verdicts == nil {
		return nil, unavailable("github_configuration")
	}
	return nil, unavailable("github_original_history_unqualified")
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
		records = append(records, PlatformReview{Repository: pr.Repository, ID: strconv.FormatUint(r.ID, 10), Head: r.Commit, Base: pr.Base, PR: pr.Number, Kind: kind, State: state, Body: r.Body, SubmittedAt: r.Submitted.Unix(), AccountID: r.User.ID, AccountLogin: r.User.Login})
	}
	return pr, producer, records, a.body, b.body, nil
}

func (s *githubPRSource) Read(ctx context.Context, q Query) (Observation, error) {
	// Even a same-package manually assembled source cannot turn current REST
	// bodies or synthetic verdict flags into proof of complete original history.
	return Observation{}, unavailable("github_original_history_unqualified")
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
			if !ok || seen[key] || strings.ToLower(key) != key {
				return unavailable("github_json_duplicate")
			}
			seen[key] = true
			if err := walkGitHubJSON(d, depth+1, rootLimit); err != nil {
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
			if err := walkGitHubJSON(d, depth+1, rootLimit); err != nil {
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
