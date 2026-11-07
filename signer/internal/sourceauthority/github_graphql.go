package sourceauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Protected installation seam. An implementation must acquire the exact query
// from api.github.com/graphql, authenticate its response, enforce these byte,
// header and single-response bounds BEFORE returning, and obey the original
// context/deadline. No live provider or credential is installed by this package.
// Returning raw GraphQL bytes preserves missing/null/false distinctions.
type githubGraphQLReader interface {
	readReview(context.Context, githubGraphQLRequest) ([]byte, error)
}
type githubGraphQLRequest struct {
	Query, NodeID          string
	BodyLimit, HeaderLimit int
	Responses              int
}

const githubOriginalReviewQuery = `query OriginalReview($id: ID!) {
 node(id: $id) { __typename ... on PullRequestReview {
 id fullDatabaseId state body lastEditedAt includesCreatedEdit isMinimized submittedAt
 commit { oid } author { login ... on User { databaseId } ... on Bot { databaseId } }
 pullRequest { number headRefOid baseRefOid baseRefName repository { nameWithOwner url } }
 userContentEdits(first: 1) { totalCount nodes { editedAt deletedAt } pageInfo { hasNextPage hasPreviousPage startCursor endCursor } }
 } }
}`

type githubReviewProof struct {
	binding      GitHubReviewBinding
	account      GitHubMember
	body, nodeID string
}

// encoding/json matches struct fields without case sensitivity. Only exact
// schema spellings enter that decoder, so aliases cannot overwrite true fields.
func graphQLField(k string) bool {
	switch k {
	case "data", "node", "__typename", "id", "fullDatabaseId", "state", "body", "lastEditedAt", "includesCreatedEdit", "isMinimized", "submittedAt", "commit", "oid", "author", "login", "databaseId", "pullRequest", "number", "headRefOid", "baseRefOid", "baseRefName", "repository", "nameWithOwner", "url", "userContentEdits", "totalCount", "nodes", "editedAt", "deletedAt", "pageInfo", "hasNextPage", "hasPreviousPage", "startCursor", "endCursor", "errors", "message", "locations", "path", "extensions":
		return true
	}
	return false
}

func validGitHubMembers(m GitHubPRMembership) bool {
	if m.Producer.ID == 0 || !ascii(m.Producer.Login, 39) || len(m.Reviewers) == 0 || len(m.Reviewers) > 4 {
		return false
	}
	ids := map[uint64]bool{m.Producer.ID: true}
	logins := map[string]bool{strings.ToLower(m.Producer.Login): true}
	for _, r := range m.Reviewers {
		if r.ID == 0 || !ascii(r.Login, 39) || ids[r.ID] || logins[strings.ToLower(r.Login)] {
			return false
		}
		ids[r.ID] = true
		logins[strings.ToLower(r.Login)] = true
	}
	return true
}
func bindSourceGitHubReview(o Observation, p Policy, m GitHubPRMembership) (PlatformReview, string, error) {
	b := GitHubReviewBinding{Repository: o.PR.Repository, BaseBranch: o.PR.BaseBranch, Head: o.PR.Head, Base: o.PR.Base, PR: o.PR.Number}
	r, v, err := BindGitHubReviewInventory(p, b, o.Reviews)
	if err != nil {
		return r, "", err
	}
	for _, a := range m.Reviewers {
		if r.AccountID == a.ID && r.AccountLogin == a.Login {
			return r, v.BodySHA256, nil
		}
	}
	return PlatformReview{}, "", rejected("github_reviewer_account")
}
func (s *githubPRSource) readOriginal(ctx context.Context, p githubReviewProof) error {
	if s == nil || s.graphql == nil || ctx == nil || acquisitionExpired(ctx) || ValidateGitHubReviewBinding(s.policy, p.binding) != nil || !ascii(p.nodeID, 256) {
		return unavailable("github_graphql_configuration")
	}
	if !s.graphBusy.CompareAndSwap(false, true) {
		return unavailable("github_graphql_busy")
	}
	defer s.graphBusy.Store(false)
	raw, err := s.graphql.readReview(acquisitionContext{ctx}, githubGraphQLRequest{githubOriginalReviewQuery, p.nodeID, MaxReviewCommentBytes + 16384, acquisitionHeaderMax, 1})
	if err != nil || acquisitionExpired(ctx) || len(raw) == 0 || len(raw) > MaxReviewCommentBytes+16384 {
		return unavailable("github_graphql_read")
	}
	if err := verifyGraphQLOriginal(raw, s.policy, p); err != nil {
		return err
	}
	if acquisitionExpired(ctx) {
		return unavailable("github_graphql_read")
	}
	return nil
}
func verifyGraphQLOriginal(raw []byte, p Policy, expected githubReviewProof) error {
	if len(raw) == 0 || len(raw) > MaxReviewCommentBytes+16384 || !validGitHubJSONStrings(raw) {
		return unavailable("github_graphql_json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walkProviderJSON(d, 0, MaxEvents, true); err != nil {
		return err
	}
	if _, err := d.Token(); err == nil {
		return unavailable("github_graphql_json")
	} // typed decoder below rejects trailing data too
	var envelope struct {
		Data *struct {
			Node *struct {
				Type       *string         `json:"__typename"`
				ID         *string         `json:"id"`
				DatabaseID json.RawMessage `json:"fullDatabaseId"`
				State      *string         `json:"state"`
				Body       *string         `json:"body"`
				LastEdited json.RawMessage `json:"lastEditedAt"`
				Includes   *bool           `json:"includesCreatedEdit"`
				Minimized  *bool           `json:"isMinimized"`
				Submitted  *time.Time      `json:"submittedAt"`
				Commit     *struct {
					OID *string `json:"oid"`
				} `json:"commit"`
				Author *struct {
					Login *string `json:"login"`
					ID    *uint64 `json:"databaseId"`
				} `json:"author"`
				PR *struct {
					Number *uint64 `json:"number"`
					Head   *string `json:"headRefOid"`
					Base   *string `json:"baseRefOid"`
					Branch *string `json:"baseRefName"`
					Repo   *struct {
						Name *string `json:"nameWithOwner"`
						URL  *string `json:"url"`
					} `json:"repository"`
				} `json:"pullRequest"`
				Edits *struct {
					Count *int            `json:"totalCount"`
					Nodes json.RawMessage `json:"nodes"`
					Page  *struct {
						Next     *bool           `json:"hasNextPage"`
						Previous *bool           `json:"hasPreviousPage"`
						Start    json.RawMessage `json:"startCursor"`
						End      json.RawMessage `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"userContentEdits"`
			} `json:"node"`
		} `json:"data"`
		Errors json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Data == nil || envelope.Data.Node == nil || len(envelope.Errors) != 0 {
		return unavailable("github_graphql_partial")
	}
	n := envelope.Data.Node
	b := expected.binding
	eq := func(v *string, s string) bool { return v != nil && *v == s }
	id := strconv.FormatUint(b.ReviewID, 10)
	var databaseID string
	if json.Unmarshal(n.DatabaseID, &databaseID) != nil {
		databaseID = string(n.DatabaseID)
	}
	if !eq(n.Type, "PullRequestReview") || !eq(n.ID, expected.nodeID) || databaseID != id || !eq(n.State, "COMMENTED") || !eq(n.Body, expected.body) || n.Commit == nil || !eq(n.Commit.OID, b.Head) || n.Author == nil || !eq(n.Author.Login, expected.account.Login) || n.Author.ID == nil || *n.Author.ID != expected.account.ID || n.Submitted == nil || n.Submitted.IsZero() {
		return rejected("github_graphql_identity_or_state")
	}
	if !bytes.Equal(n.LastEdited, []byte("null")) || n.Includes == nil || *n.Includes || n.Minimized == nil || *n.Minimized || n.Edits == nil || n.Edits.Count == nil || *n.Edits.Count != 0 || !bytes.Equal(n.Edits.Nodes, []byte("[]")) || n.Edits.Page == nil || n.Edits.Page.Next == nil || *n.Edits.Page.Next || n.Edits.Page.Previous == nil || *n.Edits.Page.Previous || !bytes.Equal(n.Edits.Page.Start, []byte("null")) || !bytes.Equal(n.Edits.Page.End, []byte("null")) {
		return rejected("github_graphql_edited_or_incomplete")
	}
	r := n.PR
	if r == nil || r.Number == nil || *r.Number != b.PR || !eq(r.Head, b.Head) || !eq(r.Base, b.Base) || !eq(r.Branch, b.BaseBranch) || r.Repo == nil || !eq(r.Repo.Name, p.RepositoryName) || !eq(r.Repo.URL, b.Repository) {
		return rejected("github_graphql_pr_binding")
	}
	_, err := VerifyGitHubReview(p, b, []byte(*n.Body))
	return err
}
