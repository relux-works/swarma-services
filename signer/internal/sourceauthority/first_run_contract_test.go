package sourceauthority

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// This is a contract compatibility probe, not a production provider decoder.
// The HTTP documents use the relevant native PR/review field shapes. The raw
// object endpoint is a synthetic oracle serving ORIGINAL signed Git bytes; it
// does not claim GitHub offers that endpoint or qualify a Git pack reader.
type firstRunPRFixture struct {
	Number uint64 `json:"number"`
	State  string `json:"state"`
	Draft  bool   `json:"draft"`
	Merged bool   `json:"merged"`
	Head   struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		SHA string `json:"sha"`
	} `json:"base"`
}

type firstRunReviewFixture struct {
	ID        uint64    `json:"id"`
	Commit    string    `json:"commit_id"`
	State     string    `json:"state"`
	Body      string    `json:"body"`
	Submitted time.Time `json:"submitted_at"`
	User      struct {
		ID    uint64 `json:"id"`
		Login string `json:"login"`
	} `json:"user"`
}

// Neither document asserts full review/rule visibility or Matrix identity.
// Fixture JSON is bounded before decoding by the existing transport candidate.
func firstRunAcquireFixture(t *testing.T, f *fixture) (PullRequest, firstRunReviewFixture, []byte) {
	t.Helper()
	prBytes, err := json.Marshal(map[string]any{
		"id": 1700, "number": f.s.observation.PR.Number,
		"state": "closed", "draft": false, "merged": true,
		"head": map[string]any{"sha": f.r.Commit},
		"base": map[string]any{"sha": f.s.observation.PR.Base},
	})
	if err != nil {
		t.Fatal(err)
	}
	reviewBytes, err := json.Marshal([]map[string]any{{
		"id": 1701, "commit_id": f.r.Commit, "state": "APPROVED",
		"body":         "Reviewed the source.",
		"submitted_at": time.Unix(f.s.observation.Reviews.Records[0].SubmittedAt, 0).UTC(),
		"user":         map[string]any{"id": 1702, "login": "fixture-reviewer"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const prPath = "/repos/fixture-owner/fixture-source/pulls/17"
	const reviewsPath = prPath + "/reviews"
	const objectPath = "/synthetic-original-commit"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("fixture reader acquired authority beyond anonymous GET")
		}
		var body []byte
		switch r.URL.Path {
		case prPath:
			body = prBytes
		case reviewsPath:
			body = reviewBytes
		case objectPath:
			body = f.s.observation.Commit
		default:
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	a, err := newSourceAcquisition(acquisitionInstallation{
		provider: "synthetic-anonymous-pr", origin: s.URL, roots: roots,
		limits: acquisitionLimits{header: 4096, metadata: 16 << 10, commit: 1 << 20, aggregate: 2 << 20, responses: 3},
		endpoints: map[string]acquisitionEndpoint{
			"pr":       {path: prPath, kind: metadataResponse},
			"reviews":  {path: reviewsPath, kind: metadataResponse},
			"original": {path: objectPath, kind: rawCommitResponse},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := a.begin(ctx, 2<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	prResponse, err := p.acquire("pr", 16<<10, 4096)
	if err != nil {
		t.Fatal(err)
	}
	reviewResponse, err := p.acquire("reviews", 16<<10, 4096)
	if err != nil {
		t.Fatal(err)
	}
	objectResponse, err := p.acquire("original", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}
	var pr firstRunPRFixture
	var reviews []firstRunReviewFixture
	if json.Unmarshal(prResponse.body, &pr) != nil || json.Unmarshal(reviewResponse.body, &reviews) != nil || len(reviews) != 1 {
		t.Fatal("invalid controlled fixture")
	}
	if pr.Number != 17 || pr.State != "closed" || !pr.Merged || pr.Draft || pr.Head.SHA != f.r.Commit || pr.Base.SHA != f.s.observation.PR.Base {
		t.Fatal("fixture PR binding")
	}
	if !bytes.Equal(objectResponse.body, f.s.observation.Commit) || fixtureOID(objectResponse.body) != pr.Head.SHA {
		t.Fatal("original signed Git bytes lost")
	}
	c, err := parseCommit(objectResponse.body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOwner(c, f.p); err != nil {
		t.Fatal(err)
	}
	if p.responsesLeft != 0 {
		t.Fatal("fixture transfer count")
	}
	return PullRequest{Repository: f.p.CanonicalRepository, Number: pr.Number, Head: pr.Head.SHA, Base: pr.Base.SHA, State: "merged"}, reviews[0], objectResponse.body
}

// Real transport success and real SSHSIG verification in a synthetic namespace
// do not supply the missing delivery identity. Both phases reject the PR-only
// tuple even with every unrelated legacy observation held at its positive value.
func TestAnonymousPRFirstRunHandoffContractGap(t *testing.T) {
	t.Run("legacy_positive_control", func(t *testing.T) {
		f := validFixture(t)
		qualifyFixture(t, f)
		if _, err := f.authority(t).BeforeSign(context.Background(), f.r); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("acquired_pr_tuple_has_no_authenticated_delivery", func(t *testing.T) {
		f := validFixture(t)
		pr, _, original := firstRunAcquireFixture(t, f)
		f.s.observation.PR, f.s.observation.Commit = pr, original
		f.s.observation.Producer = ProducerHandoff{Repository: pr.Repository, Head: pr.Head, PR: pr.Number}
		assertRefusal(t, f, ErrRejected, "producer_handoff")
	})
	t.Run("no_matrix_policy_is_unrepresentable", func(t *testing.T) {
		f := validFixture(t)
		f.p.MatrixOrigin, f.p.ProducerSender = "", ""
		f.p.Scopes, f.p.ReviewerSenders = nil, nil
		if _, err := New(f.p, f.s, f.c); err == nil {
			t.Fatal("anonymous configuration fabricated Matrix installation")
		}
	})
}

// Counterfactual legacy delivery is retained ONLY to isolate the next gate.
// No observation here is admitted installation or claimed provider coverage.
func TestAnonymousPRFirstRunReviewContractGap(t *testing.T) {
	t.Run("native_approval_is_not_core_comment", func(t *testing.T) {
		f := validFixture(t)
		pr, native, _ := firstRunAcquireFixture(t, f)
		f.s.observation.PR = pr
		r := &f.s.observation.Reviews.Records[0]
		r.Kind, r.Body = native.State, native.Body
		assertRefusal(t, f, ErrRejected, "review_withdrawal_or_binding")
	})
	t.Run("comment_body_cannot_be_rewritten_to_accept", func(t *testing.T) {
		f := validFixture(t)
		_, native, _ := firstRunAcquireFixture(t, f)
		f.s.observation.Reviews.Records[0].Body = native.Body
		assertRefusal(t, f, ErrRejected, "platform_format")
	})
	t.Run("exact_comment_still_requires_stored_verdict_coverage", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.Lookup.Scopes = nil
		assertRefusal(t, f, ErrUnavailable, "lookup_scope_coverage")
	})
	t.Run("empty_complete_frontier_does_not_create_verdict", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.Lookup.Scopes[0].Events = nil
		assertRefusal(t, f, ErrRejected, "lookup_uniqueness")
	})
	t.Run("platform_comment_is_not_stored_verdict_body", func(t *testing.T) {
		f := validFixture(t)
		if err := verdictBody(f.s.observation.Reviews.Records[0].Body, f.p, f.s.observation.PR); err == nil {
			t.Fatal("two distinct exact body grammars collapsed")
		}
	})
}
