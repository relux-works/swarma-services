package sourceauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func originalLabRecord(t *testing.T, l reviewLab) PlatformReview {
	return PlatformReview{Repository: l.b.Repository, ID: strconv.FormatUint(l.b.ReviewID, 10), Head: l.b.Head, Base: l.b.Base, PR: l.b.PR, Kind: "COMMENT", State: "active", Body: string(l.signed(t)), SubmittedAt: 100000}
}
func requireOriginal(t *testing.T, l reviewLab, r PlatformReview) {
	t.Helper()
	if _, err := VerifyGitHubReviewRecord(l.p, l.b, r); err != nil {
		t.Fatal(err)
	}
}
func TestOriginalDeliveryRecordPairedControls(t *testing.T) {
	for _, name := range []string{"copied_R2", "changed_signed_R", "noncanonical_R", "withdrawn", "missing", "other_repository", "other_PR", "other_head", "other_base", "pending", "edit", "old_tuple_only"} {
		t.Run(name, func(t *testing.T) {
			l := newReviewLab(t)
			r := originalLabRecord(t, l)
			requireOriginal(t, l, r)
			b := l.b
			switch name {
			case "copied_R2":
				r.ID = "1702"
			case "changed_signed_R":
				b.ReviewID++
				r.ID = "1702"
			case "noncanonical_R":
				r.ID = "01701"
			case "withdrawn":
				r.State = "dismissed"
			case "missing":
				r = PlatformReview{}
			case "other_repository":
				r.Repository = "https://github.com/other/repository"
			case "other_PR":
				r.PR++
			case "other_head":
				r.Head = strings.Repeat("3", 40)
			case "other_base":
				r.Base = strings.Repeat("3", 40)
			case "pending":
				r.State = "pending"
			case "edit":
				r.Body = strings.Replace(r.Body, "Original delivery", "Original Delivery", 1)
			case "old_tuple_only":
				v := l.verdict(l.b)
				v = v[:bytes.LastIndex(v[:len(v)-1], []byte("\n"))+1]
				r.Body = string(labComment(b, v, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512")))
			}
			if _, err := VerifyGitHubReviewRecord(l.p, b, r); err == nil {
				t.Fatal("invalid original accepted")
			}
			requireOriginal(t, l, originalLabRecord(t, l))
		})
	}
}
func TestCurrentInventoryCannotReinstateOrSelectCopies(t *testing.T) {
	for _, name := range []string{"dismissed", "repost", "dismiss_repost", "missing_original", "two_originals", "blocking", "conflicting_repeat", "partial", "capacity"} {
		t.Run(name, func(t *testing.T) {
			l := newReviewLab(t)
			r := originalLabRecord(t, l)
			inv := ReviewInventory{Coverage: Complete, SelectedID: "caller-selector-is-ignored", Records: []PlatformReview{r}}
			got, _, err := BindGitHubReviewInventory(l.p, l.b, inv)
			if err != nil || got.ID != r.ID {
				t.Fatal("binding control", err)
			}
			switch name {
			case "dismissed":
				inv.Records[0].State = "dismissed"
			case "repost", "dismiss_repost":
				r.ID = "1702"
				inv.Records = append(inv.Records, r)
				if name == "dismiss_repost" {
					inv.Records[0].State = "dismissed"
				}
			case "missing_original":
				r.ID = "1702"
				inv.Records = []PlatformReview{r}
			case "two_originals":
				l.b.ReviewID++
				r = originalLabRecord(t, l)
				inv.Records = append(inv.Records, r)
			case "blocking":
				r.ID = "1702"
				r.Kind = "CHANGES_REQUESTED"
				r.Body = "blocked"
				inv.Records = append(inv.Records, r)
			case "conflicting_repeat":
				r.Body = "changed"
				inv.Records = append(inv.Records, r)
			case "partial":
				inv.Coverage = Partial
			case "capacity":
				inv.Records = make([]PlatformReview, 257)
			}
			if _, _, err := BindGitHubReviewInventory(l.p, l.b, inv); err == nil {
				t.Fatal("ambiguous/withdrawn current record accepted")
			}
		})
	}
}
func TestGitHubHistoryGapCannotBeEnabledByCurrentRecord(t *testing.T) {
	l := newReviewLab(t)
	r := originalLabRecord(t, l)
	requireOriginal(t, l, r)
	f := validFixture(t)
	// Even an exact restored body has a valid signature. That does not prove no
	// edit-and-restore, deleted review, redaction or earlier withdrawal occurred.
	for _, phase := range []Phase{Prebuild, Presign} {
		_ = phase
		a, err := NewGitHubPR(l.p, f.s, f.c)
		var refusal *Refusal
		if a != nil || !errors.As(err, &refusal) || refusal.Predicate() != "github_original_history_unqualified" {
			t.Fatal("history gap hidden", err)
		}
	}
	if len(f.s.queries) != 0 {
		t.Fatal("unqualified constructor acquired source")
	}
	s := &githubPRSource{}
	if _, err := s.Read(context.Background(), Query{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("manual source bypass")
	}
	if _, err := NewForRoute(l.p, "", f.s, f.c); err == nil {
		t.Fatal("unknown route")
	}
	if _, err := New(l.p, f.s, f.c); err == nil {
		t.Fatal("empty Matrix route inferred GitHub")
	}
	qualifyFixture(t, f) // Independent legacy positive still succeeds.
}
func TestNativeGitHubCodecExactBytes(t *testing.T) {
	l := newReviewLab(t)
	raw, err := EncodePolicyForRoute(l.p, GitHubPRPolicyRoute)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePolicyForRoute(raw, GitHubPRPolicyRoute)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if p.SHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("digest")
	}
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	if len(fields) != 12 || fields["SHA256"] != nil || len(fields["ReviewerKeys"].([]any)) != 1 {
		t.Fatal("native shape")
	}
	p.SHA256 = "externally-derived-only"
	again, err := EncodePolicyForRoute(p, GitHubPRPolicyRoute)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("digest in payload")
	}
	p.ReviewerKeys[0].PublicKey[0] ^= 1
	decoded, err := DecodePolicyForRoute(raw, GitHubPRPolicyRoute)
	if err != nil || bytes.Equal(p.ReviewerKeys[0].PublicKey, decoded.ReviewerKeys[0].PublicKey) {
		t.Fatal("mutable key alias")
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte("\"Alias\""), []byte("\"alias\""), 1), bytes.Replace(raw, []byte("{\"Alias\""), []byte("{\"SHA256\":\"x\",\"Alias\""), 1)} {
		if _, err := DecodePolicyForRoute(bad, GitHubPRPolicyRoute); err == nil {
			t.Fatal("noncanonical/unknown payload accepted")
		}
	}
}
func TestGitHubProducerProvenancePairedControls(t *testing.T) {
	l := newReviewLab(t)
	base := Observation{PR: PullRequest{Repository: l.b.Repository, Head: l.b.Head, Base: l.b.Base, Number: l.b.PR, State: "merged", BaseBranch: "main", HeadRepository: "https://github.com/fork/source"}, GitHub: &GitHubHandoff{Repository: l.b.Repository, Head: l.b.Head, Base: l.b.Base, Number: l.b.PR}}
	for _, name := range []string{"base_ref", "missing_head_origin", "noncanonical_head_origin", "repository", "head", "base", "number", "open", "Matrix"} {
		t.Run(name, func(t *testing.T) {
			if err := verifyGitHubHandoff(base, l.p, GitHubPRMembership{}); err != nil {
				t.Fatal(err)
			}
			o := base
			h := *base.GitHub
			o.GitHub = &h
			switch name {
			case "base_ref":
				o.PR.BaseBranch = "other"
			case "missing_head_origin":
				o.PR.HeadRepository = ""
			case "noncanonical_head_origin":
				o.PR.HeadRepository = "https://evil.example/fork/source"
			case "repository":
				h.Repository = "https://github.com/other/repo"
			case "head":
				h.Head = "wrong"
			case "base":
				h.Base = "wrong"
			case "number":
				h.Number++
			case "open":
				o.PR.State = "open"
			case "Matrix":
				o.Producer.Origin = "invented"
			}
			if err := verifyGitHubHandoff(o, l.p, GitHubPRMembership{}); err == nil {
				t.Fatal("producer provenance accepted")
			}
		})
	}
}
