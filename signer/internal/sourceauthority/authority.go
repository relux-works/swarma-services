package sourceauthority

import (
	"bytes"
	"context"
	"strings"
	"time"
	"unicode/utf8"
)

// Authority binds trusted dependencies once, outside request handling. It stores
// no cross-phase successful observation. Source and Clock implementations must
// be concurrency safe if the eventual caller uses this component concurrently.
type Authority struct {
	policy          Policy
	source          Source
	clock           Clock
	installed       PolicySource
	installedDigest string
}

func New(policy Policy, source Source, clock Clock) (*Authority, error) {
	if source == nil || clock == nil || !validPolicy(policy) {
		return nil, unavailable("configuration")
	}
	p := policy
	p.Scopes = append([]string(nil), policy.Scopes...)
	p.ReviewerSenders = append([]string(nil), policy.ReviewerSenders...)
	p.OwnerKeys = append([]OwnerKey(nil), policy.OwnerKeys...)
	for i := range p.OwnerKeys {
		p.OwnerKeys[i].PublicKey = bytes.Clone(p.OwnerKeys[i].PublicKey)
	}
	return &Authority{policy: p, source: source, clock: clock}, nil
}

func text(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func ascii(s string, max int) bool {
	if !text(s, max) {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
func contains(values []string, value string) bool {
	for _, s := range values {
		if s == value {
			return true
		}
	}
	return false
}
func unique(values []string, maxBytes int) bool {
	seen := make(map[string]bool)
	for _, s := range values {
		if !text(s, maxBytes) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func validPolicy(p Policy) bool {
	if !ascii(p.Product, 128) || !ascii(p.Alias, 64) || !ascii(p.CanonicalRepository, 512) || !ascii(p.RepositoryName, 256) || !text(p.DefaultBranch, 255) || !lowerHex(p.SHA256, 64) || !ascii(p.MatrixOrigin, 255) || !text(p.ProducerSender, 255) {
		return false
	}
	if len(p.Scopes) < 1 || len(p.Scopes) > MaxScopes || !unique(p.Scopes, 512) || len(p.ReviewerSenders) == 0 || !unique(p.ReviewerSenders, 255) || len(p.OwnerKeys) == 0 {
		return false
	}
	for _, k := range p.OwnerKeys {
		if len(k.PublicKey) != 51 || !ascii(k.Repository, 512) || !ascii(k.Fingerprint, 256) || k.Fingerprint != fingerprint(k.PublicKey) {
			return false
		}
		if _, ok := sshEd25519Public(k.PublicKey); !ok {
			return false
		}
	}
	profile := p.Profile
	return profile.CommitBytes > 0 && profile.CommitBytes <= MaxBodyBytes && profile.AncestryCommits > 0 && profile.AncestryCommits <= MaxEvents && profile.PlatformReviews > 0 && profile.PlatformReviews <= MaxEvents && profile.CheckRecords > 0 && profile.CheckRecords <= MaxEvents
}

func validReading(r Reading) bool {
	const maxDuration = time.Duration(1<<63 - 1)
	return !r.Wall.IsZero() && r.Wall.Unix() >= 0 && r.Monotonic >= 0 &&
		r.SampleSpan >= 0 && r.SampleSpan < AuthorityBudget &&
		r.Monotonic <= maxDuration-r.SampleSpan && !r.wallEnd().Before(r.Wall) &&
		r.wallEnd().Unix() >= r.Wall.Unix() && text(r.Epoch, 256)
}
func validRequest(r Request, p Policy) bool {
	return lowerHex(r.OperationID, 32) && lowerHex(r.Nonce, 64) && lowerHex(r.Commit, 40) && r.Product == p.Product && r.Repository == p.Alias && r.PolicySHA256 == p.SHA256
}

func (a *Authority) BeforeBuild(ctx context.Context, request Request) (*Qualification, error) {
	return a.qualify(ctx, request, Prebuild)
}
func (a *Authority) BeforeSign(ctx context.Context, request Request) (*Qualification, error) {
	return a.qualify(ctx, request, Presign)
}

func (a *Authority) qualify(ctx context.Context, request Request, phase Phase) (*Qualification, error) {
	if a == nil || a.source == nil || a.clock == nil {
		return nil, unavailable("configuration")
	}
	if !validRequest(request, a.policy) {
		return nil, rejected("request_binding")
	}
	if ctx == nil {
		return nil, unavailable("authority_budget")
	}
	start, err := a.clock.Read()
	if err != nil || !validReading(start) {
		return nil, unavailable("clock")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityBudget)
	defer cancel()
	if ctx.Err() != nil {
		return nil, unavailable("authority_budget")
	}
	if err := checkInstalled(ctx, a.installed, a.installedDigest); err != nil {
		return nil, err
	}
	query := Query{request, phase}
	o, err := a.source.Read(ctx, query)
	if err != nil {
		return nil, unavailable("source_read")
	}
	now, err := a.clock.Read()
	if err != nil || !validReading(now) || now.Epoch != start.Epoch || now.Monotonic < start.end() || now.Wall.Before(start.Wall) {
		return nil, unavailable("clock")
	}
	if ctx.Err() != nil || now.end()-start.Monotonic >= AuthorityBudget {
		return nil, unavailable("authority_budget")
	}
	if o.Binding != query {
		return nil, rejected("response_binding")
	}
	if o.PolicySHA256 != a.policy.SHA256 || o.PolicyState == Revoked {
		return nil, rejected("policy_revoked_or_changed")
	}
	if o.PolicyState != Current {
		return nil, unavailable("policy_state")
	}
	if o.ObservedAt < 0 || o.ExpiresAt <= o.ObservedAt || o.ExpiresAt-o.ObservedAt > 300 || o.ObservedAt > now.Wall.Unix() || now.wallEnd().Unix() >= o.ExpiresAt {
		return nil, unavailable("lease_clock")
	}
	if err := bounded(o, a.policy.Profile); err != nil {
		return nil, err
	}
	if o.Repository.Canonical != a.policy.CanonicalRepository || o.Repository.DefaultBranch != a.policy.DefaultBranch || !lowerHex(o.Repository.DefaultHead, 40) {
		return nil, rejected("repository_default_branch")
	}
	c, err := parseCommit(o.Commit)
	if err != nil {
		return nil, err
	}
	if c.oid != request.Commit {
		return nil, rejected("commit_identity")
	}
	owner, err := verifyOwner(c, a.policy)
	if err != nil {
		return nil, err
	}
	relationship, err := verifyLanding(o, c)
	if err != nil {
		return nil, err
	}
	if o.PR.Repository != a.policy.CanonicalRepository || o.PR.Number == 0 || o.PR.Number > 9223372036854775807 || o.PR.Head != c.oid || !lowerHex(o.PR.Base, 40) || o.PR.State != "merged" {
		return nil, rejected("pull_request")
	}
	producer := o.Producer
	if producer.Origin != a.policy.MatrixOrigin || !text(producer.Scope, 512) || !text(producer.Event, 512) || producer.Sender != a.policy.ProducerSender || producer.Repository != a.policy.CanonicalRepository || producer.Head != c.oid || producer.PR != o.PR.Number || producer.State != "intact" {
		return nil, rejected("producer_handoff")
	}
	review, digest, err := verifyReview(o, a.policy)
	if err != nil {
		return nil, err
	}
	checkVerdict, err := verifyChecks(o, a.policy)
	if err != nil {
		return nil, err
	}
	if err := checkInstalled(ctx, a.installed, a.installedDigest); err != nil {
		return nil, err
	}
	// Parsing/cryptography is inside the SAME authority phase budget, not an
	// unmetered tail after the Source callback's 30-second deadline.
	final, err := a.clock.Read()
	if err != nil || !validReading(final) || final.Epoch != start.Epoch || final.Monotonic < now.end() || final.Wall.Before(now.Wall) {
		return nil, unavailable("clock")
	}
	if ctx.Err() != nil || final.end()-start.Monotonic >= AuthorityBudget {
		return nil, unavailable("authority_budget")
	}
	if final.Wall.Unix() < o.ObservedAt || final.wallEnd().Unix() >= o.ExpiresAt {
		return nil, unavailable("lease_clock")
	}
	// Anchor the receipt cap at the LEADING endpoint: pairing the old wall
	// sample with the trailing endpoint would extend the deadline by its span.
	// Check completion against this cap; arithmetic is checked before addition.
	remaining := time.Unix(o.ExpiresAt, 0).Sub(now.Wall)
	const maxDuration = time.Duration(1<<63 - 1)
	if remaining <= 0 || now.Monotonic > maxDuration-remaining {
		return nil, unavailable("lease_clock")
	}
	deadline := now.Monotonic + remaining
	if final.end() >= deadline {
		return nil, unavailable("lease_clock")
	}
	summary := Summary{Binding: query, Tree: c.tree, OwnerFingerprint: owner, DefaultHead: o.Repository.DefaultHead, Relationship: relationship, PR: o.PR.Number, PlatformReviewID: review.ID, Verdict: "ACCEPT", VerdictBodySHA256: digest, CheckPolicyRef: o.CheckPolicy.Ref, CheckVerdict: checkVerdict, ObservedAt: o.ObservedAt, ExpiresAt: o.ExpiresAt}
	return &Qualification{summary: summary, clock: a.clock, start: final, deadline: deadline, installed: a.installed, installedDigest: a.installedDigest}, nil
}

func bounded(o Observation, p Profile) error {
	if len(o.Commit) == 0 || len(o.Commit) > p.CommitBytes || len(o.LandingPath) > p.AncestryCommits || len(o.Reviews.Records) > p.PlatformReviews || len(o.Checks.Records) > p.CheckRecords || len(o.CheckPolicy.Required) > p.CheckRecords {
		return unavailable("profile_capacity")
	}
	for _, c := range o.LandingPath {
		if len(c) == 0 || len(c) > p.CommitBytes {
			return unavailable("profile_capacity")
		}
	}
	var reviewBytes int
	for _, r := range o.Reviews.Records {
		if len(r.Body) > MaxBodyBytes-reviewBytes {
			return unavailable("profile_capacity")
		}
		reviewBytes += len(r.Body)
	}
	return nil
}

func verifyChecks(o Observation, p Policy) (string, error) {
	policy, inventory := o.CheckPolicy, o.Checks
	if policy.Repository != p.CanonicalRepository || inventory.Repository != p.CanonicalRepository || inventory.Head != o.Binding.Commit {
		return "", rejected("checks_binding")
	}
	if inventory.Coverage != Complete || !ascii(policy.Ref, 256) || policy.State == "unknown" || policy.State == "" {
		return "", unavailable("checks_coverage_or_policy")
	}
	if policy.State == "no_required" {
		if len(policy.Required) != 0 {
			return "", unavailable("check_policy_inconsistent")
		}
		if len(inventory.Records) != 0 {
			return "", unavailable("no_required_nonempty_inventory")
		}
		return "no_required_and_none_present", nil
	}
	if policy.State != "required" || len(policy.Required) == 0 {
		return "", unavailable("check_policy_inconsistent")
	}
	records := make(map[CheckIdentity]CheckRecord)
	for _, record := range inventory.Records {
		if !text(record.Identity.Name, 256) || !ascii(record.Identity.Application, 256) || !text(record.ID, 256) || record.Repository != p.CanonicalRepository || record.Head != o.Binding.Commit {
			return "", rejected("check_record_binding")
		}
		if _, exists := records[record.Identity]; exists {
			return "", unavailable("ambiguous_check_inventory")
		}
		records[record.Identity] = record
	}
	seen := make(map[CheckIdentity]bool)
	for _, required := range policy.Required {
		if !text(required.Name, 256) || !ascii(required.Application, 256) || seen[required] {
			return "", unavailable("check_policy_inconsistent")
		}
		seen[required] = true
		record, exists := records[required]
		if !exists || record.State != "completed" || record.Result != "success" {
			return "", rejected("required_check")
		}
	}
	return "required_passed", nil
}
