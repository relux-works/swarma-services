package sourceauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// githubEffectiveCheckReader is a deliberately uninstalled component. Its phase
// must be the enclosing authority's already admitted phase, not a fresh budget.
// No public constructor, URL, credential, callback or resolver is introduced.
// The current acquisition interface loses pagination/visibility metadata and
// cannot account all transport work. Consequently the public port ALWAYS
// refuses before acquisition. The
// private candidate path exists for bounded offline integration development;
// it is not an authority observation or a qualified provider implementation.
type githubEffectiveCheckReader struct {
	phase        *acquisitionPhase
	policy       Policy
	query        Query
	bodyLimit    int64
	applications map[int64]string
	busy         atomic.Bool
}

var _ EffectiveGitHubChecks = (*githubEffectiveCheckReader)(nil)

var effectiveCheckKeys = [...]string{"branch", "protection", "rules", "suites", "runs", "statuses"}

// Paths deliberately exclude queries and escaped/slashed branches, which the
// admitted transport cannot represent. Default page size 30 is a refusal bound,
// never evidence for following a provider-selected URL. Full pages refuse.
func effectiveCheckPaths(p Policy, q Query) map[string]string {
	root := "/repos/" + p.RepositoryName
	return map[string]string{
		"branch":     root + "/branches/" + p.DefaultBranch,
		"protection": root + "/branches/" + p.DefaultBranch + "/protection",
		"rules":      root + "/rules/branches/" + p.DefaultBranch,
		"suites":     root + "/commits/" + q.Commit + "/check-suites",
		"runs":       root + "/commits/" + q.Commit + "/check-runs",
		"statuses":   root + "/commits/" + q.Commit + "/status",
	}
}

func (r *githubEffectiveCheckReader) ReadEffectiveGitHubChecks(ctx context.Context, q Query) (GitHubEffectiveChecks, error) {
	if r == nil || r.phase == nil || ctx == nil || q != r.query || !validRequest(q.Request, r.policy) ||
		q.Phase != Prebuild && q.Phase != Presign || !r.busy.CompareAndSwap(false, true) {
		return GitHubEffectiveChecks{}, unavailable("github_effective_checks_admission")
	}
	defer r.busy.Store(false)
	if err := r.admitted(ctx); err != nil {
		return GitHubEffectiveChecks{}, err
	}
	// The port has no admitted shared accounting/visibility contract. Do not
	// perform even one response or start resolver work on that unsupported path.
	// readCandidate is exercised only by explicit offline component assembly.
	return GitHubEffectiveChecks{}, unavailable("github_effective_checks_integration_gap")
}

func (r *githubEffectiveCheckReader) admitted(ctx context.Context) error {
	p := r.phase
	d, ok := ctx.Deadline()
	pd, pok := p.ctx.Deadline()
	if ctx != p.ctx || !ok || !pok || !d.Equal(pd) || acquisitionExpired(ctx) || acquisitionExpired(p.ctx) ||
		time.Until(d) > AuthorityBudget || r.bodyLimit <= 0 || r.bodyLimit > p.source.limits.metadata ||
		r.bodyLimit > acquisitionBodyMax || r.policy.Profile.CheckRecords <= 0 || r.policy.Profile.CheckRecords > 256 ||
		!githubRepoName(r.policy.RepositoryName) || r.policy.CanonicalRepository != "https://github.com/"+r.policy.RepositoryName ||
		!canonicalAcquisitionPath("/"+r.policy.DefaultBranch) || strings.Contains(r.policy.DefaultBranch, "/") ||
		p.source.auth != nil || p.source.connector == nil || len(r.applications) == 0 || len(r.applications) > r.policy.Profile.CheckRecords {
		return unavailable("github_effective_checks_admission")
	}
	for id, name := range r.applications {
		if id <= 0 || name != "github-app:"+strconv.FormatInt(id, 10) {
			return unavailable("github_effective_checks_application")
		}
	}
	for key, path := range effectiveCheckPaths(r.policy, r.query) {
		e, ok := p.source.endpoints["effective-"+key]
		if !ok || e.kind != metadataResponse || e.url != "https://api.github.com"+path {
			return unavailable("github_effective_checks_endpoint")
		}
	}
	return nil
}

// Charge conservative candidate parser/storage reservations to the existing
// admitted byte pool BEFORE acquiring or decoding. Never refund on failures.
// This is stricter than the phase's body counter, but is not a proof of complete
// shared transport/TLS/DNS/work accounting. That gap still refuses the port.
func (r *githubEffectiveCheckReader) reserveCandidate(ctx context.Context) error {
	p := r.phase
	p.mu.Lock()
	defer p.mu.Unlock()
	const fixed = int64(256 << 10)
	reservation := fixed + 128*r.bodyLimit + p.source.limits.header
	if acquisitionExpired(ctx) || acquisitionExpired(p.ctx) || p.closed || p.failed || p.active || p.uncertain ||
		p.responsesLeft <= 0 || p.bytesLeft <= reservation+r.bodyLimit {
		return unavailable("github_effective_checks_capacity")
	}
	p.bytesLeft -= reservation
	return nil
}

func (r *githubEffectiveCheckReader) readCandidate(ctx context.Context) (GitHubEffectiveChecks, error) {
	var raw [len(effectiveCheckKeys)][]byte
	for i, key := range effectiveCheckKeys {
		if err := r.reserveCandidate(ctx); err != nil {
			return GitHubEffectiveChecks{}, err
		}
		v, err := r.phase.acquire("effective-"+key, r.bodyLimit, r.phase.source.limits.header)
		if err != nil {
			return GitHubEffectiveChecks{}, err
		}
		raw[i] = v.body
	}
	candidate, err := r.normalizeCandidate(raw)
	if err != nil {
		return GitHubEffectiveChecks{}, err
	}
	// Reacquire every policy and inventory input under the SAME deadline/pool.
	// This detects movement, not atomic provider snapshot consistency.
	for i, key := range effectiveCheckKeys {
		if err := r.reserveCandidate(ctx); err != nil {
			return GitHubEffectiveChecks{}, err
		}
		v, err := r.phase.acquire("effective-"+key, r.bodyLimit, r.phase.source.limits.header)
		if err != nil {
			return GitHubEffectiveChecks{}, err
		}
		if !bytes.Equal(v.body, raw[i]) {
			return GitHubEffectiveChecks{}, unavailable("github_effective_checks_changed")
		}
	}
	if acquisitionExpired(ctx) || acquisitionExpired(r.phase.ctx) {
		return GitHubEffectiveChecks{}, unavailable("github_effective_checks_canceled")
	}
	return candidate, nil
}

type effectiveRequiredCheck struct {
	Context string `json:"context"`
	AppID   *int64 `json:"app_id"`
}
type effectiveNativeRun struct {
	ID         uint64    `json:"id"`
	Name       string    `json:"name"`
	Head       string    `json:"head_sha"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	Started    time.Time `json:"started_at"`
	Completed  time.Time `json:"completed_at"`
	App        struct {
		ID int64 `json:"id"`
	} `json:"app"`
	Suite struct {
		ID uint64 `json:"id"`
	} `json:"check_suite"`
}

// normalizeCandidate only handles the conservative short-page, app-pinned,
// current-branch-head subset. It NEVER emits Complete or no_required. Latest
// is the documented default check-runs filter; multiple same-identity records
// refuse rather than trusting IDs, timestamps, array order or lexical sorting.
func (r *githubEffectiveCheckReader) normalizeCandidate(raw [len(effectiveCheckKeys)][]byte) (GitHubEffectiveChecks, error) {
	var out GitHubEffectiveChecks
	var branch struct {
		Name      string `json:"name"`
		Protected *bool  `json:"protected"`
		Commit    struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	var protection struct {
		URL      string `json:"url"`
		Required *struct {
			Strict   *bool                    `json:"strict"`
			Contexts []string                 `json:"contexts"`
			Checks   []effectiveRequiredCheck `json:"checks"`
		} `json:"required_status_checks"`
	}
	var rules []struct {
		Type       string `json:"type"`
		SourceType string `json:"ruleset_source_type"`
		Source     string `json:"ruleset_source"`
		ID         uint64 `json:"ruleset_id"`
		Parameters struct {
			Strict   *bool `json:"strict_required_status_checks_policy"`
			Required []struct {
				Context string `json:"context"`
				AppID   *int64 `json:"integration_id"`
			} `json:"required_status_checks"`
		} `json:"parameters"`
	}
	var suites struct {
		Total  *int `json:"total_count"`
		Suites []struct {
			ID   uint64 `json:"id"`
			Head string `json:"head_sha"`
			App  struct {
				ID int64 `json:"id"`
			} `json:"app"`
			Repository struct {
				FullName string `json:"full_name"`
				Private  *bool  `json:"private"`
			} `json:"repository"`
		} `json:"check_suites"`
	}
	var runs struct {
		Total *int                 `json:"total_count"`
		Runs  []effectiveNativeRun `json:"check_runs"`
	}
	var statuses struct {
		SHA      string            `json:"sha"`
		Total    *int              `json:"total_count"`
		Statuses []json.RawMessage `json:"statuses"`
	}
	for i, dest := range []any{&branch, &protection, &rules, &suites, &runs, &statuses} {
		if len(raw[i]) == 0 || int64(len(raw[i])) > r.bodyLimit {
			return out, unavailable("github_effective_checks_size")
		}
		if err := strictGitHubJSON(raw[i], dest); err != nil {
			return out, err
		}
	}
	if branch.Name != r.policy.DefaultBranch || branch.Protected == nil || !*branch.Protected || branch.Commit.SHA != r.query.Commit {
		return out, rejected("github_effective_checks_branch")
	}
	if protection.URL != "https://api.github.com"+effectiveCheckPaths(r.policy, r.query)["protection"] || protection.Required == nil || protection.Required.Strict == nil ||
		protection.Required.Checks == nil || protection.Required.Contexts == nil || rules == nil || len(rules) >= 30 {
		return out, unavailable("github_effective_checks_policy_visibility")
	}
	limit := r.policy.Profile.CheckRecords
	required := make(map[CheckIdentity]bool)
	byName := make(map[string]CheckIdentity)
	add := func(name string, id *int64) error {
		if !text(name, 256) || id == nil || *id <= 0 || r.applications[*id] == "" {
			return unavailable("github_effective_checks_application")
		}
		identity := CheckIdentity{name, r.applications[*id]}
		if old, ok := byName[name]; ok && old != identity {
			return unavailable("github_effective_checks_application_ambiguity")
		}
		if !required[identity] && len(required) >= limit {
			return unavailable("github_effective_checks_capacity")
		}
		required[identity], byName[name] = true, identity
		return nil
	}
	if len(protection.Required.Checks) > limit || len(protection.Required.Contexts) > limit {
		return out, unavailable("github_effective_checks_capacity")
	}
	legacy := map[string]bool{}
	for _, check := range protection.Required.Checks {
		if legacy[check.Context] {
			return out, unavailable("github_effective_checks_duplicate_policy")
		}
		legacy[check.Context] = true
		if err := add(check.Context, check.AppID); err != nil {
			return out, err
		}
	}
	contexts := map[string]bool{}
	for _, name := range protection.Required.Contexts {
		if !legacy[name] || contexts[name] {
			return out, unavailable("github_effective_checks_legacy_context")
		}
		contexts[name] = true
	}
	if len(contexts) != len(legacy) {
		return out, unavailable("github_effective_checks_legacy_context")
	}
	ruleIDs := map[uint64]bool{}
	for _, rule := range rules {
		if rule.Type != "required_status_checks" || rule.ID == 0 || ruleIDs[rule.ID] ||
			(rule.SourceType != "Repository" && rule.SourceType != "Organization") || !text(rule.Source, 256) ||
			rule.Parameters.Strict == nil || rule.Parameters.Required == nil || len(rule.Parameters.Required) > limit {
			return out, unavailable("github_effective_checks_rules")
		}
		ruleIDs[rule.ID] = true
		seen := map[string]bool{}
		for _, check := range rule.Parameters.Required {
			if seen[check.Context] {
				return out, unavailable("github_effective_checks_duplicate_policy")
			}
			seen[check.Context] = true
			if err := add(check.Context, check.AppID); err != nil {
				return out, err
			}
		}
	}
	if len(required) == 0 {
		return out, unavailable("github_effective_checks_empty_policy")
	}
	if suites.Total == nil || runs.Total == nil || statuses.Total == nil || suites.Suites == nil || runs.Runs == nil || statuses.Statuses == nil ||
		*suites.Total != len(suites.Suites) || *runs.Total != len(runs.Runs) || *statuses.Total != len(statuses.Statuses) ||
		len(suites.Suites) >= 30 || len(runs.Runs) >= 30 || len(statuses.Statuses) >= 30 ||
		len(suites.Suites) > limit || len(runs.Runs) > limit || statuses.SHA != r.query.Commit {
		return out, unavailable("github_effective_checks_pagination")
	}
	// Legacy commit statuses cannot authenticate a configured application. Do
	// not map creator login, context text or a green combined state to an app.
	if len(statuses.Statuses) != 0 {
		return out, unavailable("github_effective_checks_status_application")
	}
	suiteApps := map[uint64]int64{}
	for _, suite := range suites.Suites {
		if suite.ID == 0 || suiteApps[suite.ID] != 0 || suite.Head != r.query.Commit || r.applications[suite.App.ID] == "" ||
			suite.Repository.FullName != r.policy.RepositoryName || suite.Repository.Private == nil || *suite.Repository.Private {
			return out, unavailable("github_effective_checks_suite")
		}
		suiteApps[suite.ID] = suite.App.ID
	}
	seenIDs := map[uint64]bool{}
	seenIdentities := map[CheckIdentity]bool{}
	for _, run := range runs.Runs {
		identity := CheckIdentity{run.Name, r.applications[run.App.ID]}
		if run.ID == 0 || run.ID > 9223372036854775807 || seenIDs[run.ID] || !text(run.Name, 256) || identity.Application == "" ||
			run.Head != r.query.Commit || suiteApps[run.Suite.ID] != run.App.ID || seenIdentities[identity] ||
			run.Started.IsZero() || run.Completed.IsZero() || run.Completed.Before(run.Started) || run.Status != "completed" || run.Conclusion != "success" {
			return GitHubEffectiveChecks{}, unavailable("github_effective_checks_latest_attempt")
		}
		seenIDs[run.ID], seenIdentities[identity] = true, true
		out.Inventory.Records = append(out.Inventory.Records, CheckRecord{Identity: identity, ID: strconv.FormatUint(run.ID, 10), Repository: r.policy.CanonicalRepository, Head: run.Head, State: run.Status, Result: run.Conclusion})
	}
	for identity := range required {
		if !seenIdentities[identity] {
			return GitHubEffectiveChecks{}, rejected("github_effective_checks_required_missing")
		}
		out.Policy.Required = append(out.Policy.Required, identity)
	}
	sort.Slice(out.Policy.Required, func(i, j int) bool {
		a, b := out.Policy.Required[i], out.Policy.Required[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Application < b.Application
	})
	sort.Slice(out.Inventory.Records, func(i, j int) bool { return out.Inventory.Records[i].ID < out.Inventory.Records[j].ID })
	out.Policy.Repository, out.Policy.Ref, out.Policy.State = r.policy.CanonicalRepository, r.policy.DefaultBranch, "required"
	out.Inventory.Repository, out.Inventory.Head, out.Inventory.Coverage = r.policy.CanonicalRepository, r.query.Commit, Partial
	return out, nil
}
