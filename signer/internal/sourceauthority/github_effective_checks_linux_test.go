//go:build linux

package sourceauthority

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type effectiveLab struct {
	r      *githubEffectiveCheckReader
	ctx    context.Context
	cancel context.CancelFunc
	body   map[string][]byte
	calls  atomic.Int32
	change func(string, int, []byte) (int, []byte)
}

func newEffectiveLab(t *testing.T) *effectiveLab {
	t.Helper()
	p := Policy{Product: "fixture", Alias: "fixture", CanonicalRepository: "https://github.com/example/project", RepositoryName: "example/project", DefaultBranch: "main", SHA256: strings.Repeat("a", 64), Profile: Profile{CheckRecords: 8}}
	q := Query{Request: Request{OperationID: strings.Repeat("b", 32), Nonce: strings.Repeat("c", 64), Product: p.Product, Repository: p.Alias, Commit: strings.Repeat("d", 40), PolicySHA256: p.SHA256}, Phase: Prebuild}
	l := &effectiveLab{body: map[string][]byte{}}
	l.body["branch"] = []byte(fmt.Sprintf(`{"name":"main","protected":true,"commit":{"sha":%q}}`, q.Commit))
	l.body["protection"] = []byte(`{"url":"https://api.github.com/repos/example/project/branches/main/protection","required_status_checks":{"strict":true,"contexts":["unit"],"checks":[{"context":"unit","app_id":17}]}}`)
	l.body["rules"] = []byte(`[{"type":"required_status_checks","ruleset_source_type":"Repository","ruleset_source":"example/project","ruleset_id":91,"parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":"unit","integration_id":17}]}}]`)
	l.body["suites"] = []byte(fmt.Sprintf(`{"total_count":1,"check_suites":[{"id":11,"head_sha":%q,"app":{"id":17},"repository":{"full_name":"example/project","private":false}}]}`, q.Commit))
	l.body["runs"] = []byte(fmt.Sprintf(`{"total_count":1,"check_runs":[{"id":21,"name":"unit","head_sha":%q,"status":"completed","conclusion":"success","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:01:00Z","app":{"id":17},"check_suite":{"id":11}}]}`, q.Commit))
	l.body["statuses"] = []byte(fmt.Sprintf(`{"sha":%q,"total_count":0,"statuses":[]}`, q.Commit))
	paths := effectiveCheckPaths(p, q)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := int(l.calls.Add(1))
		if req.Method != "GET" || req.Host != "api.github.com" || req.URL.RawQuery != "" || req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			t.Error("unexpected request authority or endpoint profile")
		}
		for key, path := range paths {
			if req.URL.Path == path {
				status, body := 200, l.body[key]
				if l.change != nil {
					status, body = l.change(key, n, body)
				}
				w.WriteHeader(status)
				_, _ = w.Write(body)
				return
			}
		}
		w.WriteHeader(404)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{providerFixtureCertificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	connector := &fixtureOwnedConnector{target: netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "https://"))}
	endpoints := map[string]acquisitionEndpoint{}
	for key, path := range paths {
		endpoints["effective-"+key] = acquisitionEndpoint{path: path, kind: metadataResponse}
	}
	a, err := newSourceAcquisition(acquisitionInstallation{provider: "effective-public-component", origin: "https://api.github.com", endpoints: endpoints, connector: connector, limits: acquisitionLimits{header: acquisitionHeaderMax, metadata: 4096, commit: 1024, aggregate: 16 << 20, responses: 16}})
	if err != nil {
		t.Fatal(err)
	}
	l.ctx, l.cancel = context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(l.cancel)
	phase, err := a.begin(l.ctx, 16<<20, 16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(phase.close)
	l.ctx = phase.ctx
	l.r = &githubEffectiveCheckReader{phase: phase, policy: p, query: q, bodyLimit: 4096, applications: map[int64]string{17: "github-app:17"}}
	return l
}

func effectiveRefusal(t *testing.T, l *effectiveLab, want string) {
	t.Helper()
	if err := l.r.admitted(l.ctx); err != nil {
		t.Fatal(err)
	}
	got, err := l.r.readCandidate(l.ctx)
	if err == nil || !reflect.DeepEqual(got, GitHubEffectiveChecks{}) {
		t.Fatalf("refusal returned material: %v", err)
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("wrong refusal: %v; want %s", err, want)
	}
}

// Positive control executes the real anonymous canonical-host TLS acquisition,
// both reads of all six endpoints and the actual decoder. Its output remains
// Partial. This is not a successful EffectiveGitHubChecks qualification.
func TestEffectiveChecksCandidatePositive(t *testing.T) {
	l := newEffectiveLab(t)
	if err := l.r.admitted(l.ctx); err != nil {
		t.Fatal(err)
	}
	before := l.r.phase.bytesLeft
	out, err := l.r.readCandidate(l.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Inventory.Coverage != Partial || out.Policy.State != "required" || len(out.Policy.Required) != 1 || len(out.Inventory.Records) != 1 || out.Policy.Required[0] != (CheckIdentity{"unit", "github-app:17"}) || l.calls.Load() != 12 {
		t.Fatal("bounded candidate path did not bind actual evidence")
	}
	if l.r.phase.responsesLeft != 4 || l.r.phase.bytesLeft >= before-12*(256<<10) {
		t.Fatal("shared pool not charged")
	}
}

func TestEffectiveChecksPublicPortFailsClosedBeforeAcquisition(t *testing.T) {
	l := newEffectiveLab(t)
	got, err := l.r.ReadEffectiveGitHubChecks(l.ctx, l.r.query)
	if err == nil || !strings.Contains(err.Error(), "integration_gap") || !reflect.DeepEqual(got, GitHubEffectiveChecks{}) || l.calls.Load() != 0 {
		t.Fatal("unqualified public port performed acquisition or returned evidence")
	}
}

func TestEffectiveChecksResponseRefusals(t *testing.T) {
	tests := []struct{ name, key, old, new, want string }{
		{"wrong_ref", "branch", `"name":"main"`, `"name":"other"`, "branch"},
		{"wrong_head", "branch", strings.Repeat("d", 40), strings.Repeat("e", 40), "branch"},
		{"unprotected", "branch", `"protected":true`, `"protected":false`, "branch"},
		{"hidden_policy", "protection", `"required_status_checks":{`, `"hidden":{`, "policy_visibility"},
		{"missing_strict", "protection", `"strict":true,`, ``, "policy_visibility"},
		{"app_any", "protection", `"app_id":17`, `"app_id":-1`, "application"},
		{"app_missing", "protection", `"app_id":17`, `"app_id":null`, "application"},
		{"wrong_app", "runs", `"app":{"id":17}`, `"app":{"id":18}`, "latest_attempt"},
		{"wrong_run_head", "runs", strings.Repeat("d", 40), strings.Repeat("e", 40), "latest_attempt"},
		{"stale_attempt", "runs", `"conclusion":"success"`, `"conclusion":"stale"`, "latest_attempt"},
		{"failed_run", "runs", `"conclusion":"success"`, `"conclusion":"failure"`, "latest_attempt"},
		{"pending_run", "runs", `"status":"completed"`, `"status":"in_progress"`, "latest_attempt"},
		{"reversed_attempt_time", "runs", `"started_at":"2026-01-01T00:00:00Z"`, `"started_at":"2026-01-01T00:02:00Z"`, "latest_attempt"},
		{"missing_pagination", "runs", `"total_count":1,`, ``, "pagination"},
		{"partial_page", "runs", `"total_count":1`, `"total_count":2`, "pagination"},
		{"partial_suites", "suites", `"total_count":1`, `"total_count":31`, "pagination"},
		{"wrong_suite_repo", "suites", `"full_name":"example/project"`, `"full_name":"other/project"`, "suite"},
		{"private_suite", "suites", `"private":false`, `"private":true`, "suite"},
		{"wrong_status_head", "statuses", strings.Repeat("d", 40), strings.Repeat("e", 40), "pagination"},
		{"failed_status", "statuses", `"total_count":0,"statuses":[]`, `"total_count":1,"statuses":[{"id":51,"context":"unit","state":"failure"}]`, "status_application"},
		{"green_status_has_no_app_identity", "statuses", `"total_count":0,"statuses":[]`, `"total_count":1,"statuses":[{"id":51,"context":"unit","state":"success"}]`, "status_application"},
		{"different_rule", "rules", `"type":"required_status_checks"`, `"type":"workflows"`, "rules"},
		{"hidden_rules_source", "rules", `"ruleset_source_type":"Repository"`, `"ruleset_source_type":""`, "rules"},
		{"ambiguous_policy_app", "rules", `"integration_id":17`, `"integration_id":18`, "application"},
		{"duplicate_json_field", "runs", `"total_count":1`, `"total_count":1,"total_count":1`, "github_json_duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newEffectiveLab(t)
			if !bytes.Contains(l.body[tt.key], []byte(tt.old)) {
				t.Fatal("mutation did not match")
			}
			l.body[tt.key] = bytes.ReplaceAll(l.body[tt.key], []byte(tt.old), []byte(tt.new))
			effectiveRefusal(t, l, tt.want)
		})
	}
}

func TestEffectiveChecksDuplicateAndEmptyRuns(t *testing.T) {
	for _, mode := range []string{"same_id", "conflicting_id", "different_attempt", "empty", "full_page"} {
		t.Run(mode, func(t *testing.T) {
			l := newEffectiveLab(t)
			var runs map[string]any
			if err := json.Unmarshal(l.body["runs"], &runs); err != nil {
				t.Fatal(err)
			}
			one := runs["check_runs"].([]any)[0]
			switch mode {
			case "empty":
				runs["check_runs"], runs["total_count"] = []any{}, 0
			case "same_id":
				runs["check_runs"], runs["total_count"] = []any{one, one}, 2
			case "full_page":
				list := make([]any, 30)
				for i := range list {
					list[i] = one
				}
				runs["check_runs"], runs["total_count"] = list, 30
			default:
				copyRun := map[string]any{}
				for k, v := range one.(map[string]any) {
					copyRun[k] = v
				}
				if mode == "conflicting_id" {
					copyRun["conclusion"] = "failure"
				} else {
					copyRun["id"] = 22
				}
				runs["check_runs"], runs["total_count"] = []any{one, copyRun}, 2
			}
			var err error
			l.body["runs"], err = json.Marshal(runs)
			if err != nil {
				t.Fatal(err)
			}
			effectiveRefusal(t, l, "")
		})
	}
}

func TestEffectiveChecksTransportAndRecheckRefusals(t *testing.T) {
	for _, mode := range []string{"404", "403", "moved_ref", "changed_policy", "cancel_inflight", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			l := newEffectiveLab(t)
			l.change = func(key string, n int, body []byte) (int, []byte) {
				if key == "protection" && (mode == "404" || mode == "403") {
					if mode == "404" {
						return 404, []byte(`{}`)
					}
					return 403, []byte(`{}`)
				}
				if mode == "oversize" && key == "rules" {
					return 200, bytes.Repeat([]byte(" "), 4097)
				}
				if mode == "cancel_inflight" && key == "runs" {
					l.cancel()
					return 200, body
				}
				if n > 6 && (mode == "moved_ref" && key == "branch" || mode == "changed_policy" && key == "protection") {
					return 200, append(append([]byte{}, body...), ' ')
				}
				return 200, body
			}
			effectiveRefusal(t, l, "")
			if mode == "404" || mode == "403" {
				if l.r.phase.responsesLeft != 14 || !l.r.phase.failed {
					t.Fatal("failed attempt not charged and poisoned")
				}
			}
		})
	}
}

func TestEffectiveChecksAdmission(t *testing.T) {
	for _, mode := range []string{"admitted", "canceled", "no_deadline", "renewed_deadline", "record_limit", "body_limit", "auth", "connector", "endpoint", "application"} {
		t.Run(mode, func(t *testing.T) {
			l := newEffectiveLab(t)
			want := "github_effective_checks_admission"
			switch mode {
			case "admitted":
				want = ""
			case "canceled":
				// Cancel the admitted context itself; parent propagation may
				// still be queued when this synchronous predicate is called.
				l.r.phase.cancel()
			case "no_deadline":
				l.ctx = context.Background()
			case "renewed_deadline":
				var cancel context.CancelFunc
				l.ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
			case "record_limit":
				l.r.policy.Profile.CheckRecords = 0
			case "body_limit":
				l.r.bodyLimit = 4097
			case "auth":
				l.r.phase.source.auth = &GitHubInstallationAuth{}
			case "connector":
				l.r.phase.source.connector = nil
			case "endpoint":
				l.r.phase.source.endpoints["effective-rules"] = installedEndpoint{url: "https://other.invalid/rules", kind: metadataResponse}
				want = "github_effective_checks_endpoint"
			case "application":
				l.r.applications[17] = "github-app:18"
				want = "github_effective_checks_application"
			}
			err := l.r.admitted(l.ctx)
			if want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if refusal, ok := err.(*Refusal); !ok || refusal.Predicate() != want {
				t.Fatalf("wanted %s, got %v", want, err)
			}
			if l.calls.Load() != 0 {
				t.Fatalf("admission initiated %d calls", l.calls.Load())
			}
		})
	}
}

func TestEffectiveChecksPublicQueryRefusal(t *testing.T) {
	l := newEffectiveLab(t)
	q := l.r.query
	q.Commit = strings.Repeat("e", 40)
	got, err := l.r.ReadEffectiveGitHubChecks(l.ctx, q)
	r, ok := err.(*Refusal)
	if !ok || r.Predicate() != "github_effective_checks_admission" || !reflect.DeepEqual(got, GitHubEffectiveChecks{}) || l.calls.Load() != 0 {
		t.Fatalf("mismatched public query admitted: %v", err)
	}
}

func TestEffectiveChecksEmptyPolicyNeverNoRequired(t *testing.T) {
	l := newEffectiveLab(t)
	l.body["protection"] = []byte(`{"url":"https://api.github.com/repos/example/project/branches/main/protection","required_status_checks":{"strict":true,"contexts":[],"checks":[]}}`)
	l.body["rules"] = []byte(`[]`)
	l.body["runs"] = []byte(`{"total_count":0,"check_runs":[]}`)
	effectiveRefusal(t, l, "empty_policy")
}

func TestEffectiveChecksCandidateSharedCapacity(t *testing.T) {
	for _, mode := range []string{"bytes", "attempts", "recheck_attempts", "canceled", "active"} {
		t.Run(mode, func(t *testing.T) {
			l := newEffectiveLab(t)
			switch mode {
			case "bytes":
				l.r.phase.bytesLeft = 1024
			case "attempts":
				l.r.phase.responsesLeft = 0
			case "recheck_attempts":
				l.r.phase.responsesLeft = 6
			case "canceled":
				l.cancel()
			case "active":
				l.r.phase.active = true
				defer func() { l.r.phase.active = false }()
			}
			out, err := l.r.readCandidate(l.ctx)
			if err == nil || !reflect.DeepEqual(out, GitHubEffectiveChecks{}) {
				t.Fatal("capacity failure returned candidate")
			}
			want := int32(0)
			if mode == "recheck_attempts" {
				want = 6
			}
			if l.calls.Load() != want {
				t.Fatalf("calls=%d want=%d", l.calls.Load(), want)
			}
		})
	}
}

// The transport currently discards Link. This fixture proves even a short page
// cannot become Complete via the public port; metadata integration is required.
func TestEffectiveChecksMissingPaginationMetadataCannotQualify(t *testing.T) {
	l := newEffectiveLab(t)
	got, err := l.r.ReadEffectiveGitHubChecks(l.ctx, l.r.query)
	if err == nil || !strings.Contains(err.Error(), "integration_gap") || !reflect.DeepEqual(got, GitHubEffectiveChecks{}) || l.calls.Load() != 0 {
		t.Fatal("missing metadata qualified or initiated a transfer")
	}
}
