package sourceauthority

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

// All keys, policy files, TLS peers and staging bytes are synthetic lab data.
// Audited authority is constructed through supported APIs, never substituted.
type finalPolicyGraph struct {
	delegate *labGraphReader
	hook     func(context.Context)
}

func (g *finalPolicyGraph) readReview(ctx context.Context, r githubGraphQLRequest) ([]byte, error) {
	raw, err := g.delegate.readReview(ctx, r)
	if g.hook != nil {
		g.hook(ctx)
	}
	return raw, err
}

type finalPolicySource struct {
	delegate PolicySource
	after    func(context.Context)
}

func (s *finalPolicySource) Snapshot(ctx context.Context) (*PolicySnapshot, error) {
	snapshot, err := s.delegate.Snapshot(ctx)
	if s.after != nil {
		s.after(ctx)
	}
	return snapshot, err
}

type protectedGitHubLab struct {
	source    *githubPRSource
	installed *finalPolicySource
	graph     *finalPolicyGraph
	clock     *fixtureClock
	request   Request
	proof     githubReviewProof
	path      string
	raw       []byte
	digest    string
}

func newProtectedGitHubLab(t *testing.T) *protectedGitHubLab {
	t.Helper()
	a, request, graph, proof := labGitHubAuthority(t)
	raw, err := EncodePolicyForRoute(a.policy, GitHubPRPolicyRoute)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policySnapshotForRoute(raw, GitHubPRPolicyRoute)
	if err != nil {
		t.Fatal(err)
	}
	p := snapshot.PolicyCopy()
	prior := a.github
	current := prior.policies.(labPolicyReader)
	current.snapshot.Digest = p.SHA256
	g := &finalPolicyGraph{delegate: graph}
	// Assemble the protected source with the canonical synthetic policy before
	// handing it to either public constructor. Only transport has a lab origin.
	source, err := newGitHubPRSource(githubPRInstallation{policy: p, members: prior.members, number: prior.number, clock: a.clock, policies: current, git: prior.git, checks: prior.checks, graphql: g})
	if err != nil {
		t.Fatal(err)
	}
	source.transport = prior.transport
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	installed, err := NewProtectedPolicySourceForRoute(context.Background(), path, uint32(os.Geteuid()), GitHubPRPolicyRoute)
	if err != nil {
		t.Fatal(err)
	}
	request.PolicySHA256 = p.SHA256
	return &protectedGitHubLab{source, &finalPolicySource{delegate: installed}, g, a.clock.(*fixtureClock), request, proof, path, raw, p.SHA256}
}

func (l *protectedGitHubLab) changePolicy(t *testing.T, fault string) {
	t.Helper()
	switch fault {
	case "unchanged":
		// A fresh inode with identical full canonical bytes is allowed.
		reinstall(t, l.path, l.raw)
	case "replaced":
		p := l.source.policy
		p.Profile.CommitBytes--
		raw, err := EncodePolicyForRoute(p, GitHubPRPolicyRoute)
		if err != nil {
			t.Fatal(err)
		}
		reinstall(t, l.path, raw)
	case "missing":
		if err := os.Remove(l.path); err != nil {
			t.Fatal(err)
		}
	case "malformed":
		reinstall(t, l.path, append(append([]byte(nil), l.raw...), '\n'))
	default:
		t.Fatal("unknown fault")
	}
}

func newProtectedGitHubAuditFixture(t *testing.T, supplied ...*protectedGitHubLab) (*auditAdapterFixture, *protectedGitHubLab) {
	t.Helper()
	l := newProtectedGitHubLab(t)
	if len(supplied) > 0 {
		l = supplied[0]
	}
	e, _, raw := newEffectFixture(t)
	e.f.r = l.request
	p := &adapterDurability{t: t, synced: map[string]map[string]bool{}}
	backend := &adapterBackend{t: t, profile: p, dir: t.TempDir(), peer: e.signPeer}
	dir := t.TempDir()
	for _, path := range []string{dir, backend.dir} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	trust := &adapterTrust{}
	policy := AuditSignerPolicy{Caller: "fixture-service", Effects: e.policy, CertificateSHA256: strings.Repeat("a", 64), RequirementSHA256: strings.Repeat("b", 64)}
	options := signingaudit.Options{Durability: p, MaxBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	signer, err := OpenAuditedSignerWithPolicySource(ctx, dir, options, l.installed, l.digest, l.source, l.clock, policy, trust, backend)
	if err != nil {
		t.Fatal("protected audited construction", err)
	}
	capture := &captureAuditSigner{inner: signer}
	runner, err := NewEffectRunnerWithPolicySource(ctx, l.installed, l.digest, l.source, l.clock, e.policy, effectBuilder{e}, capture, e)
	if err != nil {
		signer.Close()
		t.Fatal(err)
	}
	raw = graphEffectRaw(t, raw, runner.authority, l.request)
	a := &auditAdapterFixture{e, runner, raw, signer, capture, backend, trust, p, dir, options, policy, ctx, cancel}
	t.Cleanup(func() {
		if err := a.signer.Close(); err != nil {
			t.Error(err)
		}
	})
	return a, l
}

func TestFinalPolicyAtActualBuildAndSign(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, fault := range []string{"unchanged", "replaced", "missing", "malformed"} {
			t.Run(string(phase)+"/"+fault, func(t *testing.T) {
				l := newProtectedGitHubLab(t)
				e, _, raw := newEffectFixture(t)
				ctx := effectContext(t)
				runner, err := NewEffectRunnerWithPolicySource(ctx, l.installed, l.digest, l.source, l.clock, e.policy, effectBuilder{e}, effectSigner{e}, e)
				if err != nil {
					t.Fatal(err)
				}
				armed, ran := false, false
				e.auditChange = func(record EffectRecord) error {
					if record.Authority.Binding.Phase == phase {
						armed = true
					}
					return nil
				}
				l.graph.hook = func(context.Context) {
					if armed && !ran {
						ran = true
						l.changePolicy(t, fault)
					}
				}
				err = runner.Run(ctx, effectBody(t, graphEffectRaw(t, raw, runner.authority, l.request)))
				entered := e.buildCalls
				if phase == Presign {
					entered = e.signCalls
				}
				if !ran {
					t.Fatal("final read not reached")
				}
				if fault == "unchanged" {
					if err != nil || e.buildCalls != 1 || e.signCalls != 1 {
						t.Fatalf("valid entry: %v build=%d sign=%d", err, e.buildCalls, e.signCalls)
					}
				} else if err == nil || entered != 0 {
					t.Fatalf("invalid policy entered effect=%d err=%v", entered, err)
				}
				assertSnapshotClosed(t, e)
			})
		}
	}
}

func TestProtectedAuditedConstructionLifecycle(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "recovery"}[recovery], func(t *testing.T) {
			a, l := newProtectedGitHubAuditFixture(t)
			if recovery {
				a.backend.signErr = errAuditFixture
			}
			if err := a.run(t); (err != nil) != recovery {
				t.Fatal("run", err)
			}
			a.backend.signErr = nil
			if recovery {
				op, err := a.signer.Reconcile(a.id())
				if err != nil || op.State != signingaudit.Succeeded || a.backend.reconciles != 1 {
					t.Fatal("recovery", err)
				}
			}
			if err := a.signer.Fetch(a.id()); err != nil {
				t.Fatal("fetch", err)
			}
			if a.backend.signs != 1 || a.backend.verifies != 1 || a.backend.releases != 1 {
				t.Fatal("wrong effect count")
			}
			if a.capture.job.build.qualification.summary.PlatformReviewID != a.capture.job.qualification.summary.PlatformReviewID || a.capture.job.qualification.summary.PlatformReviewID != "1701" {
				t.Fatal("original review ID drift")
			}
			if err := a.signer.Sign(a.ctx, a.capture.job); err == nil || a.backend.signs != 1 {
				t.Fatal("repeated sign entered backend")
			}
			if len(l.graph.delegate.deadlines) < 6 {
				t.Fatal("missing protected observations")
			}
			assertSnapshotClosed(t, a.e)
		})
	}
}

func TestProtectedAuditedConstructorRefusals(t *testing.T) {
	a, l := newProtectedGitHubAuditFixture(t)
	if s, err := OpenAuditedSigner(t.TempDir(), a.options, l.source.policy, l.source, l.clock, a.policy, a.trust, a.backend); err == nil || s != nil {
		t.Fatal("empty Matrix route inferred GitHub")
	}
	for _, fault := range []string{"missing-policy", "missing-protected-source", "generic-source", "external-digest", "changed-policy", "cancelled", "native-trust", "native-pin"} {
		t.Run(fault, func(t *testing.T) {
			installed, source, digest, ctx, policy, trust := PolicySource(l.installed), Source(l.source), l.digest, a.ctx, a.policy, signingaudit.TrustMetadata(a.trust)
			switch fault {
			case "missing-policy":
				installed = nil
			case "missing-protected-source":
				source = nil
			case "generic-source":
				source = a.e.f.s
			case "external-digest":
				digest = strings.Repeat("0", 64)
			case "changed-policy":
				l.changePolicy(t, "replaced")
				defer reinstall(t, l.path, l.raw)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "native-trust":
				trust = nil
			case "native-pin":
				policy.CertificateSHA256 = ""
			}
			s, err := OpenAuditedSignerWithPolicySource(ctx, t.TempDir(), a.options, installed, digest, source, l.clock, policy, trust, a.backend)
			if err == nil || s != nil {
				t.Fatal("constructor accepted", fault)
			}
		})
	}
}

func TestFinalPolicyAtAuditedBackendEntry(t *testing.T) {
	for _, point := range []string{"sign", "verify", "release", "recovery"} {
		for _, fault := range []string{"unchanged", "replaced", "missing", "malformed"} {
			t.Run(point+"/"+fault, func(t *testing.T) {
				a, l := newProtectedGitHubAuditFixture(t)
				if point != "sign" {
					if point == "recovery" {
						a.backend.signErr = errAuditFixture
					}
					if err := a.run(t); (err != nil) != (point == "recovery") {
						t.Fatal("setup", err)
					}
					a.backend.signErr = nil
				}
				armed, ran, fetch := false, false, 0
				a.trust.change = func(phase signingaudit.Phase, _ signingaudit.Operation) error {
					if phase == signingaudit.Fetch {
						fetch++
					}
					if point == "sign" && phase == signingaudit.Presign || point == "verify" && fetch == 1 || point == "release" && fetch == 2 || point == "recovery" && phase == signingaudit.Recovery {
						armed = true
					}
					return nil
				}
				l.graph.hook = func(context.Context) {
					if armed && !ran {
						ran = true
						l.changePolicy(t, fault)
					}
				}
				before := []int{a.backend.signs, a.backend.verifies, a.backend.releases, a.backend.reconciles}
				var err error
				index := 0
				switch point {
				case "sign":
					err = a.run(t)
				case "verify", "release":
					err = a.signer.Fetch(a.id())
					index = map[string]int{"verify": 1, "release": 2}[point]
				case "recovery":
					_, err = a.signer.Reconcile(a.id())
					index = 3
				}
				entered := []int{a.backend.signs, a.backend.verifies, a.backend.releases, a.backend.reconciles}[index] - before[index]
				if !ran {
					t.Fatal("audited final read not reached")
				}
				if fault == "unchanged" {
					if err != nil || entered != 1 {
						t.Fatalf("valid backend entry=%d err=%v", entered, err)
					}
				} else if err == nil || entered != 0 {
					t.Fatalf("invalid policy backend entry=%d err=%v", entered, err)
				}
				assertSnapshotClosed(t, a.e)
			})
		}
	}
}

func TestFinalPolicyReadPreservesBudgetAndClock(t *testing.T) {
	for _, fault := range []string{"unchanged", "cancelled", "deadline", "lease-expired", "clock-refused", "clock-backward"} {
		t.Run(fault, func(t *testing.T) {
			l := newProtectedGitHubLab(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			a, err := NewWithPolicySource(ctx, l.installed, l.digest, l.source, l.clock)
			if err != nil {
				t.Fatal(err)
			}
			q, err := a.BeforeSign(ctx, l.request)
			if err != nil {
				t.Fatal(err)
			}
			originalStart, originalLease, originalDeadline := q.start, q.deadline, q.originalDeadline
			ran := false
			l.graph.hook = func(graphContext context.Context) {
				graphDeadline, _ := graphContext.Deadline()
				l.installed.after = func(policyContext context.Context) {
					ran = true
					d, ok := policyContext.Deadline()
					if !ok || d.After(graphDeadline) || d.After(originalDeadline) {
						t.Fatal("post-read policy check widened deadline")
					}
					switch fault {
					case "cancelled":
						cancel()
					case "deadline":
						<-ctx.Done()
					case "lease-expired":
						l.clock.advance(300 * time.Second)
					case "clock-refused":
						l.clock.err = errAuditFixture
					case "clock-backward":
						l.clock.advance(-time.Second)
					}
				}
			}
			err = q.checkFinalEffectContext(ctx)
			if !ran || (err != nil) != (fault != "unchanged") {
				t.Fatalf("post-read control reached=%t err=%v", ran, err)
			}
			if q.start != originalStart || q.deadline != originalLease || q.originalDeadline != originalDeadline {
				t.Fatal("final read renewed original bounds")
			}
		})
	}
}

// A later current observation never replaces the older original caps.
func TestProtectedAuditedOriginalCapsAfterFinalRead(t *testing.T) {
	for _, fault := range []string{"unchanged", "build-expired", "sign-expired", "cancelled", "clock-refused"} {
		t.Run(fault, func(t *testing.T) {
			a, l := newProtectedGitHubAuditFixture(t)
			if err := a.run(t); err != nil {
				t.Fatal(err)
			}
			l.clock.advance(299 * time.Second)
			armed, ran := false, false
			a.trust.change = func(signingaudit.Phase, signingaudit.Operation) error { armed = true; return nil }
			l.graph.hook = func(context.Context) {
				if !armed || ran {
					return
				}
				ran = true
				switch fault {
				case "build-expired", "sign-expired":
					// Current final read, then original build/sign. Advance the
					// fixture clock without replacing authority or lease fields.
					reads := 2
					if fault == "sign-expired" {
						reads = 3
					}
					failAt := l.clock.reads + reads
					l.clock.onRead = func(c *fixtureClock) {
						if c.reads == failAt {
							c.r.Wall = c.r.Wall.Add(time.Second)
							c.r.Monotonic += time.Second
						}
					}
				case "cancelled":
					a.cancel()
				case "clock-refused":
					l.clock.err = errAuditFixture
				}
			}
			err := a.signer.Fetch(a.id())
			if !ran {
				t.Fatal("final read not reached")
			}
			if fault == "unchanged" {
				if err != nil || a.backend.verifies != 1 || a.backend.releases != 1 {
					t.Fatal("valid original caps", err)
				}
			} else if err == nil || a.backend.verifies != 0 || a.backend.releases != 0 {
				t.Fatal("invalid original cap entered backend", err)
			}
			if a.backend.signs != 1 {
				t.Fatal("fetch resigned")
			}
		})
	}
}

func TestProtectedAuditedRestartRefusesContinuation(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "uncertain"}[recovery], func(t *testing.T) {
			a, l := newProtectedGitHubAuditFixture(t)
			if recovery {
				a.backend.signErr = errAuditFixture
			}
			if err := a.run(t); (err != nil) != recovery {
				t.Fatal("setup", err)
			}
			if err := a.signer.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			a.signer, err = OpenAuditedSignerWithPolicySource(a.ctx, a.dir, a.options, l.installed, l.digest, l.source, l.clock, a.policy, a.trust, a.backend)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.signer.Fetch(a.id()); err == nil {
				t.Fatal("restart released without original leases")
			}
			if _, err := a.signer.Reconcile(a.id()); err == nil {
				t.Fatal("restart recovered without original leases")
			}
			if err := a.signer.Sign(a.ctx, a.capture.job); err == nil || a.backend.signs != 1 || a.backend.releases != 0 || a.backend.reconciles != 0 {
				t.Fatal("restart resumed or resigned")
			}
		})
	}
}
