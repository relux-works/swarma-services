package sourceauthority

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/artifactsnapshot"
	"github.com/relux-works/swarma-services/signer/internal/manifestbody"
)

// EffectPolicy is protected installed configuration, never a release request.
// Hashes correlate available admitted bytes; they do not admit missing bytes,
// resource enforcement, a toolchain, or either endpoint identity.
type EffectPolicy struct {
	RecipeSHA256, ToolchainSHA256, Target string
	BuilderPeer, SignerPeer               string
}

// BuilderEffect and SignerEffect are trusted, constructor-bound adapters. Peer
// must authenticate the fixed endpoint used by the subsequent effect, not echo
// a requested principal. Implementations must keep that channel/identity fixed
// across Peer and the effect and obey ctx. No production adapters exist here.
// Build must independently verify DATA/closure, native isolation, the complete
// acknowledged job/result exchange and both output streams. A snapshot alone
// is not evidence that those requirements were met.
type BuilderEffect interface {
	Peer(context.Context) (string, error)
	Build(context.Context, *BuildJob) (*artifactsnapshot.Snapshot, error)
}

// Sign must enforce native first admission, immutable staging, signature checks,
// durable intent before signing and durable outcome before release. This source
// fence supplies none of those capabilities and does not release an artifact.
// Compose the existing signingaudit ordering/replay boundary; do not replace it
// with BoundaryAudit or treat a successful callback as a durable outcome.
type SignerEffect interface {
	Peer(context.Context) (string, error)
	Sign(context.Context, *SignJob) error
}

// BoundaryAudit must retain this exact scalar projection before the effect.
// It is not a substitute for the durable native intent/outcome journal. Unknown
// audit completion refuses; the runner does not retry an uncertain effect.
type BoundaryAudit interface {
	Record(context.Context, EffectRecord) error
}

// EffectRecord contains correlation and the existing neutral authority summary.
// It deliberately contains no raw messaging bodies or endpoint credentials.
type EffectRecord struct {
	Authority                             Summary
	JobSHA256, InputSHA256                string
	RecipeSHA256, ToolchainSHA256, Target string
	Peer                                  string
	Artifact                              artifactsnapshot.Receipt
}

// BuildJob owns the exact opcode17 BODY emitted by this service composition.
// It is not a caller-supplied job parser or a new wire format. The immutable
// opcode34 handle retains the actual raw bytes, not a reserialization.
type BuildJob struct {
	raw      []byte
	manifest *manifestbody.UnqualifiedOpcode34Body
	record   EffectRecord
}

func (j *BuildJob) RawBodyCopy() []byte                             { return append([]byte(nil), j.raw...) }
func (j *BuildJob) Manifest() *manifestbody.UnqualifiedOpcode34Body { return j.manifest }
func (j *BuildJob) Record() EffectRecord                            { return j.record }

// SignJob retains the original build job correlation and the owned unsigned
// snapshot while carrying a separately refreshed presign authority/nonce.
type SignJob struct {
	build    *BuildJob
	snapshot *artifactsnapshot.Snapshot
	record   EffectRecord
}

func (j *SignJob) Build() *BuildJob                     { return j.build }
func (j *SignJob) Snapshot() *artifactsnapshot.Snapshot { return j.snapshot }
func (j *SignJob) Record() EffectRecord                 { return j.record }

// EffectRunner binds the verifier and effect adapters once outside request
// handling. It serializes operations and never caches authority across phases.
// There is no installed runtime, provider/key access or native backend here.
type EffectRunner struct {
	authority *Authority
	policy    EffectPolicy
	builder   BuilderEffect
	signer    SignerEffect
	audit     BoundaryAudit
	slot      chan struct{}
	// Serializes nonce generation/state with the one active operation. Keeping
	// the last nonce also makes an entropy-source repetition a finite refusal.
	mu        sync.Mutex
	lastNonce string
	entropy   func([]byte) (int, error)
}

func NewEffectRunner(p Policy, source Source, clock Clock, effects EffectPolicy, builder BuilderEffect, signer SignerEffect, audit BoundaryAudit) (*EffectRunner, error) {
	a, err := New(p, source, clock)
	if err != nil {
		return nil, err
	}
	return newEffectRunner(a, effects, builder, signer, audit)
}

// NewEffectRunnerWithPolicySource selects the protected installed-policy route
// at construction. Both phases and their final freshness checks use the same
// fixed installation path and bound full-file digest; a reinstall requires a
// newly constructed runner. No runtime or production adapter is installed here.
func NewEffectRunnerWithPolicySource(ctx context.Context, installed PolicySource, source Source, clock Clock, effects EffectPolicy, builder BuilderEffect, signer SignerEffect, audit BoundaryAudit) (*EffectRunner, error) {
	a, err := NewWithPolicySource(ctx, installed, source, clock)
	if err != nil {
		return nil, err
	}
	return newEffectRunner(a, effects, builder, signer, audit)
}

func newEffectRunner(a *Authority, effects EffectPolicy, builder BuilderEffect, signer SignerEffect, audit BoundaryAudit) (*EffectRunner, error) {
	if !lowerHex(effects.RecipeSHA256, 64) || !lowerHex(effects.ToolchainSHA256, 64) || effects.Target != "darwin/arm64" || !text(effects.BuilderPeer, 256) || !text(effects.SignerPeer, 256) || effects.BuilderPeer == effects.SignerPeer || builder == nil || signer == nil || audit == nil {
		return nil, unavailable("effect_configuration")
	}
	return &EffectRunner{authority: a, policy: effects, builder: builder, signer: signer, audit: audit, slot: make(chan struct{}, 1), entropy: rand.Read}, nil
}

func (r *EffectRunner) nonce() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b [32]byte
	n, err := r.entropy(b[:])
	if err != nil || n != len(b) {
		return "", unavailable("service_nonce")
	}
	s := hex.EncodeToString(b[:])
	if s == r.lastNonce {
		return "", unavailable("service_nonce")
	}
	r.lastNonce = s
	return s, nil
}

type jobLease struct {
	ObservedAt int64 `json:"observed_at"`
	ExpiresAt  int64 `json:"expires_at"`
}
type jobBody struct {
	Version         uint64   `json:"version"`
	OperationID     string   `json:"operation_id"`
	Nonce           string   `json:"nonce"`
	Product         string   `json:"product_id"`
	Repository      string   `json:"repository"`
	Commit          string   `json:"commit"`
	Tree            string   `json:"tree"`
	PolicySHA256    string   `json:"policy_sha256"`
	RecipeSHA256    string   `json:"recipe_sha256"`
	ToolchainSHA256 string   `json:"toolchain_sha256"`
	Target          string   `json:"target"`
	InputSHA256     string   `json:"input_sha256"`
	Authority       jobLease `json:"authority"`
}

func peer(ctx context.Context, read func(context.Context) (string, error), expected string) error {
	got, err := read(ctx)
	if err != nil || ctx.Err() != nil {
		return unavailable("effect_peer")
	}
	if got != expected {
		return rejected("effect_peer")
	}
	return nil
}

// Run fences one build followed by one sign. Its input is only an existing
// immutable unqualified BODY; no observation, nonce, endpoint, effect callback
// or qualification flag can be supplied per operation. DATA/closure and all
// native gates remain mandatory inside the trusted effect implementations.
// The caller supplies the ORIGINAL finite job context; no deadline is renewed.
// Any error is terminal for this invocation. The durable operation custodian
// must reconcile uncertainty rather than blindly invoking Run again.
func (r *EffectRunner) Run(ctx context.Context, body *manifestbody.UnqualifiedOpcode34Body) (err error) {
	if r == nil || r.authority == nil || r.slot == nil || body == nil {
		return unavailable("effect_configuration")
	}
	if ctx == nil {
		return unavailable("job_deadline")
	}
	if deadline, ok := ctx.Deadline(); !ok || ctx.Err() != nil || time.Until(deadline) > 600*time.Second {
		return unavailable("job_deadline")
	}
	select {
	case r.slot <- struct{}{}:
		defer func() { <-r.slot }()
	default:
		return unavailable("effect_busy")
	}
	m := body.ManifestCopy()
	digest, present := body.ComputedRawSHA256()
	p := r.authority.policy
	if !present || m == nil || m.PolicySHA256 != p.SHA256 || m.RecipeSHA256 != r.policy.RecipeSHA256 || m.ToolchainSHA256 != r.policy.ToolchainSHA256 {
		return rejected("effect_input_binding")
	}
	nonce, err := r.nonce()
	if err != nil {
		return err
	}
	request := Request{m.OperationID, nonce, p.Product, p.Alias, m.Commit, p.SHA256}
	if err = peer(ctx, r.builder.Peer, r.policy.BuilderPeer); err != nil {
		return err
	}
	qualification, err := r.authority.BeforeBuild(ctx, request)
	if err != nil {
		return err
	}
	summary, _ := qualification.Summary()
	if summary.Tree != m.Tree {
		return rejected("effect_tree_binding")
	}
	input := hex.EncodeToString(digest[:])
	raw, err := json.Marshal(jobBody{1, m.OperationID, nonce, p.Product, p.Alias, m.Commit, m.Tree, p.SHA256, m.RecipeSHA256, m.ToolchainSHA256, r.policy.Target, input, jobLease{summary.ObservedAt, summary.ExpiresAt}})
	if err != nil || len(raw) > 16384 {
		return unavailable("job_body")
	}
	h := sha256.Sum256(raw)
	record := EffectRecord{Authority: summary, JobSHA256: hex.EncodeToString(h[:]), InputSHA256: input, RecipeSHA256: m.RecipeSHA256, ToolchainSHA256: m.ToolchainSHA256, Target: r.policy.Target, Peer: r.policy.BuilderPeer}
	job := &BuildJob{raw: raw, manifest: body, record: record}
	if err = r.audit.Record(ctx, record); err != nil {
		return unavailable("boundary_audit")
	}
	if ctx.Err() != nil {
		return unavailable("job_deadline")
	}
	if err = qualification.CheckFreshnessContext(ctx); err != nil {
		return err
	}
	snapshot, err := r.builder.Build(ctx, job)
	// Even a misbehaving adapter returning both a snapshot and an error must
	// not leak its owned storage. Preserve cleanup failure on every path.
	if snapshot != nil {
		defer func() {
			if snapshot.Close() != nil {
				err = errors.Join(err, unavailable("effect_cleanup"))
			}
		}()
	}
	if err != nil {
		return unavailable("build_effect")
	}
	if snapshot == nil || snapshot.Receipt().Bytes == 0 {
		return unavailable("build_snapshot")
	}
	if ctx.Err() != nil {
		return unavailable("job_deadline")
	}
	nonce, err = r.nonce()
	if err != nil {
		return err
	}
	request.Nonce = nonce
	if err = peer(ctx, r.signer.Peer, r.policy.SignerPeer); err != nil {
		return err
	}
	// This is deliberately a new Read, even when the prebuild receipt is fresh.
	qualification, err = r.authority.BeforeSign(ctx, request)
	if err != nil {
		return err
	}
	summary, _ = qualification.Summary()
	if summary.Tree != m.Tree {
		return rejected("effect_tree_binding")
	}
	record.Authority = summary
	record.Peer = r.policy.SignerPeer
	record.Artifact = snapshot.Receipt()
	if err = r.audit.Record(ctx, record); err != nil {
		return unavailable("boundary_audit")
	}
	if ctx.Err() != nil {
		return unavailable("job_deadline")
	}
	if err = qualification.CheckFreshnessContext(ctx); err != nil {
		return err
	}
	if err = r.signer.Sign(ctx, &SignJob{build: job, snapshot: snapshot, record: record}); err != nil {
		return unavailable("sign_effect")
	}
	if ctx.Err() != nil {
		return unavailable("job_deadline")
	}
	return nil
}
