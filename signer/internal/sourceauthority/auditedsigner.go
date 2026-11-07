package sourceauthority

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/artifactsnapshot"
	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

// SnapshotSigner is a trusted fixed, authenticated endpoint. SignSnapshot must
// consume only the supplied verified snapshot, retain immutable private staging,
// and verify native admission, certificate/DR and final bytes. Peer authenticates
// that same endpoint for every method; it must not select a caller endpoint.
// Reconcile, Verify and Release MUST NOT sign. No native implementation is supplied.
type SnapshotSigner interface {
	Peer(context.Context) (string, error)
	SignSnapshot(context.Context, signingaudit.Operation, *artifactsnapshot.Snapshot) (signingaudit.Signed, error)
	signingaudit.Reconciler
	signingaudit.Releaser
}

// AuditSignerPolicy comes only from protected configuration. Caller is the
// authenticated service principal, never a release-request field. Certificate
// and requirement digests select already admitted native evidence, not keys.
type AuditSignerPolicy struct {
	Caller                               string
	Effects                              EffectPolicy
	CertificateSHA256, RequirementSHA256 string
}

type auditBinding struct {
	ctx         context.Context
	request     signingaudit.Request
	inputs      signingaudit.Inputs
	build, sign *Qualification
	current     *Qualification
	phase       signingaudit.Phase
	snapshot    *artifactsnapshot.Snapshot // borrowed only during Sign; never owned
}

// AuditedSigner composes EffectRunner's SignerEffect with the existing journal.
// It retains original job contexts/leases in memory. After restart it refuses
// continuation without that binding: a journal digest cannot reconstruct a lease.
// Missing bindings never permit Sign, Reconcile or Fetch. This is a source seam,
// not an installed signer, native readiness grant, or production durability claim.
type AuditedSigner struct {
	mu          sync.Mutex
	authority   *Authority
	policy      AuditSignerPolicy
	backend     SnapshotSigner
	nativeTrust signingaudit.TrustMetadata
	audit       *signingaudit.Audit
	bindings    map[string]*auditBinding
	lastNonce   string
	closed      bool
}

var _ SignerEffect = (*AuditedSigner)(nil)

// OpenAuditedSigner binds all privileged dependencies once, outside requests.
// nativeTrust must freshly check current protected native admission/policy on
// every call, including recovery/fetch. Source separately refreshes exact-source
// authority. Options and directory follow signingaudit's existing contract.
func OpenAuditedSigner(dir string, options signingaudit.Options, p Policy, source Source, clock Clock, policy AuditSignerPolicy, nativeTrust signingaudit.TrustMetadata, backend SnapshotSigner) (*AuditedSigner, error) {
	a, err := New(p, source, clock)
	if err != nil {
		return nil, err
	}
	e := policy.Effects
	if !ascii(policy.Caller, 256) || !text(e.BuilderPeer, 256) || !text(e.SignerPeer, 256) || e.BuilderPeer == e.SignerPeer || !lowerHex(e.RecipeSHA256, 64) || !lowerHex(e.ToolchainSHA256, 64) || e.Target != "darwin/arm64" || !lowerHex(policy.CertificateSHA256, 64) || !lowerHex(policy.RequirementSHA256, 64) || nativeTrust == nil || backend == nil {
		return nil, signingaudit.ErrInvalid
	}
	s := &AuditedSigner{authority: a, policy: policy, backend: backend, nativeTrust: nativeTrust, bindings: make(map[string]*auditBinding)}
	s.audit, err = signingaudit.Open(dir, options, auditTrust{s}, auditSign{s}, auditRelease{s})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *AuditedSigner) Peer(ctx context.Context) (string, error) {
	if s == nil || s.audit == nil || ctx == nil {
		return "", signingaudit.ErrInvalid
	}
	if !s.mu.TryLock() {
		return "", signingaudit.ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return "", signingaudit.ErrAudit
	}
	if err := peer(ctx, s.backend.Peer, s.policy.Effects.SignerPeer); err != nil {
		return "", err
	}
	return s.policy.Effects.SignerPeer, nil
}

// Sign durably accepts exact locally computed bindings, then asks Audit.Run to
// refresh trust and persist intent before callback entry. It never releases bytes.
// Existing requests are inspected, never resumed by a repeated Sign invocation.
func (s *AuditedSigner) Sign(ctx context.Context, job *SignJob) error {
	if s == nil || s.audit == nil || ctx == nil {
		return signingaudit.ErrInvalid
	}
	if !s.mu.TryLock() {
		return signingaudit.ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return signingaudit.ErrAudit
	}
	b, err := s.bind(ctx, job)
	if err != nil {
		return err
	}
	if _, err := s.audit.Inspect(s.policy.Caller, b.request.RequestID); !errors.Is(err, signingaudit.ErrNotFound) {
		if err != nil {
			return err
		}
		return signingaudit.ErrUncertain
	}
	// Retain only scalar identity, qualifications and original context. Raw bodies
	// are hashed before acceptance; the borrowed snapshot is dropped on every exit.
	defer func() { b.snapshot = nil }()
	op, err := s.audit.Accept(b.request, b.inputs)
	if err != nil {
		return err
	}
	s.bindings[op.ID] = b
	_, err = s.audit.Run(b.ctx, op.ID)
	return err
}

func (s *AuditedSigner) bind(ctx context.Context, j *SignJob) (*auditBinding, error) {
	if ctx.Err() != nil || j == nil || j.build == nil || j.build.ctx == nil {
		return nil, signingaudit.ErrInvalid
	}
	// The public effect interface cannot replace or renew the context retained
	// when the service constructed opcode17, including its cancellation signal.
	ctx = j.build.ctx
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || time.Until(deadline) > 600*time.Second || j == nil || j.build == nil || j.snapshot == nil || j.qualification == nil || j.build.qualification == nil || j.build.manifest == nil {
		return nil, signingaudit.ErrInvalid
	}
	br, r := j.build.record, j.record
	bs, bok := j.build.qualification.Summary()
	ss, sok := j.qualification.Summary()
	if !bok || !sok || bs != br.Authority || ss != r.Authority || bs.Binding.Phase != Prebuild || ss.Binding.Phase != Presign || bs.Binding.Nonce == ss.Binding.Nonce {
		return nil, signingaudit.ErrInvalid
	}
	if s.authority.github != nil && bs.PlatformReviewID != ss.PlatformReviewID {
		return nil, signingaudit.ErrAuthority
	}
	if j.build.qualification.CheckFreshness() != nil || j.qualification.CheckFreshness() != nil {
		return nil, signingaudit.ErrAuthority
	}
	m := j.build.manifest.ManifestCopy()
	if m == nil {
		return nil, signingaudit.ErrInvalid
	}
	p, e := s.authority.policy, s.policy.Effects
	pre, post := bs.Binding.Request, ss.Binding.Request
	post.Nonce = pre.Nonce
	if pre != post || !validRequest(pre, p) || pre.OperationID != m.OperationID || pre.Commit != m.Commit || bs.Tree != m.Tree || ss.Tree != m.Tree || m.PolicySHA256 != p.SHA256 || m.RecipeSHA256 != e.RecipeSHA256 || m.ToolchainSHA256 != e.ToolchainSHA256 {
		return nil, signingaudit.ErrConflict
	}
	var body jobBody
	if json.Unmarshal(j.build.raw, &body) != nil {
		return nil, signingaudit.ErrInvalid
	}
	input := digestBytes(j.build.manifest.RawBodyCopy())
	rawhash, present := j.build.manifest.ComputedRawSHA256()
	expected := jobBody{1, m.OperationID, pre.Nonce, p.Product, p.Alias, m.Commit, m.Tree, p.SHA256, e.RecipeSHA256, e.ToolchainSHA256, e.Target, input, jobLease{bs.ObservedAt, bs.ExpiresAt}}
	if !present || hex.EncodeToString(rawhash[:]) != input || body != expected || len(j.build.raw) > 16384 {
		return nil, signingaudit.ErrConflict
	}
	jobhash := digestBytes(j.build.raw)
	for _, v := range []EffectRecord{br, r} {
		if v.JobSHA256 != jobhash || v.InputSHA256 != input || v.RecipeSHA256 != e.RecipeSHA256 || v.ToolchainSHA256 != e.ToolchainSHA256 || v.Target != e.Target {
			return nil, signingaudit.ErrConflict
		}
	}
	if br.Peer != e.BuilderPeer || r.Peer != e.SignerPeer || r.Artifact != j.snapshot.Receipt() {
		return nil, signingaudit.ErrConflict
	}
	// Rehash the actual read-only descriptor, not just the builder/caller receipt.
	receipt := j.snapshot.Receipt()
	if receipt.Bytes < 1 || receipt.Bytes > artifactsnapshot.MaxBytes {
		return nil, signingaudit.ErrArtifact
	}
	h := sha256.New()
	var buf [32 << 10]byte
	for offset := int64(0); offset < receipt.Bytes; {
		if ctx.Err() != nil {
			return nil, signingaudit.ErrAuthority
		}
		size := int64(len(buf))
		if receipt.Bytes-offset < size {
			size = receipt.Bytes - offset
		}
		n, err := j.snapshot.ReadAt(buf[:size], offset)
		if err != nil || int64(n) != size {
			return nil, signingaudit.ErrArtifact
		}
		_, _ = h.Write(buf[:n])
		offset += int64(n)
	}
	var extra [1]byte
	if n, err := j.snapshot.ReadAt(extra[:], receipt.Bytes); n != 0 || !errors.Is(err, io.EOF) || hex.EncodeToString(h.Sum(nil)) != receipt.SHA256 {
		return nil, signingaudit.ErrArtifact
	}
	authority, _ := json.Marshal(ss)
	in := signingaudit.Inputs{Tree: m.Tree, PolicySHA256: p.SHA256, RecipeSHA256: e.RecipeSHA256, ToolchainSHA256: e.ToolchainSHA256, InputSHA256: input, JobSHA256: jobhash, AuthoritySHA256: digestBytes(authority), UnsignedSHA256: receipt.SHA256, UnsignedBytes: receipt.Bytes, CertificateSHA256: s.policy.CertificateSHA256, RequirementSHA256: s.policy.RequirementSHA256, Target: e.Target}
	req := signingaudit.Request{Caller: s.policy.Caller, Version: 1, RequestID: m.OperationID, ProductID: p.Product, Repository: p.Alias, Commit: m.Commit}
	return &auditBinding{ctx: ctx, request: req, inputs: in, build: j.build.qualification, sign: j.qualification, snapshot: j.snapshot}, nil
}

func digestBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// matchedBinding authenticates only the exact retained operation identity. It
// performs no fallible clock/read check, so refresh can invalidate earlier
// success before checking either original lease.
func (s *AuditedSigner) matchedBinding(op signingaudit.Operation) (*auditBinding, error) {
	b := s.bindings[op.ID]
	if b == nil || b.request != op.Request || b.inputs != op.Inputs {
		return nil, signingaudit.ErrAuthority
	}
	return b, nil
}

func (s *AuditedSigner) binding(op signingaudit.Operation) (*auditBinding, error) {
	b, err := s.matchedBinding(op)
	if err != nil {
		return nil, err
	}
	if b.ctx.Err() != nil || b.build.CheckFreshness() != nil || b.sign.CheckFreshness() != nil {
		return nil, signingaudit.ErrAuthority
	}
	return b, nil
}

// entry retains the successful current check for this exact operation and phase.
// Call it after every blocking step, directly before entering the backend. The
// current lease supplements both original caps; it never replaces either one.
func (s *AuditedSigner) entry(ctx context.Context, phase signingaudit.Phase, op signingaudit.Operation) (*auditBinding, error) {
	b, err := s.binding(op)
	if err != nil || b.phase != phase || b.current.checkFinalEffectContext(ctx) != nil || b.ctx.Err() != nil || ctx.Err() != nil {
		return nil, signingaudit.ErrAuthority
	}
	return b, nil
}

type auditTrust struct{ s *AuditedSigner }

func (t auditTrust) Check(ctx context.Context, phase signingaudit.Phase, op signingaudit.Operation) error {
	s := t.s
	b, err := s.matchedBinding(op)
	if err != nil {
		return err
	}
	// A failed new check must not leave an older successful check usable.
	b.current, b.phase = nil, ""
	if _, err = s.binding(op); err != nil {
		return err
	}
	if ctx.Err() != nil || peer(ctx, s.backend.Peer, s.policy.Effects.SignerPeer) != nil {
		return signingaudit.ErrAuthority
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return signingaudit.ErrAuthority
	}
	n := hex.EncodeToString(nonce[:])
	if n == s.lastNonce || n == b.sign.summary.Binding.Nonce || n == b.build.summary.Binding.Nonce {
		return signingaudit.ErrAuthority
	}
	s.lastNonce = n
	req := b.sign.summary.Binding.Request
	req.Nonce = n
	q, err := s.authority.BeforeSign(ctx, req)
	if err != nil {
		return err
	}
	summary, _ := q.Summary()
	if s.authority.github != nil && summary.PlatformReviewID != b.sign.summary.PlatformReviewID {
		return signingaudit.ErrAuthority
	}
	if summary.Tree != op.Inputs.Tree {
		return signingaudit.ErrAuthority
	}
	if err = s.nativeTrust.Check(ctx, phase, op); err != nil {
		return err
	}
	// Neither a new authority lease nor a slow trust callback renews the original.
	if _, err = s.binding(op); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return signingaudit.ErrAuthority
	}
	if err = q.CheckFreshness(); err != nil {
		return err
	}
	b.current, b.phase = q, phase
	return nil
}

type auditSign struct{ s *AuditedSigner }

func (a auditSign) Sign(ctx context.Context, op signingaudit.Operation) (signingaudit.Signed, error) {
	b, err := a.s.binding(op)
	if err != nil || ctx.Err() != nil || b.snapshot == nil {
		return signingaudit.Signed{}, signingaudit.ErrAuthority
	}
	if err = peer(ctx, a.s.backend.Peer, a.s.policy.Effects.SignerPeer); err != nil {
		return signingaudit.Signed{}, err
	}
	// Audit has already durably persisted intent. Any failure from this point is
	// possible signing, including panic and cancellation. Audit never retries it.
	if _, err = a.s.entry(ctx, signingaudit.Presign, op); err != nil {
		return signingaudit.Signed{}, signingaudit.ErrAuthority
	}
	return a.s.backend.SignSnapshot(ctx, op, b.snapshot)
}

type auditRelease struct{ s *AuditedSigner }

func (a auditRelease) Verify(ctx context.Context, op signingaudit.Operation) error {
	if _, err := a.s.binding(op); err != nil {
		return err
	}
	if err := peer(ctx, a.s.backend.Peer, a.s.policy.Effects.SignerPeer); err != nil {
		return err
	}
	if _, err := a.s.entry(ctx, signingaudit.Fetch, op); err != nil {
		return err
	}
	return a.s.backend.Verify(ctx, op)
}
func (a auditRelease) Release(ctx context.Context, op signingaudit.Operation) error {
	if _, err := a.s.binding(op); err != nil {
		return err
	}
	if err := peer(ctx, a.s.backend.Peer, a.s.policy.Effects.SignerPeer); err != nil {
		return err
	}
	if _, err := a.s.entry(ctx, signingaudit.Fetch, op); err != nil {
		return signingaudit.ErrAuthority
	}
	if err := a.s.backend.Release(ctx, op); err != nil {
		return signingaudit.ErrArtifact
	}
	return nil
}

type auditReconcile struct{ s *AuditedSigner }

func (a auditReconcile) Reconcile(ctx context.Context, op signingaudit.Operation) (signingaudit.Signed, error) {
	if _, err := a.s.binding(op); err != nil {
		return signingaudit.Signed{}, err
	}
	if err := peer(ctx, a.s.backend.Peer, a.s.policy.Effects.SignerPeer); err != nil {
		return signingaudit.Signed{}, err
	}
	if _, err := a.s.entry(ctx, signingaudit.Recovery, op); err != nil {
		return signingaudit.Signed{}, signingaudit.ErrAuthority
	}
	return a.s.backend.Reconcile(ctx, op)
}

// Reconcile uses ONLY existing signer-private staging, current trust and the
// retained original context/leases. It cannot reconstruct bindings after restart.
func (s *AuditedSigner) Reconcile(requestID string) (signingaudit.Operation, error) {
	if s == nil || s.audit == nil {
		return signingaudit.Operation{}, signingaudit.ErrInvalid
	}
	if !s.mu.TryLock() {
		return signingaudit.Operation{}, signingaudit.ErrBusy
	}
	defer s.mu.Unlock()
	op, err := s.audit.Inspect(s.policy.Caller, requestID)
	if err != nil {
		return op, err
	}
	b, err := s.binding(op)
	if err != nil {
		return op, err
	}
	return s.audit.Reconcile(b.ctx, op.ID, auditReconcile{s})
}

// Fetch delegates durable-outcome gating, independent byte verification and both
// fresh trust checks to the existing Audit. No release occurs inside Sign.
func (s *AuditedSigner) Fetch(requestID string) error {
	if s == nil || s.audit == nil {
		return signingaudit.ErrInvalid
	}
	if !s.mu.TryLock() {
		return signingaudit.ErrBusy
	}
	defer s.mu.Unlock()
	op, err := s.audit.Inspect(s.policy.Caller, requestID)
	if err != nil {
		return err
	}
	b, err := s.binding(op)
	if err != nil {
		return err
	}
	return s.audit.Fetch(b.ctx, s.policy.Caller, op.ID)
}

func (s *AuditedSigner) Inspect(requestID string) (signingaudit.Operation, error) {
	if s == nil || s.audit == nil {
		return signingaudit.Operation{}, signingaudit.ErrInvalid
	}
	if !s.mu.TryLock() {
		return signingaudit.Operation{}, signingaudit.ErrBusy
	}
	defer s.mu.Unlock()
	return s.audit.Inspect(s.policy.Caller, requestID)
}

func (s *AuditedSigner) Close() error {
	if s == nil || s.audit == nil {
		return signingaudit.ErrInvalid
	}
	if !s.mu.TryLock() {
		return signingaudit.ErrBusy
	}
	defer s.mu.Unlock()
	err := s.audit.Close()
	if err == nil {
		s.closed = true
		s.bindings = nil
	}
	return err
}
