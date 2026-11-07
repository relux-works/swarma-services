// Package signingaudit implements the local ordering and replay boundary for one
// signing operation. It is not a service, source-authority verifier or native signer.
package signingaudit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
)

var (
	ErrInvalid   = errors.New("invalid_request")
	ErrConflict  = errors.New("request_conflict")
	ErrBusy      = errors.New("busy")
	ErrAudit     = errors.New("audit_unavailable")
	ErrUncertain = errors.New("outcome_uncertain")
	ErrAuthority = errors.New("authority_unavailable")
	ErrArtifact  = errors.New("artifact_unavailable")
	ErrNotFound  = errors.New("request_not_found")
	ErrCorrupt   = errors.New("audit_history_invalid")
	ErrLocked    = errors.New("audit_writer_locked")
)

// Request is already authenticated and decoded by the caller. Caller is a trusted
// principal identifier, never a client-asserted UID. Its namespace scopes RequestID.
type Request struct {
	Caller     string
	Version    int
	RequestID  string
	ProductID  string
	Repository string
	Commit     string
}

// Inputs binds verified, retained inputs. The source/job/manifest digests hash
// actual retained bytes, not a reserialization. Policy selects all other values.
// No path, command, key material or provider response belongs here.
type Inputs struct {
	Tree              string
	PolicySHA256      string
	RecipeSHA256      string
	ToolchainSHA256   string
	InputSHA256       string
	JobSHA256         string
	AuthoritySHA256   string
	UnsignedSHA256    string
	UnsignedBytes     int64
	CertificateSHA256 string
	RequirementSHA256 string
	Target            string
}

// Signed is verified metadata for signer-private immutable staging. Returning it
// is a claim by the injected signer/reconciler; Fetch independently calls Verify.
type Signed struct {
	SHA256            string
	Bytes             int64
	CertificateSHA256 string
	RequirementSHA256 string
}

type State string

const (
	Pending   State = "pending"
	Succeeded State = "succeeded"
	Refused   State = "refused"
	Uncertain State = "uncertain"
)

// Operation is a value snapshot. No returned value can mutate the replay index.
type Operation struct {
	ID      string
	Request Request
	Inputs  Inputs
	State   State
	Phase   string
	Signed  Signed
	Receipt Anchor
}

// Anchor supports external checkpoint custody. The journal cannot detect a
// coherent rollback beyond the latest independently retained anchor.
type Anchor struct {
	Sequence uint64
	Digest   string
}

type Phase string

const (
	Presign  Phase = "presign"
	Recovery Phase = "recovery"
	Fetch    Phase = "fetch"
)

// TrustMetadata must check the current protected admission/policy and exact-source
// authority for the stored operation, including fresh bounded qualification and
// clock/restart rules. It must refuse a changed policy or unavailable evidence.
// It must not build, sign, fetch arbitrary destinations or cache authority here.
// Every call is fresh; this package never reuses a lease across calls/restarts.
type TrustMetadata interface {
	Check(context.Context, Phase, Operation) error
}

// Signer must sign only the verified snapshot and verify certificate/DR and final
// bytes. Any error, cancellation or panic after entry means a possible effect.
type Signer interface {
	Sign(context.Context, Operation) (Signed, error)
}

// Reconciler establishes completed child cleanup and verifies existing private
// staging against the recorded intent and current policy. It MUST NOT sign. An
// absent artifact/error never proves that no signature existed.
type Reconciler interface {
	Reconcile(context.Context, Operation) (Signed, error)
}

// Releaser.Verify independently checks immutable stored artifact bytes/hash/size
// and native evidence. Release must emit only those same verified bytes, with the
// installed absolute transfer deadline. Neither method may build or sign.
// Caller must preserve custody between Verify and Release. Release may partially
// transfer on error; the historical outcome remains unchanged.
type Releaser interface {
	Verify(context.Context, Operation) error
	Release(context.Context, Operation) error
}

// Audit owns one locked journal, its replay index and the single active gate.
type Audit struct {
	mu         sync.Mutex
	j          *journal
	byRequest  map[Request]string
	operations map[string]Operation
	active     string
	running    bool
	poisoned   bool
	tailHold   bool
	closed     bool
	trust      TrustMetadata
	signer     Signer
	releaser   Releaser
}

// Open replays a private existing 0700 directory without truncation. All injected
// interfaces and an explicitly selected durability profile are mandatory.
func Open(dir string, options Options, trust TrustMetadata, signer Signer, releaser Releaser) (*Audit, error) {
	if trust == nil || signer == nil || releaser == nil {
		return nil, ErrInvalid
	}
	a := &Audit{byRequest: make(map[Request]string), operations: make(map[string]Operation), trust: trust, signer: signer, releaser: releaser}
	j, err := openJournal(dir, options, a.apply)
	if err != nil {
		return nil, err
	}
	a.j = j
	if a.active != "" {
		op := a.operations[a.active]
		// Even an accepted pre-intent operation is never automatically resumed.
		// Explicit Run is safe only when complete history proves no intent.
		if op.Phase == "signing" || j.torn {
			op.State, op.Phase = Uncertain, "reconciling"
			a.operations[op.ID] = op
		}
	}
	a.tailHold = j.torn
	return a, nil
}

// Accept durably records acceptance before any work. A matching retry only
// returns the stored state. Changed semantic/input/policy/authority values conflict.
func (a *Audit) Accept(req Request, in Inputs) (Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !validRequest(req) || !validInputs(in) {
		return Operation{}, ErrInvalid
	}
	for key, id := range a.byRequest {
		if key.Caller == req.Caller && key.RequestID == req.RequestID {
			op := a.operations[id]
			if key != req || op.Inputs != in {
				return op, ErrConflict
			}
			return op, nil
		}
	}
	if a.unavailable() {
		return Operation{}, ErrAudit
	}
	if a.active != "" || a.tailHold || a.running {
		return Operation{}, ErrBusy
	}
	if !a.j.canAccept() {
		return Operation{}, ErrAudit
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Operation{}, ErrAudit
	}
	op := Operation{ID: hex.EncodeToString(id[:]), Request: req, Inputs: in, State: Pending, Phase: "qualifying"}
	if _, exists := a.operations[op.ID]; exists {
		return Operation{}, ErrAudit
	}
	if err := a.append("accepted", op); err != nil {
		return Operation{}, err
	}
	return a.operations[op.ID], nil
}

// Inspect never invokes authority, signing or release, and hides foreign IDs.
func (a *Audit) Inspect(caller, requestID string) (Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for req, id := range a.byRequest {
		if req.Caller == caller && req.RequestID == requestID {
			return a.operations[id], nil
		}
	}
	if a.tailHold {
		return Operation{}, ErrUncertain
	}
	return Operation{}, ErrNotFound
}

// Run is an explicit once-only continuation of an accepted pre-intent operation.
// It does not release artifact bytes. Client retries must call Accept/Inspect.
func (a *Audit) Run(ctx context.Context, id string) (Operation, error) {
	a.mu.Lock()
	op, ok := a.operations[id]
	if !ok {
		a.mu.Unlock()
		return Operation{}, ErrNotFound
	}
	if a.unavailable() {
		a.mu.Unlock()
		return op, ErrAudit
	}
	if a.running {
		a.mu.Unlock()
		return op, ErrBusy
	}
	if op.State != Pending || op.Phase != "qualifying" || a.tailHold {
		a.mu.Unlock()
		return op, ErrUncertain
	}
	a.running = true
	a.mu.Unlock()
	defer a.stopRunning()
	if err := ctx.Err(); err != nil {
		return a.refuse(op)
	}
	if err := a.trust.Check(ctx, Presign, op); err != nil {
		return a.refuse(op)
	}
	if err := ctx.Err(); err != nil {
		return a.refuse(op)
	}
	a.mu.Lock()
	op.Phase = "signing"
	err := a.append("intent", op) // PRE_SIGN_INTENT: must be durable before callback entry.
	op = a.operations[id]
	a.mu.Unlock()
	if err != nil {
		return op, err
	}
	// Mark uncertainty in memory BEFORE entry, including panic/cancellation paths.
	a.mu.Lock()
	op.State, op.Phase = Uncertain, "reconciling"
	a.operations[id] = op
	a.mu.Unlock()
	signed, err := a.signer.Sign(ctx, op)
	if err != nil || ctx.Err() != nil || !validSigned(signed, op.Inputs) {
		return op, ErrUncertain
	}
	return a.complete(op, signed, "outcome")
}

func (a *Audit) refuse(op Operation) (Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	op.State, op.Phase = Refused, ""
	if err := a.append("refused", op); err != nil {
		return a.operations[op.ID], err
	}
	return a.operations[op.ID], ErrAuthority
}

func (a *Audit) complete(op Operation, signed Signed, kind string) (Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	op.State, op.Phase, op.Signed = Succeeded, "", signed
	if err := a.append(kind, op); err != nil {
		return a.operations[op.ID], err
	}
	return a.operations[op.ID], nil
}

// Reconcile appends verified recovery success without rewriting any prior intent.
// A failed reconciliation preserves the active gate and never calls Sign.
func (a *Audit) Reconcile(ctx context.Context, id string, reconciler Reconciler) (Operation, error) {
	a.mu.Lock()
	op, ok := a.operations[id]
	if !ok {
		a.mu.Unlock()
		return Operation{}, ErrNotFound
	}
	if a.unavailable() {
		a.mu.Unlock()
		return op, ErrAudit
	}
	if a.running {
		a.mu.Unlock()
		return op, ErrBusy
	}
	if reconciler == nil || op.State != Uncertain || a.active != id {
		a.mu.Unlock()
		return op, ErrUncertain
	}
	// A torn tail can hide additional effects/transitions. This candidate refuses
	// reconciliation until a custodian supplies a separately agreed tail protocol.
	if a.tailHold {
		a.mu.Unlock()
		return op, ErrUncertain
	}
	a.running = true
	a.mu.Unlock()
	defer a.stopRunning()
	if ctx.Err() != nil || a.trust.Check(ctx, Recovery, op) != nil {
		return op, ErrAuthority
	}
	signed, err := reconciler.Reconcile(ctx, op)
	if err != nil || ctx.Err() != nil || !validSigned(signed, op.Inputs) {
		return op, ErrUncertain
	}
	return a.complete(op, signed, "recovered")
}

// Fetch separates current release eligibility from immutable historical success.
// It refreshes trust after byte verification immediately before Release.
func (a *Audit) Fetch(ctx context.Context, caller, id string) error {
	a.mu.Lock()
	op, ok := a.operations[id]
	if !ok || op.Request.Caller != caller {
		a.mu.Unlock()
		return ErrNotFound
	}
	if a.unavailable() {
		a.mu.Unlock()
		return ErrAudit
	}
	if a.tailHold || op.State != Succeeded {
		a.mu.Unlock()
		return ErrUncertain
	}
	// Serialize release with Run/Reconcile and Close without queuing callers.
	if a.running {
		a.mu.Unlock()
		return ErrBusy
	}
	a.running = true
	a.mu.Unlock()
	defer a.stopRunning()
	if ctx.Err() != nil || a.trust.Check(ctx, Fetch, op) != nil {
		return ErrAuthority
	}
	if a.releaser.Verify(ctx, op) != nil {
		return ErrArtifact
	}
	if ctx.Err() != nil || a.trust.Check(ctx, Fetch, op) != nil {
		return ErrAuthority
	}
	return a.releaser.Release(ctx, op)
}

// Close refuses to drop the process-wide writer lock while a callback is active.
func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return ErrBusy
	}
	if a.closed {
		return nil
	}
	a.closed = true
	return a.j.close()
}

func (a *Audit) unavailable() bool { return a.closed || a.poisoned }
func (a *Audit) stopRunning()      { a.mu.Lock(); a.running = false; a.mu.Unlock() }

func (a *Audit) append(kind string, op Operation) error {
	r, err := a.j.append(kind, op)
	if err != nil {
		a.poisoned = true
		if a.active != "" {
			old := a.operations[a.active]
			old.State, old.Phase = Uncertain, "reconciling"
			a.operations[old.ID] = old
		}
		return err
	}
	if err := a.apply(r); err != nil {
		a.poisoned = true
		return ErrCorrupt
	}
	return nil
}

func (a *Audit) apply(r record) error {
	op := r.Operation
	if !hexValue(op.ID, 32) || !validRequest(op.Request) || !validInputs(op.Inputs) || op.Receipt != (Anchor{}) {
		return ErrCorrupt
	}
	old, exists := a.operations[op.ID]
	if r.Kind == "accepted" {
		if exists || a.active != "" || op.State != Pending || op.Phase != "qualifying" || op.Signed != (Signed{}) {
			return ErrCorrupt
		}
		for req := range a.byRequest {
			if req.Caller == op.Request.Caller && req.RequestID == op.Request.RequestID {
				return ErrCorrupt
			}
		}
		a.byRequest[op.Request], a.active = op.ID, op.ID
	} else {
		if !exists || a.active != op.ID || old.Request != op.Request || old.Inputs != op.Inputs {
			return ErrCorrupt
		}
		switch r.Kind {
		case "intent":
			if old.State != Pending || old.Phase != "qualifying" || op.State != Pending || op.Phase != "signing" || op.Signed != (Signed{}) {
				return ErrCorrupt
			}
		case "refused":
			if old.State != Pending || old.Phase != "qualifying" || op.State != Refused || op.Phase != "" || op.Signed != (Signed{}) {
				return ErrCorrupt
			}
			a.active = ""
		case "outcome", "recovered":
			if old.Phase != "signing" && old.State != Uncertain {
				return ErrCorrupt
			}
			if op.State != Succeeded || op.Phase != "" || !validSigned(op.Signed, op.Inputs) {
				return ErrCorrupt
			}
			op.Receipt = Anchor{r.Sequence, r.Digest}
			a.active = ""
		default:
			return ErrCorrupt
		}
	}
	a.operations[op.ID] = op
	return nil
}

func validRequest(r Request) bool {
	return boundedASCII(r.Caller, 256) && r.Version == 1 && identifier(r.RequestID, 64) && boundedASCII(r.ProductID, 128) && boundedASCII(r.Repository, 64) && hexValue(r.Commit, 40)
}
func validInputs(i Inputs) bool {
	for _, v := range []string{i.PolicySHA256, i.RecipeSHA256, i.ToolchainSHA256, i.InputSHA256, i.JobSHA256, i.AuthoritySHA256, i.UnsignedSHA256, i.CertificateSHA256, i.RequirementSHA256} {
		if !hexValue(v, 64) {
			return false
		}
	}
	return hexValue(i.Tree, 40) && i.Target == "darwin/arm64" && i.UnsignedBytes > 0 && i.UnsignedBytes <= 268435456
}
func validSigned(s Signed, i Inputs) bool {
	return hexValue(s.SHA256, 64) && s.Bytes > 0 && s.Bytes <= 268435456 && s.CertificateSHA256 == i.CertificateSHA256 && s.RequirementSHA256 == i.RequirementSHA256
}
func hexValue(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func boundedASCII(s string, n int) bool {
	if len(s) == 0 || len(s) > n {
		return false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func identifier(s string, n int) bool {
	if !boundedASCII(s, n) {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
