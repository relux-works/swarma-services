package sourceauthority

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/artifactsnapshot"
	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

var errAuditFixture = errors.New("inert fixture fault")

type auditFrame struct {
	Kind      string
	Operation signingaudit.Operation
}

func lastAuditFrame(t *testing.T, f *os.File) auditFrame {
	t.Helper()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, st.Size())
	if _, err = f.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	var last auditFrame
	for len(data) >= 4 {
		n := int(binary.BigEndian.Uint32(data))
		data = data[4:]
		if n > len(data) {
			break
		}
		var r auditFrame
		if json.Unmarshal(data[:n], &r) != nil {
			t.Fatal("frame JSON")
		}
		if r.Kind != "" {
			last = r
		}
		data = data[n:]
	}
	return last
}

type adapterDurability struct {
	t      *testing.T
	fail   string
	synced map[string]map[string]bool
	hook   func(string)
}

func (*adapterDurability) Name() string { return "local-fsync-fixture-v1" }
func (p *adapterDurability) File(f *os.File) error {
	r := lastAuditFrame(p.t, f)
	if p.hook != nil {
		p.hook(r.Kind)
	}
	if p.fail != "" && p.fail == r.Kind {
		return errAuditFixture
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if p.synced[r.Operation.ID] == nil {
		p.synced[r.Operation.ID] = map[string]bool{}
	}
	p.synced[r.Operation.ID][r.Kind] = true
	return nil
}
func (*adapterDurability) Directory(f *os.File) error { return f.Sync() }
func (p *adapterDurability) has(id, kind string) bool { return p.synced[id][kind] }

type adapterTrust struct {
	calls  []signingaudit.Phase
	change func(signingaudit.Phase, signingaudit.Operation) error
}

func (t *adapterTrust) Check(_ context.Context, p signingaudit.Phase, op signingaudit.Operation) error {
	t.calls = append(t.calls, p)
	if t.change != nil {
		return t.change(p, op)
	}
	return nil
}

type adapterBackend struct {
	t                                            *testing.T
	profile                                      *adapterDurability
	dir                                          string
	peer                                         string
	signs, reconciles, verifies, releases        int
	signErr, reconcileErr, verifyErr, releaseErr error
	signHook                                     func()
	peerHook                                     func()
	verifyHook                                   func()
	panicSign                                    bool
	badPin                                       bool
	partialRelease                               bool
	released                                     []byte
	op                                           signingaudit.Operation
}

func (b *adapterBackend) Peer(ctx context.Context) (string, error) {
	if b.peerHook != nil {
		b.peerHook()
	}
	return b.peer, nil
}
func (b *adapterBackend) metadata(op signingaudit.Operation) (signingaudit.Signed, error) {
	data, err := os.ReadFile(filepath.Join(b.dir, op.ID))
	if err != nil {
		return signingaudit.Signed{}, err
	}
	cert := op.Inputs.CertificateSHA256
	if b.badPin {
		cert = strings.Repeat("0", 64)
	}
	return signingaudit.Signed{SHA256: digestBytes(data), Bytes: int64(len(data)), CertificateSHA256: cert, RequirementSHA256: op.Inputs.RequirementSHA256}, nil
}
func (b *adapterBackend) SignSnapshot(ctx context.Context, op signingaudit.Operation, snapshot *artifactsnapshot.Snapshot) (signingaudit.Signed, error) {
	b.signs++
	b.op = op
	if !b.profile.has(op.ID, "intent") {
		b.t.Fatal("SIGN WITHOUT FSYNCED EXACT INTENT")
	}
	data := make([]byte, op.Inputs.UnsignedBytes)
	if _, err := snapshot.ReadAt(data, 0); err != nil || digestBytes(data) != op.Inputs.UnsignedSHA256 {
		b.t.Fatal("wrong actual sign input")
	}
	// This is inert staging, never a native signature or production receipt.
	staged := append([]byte("inert signed fixture:"), data...)
	f, err := os.OpenFile(filepath.Join(b.dir, op.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return signingaudit.Signed{}, err
	}
	if _, err = f.Write(staged); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return signingaudit.Signed{}, err
	}
	if b.signHook != nil {
		b.signHook()
	}
	if b.panicSign {
		panic(errAuditFixture)
	}
	signed, err := b.metadata(op)
	if b.badPin {
		signed.CertificateSHA256 = strings.Repeat("0", 64)
	}
	if b.signErr != nil {
		err = b.signErr
	}
	return signed, err
}
func (b *adapterBackend) Reconcile(_ context.Context, op signingaudit.Operation) (signingaudit.Signed, error) {
	b.reconciles++
	if b.reconcileErr != nil {
		return signingaudit.Signed{}, b.reconcileErr
	}
	return b.metadata(op)
}
func (b *adapterBackend) Verify(_ context.Context, op signingaudit.Operation) error {
	b.verifies++
	if b.verifyHook != nil {
		b.verifyHook()
	}
	if b.verifyErr != nil {
		return b.verifyErr
	}
	m, err := b.metadata(op)
	if err != nil {
		return err
	}
	if m != op.Signed {
		return errAuditFixture
	}
	return nil
}
func (b *adapterBackend) Release(_ context.Context, op signingaudit.Operation) error {
	if !b.profile.has(op.ID, "outcome") && !b.profile.has(op.ID, "recovered") {
		b.t.Fatal("RELEASE WITHOUT FSYNCED EXACT OUTCOME")
	}
	b.releases++
	data, err := os.ReadFile(filepath.Join(b.dir, op.ID))
	if err != nil {
		return err
	}
	if b.partialRelease {
		data = data[:len(data)/2]
	}
	b.released = append(b.released, data...)
	return b.releaseErr
}

type captureAuditSigner struct {
	inner           *AuditedSigner
	job             *SignJob
	change          func(*SignJob)
	contextOverride context.Context
}

func (c *captureAuditSigner) Peer(ctx context.Context) (string, error) { return c.inner.Peer(ctx) }
func (c *captureAuditSigner) Sign(ctx context.Context, j *SignJob) error {
	c.job = j
	if c.change != nil {
		c.change(j)
	}
	if c.contextOverride != nil {
		ctx = c.contextOverride
	}
	return c.inner.Sign(ctx, j)
}

type auditAdapterFixture struct {
	e       *effectFixture
	runner  *EffectRunner
	raw     []byte
	signer  *AuditedSigner
	capture *captureAuditSigner
	backend *adapterBackend
	trust   *adapterTrust
	profile *adapterDurability
	dir     string
	options signingaudit.Options
	policy  AuditSignerPolicy
	ctx     context.Context
	cancel  context.CancelFunc
}

func newAuditAdapterFixture(t *testing.T) *auditAdapterFixture {
	t.Helper()
	e, r, raw := newEffectFixture(t)
	p := &adapterDurability{t: t, synced: map[string]map[string]bool{}}
	backend := &adapterBackend{t: t, profile: p, dir: t.TempDir(), peer: e.signPeer}
	dir := t.TempDir()
	for _, d := range []string{dir, backend.dir} {
		if err := os.Chmod(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	trust := &adapterTrust{}
	policy := AuditSignerPolicy{Caller: "fixture-service", Effects: e.policy, CertificateSHA256: strings.Repeat("a", 64), RequirementSHA256: strings.Repeat("b", 64)}
	options := signingaudit.Options{Durability: p, MaxBytes: 1 << 20}
	s, err := OpenAuditedSigner(dir, options, e.f.p, e.f.s, e.f.c, policy, trust, backend)
	if err != nil {
		t.Fatal(err)
	}
	c := &captureAuditSigner{inner: s}
	r.signer = c
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a := &auditAdapterFixture{e: e, runner: r, raw: raw, signer: s, capture: c, backend: backend, trust: trust, profile: p, dir: dir, options: options, policy: policy, ctx: ctx, cancel: cancel}
	t.Cleanup(func() {
		cancel()
		if err := a.signer.Close(); err != nil {
			t.Error(err)
		}
	})
	return a
}
func (a *auditAdapterFixture) run(t *testing.T) error {
	t.Helper()
	return a.runner.Run(a.ctx, effectBody(t, a.raw))
}
func (a *auditAdapterFixture) id() string { return a.e.f.r.OperationID }
func (a *auditAdapterFixture) assertNoRelease(t *testing.T) {
	t.Helper()
	if a.backend.releases != 0 {
		t.Fatal("released forbidden bytes")
	}
	assertSnapshotClosed(t, a.e)
}

func TestAuditedSignerDurableOrderingAndActualBindings(t *testing.T) {
	a := newAuditAdapterFixture(t)
	if err := a.run(t); err != nil {
		t.Fatal(err)
	}
	op, err := a.signer.Inspect(a.id())
	if err != nil {
		t.Fatal(err)
	}
	if op.State != signingaudit.Succeeded || !a.profile.has(op.ID, "accepted") || !a.profile.has(op.ID, "intent") || !a.profile.has(op.ID, "outcome") || a.backend.signs != 1 || a.backend.releases != 0 {
		t.Fatal("ordering or state")
	}
	j := a.capture.job
	if op.Request.RequestID != j.record.Authority.Binding.OperationID || op.Inputs.JobSHA256 != digestBytes(j.build.RawBodyCopy()) || op.Inputs.InputSHA256 != digestBytes(j.build.Manifest().RawBodyCopy()) || op.Inputs.UnsignedSHA256 != j.snapshot.Receipt().SHA256 || op.Inputs.UnsignedBytes != j.snapshot.Receipt().Bytes {
		t.Fatal("binding drift")
	}
	authority, _ := json.Marshal(j.record.Authority)
	if op.Inputs.AuthoritySHA256 != digestBytes(authority) {
		t.Fatal("authority binding")
	}
	if len(a.e.f.s.queries) != 3 {
		t.Fatal("audit presign did not freshly read source")
	}
	for _, b := range a.signer.bindings {
		if b.snapshot != nil {
			t.Fatal("borrowed snapshot retained")
		}
	}
	if err := a.signer.Fetch(a.id()); err != nil {
		t.Fatal(err)
	}
	if a.backend.verifies != 1 || a.backend.releases != 1 || len(a.e.f.s.queries) != 5 || int64(len(a.backend.released)) != op.Signed.Bytes || digestBytes(a.backend.released) != op.Signed.SHA256 {
		t.Fatal("fetch did not verify and refresh twice")
	}
	if err := a.signer.Sign(a.ctx, j); err == nil || a.backend.signs != 1 {
		t.Fatal("repeated Sign retried")
	}
	assertSnapshotClosed(t, a.e)
}

func TestAuditedSignerFlushFailuresAndPartialSign(t *testing.T) {
	for _, kind := range []string{"accepted", "intent", "outcome"} {
		t.Run(kind, func(t *testing.T) {
			a := newAuditAdapterFixture(t)
			a.profile.fail = kind
			if err := a.run(t); err == nil {
				t.Fatal("flush failure accepted")
			}
			want := 0
			if kind == "outcome" {
				want = 1
			}
			if a.backend.signs != want {
				t.Fatal("wrong sign count")
			}
			if err := a.signer.Fetch(a.id()); err == nil {
				t.Fatal("flush failure released")
			}
			if _, err := a.signer.Reconcile(a.id()); err == nil {
				t.Fatal("poisoned writer reconciled")
			}
			if a.capture.job != nil {
				if err := a.signer.Sign(a.ctx, a.capture.job); err == nil {
					t.Fatal("retry accepted")
				}
			}
			if a.backend.signs != want {
				t.Fatal("resigned after flush failure")
			}
			a.assertNoRelease(t)
		})
	}
}

func TestAuditedSignerUncertainRecoveryRefreshesNeverResigns(t *testing.T) {
	a := newAuditAdapterFixture(t)
	a.backend.signErr = errAuditFixture
	if err := a.run(t); err == nil {
		t.Fatal("uncertainty accepted")
	}
	op, _ := a.signer.Inspect(a.id())
	if op.State != signingaudit.Uncertain {
		t.Fatal("uncertainty lost")
	}
	if err := a.signer.Fetch(a.id()); err == nil {
		t.Fatal("uncertain fetch")
	}
	a.e.f.s.observation.PolicyState = Revoked
	if _, err := a.signer.Reconcile(a.id()); err == nil || a.backend.reconciles != 0 {
		t.Fatal("revoked recovery")
	}
	a.e.f.s.observation.PolicyState = Current
	a.backend.reconcileErr = errAuditFixture
	if _, err := a.signer.Reconcile(a.id()); err == nil {
		t.Fatal("missing staging accepted")
	}
	a.backend.reconcileErr = nil
	op, err := a.signer.Reconcile(a.id())
	if err != nil || op.State != signingaudit.Succeeded || a.backend.signs != 1 {
		t.Fatalf("recovery: %v", err)
	}
	a.e.f.s.observation.PolicyState = Revoked
	if err := a.signer.Fetch(a.id()); err == nil {
		t.Fatal("revoked fetch")
	}
	a.e.f.s.observation.PolicyState = Current
	if err := a.signer.Fetch(a.id()); err != nil {
		t.Fatal(err)
	}
	if a.backend.signs != 1 || a.backend.releases != 1 {
		t.Fatal("recovery resigned")
	}
	assertSnapshotClosed(t, a.e)
}

func TestAuditedSignerRestartCannotReconstructOriginalLease(t *testing.T) {
	for _, outcome := range []string{"uncertain", "success", "outcome-flush-failure"} {
		t.Run(outcome, func(t *testing.T) {
			a := newAuditAdapterFixture(t)
			if outcome == "uncertain" {
				a.backend.signErr = errAuditFixture
			}
			if outcome == "outcome-flush-failure" {
				a.profile.fail = "outcome"
			}
			err := a.run(t)
			if outcome == "success" && err != nil {
				t.Fatal(err)
			}
			if err = a.signer.Close(); err != nil {
				t.Fatal(err)
			}
			a.profile.fail = ""
			a.signer, err = OpenAuditedSigner(a.dir, a.options, a.e.f.p, a.e.f.s, a.e.f.c, a.policy, a.trust, a.backend)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.signer.Reconcile(a.id()); err == nil {
				t.Fatal("restart reconstructed lease")
			}
			if err = a.signer.Fetch(a.id()); err == nil {
				t.Fatal("restart fetch without original binding")
			}
			if err = a.signer.Sign(a.ctx, a.capture.job); err == nil {
				t.Fatal("restart reentered signer")
			}
			if a.backend.signs != 1 {
				t.Fatal("restart resigned")
			}
			a.assertNoRelease(t)
		})
	}
}

func TestAuditedSignerTrustAndLateCancellationNegatives(t *testing.T) {
	for _, fault := range []string{"revocation", "stale-head", "changed-policy", "native-trust", "lease-expires-in-trust", "epoch-change", "cancel-in-trust", "cancel-after-intent", "cancel-after-partial-sign", "wrong-pin", "peer-before-sign", "cancel-after-verify", "revoke-after-verify", "expire-after-verify"} {
		t.Run(fault, func(t *testing.T) {
			a := newAuditAdapterFixture(t)
			a.capture.change = func(*SignJob) {
				switch fault {
				case "revocation":
					a.e.f.s.observation.PolicyState = Revoked
				case "stale-head":
					a.e.f.s.observation.Repository.DefaultHead = strings.Repeat("f", 40)
				case "changed-policy":
					a.e.f.s.observation.PolicySHA256 = strings.Repeat("f", 64)
				case "native-trust":
					a.trust.change = func(signingaudit.Phase, signingaudit.Operation) error { return errAuditFixture }
				case "lease-expires-in-trust":
					a.trust.change = func(signingaudit.Phase, signingaudit.Operation) error { a.e.f.c.advance(300 * time.Second); return nil }
				case "epoch-change":
					a.e.f.c.r.Epoch += "-changed"
				case "cancel-in-trust":
					a.trust.change = func(signingaudit.Phase, signingaudit.Operation) error { a.cancel(); return nil }
				case "cancel-after-intent":
					a.profile.hook = func(k string) {
						if k == "intent" {
							a.cancel()
						}
					}
				case "cancel-after-partial-sign":
					a.backend.signHook = a.cancel
				case "wrong-pin":
					a.backend.badPin = true
				case "peer-before-sign":
					a.trust.change = func(signingaudit.Phase, signingaudit.Operation) error { a.backend.peer = "wrong-endpoint"; return nil }
				case "cancel-after-verify":
					a.backend.verifyHook = a.cancel
				case "revoke-after-verify":
					a.backend.verifyHook = func() { a.e.f.s.observation.PolicyState = Revoked }
				case "expire-after-verify":
					a.backend.verifyHook = func() { a.e.f.c.advance(300 * time.Second) }
				}
			}
			err := a.run(t)
			fetchCase := strings.HasSuffix(fault, "after-verify")
			if fetchCase {
				if err != nil {
					t.Fatal(err)
				}
				if err = a.signer.Fetch(a.id()); err == nil {
					t.Fatal("late fetch accepted")
				}
			} else if err == nil {
				t.Fatal("negative sign accepted")
			}
			want := 0
			if fault == "cancel-after-partial-sign" || fault == "wrong-pin" || fetchCase {
				want = 1
			}
			if a.backend.signs != want {
				t.Fatalf("signs=%d want=%d", a.backend.signs, want)
			}
			if _, err = a.signer.Reconcile(a.id()); err == nil && !fetchCase {
				t.Fatal("negative recovery accepted")
			}
			if a.backend.signs != want {
				t.Fatal("negative recovery resigned")
			}
			a.assertNoRelease(t)
		})
	}
}

func TestAuditedSignerRejectsTamperedAndClosedInput(t *testing.T) {
	for _, fault := range []string{"job-bytes", "job-hash", "input-hash", "operation", "snapshot-receipt", "closed-snapshot", "tree", "raw-manifest", "original-lease", "missing-qualification", "peer"} {
		t.Run(fault, func(t *testing.T) {
			a := newAuditAdapterFixture(t)
			a.capture.change = func(j *SignJob) {
				switch fault {
				case "job-bytes":
					j.build.raw = append(j.build.raw, ' ')
				case "job-hash":
					j.record.JobSHA256 = strings.Repeat("0", 64)
				case "input-hash":
					j.record.InputSHA256 = strings.Repeat("0", 64)
				case "operation":
					j.record.Authority.Binding.OperationID = strings.Repeat("0", 32)
				case "snapshot-receipt":
					j.record.Artifact.SHA256 = strings.Repeat("0", 64)
				case "closed-snapshot":
					if err := j.snapshot.Close(); err != nil {
						t.Fatal(err)
					}
				case "tree":
					j.record.Authority.Tree = strings.Repeat("0", 40)
				case "raw-manifest":
					j.build.manifest = effectBody(t, append([]byte(" "), a.raw...))
				case "original-lease":
					j.build.qualification.deadline = a.e.f.c.r.Monotonic
				case "missing-qualification":
					j.qualification = nil
				case "peer":
					j.record.Peer = "foreign"
				}
			}
			if err := a.run(t); err == nil || a.backend.signs != 0 {
				t.Fatal("tampered sign input accepted")
			}
			a.assertNoRelease(t)
		})
	}
}

func TestAuditedSignerPanicCleanupAndNoRetry(t *testing.T) {
	a := newAuditAdapterFixture(t)
	a.backend.panicSign = true
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing fixture panic")
			}
		}()
		_ = a.run(t)
	}()
	op, err := a.signer.Inspect(a.id())
	if err != nil || op.State != signingaudit.Uncertain {
		t.Fatal("panic lost uncertainty")
	}
	if err = a.signer.Sign(a.ctx, a.capture.job); err == nil || a.backend.signs != 1 {
		t.Fatal("panic retried")
	}
	a.backend.panicSign = false
	if _, err = a.signer.Reconcile(a.id()); err != nil {
		t.Fatal(err)
	}
	if a.backend.signs != 1 {
		t.Fatal("panic recovery signed")
	}
	a.assertNoRelease(t)
}

func TestAuditedSignerBackendErrorsAndClosedGate(t *testing.T) {
	for _, fault := range []string{"verify", "release", "partial-release", "peer-fetch"} {
		t.Run(fault, func(t *testing.T) {
			a := newAuditAdapterFixture(t)
			if err := a.run(t); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "verify":
				a.backend.verifyErr = errAuditFixture
			case "release", "partial-release":
				a.backend.releaseErr = errAuditFixture
				a.backend.partialRelease = fault == "partial-release"
			case "peer-fetch":
				a.backend.peer = "wrong"
			}
			if err := a.signer.Fetch(a.id()); err == nil {
				t.Fatal("backend error hidden")
			}
			op, err := a.signer.Inspect(a.id())
			if err != nil || op.State != signingaudit.Succeeded || a.backend.signs != 1 {
				t.Fatal("release changed history")
			}
			if fault == "partial-release" && (len(a.backend.released) == 0 || int64(len(a.backend.released)) != op.Signed.Bytes/2) {
				t.Fatal("partial fixture transfer was not exercised")
			}
			if err = a.signer.Close(); err != nil {
				t.Fatal(err)
			}
			if err = a.signer.Sign(a.ctx, a.capture.job); !errors.Is(err, signingaudit.ErrAudit) {
				t.Fatal("closed sign")
			}
			if _, err = a.signer.Peer(a.ctx); !errors.Is(err, signingaudit.ErrAudit) {
				t.Fatal("closed peer")
			}
			if err = a.signer.Fetch(a.id()); err == nil {
				t.Fatal("closed fetch")
			}
			assertSnapshotClosed(t, a.e)
		})
	}
}

func TestAuditedSignerOriginalContextCannotBeRenewed(t *testing.T) {
	a := newAuditAdapterFixture(t)
	renewed, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a.capture.contextOverride = renewed
	a.capture.change = func(*SignJob) { a.cancel() }
	if err := a.run(t); err == nil || a.backend.signs != 0 {
		t.Fatal("replacement context renewed cancelled job")
	}
	a.assertNoRelease(t)
}

func TestAuditedSignerBusyRetainsWriterAndSnapshot(t *testing.T) {
	a := newAuditAdapterFixture(t)
	entered, proceed, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	a.backend.signHook = func() { close(entered); <-proceed }
	go func() { done <- a.runner.Run(a.ctx, effectBody(t, a.raw)) }()
	<-entered
	if err := a.signer.Close(); !errors.Is(err, signingaudit.ErrBusy) {
		t.Error("closed active journal")
	}
	if _, err := a.signer.Peer(a.ctx); !errors.Is(err, signingaudit.ErrBusy) {
		t.Error("busy peer")
	}
	if err := a.signer.Sign(a.ctx, nil); !errors.Is(err, signingaudit.ErrBusy) {
		t.Error("busy sign")
	}
	if _, err := a.signer.Inspect(a.id()); !errors.Is(err, signingaudit.ErrBusy) {
		t.Error("busy inspect")
	}
	if _, err := a.signer.Reconcile(a.id()); !errors.Is(err, signingaudit.ErrBusy) {
		t.Error("busy recovery")
	}
	if err := a.signer.Fetch(a.id()); !errors.Is(err, signingaudit.ErrBusy) {
		t.Error("busy fetch")
	}
	// A second writer cannot acquire custody while the effect is active.
	other, err := OpenAuditedSigner(a.dir, a.options, a.e.f.p, a.e.f.s, a.e.f.c, a.policy, a.trust, a.backend)
	if err == nil {
		_ = other.Close()
		t.Error("writer custody escaped")
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if a.backend.signs != 1 {
		t.Fatal("concurrency resigned")
	}
	assertSnapshotClosed(t, a.e)
}

func TestAuditedSignerUnknownIdentityAndUnavailableConstruction(t *testing.T) {
	a := newAuditAdapterFixture(t)
	if _, err := a.signer.Inspect("foreign"); !errors.Is(err, signingaudit.ErrNotFound) {
		t.Fatal("foreign inspect")
	}
	if _, err := a.signer.Reconcile("foreign"); !errors.Is(err, signingaudit.ErrNotFound) {
		t.Fatal("foreign recovery")
	}
	if err := a.signer.Fetch("foreign"); !errors.Is(err, signingaudit.ErrNotFound) {
		t.Fatal("foreign fetch")
	}
	bad := a.policy
	bad.Effects.SignerPeer = bad.Effects.BuilderPeer
	if _, err := OpenAuditedSigner(a.dir, a.options, a.e.f.p, a.e.f.s, a.e.f.c, bad, a.trust, a.backend); err == nil {
		t.Fatal("colliding endpoints accepted")
	}
	if _, err := OpenAuditedSigner(a.dir, a.options, a.e.f.p, nil, a.e.f.c, a.policy, a.trust, a.backend); err == nil {
		t.Fatal("absent source accepted")
	}
	if _, err := OpenAuditedSigner(a.dir, a.options, a.e.f.p, a.e.f.s, a.e.f.c, a.policy, nil, a.backend); err == nil {
		t.Fatal("absent native trust accepted")
	}
	if _, err := OpenAuditedSigner(a.dir, a.options, a.e.f.p, a.e.f.s, a.e.f.c, a.policy, a.trust, nil); err == nil {
		t.Fatal("absent endpoint accepted")
	}
	if err := a.signer.Sign(a.ctx, nil); err == nil {
		t.Fatal("missing job accepted")
	}
	if _, err := a.signer.Peer(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	for _, s := range []*AuditedSigner{nil, {}} {
		if err := s.Sign(a.ctx, nil); err == nil {
			t.Fatal("zero sign")
		}
		if _, err := s.Peer(a.ctx); err == nil {
			t.Fatal("zero peer")
		}
		if _, err := s.Inspect("none"); err == nil {
			t.Fatal("zero inspect")
		}
		if _, err := s.Reconcile("none"); err == nil {
			t.Fatal("zero reconcile")
		}
		if err := s.Fetch("none"); err == nil {
			t.Fatal("zero fetch")
		}
		if err := s.Close(); err == nil {
			t.Fatal("zero close")
		}
	}
	a.assertNoRelease(t)
}

func TestAuditedSignerTrustPanicCannotResumePendingOperation(t *testing.T) {
	a := newAuditAdapterFixture(t)
	a.trust.change = func(signingaudit.Phase, signingaudit.Operation) error { panic(errAuditFixture) }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing fixture panic")
			}
		}()
		_ = a.run(t)
	}()
	if a.backend.signs != 0 {
		t.Fatal("trust panic signed")
	}
	op, err := a.signer.Inspect(a.id())
	if err != nil || op.State != signingaudit.Pending {
		t.Fatal("pending acceptance lost")
	}
	a.trust.change = nil
	if _, err = a.signer.Reconcile(a.id()); err == nil {
		t.Fatal("pre-intent panic resumed")
	}
	if err = a.signer.Sign(a.ctx, a.capture.job); err == nil || a.backend.signs != 0 {
		t.Fatal("pending operation resigned")
	}
	a.assertNoRelease(t)
}
