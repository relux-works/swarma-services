package signingaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var errFixture = errors.New("fixture fault")

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func request() Request {
	return Request{"fixture-caller", 1, "request_1", "curator", "curator-core", strings.Repeat("a", 40)}
}
func inputs() Inputs {
	i := Inputs{Tree: strings.Repeat("b", 40), Target: "darwin/arm64", UnsignedBytes: 23}
	i.PolicySHA256 = digest([]byte("policy"))
	i.RecipeSHA256 = digest([]byte("recipe"))
	i.ToolchainSHA256 = digest([]byte("toolchain"))
	i.InputSHA256 = digest([]byte("exact manifest bytes"))
	i.JobSHA256 = digest([]byte("exact job bytes"))
	i.AuthoritySHA256 = digest([]byte("private projection"))
	i.UnsignedSHA256 = digest([]byte("unsigned verified bytes"))
	i.CertificateSHA256 = digest([]byte("fixture public certificate"))
	i.RequirementSHA256 = digest([]byte("fixture requirement blob"))
	return i
}

// Each successful profile call performs a real fsync. Faults happen at the exact
// selected file/directory boundary, with the actual write left on disk.
type faultProfile struct {
	mu       sync.Mutex
	failKind string
	failDir  bool
	durable  []string
}

func (*faultProfile) Name() string { return "local-fsync-fixture-v1" }
func (p *faultProfile) File(f *os.File) error {
	b, err := os.ReadFile(f.Name())
	if err != nil {
		return err
	}
	kind := lastKind(b)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failKind != "" && p.failKind == kind {
		return errFixture
	}
	if err := f.Sync(); err != nil {
		return err
	}
	p.durable = append(p.durable, kind)
	return nil
}
func (p *faultProfile) Directory(f *os.File) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDir {
		return errFixture
	}
	return f.Sync()
}
func (p *faultProfile) fail(kind string) { p.mu.Lock(); p.failKind = kind; p.mu.Unlock() }
func (p *faultProfile) has(kind string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range p.durable {
		if k == kind {
			return true
		}
	}
	return false
}
func lastKind(b []byte) string {
	r := bytes.NewReader(b)
	var last string
	for {
		b, partial, err := readFrame(r)
		if err != nil || partial {
			return last
		}
		var rec record
		if decodeExact(b, &rec) {
			last = rec.Kind
		}
	}
}

type fakeTrust struct {
	deny  atomic.Bool
	calls atomic.Int32
}

func (f *fakeTrust) Check(ctx context.Context, _ Phase, _ Operation) error {
	f.calls.Add(1)
	if f.deny.Load() || ctx.Err() != nil {
		return errFixture
	}
	return nil
}

type fakeEffects struct {
	t            *testing.T
	dir          string
	journal      string
	profile      *faultProfile
	signs        atomic.Int32
	releases     atomic.Int32
	entered      chan struct{}
	proceed      chan struct{}
	signError    bool
	badSignature bool
	verifyHook   func()
}

func (f *fakeEffects) Sign(ctx context.Context, op Operation) (Signed, error) {
	f.signs.Add(1)
	b, err := os.ReadFile(filepath.Join(f.journal, journalName))
	if err != nil {
		return Signed{}, err
	}
	if lastKind(b) != "intent" || !f.profile.has("intent") {
		f.t.Error("SIGN_ENTERED_WITHOUT_DURABLE_INTENT")
	}
	s, err := f.stage(op)
	if err != nil {
		return Signed{}, err
	}
	if f.entered != nil {
		close(f.entered)
	}
	if f.proceed != nil {
		select {
		case <-f.proceed:
		case <-ctx.Done():
			return Signed{}, ctx.Err()
		}
	}
	if f.signError {
		return Signed{}, errFixture
	}
	if f.badSignature {
		s.CertificateSHA256 = digest([]byte("wrong certificate"))
	}
	return s, nil
}
func (f *fakeEffects) stage(op Operation) (Signed, error) {
	b := []byte("fake signed bytes for " + op.ID)
	file, err := os.OpenFile(filepath.Join(f.dir, op.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Signed{}, err
	}
	if _, err = file.Write(b); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		d, e := os.Open(f.dir)
		if e != nil {
			return Signed{}, e
		}
		err = d.Sync()
		_ = d.Close()
	}
	return Signed{digest(b), int64(len(b)), op.Inputs.CertificateSHA256, op.Inputs.RequirementSHA256}, err
}
func (f *fakeEffects) Reconcile(_ context.Context, op Operation) (Signed, error) {
	b, err := os.ReadFile(filepath.Join(f.dir, op.ID))
	if err != nil {
		return Signed{}, err
	}
	return Signed{digest(b), int64(len(b)), op.Inputs.CertificateSHA256, op.Inputs.RequirementSHA256}, nil
}
func (f *fakeEffects) Verify(_ context.Context, op Operation) error {
	b, err := os.ReadFile(filepath.Join(f.dir, op.ID))
	if err != nil {
		return err
	}
	if int64(len(b)) != op.Signed.Bytes || digest(b) != op.Signed.SHA256 {
		return errFixture
	}
	if f.verifyHook != nil {
		f.verifyHook()
	}
	return nil
}
func (f *fakeEffects) Release(_ context.Context, op Operation) error {
	b, err := os.ReadFile(filepath.Join(f.journal, journalName))
	if err != nil {
		return err
	}
	if (lastKind(b) != "outcome" && lastKind(b) != "recovered") || (!f.profile.has("outcome") && !f.profile.has("recovered")) || op.Receipt.Sequence < 3 || !hexValue(op.Receipt.Digest, 64) {
		f.t.Error("RELEASE_ENTERED_WITHOUT_DURABLE_OUTCOME")
	}
	f.releases.Add(1)
	return nil
}

type fixture struct {
	a       *Audit
	dir     string
	p       *faultProfile
	trust   *fakeTrust
	effects *fakeEffects
	opts    Options
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	stage := t.TempDir()
	p := &faultProfile{}
	trust := &fakeTrust{}
	effects := &fakeEffects{t: t, dir: stage, journal: dir, profile: p}
	f := &fixture{dir: dir, p: p, trust: trust, effects: effects, opts: Options{Durability: p, MaxBytes: 1 << 20}}
	f.reopen(t)
	t.Cleanup(func() {
		if f.a != nil {
			if err := f.a.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return f
}
func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	a, err := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
}
func (f *fixture) restart(t *testing.T) {
	t.Helper()
	if err := f.a.Close(); err != nil {
		t.Fatal(err)
	}
	f.a = nil
	f.reopen(t)
}
func accepted(t *testing.T, f *fixture) Operation {
	t.Helper()
	op, err := f.a.Accept(request(), inputs())
	if err != nil {
		t.Fatal(err)
	}
	return op
}
func succeeded(t *testing.T, f *fixture) Operation {
	t.Helper()
	op := accepted(t, f)
	op, err := f.a.Run(context.Background(), op.ID)
	if err != nil || op.State != Succeeded {
		t.Fatalf("Run: %+v %v", op, err)
	}
	return op
}
func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOrderingRetryFetchAndReplay(t *testing.T) {
	f := newFixture(t)
	op := succeeded(t, f)
	if f.effects.signs.Load() != 1 || !f.p.has("accepted") || !f.p.has("intent") || !f.p.has("outcome") {
		t.Fatal("missing ordered effects")
	}
	before, err := os.ReadFile(filepath.Join(f.dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.a.Accept(request(), inputs())
	if err != nil || retry != op {
		t.Fatalf("matching retry: %+v %v", retry, err)
	}
	if err := f.a.Fetch(context.Background(), request().Caller, op.ID); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	retry, err = f.a.Accept(request(), inputs())
	if err != nil || retry != op {
		t.Fatalf("replay: %+v %v", retry, err)
	}
	if err := f.a.Fetch(context.Background(), request().Caller, op.ID); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(f.dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || f.effects.signs.Load() != 1 || f.effects.releases.Load() != 2 {
		t.Fatal("retry/fetch rewrote history or signed")
	}
	_, err = f.a.Inspect("foreign-caller", request().RequestID)
	wantErr(t, err, ErrNotFound)
	wantErr(t, f.a.Fetch(context.Background(), "foreign-caller", op.ID), ErrNotFound)
}

func TestConcurrentSingleFlightAndInspection(t *testing.T) {
	f := newFixture(t)
	op := accepted(t, f)
	f.effects.entered = make(chan struct{})
	f.effects.proceed = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := f.a.Run(context.Background(), op.ID); done <- err }()
	<-f.effects.entered
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			retry, err := f.a.Accept(request(), inputs())
			if err != nil || retry.ID != op.ID || retry.State != Uncertain {
				t.Errorf("retry: %+v %v", retry, err)
			}
		}()
	}
	r := request()
	r.RequestID = "different"
	_, err := f.a.Accept(r, inputs())
	wantErr(t, err, ErrBusy)
	_, err = f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrBusy)
	wantErr(t, f.a.Close(), ErrBusy)
	wantErr(t, f.a.Fetch(context.Background(), r.Caller, op.ID), ErrUncertain)
	wg.Wait()
	close(f.effects.proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.effects.signs.Load() != 1 {
		t.Fatal("duplicate signing")
	}
	// A second operation may be accepted only after the first terminal outcome.
	if _, err = f.a.Accept(r, inputs()); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseRequiresDurableOutcome(t *testing.T) {
	f := newFixture(t)
	op := succeeded(t, f)
	// The release instrument independently reads the real journal and the
	// successful flush receipts at callback entry, without an earlier assertion
	// hiding a forbidden release under a deliberately bypassed outcome flush.
	if err := f.a.Fetch(context.Background(), op.Request.Caller, op.ID); err != nil {
		t.Fatal(err)
	}
	if f.effects.releases.Load() != 1 {
		t.Fatal("valid release neighbor did not run")
	}
}

func TestConcurrentDoubleAcceptance(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same", false: "different"}[same], func(t *testing.T) {
			f := newFixture(t)
			start := make(chan struct{})
			type result struct {
				op  Operation
				err error
			}
			results := make(chan result, 2)
			for n := 0; n < 2; n++ {
				go func(n int) {
					<-start
					r := request()
					if !same && n == 1 {
						r.RequestID = "request_2"
					}
					op, err := f.a.Accept(r, inputs())
					results <- result{op, err}
				}(n)
			}
			close(start)
			first, second := <-results, <-results
			if same {
				if first.err != nil || second.err != nil || first.op.ID != second.op.ID {
					t.Fatalf("same request not deduplicated: %+v %+v", first, second)
				}
			} else {
				if first.err != nil {
					first, second = second, first
				}
				if first.err != nil {
					t.Fatal(first.err)
				}
				wantErr(t, second.err, ErrBusy)
			}
			if f.effects.signs.Load() != 0 {
				t.Fatal("accept signed")
			}
		})
	}
}

func TestChangedSemanticInputsAndPolicyConflict(t *testing.T) {
	f := newFixture(t)
	original := succeeded(t, f)
	requestChanges := []func(*Request){func(r *Request) { r.Version = 2 }, func(r *Request) { r.ProductID = "other" }, func(r *Request) { r.Repository = "other" }, func(r *Request) { r.Commit = strings.Repeat("c", 40) }}
	for n, change := range requestChanges {
		r := request()
		change(&r)
		_, err := f.a.Accept(r, inputs())
		if n == 0 {
			wantErr(t, err, ErrInvalid)
		} else {
			wantErr(t, err, ErrConflict)
		}
	}
	changes := []func(*Inputs){func(i *Inputs) { i.Tree = strings.Repeat("c", 40) }, func(i *Inputs) { i.PolicySHA256 = digest([]byte("new")) }, func(i *Inputs) { i.RecipeSHA256 = digest([]byte("new")) }, func(i *Inputs) { i.ToolchainSHA256 = digest([]byte("new")) }, func(i *Inputs) { i.InputSHA256 = digest([]byte("new")) }, func(i *Inputs) { i.JobSHA256 = digest([]byte("new")) }, func(i *Inputs) { i.AuthoritySHA256 = digest([]byte("new")) }, func(i *Inputs) { i.UnsignedSHA256 = digest([]byte("new")) }, func(i *Inputs) { i.UnsignedBytes++ }, func(i *Inputs) { i.CertificateSHA256 = digest([]byte("new")) }, func(i *Inputs) { i.RequirementSHA256 = digest([]byte("new")) }}
	for _, change := range changes {
		in := inputs()
		change(&in)
		got, err := f.a.Accept(request(), in)
		wantErr(t, err, ErrConflict)
		if got != original {
			t.Fatal("stored inputs changed")
		}
	}
	retry, err := f.a.Accept(request(), inputs())
	if err != nil || retry != original {
		t.Fatal("valid neighbor failed")
	}
	if f.effects.signs.Load() != 1 {
		t.Fatal("retry signed")
	}
}

func TestIntentAndOutcomeFlushFailures(t *testing.T) {
	for _, kind := range []string{"accepted", "intent", "outcome"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			if kind == "accepted" {
				f.p.fail(kind)
				_, err := f.a.Accept(request(), inputs())
				wantErr(t, err, ErrAudit)
				if f.effects.signs.Load() != 0 {
					t.Fatal("accept failure signed")
				}
				return
			}
			op := accepted(t, f)
			f.p.fail(kind)
			_, err := f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrAudit)
			wantErr(t, f.a.Fetch(context.Background(), op.Request.Caller, op.ID), ErrAudit)
			if f.effects.releases.Load() != 0 {
				t.Fatal("OUTCOME_FAILURE_RELEASED")
			}
			if kind == "intent" && f.effects.signs.Load() != 0 {
				t.Fatal("INTENT_FAILURE_SIGNED")
			}
			if kind == "outcome" && f.effects.signs.Load() != 1 {
				t.Fatal("outcome fault did not reach signer")
			}
			_, err = f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrAudit)
			f.p.fail("")
			f.restart(t)
			retry, err := f.a.Accept(request(), inputs())
			if err != nil {
				t.Fatal(err)
			}
			if kind == "intent" {
				if retry.State != Uncertain {
					t.Fatal("persisted intent must remain uncertain")
				}
				_, err = f.a.Run(context.Background(), op.ID)
				wantErr(t, err, ErrUncertain)
			} else {
				// A complete outcome from a failed flush is usable ONLY after Open's
				// successful real replay fsync. It never invokes signing again.
				if retry.State != Succeeded || !f.p.has("outcome") {
					t.Fatal("missing replay durability")
				}
				if err := f.a.Fetch(context.Background(), op.Request.Caller, op.ID); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestWriteFailuresAndPoisonedWriter(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-write", true: "partial-write"}[short], func(t *testing.T) {
			f := newFixture(t)
			op := accepted(t, f)
			f.a.j.write = func(b []byte) (int, error) {
				if short {
					n, err := f.a.j.file.Write(b[:len(b)/2])
					if err != nil {
						return n, err
					}
					return n, io.ErrShortWrite
				}
				return 0, errFixture
			}
			_, err := f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrAudit)
			if f.effects.signs.Load() != 0 {
				t.Fatal("write failure signed")
			}
			_, err = f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrAudit)
			f.restart(t)
			if short {
				r := request()
				r.RequestID = "new"
				_, err = f.a.Accept(r, inputs())
				wantErr(t, err, ErrBusy)
				_, err = f.a.Run(context.Background(), op.ID)
				wantErr(t, err, ErrUncertain)
			}
		})
	}
}

func TestUncertainRecoveryNeverResigns(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-process", true: "restart"}[restart], func(t *testing.T) {
			f := newFixture(t)
			op := accepted(t, f)
			f.effects.signError = true
			_, err := f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrUncertain)
			if restart {
				f.restart(t)
			}
			retry, err := f.a.Accept(request(), inputs())
			if err != nil || retry.State != Uncertain {
				t.Fatalf("uncertainty lost: %+v %v", retry, err)
			}
			_, err = f.a.Run(context.Background(), op.ID)
			wantErr(t, err, ErrUncertain)
			r := request()
			r.RequestID = "another"
			_, err = f.a.Accept(r, inputs())
			wantErr(t, err, ErrBusy)
			wantErr(t, f.a.Fetch(context.Background(), op.Request.Caller, op.ID), ErrUncertain)
			before, err := os.ReadFile(filepath.Join(f.dir, journalName))
			if err != nil {
				t.Fatal(err)
			}
			f.trust.deny.Store(true)
			_, err = f.a.Reconcile(context.Background(), op.ID, f.effects)
			wantErr(t, err, ErrAuthority)
			f.trust.deny.Store(false)
			recovered, err := f.a.Reconcile(context.Background(), op.ID, f.effects)
			if err != nil || recovered.State != Succeeded {
				t.Fatalf("recovery: %+v %v", recovered, err)
			}
			after, err := os.ReadFile(filepath.Join(f.dir, journalName))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(after, before) || len(after) <= len(before) {
				t.Fatal("recovery rewrote history")
			}
			if err := f.a.Fetch(context.Background(), op.Request.Caller, op.ID); err != nil {
				t.Fatal(err)
			}
			if f.effects.signs.Load() != 1 || f.effects.releases.Load() != 1 {
				t.Fatal("RECOVERY_RESIGNED_OR_RELEASE_COUNT")
			}
		})
	}
}

func TestMissingRecoveryArtifactHoldsGate(t *testing.T) {
	f := newFixture(t)
	op := accepted(t, f)
	f.effects.signError = true
	_, err := f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrUncertain)
	if err := os.Remove(filepath.Join(f.effects.dir, op.ID)); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	_, err = f.a.Reconcile(context.Background(), op.ID, f.effects)
	wantErr(t, err, ErrUncertain)
	_, err = f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrUncertain)
	if f.effects.signs.Load() != 1 {
		t.Fatal("absence silently authorized resign")
	}
}

func TestUncertainOperationCannotReenterSigner(t *testing.T) {
	f := newFixture(t)
	op := accepted(t, f)
	f.effects.signError = true
	_, err := f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrUncertain)
	_, err = f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrUncertain)
	if f.effects.signs.Load() != 1 {
		t.Fatal("UNCERTAIN_OPERATION_REENTERED_SIGNER")
	}
	f.restart(t)
	_, err = f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrUncertain)
	if f.effects.signs.Load() != 1 {
		t.Fatal("REPLAYED_INTENT_REENTERED_SIGNER")
	}
}

type panicSigner struct{ effects *fakeEffects }

func (p panicSigner) Sign(ctx context.Context, op Operation) (Signed, error) {
	_, _ = p.effects.Sign(ctx, op)
	panic("fixture panic after possible signing")
}

func TestSignerPanicPreservesUncertainty(t *testing.T) {
	f := newFixture(t)
	op := accepted(t, f)
	f.a.signer = panicSigner{f.effects}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected fixture panic")
			}
		}()
		_, _ = f.a.Run(context.Background(), op.ID)
	}()
	got, err := f.a.Inspect(op.Request.Caller, op.Request.RequestID)
	if err != nil || got.State != Uncertain {
		t.Fatal("panic lost possible effect")
	}
	f.restart(t)
	_, err = f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrUncertain)
	if f.effects.signs.Load() != 1 {
		t.Fatal("panic recovery signed again")
	}
}

func TestCurrentTrustAndArtifactRefusalPreserveHistory(t *testing.T) {
	f := newFixture(t)
	op := succeeded(t, f)
	f.trust.deny.Store(true)
	wantErr(t, f.a.Fetch(context.Background(), op.Request.Caller, op.ID), ErrAuthority)
	f.trust.deny.Store(false)
	f.effects.verifyHook = func() { f.trust.deny.Store(true) }
	wantErr(t, f.a.Fetch(context.Background(), op.Request.Caller, op.ID), ErrAuthority)
	f.effects.verifyHook = nil
	f.trust.deny.Store(false)
	if err := os.WriteFile(filepath.Join(f.effects.dir, op.ID), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	wantErr(t, f.a.Fetch(context.Background(), op.Request.Caller, op.ID), ErrArtifact)
	got, err := f.a.Inspect(op.Request.Caller, op.Request.RequestID)
	if err != nil || got != op {
		t.Fatal("historical success erased")
	}
	if f.effects.releases.Load() != 0 || f.effects.signs.Load() != 1 {
		t.Fatal("refusal effects")
	}
}

func TestPresignRefusalAndCancellation(t *testing.T) {
	f := newFixture(t)
	op := accepted(t, f)
	f.trust.deny.Store(true)
	got, err := f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrAuthority)
	if got.State != Refused || f.effects.signs.Load() != 0 {
		t.Fatal("presign refusal did not prevent sign")
	}
	f.restart(t)
	retry, err := f.a.Accept(request(), inputs())
	if err != nil || retry != got {
		t.Fatal("refusal replay")
	}
	r := request()
	r.RequestID = "next"
	op, err = f.a.Accept(r, inputs())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.a.Run(ctx, op.ID)
	wantErr(t, err, ErrAuthority)
	if f.effects.signs.Load() != 0 {
		t.Fatal("cancelled operation signed")
	}
}

func TestCancellationAfterPossibleSignatureAndWrongPin(t *testing.T) {
	for _, badPin := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "pin"}[badPin], func(t *testing.T) {
			f := newFixture(t)
			op := accepted(t, f)
			if badPin {
				f.effects.badSignature = true
				_, err := f.a.Run(context.Background(), op.ID)
				wantErr(t, err, ErrUncertain)
			} else {
				f.effects.entered = make(chan struct{})
				f.effects.proceed = make(chan struct{})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := f.a.Run(ctx, op.ID); done <- err }()
				<-f.effects.entered
				cancel()
				wantErr(t, <-done, ErrUncertain)
			}
			f.restart(t)
			got, err := f.a.Inspect(op.Request.Caller, op.Request.RequestID)
			if err != nil || got.State != Uncertain {
				t.Fatal("possible signature forgotten")
			}
			wantErr(t, f.a.Fetch(context.Background(), op.Request.Caller, op.ID), ErrUncertain)
		})
	}
}
