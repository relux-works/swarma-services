package sourceauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/artifactsnapshot"
	"github.com/relux-works/swarma-services/signer/internal/manifestbody"
)

// These adapters execute only synthetic in-process effects. No native signer,
// provider, production identity or installed resource policy is represented.
type effectFixture struct {
	f                     *fixture
	policy                EffectPolicy
	order                 []string
	buildCalls, signCalls int
	buildPeer, signPeer   string
	buildErr, signErr     error
	auditChange           func(EffectRecord) error
	buildChange           func(*BuildJob)
	peerChange            func()
	job                   *BuildJob
	signJob               *SignJob
	snapshot              *artifactsnapshot.Snapshot
	records               []EffectRecord
	parent                string
	t                     *testing.T
}
type effectBuilder struct{ e *effectFixture }
type effectSigner struct{ e *effectFixture }

func (b effectBuilder) Peer(context.Context) (string, error) {
	b.e.order = append(b.e.order, "builder_peer")
	return b.e.buildPeer, nil
}
func (s effectSigner) Peer(context.Context) (string, error) {
	s.e.order = append(s.e.order, "signer_peer")
	if s.e.peerChange != nil {
		s.e.peerChange()
	}
	return s.e.signPeer, nil
}
func (b effectBuilder) Build(ctx context.Context, j *BuildJob) (*artifactsnapshot.Snapshot, error) {
	e := b.e
	e.order = append(e.order, "build")
	e.buildCalls++
	e.job = j
	if e.buildChange != nil {
		e.buildChange(j)
	}
	if e.buildErr != nil {
		return nil, e.buildErr
	}
	data := []byte("synthetic unsigned artifact")
	h := sha256.Sum256(data)
	r := artifactsnapshot.Receipt{SHA256: hex.EncodeToString(h[:]), Bytes: int64(len(data))}
	reader, writer := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer writer.Close()
		_, _ = writer.Write(append(append([]byte(nil), data...), data...))
	}()
	snapshot, err := artifactsnapshot.Verify(ctx, e.parent, reader, r, r)
	<-done
	e.snapshot = snapshot
	return snapshot, err
}
func (s effectSigner) Sign(_ context.Context, j *SignJob) error {
	s.e.order = append(s.e.order, "sign")
	s.e.signCalls++
	s.e.signJob = j
	var first [1]byte
	if _, err := j.Snapshot().ReadAt(first[:], 0); err != nil {
		return err
	}
	return s.e.signErr
}
func (e *effectFixture) Record(_ context.Context, r EffectRecord) error {
	e.order = append(e.order, "audit_"+string(r.Authority.Binding.Phase))
	e.records = append(e.records, r)
	if e.auditChange != nil {
		return e.auditChange(r)
	}
	return nil
}
func newEffectFixture(t *testing.T) (*effectFixture, *EffectRunner, []byte) {
	t.Helper()
	f := validFixture(t)
	e := &effectFixture{f: f, policy: EffectPolicy{strings.Repeat("d", 64), strings.Repeat("e", 64), "darwin/arm64", "fixture-builder", "fixture-signer"}, buildPeer: "fixture-builder", signPeer: "fixture-signer", t: t, parent: t.TempDir()}
	if err := os.Chmod(e.parent, 0700); err != nil {
		t.Fatal(err)
	}
	f.s.change = func(_ context.Context, q Query, _ *Observation) { e.order = append(e.order, "source_"+string(q.Phase)) }
	r, err := NewEffectRunner(f.p, f.s, f.c, e.policy, effectBuilder{e}, effectSigner{e}, e)
	if err != nil {
		t.Fatal(err)
	}
	// Literal independent BODY shape. Empty DATA and synthetic digests do not
	// qualify a source closure; the fixture backend has no native capability.
	raw := []byte(fmt.Sprintf(`{ "version":1,"operation_id":%q,"transfer_id":"11111111111111111111111111111111","commit":%q,"tree":%q,"policy_sha256":%q,"recipe_sha256":%q,"toolchain_sha256":%q,"entries":[{"root":"source","path":"go.mod","kind":"file","mode":"100644","size":0,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","link_target":""}],"module_receipt":{"source_go_mod_sha256":"1111111111111111111111111111111111111111111111111111111111111111","source_go_sum_sha256":"2222222222222222222222222222222222222222222222222222222222222222","modules":[]},"data_bytes":0}`, f.r.OperationID, f.r.Commit, strings.Repeat("1", 40), f.p.SHA256, e.policy.RecipeSHA256, e.policy.ToolchainSHA256))
	return e, r, raw
}
func effectBody(t *testing.T, raw []byte) *manifestbody.UnqualifiedOpcode34Body {
	t.Helper()
	body, err := manifestbody.DecodeOpcode34BodyShape(raw)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func effectContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func assertEffectRefusal(t *testing.T, err error, predicate string) {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Predicate() != predicate {
		t.Fatalf("wanted %s, got %v", predicate, err)
	}
}
func assertSnapshotClosed(t *testing.T, e *effectFixture) {
	t.Helper()
	if e.snapshot != nil {
		if _, err := e.snapshot.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
			t.Fatal("snapshot leaked")
		}
	}
	files, err := os.ReadDir(e.parent)
	if err != nil || len(files) != 0 {
		t.Fatal("staging remains")
	}
}

func TestEffectRunnerFreshReadsAndExactRetainedBytes(t *testing.T) {
	e, r, raw := newEffectFixture(t)
	body := effectBody(t, raw)
	if err := r.Run(effectContext(t), body); err != nil {
		t.Fatal(err)
	}
	want := []string{"builder_peer", "source_prebuild", "audit_prebuild", "build", "signer_peer", "source_presign", "audit_presign", "sign"}
	if !reflect.DeepEqual(e.order, want) {
		t.Fatalf("effect ordering: %v", e.order)
	}
	if e.buildCalls != 1 || e.signCalls != 1 || len(e.f.s.queries) != 2 || e.f.s.queries[0].Nonce == e.f.s.queries[1].Nonce {
		t.Fatal("phases did not independently refresh")
	}
	if !bytes.Equal(e.job.Manifest().RawBodyCopy(), raw) {
		t.Fatal("manifest reserialized")
	}
	var job map[string]json.RawMessage
	if err := json.Unmarshal(e.job.RawBodyCopy(), &job); err != nil {
		t.Fatal(err)
	}
	keys := []string{"version", "operation_id", "nonce", "product_id", "repository", "commit", "tree", "policy_sha256", "recipe_sha256", "toolchain_sha256", "target", "input_sha256", "authority"}
	if len(job) != len(keys) {
		t.Fatal("job member set changed")
	}
	for _, k := range keys {
		if _, ok := job[k]; !ok {
			t.Fatalf("missing job field %s", k)
		}
	}
	var lease map[string]int64
	if err := json.Unmarshal(job["authority"], &lease); err != nil || len(lease) != 2 || lease["observed_at"] != e.f.s.observation.ObservedAt || lease["expires_at"] != e.f.s.observation.ExpiresAt {
		t.Fatal("job lease changed")
	}
	h := sha256.Sum256(e.job.RawBodyCopy())
	input := sha256.Sum256(raw)
	first, last := e.records[0], e.records[1]
	if first.JobSHA256 != hex.EncodeToString(h[:]) || first.InputSHA256 != hex.EncodeToString(input[:]) || last.JobSHA256 != first.JobSHA256 || last.InputSHA256 != first.InputSHA256 || last.Artifact != e.snapshot.Receipt() || e.signJob.Build() != e.job || last.Authority.Binding.Phase != Presign {
		t.Fatal("audit/job/artifact correlation changed")
	}
	copy := e.job.RawBodyCopy()
	copy[0] ^= 1
	if bytes.Equal(copy, e.job.RawBodyCopy()) {
		t.Fatal("mutable job exposure")
	}
	for i, q := range e.f.s.queries {
		if q.OperationID != e.f.r.OperationID || q.Product != e.f.p.Product || q.Repository != e.f.p.Alias || q.Commit != e.f.r.Commit || q.PolicySHA256 != e.f.p.SHA256 || q.Nonce == e.f.r.Nonce || len(q.Nonce) != 64 || q != e.records[i].Authority.Binding {
			t.Fatal("boundary request drift")
		}
	}
	assertSnapshotClosed(t, e)
}

func TestEffectRunnerPresignRevocationBlocksSign(t *testing.T) {
	for _, change := range []string{"policy", "review", "check", "clock", "provider"} {
		t.Run(change, func(t *testing.T) {
			e, r, raw := newEffectFixture(t)
			e.buildChange = func(*BuildJob) {
				switch change {
				case "policy":
					e.f.s.observation.PolicyState = Revoked
				case "review":
					e.f.s.observation.Reviews.Records[0].State = "withdrawn"
				case "check":
					e.f.s.observation.Checks.Records[0].Result = "failure"
				case "clock":
					e.f.c.err = errors.New("synthetic unavailable")
				case "provider":
					e.f.s.err = errors.New("synthetic unavailable")
				}
			}
			if err := r.Run(effectContext(t), effectBody(t, raw)); err == nil || e.buildCalls != 1 || e.signCalls != 0 || len(e.records) != 1 {
				t.Fatal("presign failure reached sign")
			}
			if change != "clock" && len(e.f.s.queries) != 2 {
				t.Fatal("presign read was bypassed")
			}
			assertSnapshotClosed(t, e)
		})
	}
}

func TestEffectRunnerRefusalsBeforeEffects(t *testing.T) {
	for _, name := range []string{"policy", "recipe", "toolchain", "tree", "builder_peer", "signer_peer", "audit_build", "audit_sign", "expiry_build", "expiry_sign", "cancel_audit", "build_error", "sign_error", "repeat_nonce", "entropy"} {
		t.Run(name, func(t *testing.T) {
			e, r, raw := newEffectFixture(t)
			predicate := "effect_input_binding"
			builds, signs := 0, 0
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			switch name {
			case "policy":
				raw = bytes.Replace(raw, []byte(e.f.p.SHA256), []byte(strings.Repeat("9", 64)), 1)
			case "recipe":
				raw = bytes.Replace(raw, []byte(e.policy.RecipeSHA256), []byte(strings.Repeat("9", 64)), 1)
			case "toolchain":
				raw = bytes.Replace(raw, []byte(e.policy.ToolchainSHA256), []byte(strings.Repeat("9", 64)), 1)
			case "tree":
				raw = bytes.Replace(raw, []byte(strings.Repeat("1", 40)), []byte(strings.Repeat("9", 40)), 1)
				predicate = "effect_tree_binding"
			case "builder_peer":
				e.buildPeer = "foreign"
				predicate = "effect_peer"
			case "signer_peer":
				e.signPeer = "foreign"
				predicate = "effect_peer"
				builds = 1
			case "audit_build", "audit_sign":
				predicate = "boundary_audit"
				phase := Prebuild
				if name == "audit_sign" {
					phase = Presign
					builds = 1
				}
				e.auditChange = func(record EffectRecord) error {
					if record.Authority.Binding.Phase == phase {
						return errors.New("synthetic audit failure")
					}
					return nil
				}
			case "expiry_build", "expiry_sign":
				predicate = "lease_clock"
				phase := Prebuild
				if name == "expiry_sign" {
					phase = Presign
					builds = 1
				}
				e.auditChange = func(record EffectRecord) error {
					if record.Authority.Binding.Phase == phase {
						e.f.c.advance(300 * time.Second)
					}
					return nil
				}
			case "cancel_audit":
				predicate = "job_deadline"
				e.auditChange = func(EffectRecord) error { cancel(); return nil }
			case "build_error":
				predicate = "build_effect"
				builds = 1
				e.buildErr = errors.New("synthetic build failure")
			case "sign_error":
				predicate = "sign_effect"
				builds = 1
				signs = 1
				e.signErr = errors.New("synthetic sign failure")
			case "repeat_nonce":
				predicate = "service_nonce"
				builds = 1
				r.entropy = func(b []byte) (int, error) { clear(b); return len(b), nil }
			case "entropy":
				predicate = "service_nonce"
				r.entropy = func([]byte) (int, error) { return 0, errors.New("synthetic entropy failure") }
			}
			err := r.Run(ctx, effectBody(t, raw))
			assertEffectRefusal(t, err, predicate)
			if e.buildCalls != builds || e.signCalls != signs {
				t.Fatalf("unexpected effects: build=%d sign=%d", e.buildCalls, e.signCalls)
			}
			assertSnapshotClosed(t, e)
		})
	}
}

func TestEffectRunnerOriginalJobDeadlineAndBusy(t *testing.T) {
	e, r, raw := newEffectFixture(t)
	body := effectBody(t, raw)
	for _, ctx := range []context.Context{nil, context.Background()} {
		assertEffectRefusal(t, r.Run(ctx, body), "job_deadline")
	}
	long, cancel := context.WithTimeout(context.Background(), 601*time.Second)
	defer cancel()
	assertEffectRefusal(t, r.Run(long, body), "job_deadline")
	ctx, stop := context.WithCancel(effectContext(t))
	stop()
	assertEffectRefusal(t, r.Run(ctx, body), "job_deadline")
	r.slot <- struct{}{}
	assertEffectRefusal(t, r.Run(effectContext(t), body), "effect_busy")
	<-r.slot
	if e.buildCalls != 0 || e.signCalls != 0 || len(e.f.s.queries) != 0 {
		t.Fatal("invalid job reached effects")
	}
}
