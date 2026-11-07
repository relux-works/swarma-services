package sourceauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// All filesystem material here is a declared synthetic public-policy fixture,
// exclusively inside the test's private temporary tree. No installed config,
// foreign UID credential, native effect or persisted private key is accessed.
func installedFixture(t *testing.T) (*fixture, *ProtectedPolicySource, string, []byte) {
	t.Helper()
	f := validFixture(t)
	b, err := EncodePolicy(f.p)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewProtectedPolicySource(context.Background(), path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	return f, s, path, b
}

func reinstall(t *testing.T, path string, b []byte) {
	t.Helper()
	next := path + ".next"
	if err := os.WriteFile(next, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedPolicyNativeMappingAndOwnership(t *testing.T) {
	f, s, _, raw := installedFixture(t)
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if snap.SHA256() != hex.EncodeToString(h[:]) || snap.PolicyCopy().SHA256 != f.p.SHA256 || snap.SHA256() == f.p.SHA256 {
		t.Fatal("raw and native identity binding")
	}
	copy := snap.PolicyCopy()
	copy.Scopes[0] = "mutated"
	copy.ReviewerSenders[0] = "mutated"
	copy.OwnerKeys[0].PublicKey[0] ^= 1
	rawCopy := snap.RawCopy()
	rawCopy[0] = 'x'
	if !bytes.Equal(snap.RawCopy(), raw) {
		t.Fatal("snapshot aliases raw copy")
	}
	got, err := EncodePolicy(snap.PolicyCopy())
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("snapshot aliases native field copies")
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 12 {
		t.Fatal("native shape changed")
	}
	for _, name := range []string{"Product", "Alias", "CanonicalRepository", "RepositoryName", "DefaultBranch", "SHA256", "MatrixOrigin", "ProducerSender", "ReviewerSenders", "Scopes", "OwnerKeys", "Profile"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("missing native field %s", name)
		}
	}
}

func TestProtectedPolicyStrictCodec(t *testing.T) {
	_, _, _, raw := installedFixture(t)
	cases := map[string][]byte{
		"whitespace":        append(bytes.Clone(raw), '\n'),
		"bom":               append([]byte{0xef, 0xbb, 0xbf}, raw...),
		"unknown":           bytes.Replace(raw, []byte(`{"Alias":`), []byte(`{"Extra":0,"Alias":`), 1),
		"duplicate":         bytes.Replace(raw, []byte(`{"Alias":`), []byte(`{"Alias":"other","Alias":`), 1),
		"escaped_duplicate": bytes.Replace(raw, []byte(`{"Alias":`), []byte(`{"\u0041lias":"other","Alias":`), 1),
		"wrong_case":        bytes.Replace(raw, []byte(`"Alias":`), []byte(`"alias":`), 1),
		"nested_unknown":    bytes.Replace(raw, []byte(`"Profile":{`), []byte(`"Profile":{"Extra":0,`), 1),
		"owner_unknown":     bytes.Replace(raw, []byte(`"OwnerKeys":[{`), []byte(`"OwnerKeys":[{"Extra":0,`), 1),
		"missing":           bytes.Replace(raw, []byte(`"Alias":"fixture-source",`), nil, 1),
		"float":             bytes.Replace(raw, []byte(`"CheckRecords":256`), []byte(`"CheckRecords":256.0`), 1),
		"exponent":          bytes.Replace(raw, []byte(`"CheckRecords":256`), []byte(`"CheckRecords":256e0`), 1),
		"negative_zero":     bytes.Replace(raw, []byte(`"CheckRecords":256`), []byte(`"CheckRecords":-0`), 1),
		"integer_overflow":  bytes.Replace(raw, []byte(`"CheckRecords":256`), []byte(`"CheckRecords":9007199254740992`), 1),
		"surrogate":         bytes.Replace(raw, []byte(`"Alias":"fixture-source"`), []byte(`"Alias":"\ud800"`), 1),
		"invalid_utf8":      append([]byte{'"', 0xff, '"'}, raw...),
		"extra_document":    append(bytes.Clone(raw), []byte(`{}`)...),
		"null":              []byte(`null`),
		"empty":             {},
		"oversize":          bytes.Repeat([]byte{' '}, MaxPolicyBytes+1),
		"invalid_core":      bytes.Replace(raw, []byte(`"Alias":"fixture-source"`), []byte(`"Alias":""`), 1),
	}
	// These controls are canonical ASCII JSON, independently serialized by
	// encoding/json's sorted map writer. Thus their refusal must enforce the
	// exact native shape, rather than just noncanonical ordering or escaping.
	for _, name := range []string{"unknown", "nested_unknown", "owner_unknown", "wrong_case"} {
		var v any
		if err := json.Unmarshal(cases[name], &v); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = b
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, b) {
				t.Fatal("control did not mutate fixture")
			}
			if _, err := DecodePolicy(b); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	// Non-ASCII, HTML characters and Unicode separators use minimal CCJ-1 UTF-8
	// with no normalization, while the core continues to own field validity.
	p, _ := DecodePolicy(raw)
	p.DefaultBranch = "branche-é-<>&-\u2028"
	b, err := EncodePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`\u2028`)) || bytes.Contains(b, []byte(`\u003c`)) || !bytes.Contains(b, []byte(p.DefaultBranch)) {
		t.Fatal("CCJ-1 string encoding")
	}
	q, err := DecodePolicy(b)
	if err != nil || q.DefaultBranch != p.DefaultBranch {
		t.Fatal("native Unicode roundtrip")
	}
}

func TestProtectedPolicyFilesystemRefusals(t *testing.T) {
	tests := map[string]func(*testing.T, *ProtectedPolicySource, string, []byte){
		"mode": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if err := os.Chmod(p, 0640); err != nil {
				t.Fatal(err)
			}
		},
		"special_mode": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if err := os.Chmod(p, 0600|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, _ *ProtectedPolicySource, p string, b []byte) {
			target := p + ".target"
			if err := os.WriteFile(target, b, 0600); err != nil {
				t.Fatal(err)
			}
			if os.Remove(p) != nil || os.Symlink(target, p) != nil {
				t.Fatal("symlink setup")
			}
		},
		"hardlink": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if err := os.Link(p, p+".link"); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if os.Remove(p) != nil || syscall.Mkfifo(p, 0600) != nil {
				t.Fatal("fifo setup")
			}
		},
		"directory": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if os.Remove(p) != nil || os.Mkdir(p, 0700) != nil {
				t.Fatal("directory setup")
			}
		},
		"oversize": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if err := os.Truncate(p, MaxPolicyBytes+1); err != nil {
				t.Fatal(err)
			}
		},
		"empty": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if err := os.Truncate(p, 0); err != nil {
				t.Fatal(err)
			}
		},
		"missing": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		},
		"directory_mode": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			if err := os.Chmod(filepath.Dir(p), 0770); err != nil {
				t.Fatal(err)
			}
		},
		"wrong_expected_uid": func(_ *testing.T, s *ProtectedPolicySource, _ string, _ []byte) { s.uid++ },
		"directory_replaced": func(t *testing.T, _ *ProtectedPolicySource, p string, b []byte) {
			dir := filepath.Dir(p)
			old := dir + ".old"
			if os.Rename(dir, old) != nil || os.Mkdir(dir, 0700) != nil || os.WriteFile(p, b, 0600) != nil {
				t.Fatal("directory replacement setup")
			}
			t.Cleanup(func() { os.RemoveAll(old) })
		},
		"ancestor_symlink": func(t *testing.T, _ *ProtectedPolicySource, p string, _ []byte) {
			dir := filepath.Dir(p)
			old := dir + ".old"
			if os.Rename(dir, old) != nil || os.Symlink(old, dir) != nil {
				t.Fatal("ancestor symlink setup")
			}
			t.Cleanup(func() { os.RemoveAll(old) })
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			_, s, path, raw := installedFixture(t)
			mutate(t, s, path, raw)
			if _, err := s.Snapshot(context.Background()); err == nil {
				t.Fatal("unsafe installed file accepted")
			}
		})
	}
}

func TestProtectedPolicyCancellationAndDeadline(t *testing.T) {
	_, s, path, _ := installedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{ctx, nil} {
		if _, err := s.Snapshot(c); err == nil {
			t.Fatal("cancellation ignored")
		}
		if _, err := NewProtectedPolicySource(c, path, uint32(os.Geteuid())); err == nil {
			t.Fatal("constructor cancellation ignored")
		}
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := s.Snapshot(expired); err == nil {
		t.Fatal("absolute deadline ignored")
	}
	for _, p := range []string{"relative", "/", "/private/../private/policy"} {
		if _, err := NewProtectedPolicySource(context.Background(), p, uint32(os.Geteuid())); err == nil {
			t.Fatal("noncanonical path accepted")
		}
	}
}

func TestProtectedPolicyAtomicUpdateAndOldLease(t *testing.T) {
	f, s, path, _ := installedFixture(t)
	a, err := NewWithPolicySource(context.Background(), s, f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	q, err := a.BeforeBuild(context.Background(), f.r)
	if err != nil {
		t.Fatal(err)
	}
	p := f.p
	p.DefaultBranch = "replacement" // intentionally retain native SHA256
	b, err := EncodePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	reinstall(t, path, b)
	if err := q.CheckFreshness(); !errors.Is(err, ErrRejected) {
		t.Fatalf("old qualification survived installed digest change: %v", err)
	}
	if _, err := a.BeforeSign(context.Background(), f.r); !errors.Is(err, ErrRejected) {
		t.Fatalf("presign reused old policy: %v", err)
	}
	newSnapshot, err := s.Snapshot(context.Background())
	if err != nil || newSnapshot.PolicyCopy().DefaultBranch != "replacement" {
		t.Fatal("atomic reinstall not read")
	}
	if _, err := NewWithPolicySource(context.Background(), s, f.s, f.c); err != nil {
		t.Fatal("legitimate replacement cannot be rebound")
	}
}

func TestProtectedPolicyRacedProviderRead(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		t.Run(string(phase), func(t *testing.T) {
			f, s, path, _ := installedFixture(t)
			a, err := NewWithPolicySource(context.Background(), s, f.s, f.c)
			if err != nil {
				t.Fatal(err)
			}
			f.s.change = func(_ context.Context, _ Query, _ *Observation) {
				p := f.p
				p.Scopes = []string{"!replacement:fixture.invalid"}
				b, err := EncodePolicy(p)
				if err != nil {
					t.Fatal(err)
				}
				reinstall(t, path, b)
			}
			q, err := a.qualify(context.Background(), f.r, phase)
			if q != nil || !errors.Is(err, ErrRejected) {
				t.Fatalf("racing digest allowed qualification: %v", err)
			}
		})
	}
}

func TestProtectedPolicyAtomicRaceNeverHybrid(t *testing.T) {
	f, s, path, first := installedFixture(t)
	p := f.p
	p.DefaultBranch = "other-branch"
	p.Scopes = []string{"!other:fixture.invalid"}
	second, err := EncodePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			select {
			case <-stop:
				return
			default:
			}
			b := first
			if i%2 == 0 {
				b = second
			}
			if err := os.WriteFile(path+".race", b, 0600); err != nil {
				errs <- err
				return
			}
			if err := os.Rename(path+".race", path); err != nil {
				errs <- err
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		snap, err := s.Snapshot(context.Background())
		if err != nil {
			continue
		}
		b := snap.RawCopy()
		if !bytes.Equal(b, first) && !bytes.Equal(b, second) {
			t.Error("torn configuration escaped")
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
	// After activity stops a complete current install must be readable.
	if _, err := s.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedPolicyNoPrivateDiagnostic(t *testing.T) {
	_, s, path, _ := installedFixture(t)
	if err := os.WriteFile(path, []byte(`{"Unrecognized":"PRIVATE_DIAGNOSTIC_SENTINEL"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Snapshot(context.Background())
	if err == nil || strings.Contains(err.Error(), "PRIVATE_DIAGNOSTIC_SENTINEL") || strings.Contains(err.Error(), path) {
		t.Fatal("private diagnostic escaped")
	}
}

// Exercise the public protected effect constructor, rather than manually
// replacing an Authority field. All adapters remain synthetic in-process
// fixtures; no native builder, signer, provider or durable release is invoked.
func TestProtectedPolicyEffectBoundaryReplacement(t *testing.T) {
	for _, point := range []string{"none", "prebuild_audit", "build", "presign_audit"} {
		t.Run(point, func(t *testing.T) {
			e, _, raw := newEffectFixture(t)
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "policy.json")
			b, err := EncodePolicy(e.f.p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			s, err := NewProtectedPolicySource(context.Background(), path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			r, err := NewEffectRunnerWithPolicySource(context.Background(), s, e.f.s, e.f.c, e.policy, effectBuilder{e}, effectSigner{e}, e)
			if err != nil {
				t.Fatal(err)
			}
			replace := func() {
				p := e.f.p
				p.Scopes = []string{"!reinstalled:fixture.invalid"}
				b, err := EncodePolicy(p)
				if err != nil {
					t.Fatal(err)
				}
				reinstall(t, path, b)
			}
			e.auditChange = func(record EffectRecord) error {
				if point == "prebuild_audit" && record.Authority.Binding.Phase == Prebuild || point == "presign_audit" && record.Authority.Binding.Phase == Presign {
					replace()
				}
				return nil
			}
			if point == "build" {
				e.buildChange = func(*BuildJob) { replace() }
			}
			err = r.Run(effectContext(t), effectBody(t, raw))
			if point == "none" {
				if err != nil || e.buildCalls != 1 || e.signCalls != 1 {
					t.Fatalf("protected positive control: %v", err)
				}
			} else {
				if !errors.Is(err, ErrRejected) || e.signCalls != 0 {
					t.Fatalf("replacement reached signer: %v", err)
				}
				if point == "prebuild_audit" && e.buildCalls != 0 {
					t.Fatal("replacement reached builder")
				}
			}
			assertSnapshotClosed(t, e)
		})
	}
}

type deadlinePolicySource struct {
	s         *ProtectedPolicySource
	deadlines []time.Time
}

func (s *deadlinePolicySource) Snapshot(ctx context.Context) (*PolicySnapshot, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("missing deadline")
	}
	s.deadlines = append(s.deadlines, deadline)
	return s.s.Snapshot(ctx)
}

func TestProtectedPolicyOriginalAbsoluteDeadline(t *testing.T) {
	f, s, _, _ := installedFixture(t)
	parentDeadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), parentDeadline)
	defer cancel()
	capture := &deadlinePolicySource{s: s}
	a, err := NewWithPolicySource(ctx, capture, f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	q, err := a.BeforeBuild(ctx, f.r)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.CheckFreshnessContext(ctx); err != nil {
		t.Fatal(err)
	}
	f.r.Nonce = strings.Repeat("f", 64)
	if _, err := a.BeforeSign(ctx, f.r); err != nil {
		t.Fatal(err)
	}
	if len(capture.deadlines) != 6 {
		t.Fatalf("independent installation reads: %d", len(capture.deadlines))
	}
	for _, d := range capture.deadlines {
		if d.After(parentDeadline) {
			t.Fatal("original absolute deadline renewed")
		}
	}
	cancel()
	if err := q.CheckFreshnessContext(ctx); err == nil {
		t.Fatal("effect cancellation ignored")
	}
}

func TestProtectedPolicyExactByteCapacity(t *testing.T) {
	f, s, path, _ := installedFixture(t)
	p := f.p
	room := 255 - len(p.ProducerSender)
	var b []byte
	for i := 0; ; i++ {
		var err error
		b, err = EncodePolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		remaining := MaxPolicyBytes - len(b)
		if remaining <= room {
			p.ProducerSender += strings.Repeat("x", remaining)
			break
		}
		prefix := fmt.Sprintf("@capacity-%d:", i)
		p.ReviewerSenders = append(p.ReviewerSenders, prefix+strings.Repeat("x", 200-len(prefix)))
	}
	b, err := EncodePolicy(p)
	if err != nil || len(b) != MaxPolicyBytes {
		t.Fatalf("exact capacity encoding %d: %v", len(b), err)
	}
	reinstall(t, path, b)
	snap, err := s.Snapshot(context.Background())
	if err != nil || !bytes.Equal(snap.RawCopy(), b) {
		t.Fatalf("exact capacity refused: %v", err)
	}
	if _, err := DecodePolicy(append(b, ' ')); err == nil {
		t.Fatal("capacity plus one accepted")
	}
}
