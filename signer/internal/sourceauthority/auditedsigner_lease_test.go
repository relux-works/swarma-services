package sourceauthority

import (
	"context"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

// Advance the real fixture clock at fsync/authentication, leaving source
// observations and the production adapter intact. Each expiring lease has a
// valid neighbor with identical delay and endpoint behavior.
func TestAuditedSignerLeaseAtEveryBackendEntry(t *testing.T) {
	for _, path := range []string{"intent-sign", "peer-sign", "peer-verify", "peer-recover", "peer-release"} {
		for _, lease := range []struct {
			name                 string
			build, sign, current int64
			delay                time.Duration
			allowed              bool
		}{
			{"short-valid", 300, 300, 1, 0, true},
			{"delayed-valid", 300, 300, 300, 2 * time.Second, true},
			{"current-expired", 300, 300, 1, 2 * time.Second, false},
			{"build-expired", 1, 300, 300, 2 * time.Second, false},
			{"sign-expired", 300, 1, 300, 2 * time.Second, false},
			{"all-expired", 300, 300, 1, 300 * time.Second, false},
		} {
			t.Run(path+"/"+lease.name, func(t *testing.T) {
				a := newAuditAdapterFixture(t)
				latest := int64(300) // Set up recovery/fetch with a valid original sign.
				a.e.f.s.change = func(_ context.Context, _ Query, o *Observation) {
					ttl := latest
					switch len(a.e.f.s.queries) {
					case 1:
						ttl = lease.build
					case 2:
						ttl = lease.sign
					}
					o.ObservedAt = a.e.f.c.r.Wall.Unix()
					o.Lookup.ObservedAt = o.ObservedAt
					o.ExpiresAt = o.ObservedAt + ttl
				}
				isSign := path == "intent-sign" || path == "peer-sign"
				if !isSign {
					if path == "peer-recover" {
						a.backend.signErr = errAuditFixture
					}
					err := a.run(t)
					if (err != nil) != (path == "peer-recover") {
						t.Fatalf("setup: %v", err)
					}
					a.backend.signErr = nil
				}
				latest = lease.current
				advance := func() { a.e.f.c.advance(lease.delay) }
				if path == "intent-sign" {
					a.profile.hook = func(kind string) {
						if kind == "intent" {
							advance()
						}
					}
				} else {
					fetchChecks := 0
					a.trust.change = func(p signingaudit.Phase, _ signingaudit.Operation) error {
						if p == signingaudit.Fetch {
							fetchChecks++
						}
						if path == "peer-sign" && p == signingaudit.Presign ||
							path == "peer-recover" && p == signingaudit.Recovery ||
							path == "peer-verify" && fetchChecks == 1 ||
							path == "peer-release" && fetchChecks == 2 {
							a.backend.peerHook = func() {
								a.backend.peerHook = nil
								advance()
							}
						}
						return nil
					}
				}
				beforeQueries := len(a.e.f.s.queries)
				var err error
				var entered, wantQueries int
				switch path {
				case "intent-sign", "peer-sign":
					err = a.run(t)
					entered, wantQueries = a.backend.signs, 3
				case "peer-recover":
					_, err = a.signer.Reconcile(a.id())
					entered, wantQueries = a.backend.reconciles, 1
				case "peer-verify":
					err = a.signer.Fetch(a.id())
					entered, wantQueries = a.backend.verifies, 1
					if lease.allowed {
						wantQueries = 2
					}
				case "peer-release":
					err = a.signer.Fetch(a.id())
					entered, wantQueries = a.backend.releases, 2
				}
				t.Logf("wall=%d build=%ds sign=%ds current=%ds delay=%s entered=%d err=%v", a.e.f.c.r.Wall.Unix(), lease.build, lease.sign, lease.current, lease.delay, entered, err)
				if lease.allowed {
					if err != nil || entered != 1 {
						t.Fatalf("valid entry: count=%d err=%v", entered, err)
					}
				} else {
					if err == nil || entered != 0 {
						t.Fatalf("expired entry: count=%d err=%v", entered, err)
					}
					a.assertNoRelease(t)
					if isSign {
						op, inspectErr := a.signer.Inspect(a.id())
						if inspectErr != nil || op.State != signingaudit.Uncertain || !a.profile.has(op.ID, "intent") {
							t.Fatalf("post-intent expiry lost uncertainty: %+v %v", op, inspectErr)
						}
					}
				}
				if got := len(a.e.f.s.queries) - beforeQueries; got != wantQueries {
					t.Fatalf("unexpected requalification: got=%d want=%d", got, wantQueries)
				}
				if !isSign && a.backend.signs != 1 {
					t.Fatal("non-signing path retried signing")
				}
			})
		}
	}
}
