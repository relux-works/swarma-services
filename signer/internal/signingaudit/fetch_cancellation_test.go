package signingaudit

import (
	"bytes"
	"context"
	"testing"
)

type fetchTrustFunc func(context.Context, Phase, Operation) error

func (f fetchTrustFunc) Check(ctx context.Context, phase Phase, op Operation) error {
	return f(ctx, phase, op)
}

// Claim: cancellation observed before release, including inside a successful
// trust callback, prevents transfer without changing durable signing history.
func TestFetchCancellationBeforeRelease(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cancelAt   string
		wantChecks int
		wantVerify int
	}{
		{"valid", "", 2, 1},
		{"already_cancelled", "before", 0, 0},
		{"initial_trust", "initial", 1, 0},
		{"artifact_verification", "verify", 1, 1},
		{"final_trust", "final", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			op := succeeded(t, f)
			before := journalBytes(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks, verifies := 0, 0
			f.a.trust = fetchTrustFunc(func(ctx context.Context, phase Phase, got Operation) error {
				if phase != Fetch || got != op {
					t.Fatal("fetch trust received wrong phase or historical operation")
				}
				checks++
				if checks == 1 && tc.cancelAt == "initial" || checks == 2 && tc.cancelAt == "final" {
					cancel()
				}
				// Cancellation may race a successful provider result. The audit
				// boundary must check the context again before the next callback.
				return nil
			})
			f.effects.verifyHook = func() {
				verifies++
				if tc.cancelAt == "verify" {
					cancel()
				}
			}
			if tc.cancelAt == "before" {
				cancel()
			}
			err := f.a.Fetch(ctx, op.Request.Caller, op.ID)
			if tc.cancelAt == "" {
				if err != nil || f.effects.releases.Load() != 1 {
					t.Fatalf("valid fetch: error=%v releases=%d", err, f.effects.releases.Load())
				}
			} else {
				if f.effects.releases.Load() != 0 {
					t.Error("cancelled fetch entered release")
				}
				wantErr(t, err, ErrAuthority)
			}
			if checks != tc.wantChecks || verifies != tc.wantVerify {
				t.Fatalf("callbacks: checks=%d verify=%d, want %d/%d", checks, verifies, tc.wantChecks, tc.wantVerify)
			}
			if f.effects.signs.Load() != 1 || !bytes.Equal(before, journalBytes(t, f)) {
				t.Fatal("fetch changed signing history or signed again")
			}
			f.restart(t)
			got, err := f.a.Inspect(op.Request.Caller, op.Request.RequestID)
			if err != nil || got != op {
				t.Fatal("fetch changed historical success on replay")
			}
			f.effects.verifyHook = nil
			prior := f.effects.releases.Load()
			if err := f.a.Fetch(context.Background(), op.Request.Caller, op.ID); err != nil || f.effects.releases.Load() != prior+1 {
				t.Fatalf("fresh fetch after replay: %v", err)
			}
		})
	}
}
