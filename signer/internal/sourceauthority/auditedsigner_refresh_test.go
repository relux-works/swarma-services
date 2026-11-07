package sourceauthority

import (
	"context"
	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
	"testing"
)

// Exercise the actual trust bridge and its retained state. The valid neighbor
// and three downstream failures distinguish clear-on-success from clear-on-error.
func TestReviewRefreshInvalidatesEveryFailure(t *testing.T) {
	for _, fault := range []string{"valid", "source-error", "native-error", "endpoint-error", "original-clock-error"} {
		t.Run(fault, func(t *testing.T) {
			a := newAuditAdapterFixture(t)
			if err := a.run(t); err != nil {
				t.Fatal(err)
			}
			op, err := a.signer.Inspect(a.id())
			if err != nil {
				t.Fatal(err)
			}
			check := auditTrust{a.signer}
			if err = check.Check(a.ctx, signingaudit.Fetch, op); err != nil {
				t.Fatal(err)
			}
			b := a.signer.bindings[op.ID]
			old := b.current
			if old == nil || b.phase != signingaudit.Fetch {
				t.Fatal("missing successful neighbor")
			}
			switch fault {
			case "source-error":
				a.e.f.s.err = errAuditFixture
			case "native-error":
				a.trust.change = func(signingaudit.Phase, signingaudit.Operation) error { return errAuditFixture }
			case "endpoint-error":
				a.backend.peer = "wrong-endpoint"
			case "original-clock-error":
				// Fetch first validates both original leases; fail its bridge's next
				// original-lease read, after that public-entry validation has succeeded.
				failAt := a.e.f.c.reads + 3
				a.e.f.c.onRead = func(c *fixtureClock) {
					if c.reads == failAt {
						c.err = errAuditFixture
					}
				}
			}
			before := len(a.e.f.s.queries)
			if fault == "original-clock-error" {
				err = a.signer.Fetch(a.id())
			} else {
				err = check.Check(a.ctx, signingaudit.Fetch, op)
			}
			t.Logf("fault=%s err=%v retained=%t same_previous=%t phase=%q new_source_queries=%d", fault, err, b.current != nil, b.current == old, b.phase, len(a.e.f.s.queries)-before)
			if fault == "valid" {
				if err != nil || b.current == nil || b.current == old {
					t.Fatal("valid refresh not replaced")
				}
				if err = (auditRelease{a.signer}).Verify(a.ctx, op); err != nil || a.backend.verifies != 1 {
					t.Fatal("valid gate failed")
				}
				return
			}
			if err == nil {
				t.Fatal("failed refresh accepted")
			}
			// Restore only the transient error, not a lease, source qualification,
			// context or clock reading. A failed refresh must have revoked old success.
			a.e.f.s.err = nil
			a.trust.change = nil
			a.backend.peer = a.e.signPeer
			a.e.f.c.err = nil
			a.e.f.c.onRead = nil
			if b.current != nil || b.phase != "" {
				verifyErr := (auditRelease{a.signer}).Verify(a.ctx, op)
				t.Errorf("failed refresh retained previous authorization: verify_err=%v backend_verifies=%d", verifyErr, a.backend.verifies)
			} else if err = (auditRelease{a.signer}).Verify(a.ctx, op); err == nil || a.backend.verifies != 0 {
				t.Fatal("cleared authorization reused")
			}
		})
	}
}

func TestReviewPublicFailedRefreshDoesNotEnterBackend(t *testing.T) {
	a := newAuditAdapterFixture(t)
	if err := a.run(t); err != nil {
		t.Fatal(err)
	}
	if err := a.signer.Fetch(a.id()); err != nil {
		t.Fatal(err)
	}
	beforeQueries := len(a.e.f.s.queries)
	beforeVerify, beforeRelease := a.backend.verifies, a.backend.releases
	failAt := a.e.f.c.reads + 3
	a.e.f.c.onRead = func(c *fixtureClock) {
		if c.reads == failAt {
			c.err = errAuditFixture
		}
	}
	err := a.signer.Fetch(a.id())
	if err == nil || a.backend.verifies != beforeVerify || a.backend.releases != beforeRelease || len(a.e.f.s.queries) != beforeQueries {
		t.Fatal("public failed refresh entered backend")
	}
	a.e.f.c.onRead = nil
	a.e.f.c.err = nil
	if err = a.signer.Fetch(a.id()); err != nil {
		t.Fatal(err)
	}
	if len(a.e.f.s.queries) != beforeQueries+2 || a.backend.verifies != beforeVerify+1 || a.backend.releases != beforeRelease+1 {
		t.Fatal("public retry bypassed fresh qualification")
	}
	t.Log("public failure refused; retry performs two new source qualifications")
}

func TestReviewOperationAndPhaseEntryBinding(t *testing.T) {
	a := newAuditAdapterFixture(t)
	if err := a.run(t); err != nil {
		t.Fatal(err)
	}
	op, err := a.signer.Inspect(a.id())
	if err != nil {
		t.Fatal(err)
	}
	if err = (auditTrust{a.signer}).Check(a.ctx, signingaudit.Fetch, op); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"id", "request", "inputs", "phase", "cancel"} {
		t.Run(change, func(t *testing.T) {
			changed := op
			phase := signingaudit.Fetch
			ctx := a.ctx
			switch change {
			case "id":
				changed.ID = "foreign-operation"
			case "request":
				changed.Request.RequestID = "foreign-request"
			case "inputs":
				changed.Inputs.JobSHA256 = "foreign-job"
			case "phase":
				phase = signingaudit.Recovery
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := a.signer.entry(ctx, phase, changed); err == nil {
				t.Fatal("foreign or cancelled entry allowed")
			}
		})
	}
}
