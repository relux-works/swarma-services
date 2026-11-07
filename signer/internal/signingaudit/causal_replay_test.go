package signingaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestJournalOutcomeRequiresPriorIntent(t *testing.T) {
	for _, omitIntent := range []bool{false, true} {
		name := "accepted-intent-outcome"
		if omitIntent {
			name = "accepted-outcome-without-intent"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			// Generate valid request, input and signed metadata through the existing
			// inert fixture. No private signer or key is involved.
			op := succeeded(t, f)
			parts := frames(t, journalBytes(t, f))
			if len(parts) != 4 {
				t.Fatalf("want header, accepted, intent, outcome; got %d frames", len(parts))
			}
			closeFixture(t, f)

			var outcome record
			if !decodeExact(parts[3], &outcome) || outcome.Kind != "outcome" {
				t.Fatal("fixture has no canonical outcome")
			}
			stored := op
			stored.Receipt = Anchor{}
			if outcome.Operation != stored || stored.State != Succeeded || stored.Phase != "" {
				t.Fatal("fixture outcome must retain successful metadata and no stored receipt")
			}
			if omitIntent {
				var acceptance record
				if !decodeExact(parts[1], &acceptance) || acceptance.Kind != "accepted" {
					t.Fatal("fixture has no canonical acceptance")
				}
				// Remove the intent completely, relink the genuine successful outcome
				// to acceptance, and stop there: no stale following frame can refuse it.
				outcome.Sequence = acceptance.Sequence + 1
				outcome.Previous = acceptance.Digest
				outcome.Digest = recordDigest(outcome)
				encoded, err := json.Marshal(outcome)
				if err != nil {
					t.Fatal(err)
				}
				parts = [][]byte{parts[0], parts[1], encoded}
			}

			// Both histories satisfy the independent framing, header, canonical
			// encoding and chain gates before exercising persisted-history replay.
			var h header
			if !decodeExact(parts[0], &h) || h != (header{1, f.opts.Durability.Name(), f.opts.MaxBytes}) || f.opts.Checkpoint != (Anchor{}) {
				t.Fatal("fixture profile, budget or checkpoint mismatch")
			}
			var last Anchor
			for i, part := range parts[1:] {
				var r record
				if !decodeExact(part, &r) || r.Schema != 1 || r.Sequence != uint64(i+1) || r.Previous != last.Digest || r.Digest != recordDigest(r) {
					t.Fatalf("fixture record %d has invalid encoding or hash chain", i+1)
				}
				last = Anchor{r.Sequence, r.Digest}
			}
			before := frameBytes(t, parts)
			if int64(len(before)) > f.opts.MaxBytes {
				t.Fatal("fixture exceeds journal budget")
			}
			replaceFixtureJournal(t, f, before)
			artifactPath := filepath.Join(f.effects.dir, op.ID)
			artifactBefore, err := os.ReadFile(artifactPath)
			if err != nil {
				t.Fatal(err)
			}
			trustBefore := f.trust.calls.Load()
			signsBefore := f.effects.signs.Load()
			releasesBefore := f.effects.releases.Load()
			verifyCalled := false
			f.effects.verifyHook = func() { verifyCalled = true }

			replayed, replayErr := Open(f.dir, f.opts, f.trust, f.effects, f.effects)
			if replayed != nil {
				f.a = replayed // Close even if the forbidden history unexpectedly opens.
			}
			if !bytes.Equal(before, journalBytes(t, f)) {
				t.Error("replay rewrote journal bytes")
			}
			entries, err := os.ReadDir(f.dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != journalName {
				t.Fatal("replay changed journal directory contents", err)
			}
			artifactAfter, err := os.ReadFile(artifactPath)
			if err != nil || !bytes.Equal(artifactBefore, artifactAfter) {
				t.Fatal("replay changed inert staged bytes", err)
			}
			if f.trust.calls.Load() != trustBefore || f.effects.signs.Load() != signsBefore || f.effects.releases.Load() != releasesBefore || verifyCalled {
				t.Error("replay invoked trust, signing, verification or release effects")
			}
			if omitIntent {
				if !errors.Is(replayErr, ErrCorrupt) || replayed != nil {
					t.Fatalf("accepted -> outcome without intent: got %v, want ErrCorrupt and no audit", replayErr)
				}
				return
			}
			if replayErr != nil || replayed == nil {
				t.Fatal("legal accepted -> intent -> outcome replay failed", replayErr)
			}
			got, err := replayed.Inspect(op.Request.Caller, op.Request.RequestID)
			if err != nil || got != op || got.Receipt != last {
				t.Fatal("legal replay lost the operation or exact outcome receipt", err)
			}
		})
	}
}
