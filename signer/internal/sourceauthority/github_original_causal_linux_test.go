package sourceauthority

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func originalDeltaBytesRefusal(t *testing.T, got []byte, err error, predicate string) {
	t.Helper()
	r, ok := err.(*Refusal)
	if got != nil || !ok || r.Predicate() != predicate {
		t.Fatalf("wanted %s without bytes, got %v", predicate, err)
	}
}

func TestOriginalGitDeltaResultCeilingCausal(t *testing.T) {
	base := []byte("tree " + strings.Repeat("1", 40) + "\n\n" + strings.Repeat("message\n", 8))
	if len(base) > 255 {
		t.Fatal("fixture copy size must fit one byte")
	}
	// Both copies are valid and produce a parseable commit. Removing only the
	// declared-result ceiling therefore cannot hide behind a final-size error.
	delta := append(originalDeltaSizes(len(base), 2*len(base)), 0x90, byte(len(base)), 0x90, byte(len(base)))
	pack := originalDeltaPack(t, originalDeltaEntry{1, "", base}, originalDeltaEntry{7, fixtureOID(base), delta})
	t.Run("over-ceiling", func(t *testing.T) {
		got, err := originalGitUnpack(originalDeltaPhase(t), pack, len(base), 2)
		originalDeltaRefusal(t, got, err, "github_git_delta_result_size")
	})
	t.Run("exact-ceiling", func(t *testing.T) {
		objects, err := originalGitUnpack(originalDeltaPhase(t), pack, 2*len(base), 2)
		want := append(append([]byte(nil), base...), base...)
		if err != nil || len(objects) != 2 || !bytes.Equal(objects[fixtureOID(want)], want) {
			t.Fatal("valid result at exact ceiling refused or changed", err)
		}
	})
}

func TestOriginalGitDeltaVarintOverflowCausal(t *testing.T) {
	// The tenth byte is terminal: this reaches the shift-overflow guard,
	// rather than merely exhausting the ten-byte continuation limit. Without
	// that guard, the high bit is lost and the value aliases the valid size 10.
	bad := append([]byte{0x8a}, bytes.Repeat([]byte{0x80}, 8)...)
	bad = append(bad, 0x02)
	valid := append([]byte(nil), bad...)
	valid[9] = 0
	base := []byte("abcdefghij")
	tail := []byte{1, 1, 'x'} // result size 1 and one literal instruction
	t.Run("overflow", func(t *testing.T) {
		if _, _, ok := originalGitDeltaSize(bad); ok {
			t.Error("overflowing terminal varint accepted")
		}
		got, err := originalGitApplyDelta(originalDeltaPhase(t), base, append(bad, tail...), 4096)
		originalDeltaBytesRefusal(t, got, err, "github_git_delta_base_size")
	})
	t.Run("representable-neighbor", func(t *testing.T) {
		if size, rest, ok := originalGitDeltaSize(valid); !ok || size != 10 || len(rest) != 0 {
			t.Fatal("adjacent representable varint refused")
		}
		got, err := originalGitApplyDelta(originalDeltaPhase(t), base, append(valid, tail...), 4096)
		if err != nil || !bytes.Equal(got, []byte("x")) {
			t.Fatal("adjacent valid base size refused", err)
		}
	})
}

func TestOriginalGitResolutionReservationCausal(t *testing.T) {
	a := []byte("tree " + strings.Repeat("1", 40) + "\n\nBase.\n")
	b := bytes.Replace(a, []byte("Base"), []byte("Next"), 1)
	pack := originalDeltaPack(t, originalDeltaEntry{1, "", a}, originalDeltaEntry{1, "", b})
	// Independently enumerate the pre-resolution charges, not a successful
	// run's observed total. No deltas means no later output reservation can
	// conceal removal of the n*n*32 debit.
	beforeResolution := int64(len(pack)) + 2*256 + int64(len(a)+len(b))*64 + 2*65536
	const reservation = 2 * 2 * 32
	for _, spare := range []int64{reservation - 1, reservation} {
		t.Run(map[bool]string{true: "short-by-one", false: "exact-budget"}[spare < reservation], func(t *testing.T) {
			p := originalDeltaPhase(t)
			p.bytesLeft = beforeResolution + spare
			deadline, _ := p.ctx.Deadline()
			objects, err := originalGitUnpack(p, pack, 4096, 2)
			if spare < reservation {
				originalDeltaRefusal(t, objects, err, "github_git_aggregate")
				if p.bytesLeft != spare {
					t.Fatal("failed reservation refunded or debited the ledger")
				}
			} else if err != nil || p.bytesLeft != 0 || len(objects) != 2 || !bytes.Equal(objects[fixtureOID(a)], a) || !bytes.Equal(objects[fixtureOID(b)], b) {
				t.Fatal("exact resolution allowance changed", err)
			}
			if after, _ := p.ctx.Deadline(); !deadline.Equal(after) {
				t.Fatal("reservation renewed deadline")
			}
		})
	}
}

// Model a phase observing DeadlineExceeded at a specified expiry check. The
// absolute deadline never changes. This pins the loop's expiry observation,
// without sleeping, scheduler races, a clock hook or a production test seam.
// It does not qualify a native clock or the separate wall-time comparison.
type originalDeltaExpiryContext struct {
	deadline         time.Time
	checks, expireAt int
	done             chan struct{}
	expired          bool
}

func (c *originalDeltaExpiryContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *originalDeltaExpiryContext) Done() <-chan struct{}       { return c.done }
func (c *originalDeltaExpiryContext) Value(any) any               { return nil }
func (c *originalDeltaExpiryContext) Err() error {
	c.checks++
	if c.checks >= c.expireAt {
		if !c.expired {
			close(c.done)
			c.expired = true
		}
		return context.DeadlineExceeded
	}
	return nil
}

func originalDeltaExpiryPhase(expireAt int) (*acquisitionPhase, *originalDeltaExpiryContext) {
	c := &originalDeltaExpiryContext{deadline: time.Now().Add(3 * time.Second), expireAt: expireAt, done: make(chan struct{})}
	return &acquisitionPhase{ctx: c, bytesLeft: acquisitionAggregateMax}, c
}

func TestOriginalGitInstructionExpiryCausal(t *testing.T) {
	base := []byte("abcdefghij")
	delta := append(originalDeltaSizes(len(base), 2), 1, 'x', 1, 'y')
	for _, expireAt := range []int{3, 4} {
		t.Run(map[bool]string{true: "second-instruction-expired", false: "unexpired-neighbor"}[expireAt == 3], func(t *testing.T) {
			// Reservation = check 1, first instruction = 2, second = 3.
			p, c := originalDeltaExpiryPhase(expireAt)
			deadline, _ := p.ctx.Deadline()
			got, err := originalGitApplyDelta(p, base, delta, 4096)
			if expireAt == 3 {
				originalDeltaBytesRefusal(t, got, err, "github_git_aggregate")
				if !c.expired {
					t.Fatal("fixture did not observe expiry")
				}
			} else if err != nil || !bytes.Equal(got, []byte("xy")) || c.expired {
				t.Fatal("adjacent unexpired instruction refused", err)
			}
			if c.checks != 3 || p.bytesLeft != acquisitionAggregateMax-(2*64+65536) || p.ctx != c {
				t.Fatal("instruction checkpoint count or original phase/ledger changed")
			}
			if after, _ := p.ctx.Deadline(); !deadline.Equal(after) {
				t.Fatal("instruction loop renewed deadline")
			}
		})
	}
}

func TestOriginalGitResolutionExpiryCausal(t *testing.T) {
	a := []byte("tree " + strings.Repeat("1", 40) + "\n\nBase.\n")
	b := bytes.Replace(a, []byte("Base"), []byte("Next"), 1)
	entry := originalDeltaEntry{7, strings.Repeat("0", 40), originalDeltaLiteral(len(a), b)}
	pack := originalDeltaPack(t, entry, entry)
	// Two missing bases deliberately leave no apply/reservation check after
	// the loop check. Removing it must expose unresolved, not an aggregate
	// refusal from a later guard. Check 6 is the second resolution iteration:
	// initial pack reservation, two inflations, scan reservation, then 5/6.
	wantLeft := acquisitionAggregateMax - int64(len(pack)) - 2*256 - int64(2*len(entry.data))*64 - 2*65536 - 2*2*32
	t.Run("second-iteration-expired", func(t *testing.T) {
		p, c := originalDeltaExpiryPhase(6)
		deadline, _ := p.ctx.Deadline()
		got, err := originalGitUnpack(p, pack, 4096, 2)
		originalDeltaRefusal(t, got, err, "github_git_aggregate")
		if c.checks != 6 || !c.expired || p.bytesLeft != wantLeft || p.ctx != c {
			t.Fatal("resolution checkpoint count or original phase/ledger changed")
		}
		if after, _ := p.ctx.Deadline(); !deadline.Equal(after) {
			t.Fatal("resolution loop renewed deadline")
		}
	})
	// Later expiry reaches the distinct unresolved-base guard on these bytes.
	t.Run("unexpired-missing-base", func(t *testing.T) {
		p, c := originalDeltaExpiryPhase(7)
		got, err := originalGitUnpack(p, pack, 4096, 2)
		originalDeltaRefusal(t, got, err, "github_git_delta_unresolved")
		if c.expired || c.checks != 6 || p.bytesLeft != wantLeft {
			t.Fatal("unexpired missing-base neighbor changed")
		}
	})
	// Supplying the exact in-pack base is the valid neighboring pack.
	t.Run("valid-in-pack-base", func(t *testing.T) {
		entry.base = fixtureOID(a)
		p, _ := originalDeltaExpiryPhase(100)
		got, err := originalGitUnpack(p, originalDeltaPack(t, originalDeltaEntry{1, "", a}, entry), 4096, 2)
		if err != nil || len(got) != 2 || !bytes.Equal(got[fixtureOID(b)], b) {
			t.Fatal("valid in-pack-base neighbor refused", err)
		}
	})
}
