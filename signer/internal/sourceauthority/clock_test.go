package sourceauthority

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// These controls inject synthetic samples into the private implementation seam;
// they establish source behavior, never actual host/native clock admission.
type processTimeline struct {
	base  time.Time
	wall  time.Time
	mono  time.Duration
	skew  time.Duration
	span  time.Duration
	pid   int
	err   error
	reads int
	hook  func(*processTimeline)
}

func newTimeline() *processTimeline {
	return &processTimeline{base: time.Now(), wall: time.Unix(1740000100, 0).UTC(),
		span: 2 * time.Nanosecond, pid: 123}
}

func (s *processTimeline) sample() (processTime, error) {
	s.reads++
	if s.hook != nil {
		s.hook(s)
	}
	return processTime{s.base.Add(s.mono), s.wall.Add(s.mono + s.skew + s.span/2),
		s.base.Add(s.mono + s.span), s.pid}, s.err
}

func timelineClock(t *testing.T, s *processTimeline) *ProcessClock {
	t.Helper()
	c, err := newProcessClock(s.sample, "synthetic-epoch")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func clockUnavailable(t *testing.T, r Reading, err error) {
	t.Helper()
	if r != (Reading{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected empty reading and unavailable, got %+v, %v", r, err)
	}
}

func TestProcessClockContinuity(t *testing.T) {
	s := newTimeline()
	c := timelineClock(t, s)
	s.mono = time.Second
	a, err := c.Read()
	if err != nil || a.Epoch != "synthetic-epoch" || a.Monotonic != time.Second || a.SampleSpan != s.span ||
		a.Wall != s.wall.Add(time.Second+s.span/2) || a.Wall.Location() != time.UTC {
		t.Fatalf("valid sample refused or changed: %+v, %v", a, err)
	}
	s.mono += time.Second
	b, err := c.Read()
	if err != nil || b.Monotonic-a.Monotonic != time.Second || b.Epoch != a.Epoch {
		t.Fatal("continuous sample lost its epoch", err)
	}
}

func TestProcessClockFaultsLatch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*processTimeline)
	}{
		{"process_changed", func(s *processTimeline) { s.pid++ }},
		{"unknown_time", func(s *processTimeline) { s.err = errors.New("synthetic clock failure") }},
		{"zero_wall", func(s *processTimeline) { s.wall = time.Time{}; s.mono = 0; s.span = 0 }},
		{"negative_wall", func(s *processTimeline) { s.wall = time.Unix(-2, 0); s.mono = 0 }},
		{"missing_monotonic", func(s *processTimeline) { s.base = s.base.Round(0) }},
		{"wall_backward", func(s *processTimeline) { s.skew = -3 * time.Second }},
		{"wall_forward", func(s *processTimeline) { s.skew = time.Second }},
		{"wall_lags_without_moving_backward", func(s *processTimeline) { s.skew = -time.Millisecond }},
		{"monotonic_backward", func(s *processTimeline) { s.mono = time.Nanosecond }},
		{"reversed_bracket", func(s *processTimeline) { s.span = -time.Nanosecond }},
		{"bracket_at_budget", func(s *processTimeline) { s.span = AuthorityBudget }},
		{"duration_saturation", func(s *processTimeline) { s.mono = time.Duration(1<<63 - 1); s.span = 0 }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s := newTimeline()
			c := timelineClock(t, s)
			s.mono = time.Second
			if _, err := c.Read(); err != nil {
				t.Fatal("positive partner failed", err)
			}
			s.mono = 2 * time.Second
			tt.mutate(s)
			r, err := c.Read()
			clockUnavailable(t, r, err)
			reads := s.reads
			// Restoring plausible samples cannot revive this instance or epoch.
			s.err = nil
			s.mono = 3 * time.Second
			s.skew = 0
			r, err = c.Read()
			clockUnavailable(t, r, err)
			if s.reads != reads || c.epoch != "" {
				t.Fatal("faulted instance sampled again or kept its epoch")
			}
		})
	}
}

func TestProcessClockAbsentAndInitialUnknown(t *testing.T) {
	for _, c := range []*ProcessClock{nil, {}} {
		r, err := c.Read()
		clockUnavailable(t, r, err)
	}
	s := newTimeline()
	s.err = errors.New("synthetic unavailable")
	if c, err := newProcessClock(s.sample, "synthetic"); c != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown initial time accepted")
	}
	s.err = nil
	s.base = s.base.Round(0)
	if c, err := newProcessClock(s.sample, "synthetic"); c != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("wall-only clock accepted")
	}
}

func TestProcessClockMeasuredUncertainty(t *testing.T) {
	s := newTimeline()
	s.span = 100 * time.Nanosecond
	c := timelineClock(t, s)
	s.mono = time.Second
	s.skew = 49 * time.Nanosecond
	if _, err := c.Read(); err != nil {
		t.Fatal("overlapping measured intervals refused", err)
	}
	s.mono += time.Second
	s.skew = -49 * time.Nanosecond
	if _, err := c.Read(); err != nil {
		t.Fatal("shared offset interval lost", err)
	}
	s.mono += time.Second
	s.skew = 52 * time.Nanosecond
	r, err := c.Read()
	clockUnavailable(t, r, err)
}

func TestProcessClockRealEpochAndConcurrentReads(t *testing.T) {
	a, err := NewProcessClock()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewProcessClock()
	if err != nil {
		t.Fatal(err)
	}
	x, err := a.Read()
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Read()
	if err != nil || len(x.Epoch) != 64 || x.Epoch == y.Epoch {
		t.Fatal("new instance did not create an independent epoch", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				r, err := a.Read()
				if err != nil || !validReading(r) || r.Epoch != x.Epoch || r.Monotonic < x.Monotonic {
					t.Error("real same-process continuity refused", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func authorityWithTimeline(t *testing.T, s *processTimeline) (*Authority, *fixture, *ProcessClock) {
	t.Helper()
	f := validFixture(t)
	c := timelineClock(t, s)
	a, err := New(f.p, f.s, c)
	if err != nil {
		t.Fatal(err)
	}
	// Each synthetic read consumes a bounded, positive sampling interval.
	s.hook = func(s *processTimeline) { s.mono += time.Microsecond }
	return a, f, c
}

func TestProcessClockLeaseAndIndependentPresign(t *testing.T) {
	a, f, _ := authorityWithTimeline(t, newTimeline())
	q, err := a.BeforeBuild(context.Background(), f.r)
	if err != nil || q.CheckFreshness() != nil {
		t.Fatal("same-process lease failed", err)
	}
	if len(f.s.queries) != 1 {
		t.Fatal("freshness performed a source read")
	}
	r := f.r
	r.Nonce = strings.Repeat("e", 64)
	if signed, err := a.BeforeSign(context.Background(), r); err != nil || signed.CheckFreshness() != nil ||
		len(f.s.queries) != 2 || f.s.queries[1].Phase != Presign || f.s.queries[0].Nonce == f.s.queries[1].Nonce {
		t.Fatal("independent presign positive partner failed", err)
	}
	f.s.err = errors.New("synthetic failed refresh")
	r.Nonce = strings.Repeat("f", 64)
	if signed, err := a.BeforeSign(context.Background(), r); signed != nil || !errors.Is(err, ErrUnavailable) ||
		len(f.s.queries) != 3 || f.s.queries[2].Phase != Presign {
		t.Fatal("fresh local lease replaced independent presign source read", err)
	}
}

func TestProcessClockLeaseFractionalCapAndFaults(t *testing.T) {
	for _, fault := range []string{"expiry", "process_changed", "unknown", "backward", "discontinuity"} {
		t.Run(fault, func(t *testing.T) {
			s := newTimeline()
			s.wall = s.wall.Add(900 * time.Millisecond)
			a, f, _ := authorityWithTimeline(t, s)
			f.s.observation.ExpiresAt = f.s.observation.ObservedAt + 1
			q, err := a.BeforeBuild(context.Background(), f.r)
			if err != nil || q.CheckFreshness() != nil {
				t.Fatal("positive lease partner failed", err)
			}
			switch fault {
			case "expiry":
				// Stop one nanosecond before wall expiry while reaching the
				// conservatively capped monotonic endpoint. No upward rounding.
				s.hook = nil
				s.mono = 100*time.Millisecond - time.Nanosecond
				s.skew = -time.Nanosecond // inside the measured uncertainty
				if s.wall.Add(s.mono+s.skew+s.span/2).Unix() >= q.summary.ExpiresAt || s.mono < q.deadline {
					t.Fatal("control failed to isolate the monotonic cap")
				}
			case "process_changed":
				s.pid++
			case "unknown":
				s.err = errors.New("synthetic unknown")
			case "backward":
				s.skew -= time.Second
			case "discontinuity":
				s.skew += time.Millisecond
			}
			if !errors.Is(q.CheckFreshness(), ErrUnavailable) {
				t.Fatal("invalid or expired qualification stayed fresh")
			}
		})
	}
}

func TestProcessClockFaultDuringQualification(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, fault := range []string{"expiry", "budget", "process_changed", "unknown", "backward", "forward"} {
			t.Run(string(phase)+"/"+fault, func(t *testing.T) {
				s := newTimeline()
				a, f, _ := authorityWithTimeline(t, s)
				f.s.observation.ExpiresAt = f.s.observation.ObservedAt + 1
				reads := 0
				s.hook = func(s *processTimeline) {
					reads++
					s.mono += time.Microsecond
					if reads != 3 { // after source acquisition and local verification
						return
					}
					switch fault {
					case "expiry":
						s.mono += time.Second
					case "budget":
						s.mono += AuthorityBudget
					case "process_changed":
						s.pid++
					case "unknown":
						s.err = errors.New("synthetic unknown")
					case "backward":
						s.skew -= time.Second
					case "forward":
						s.skew += time.Second
					}
				}
				boundary := a.BeforeBuild
				if phase == Presign {
					boundary = a.BeforeSign
					f.r.Nonce = strings.Repeat("e", 64)
				}
				q, err := boundary(context.Background(), f.r)
				predicate := "clock"
				if fault == "expiry" {
					predicate = "lease_clock"
				} else if fault == "budget" {
					predicate = "authority_budget"
				}
				var refusal *Refusal
				if q != nil || !errors.Is(err, ErrUnavailable) || !errors.As(err, &refusal) || refusal.Predicate() != predicate || len(f.s.queries) != 1 {
					t.Fatalf("expected %s refusal after one source read, got %v", predicate, err)
				}
			})
		}
	}
}
