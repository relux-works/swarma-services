package sourceauthority

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The wall sample can occur anywhere inside a measured monotonic bracket.
// These synthetic pauses establish source behavior, never native admission.
type samplingTimeline struct {
	base, wall             time.Time
	next, end              time.Duration
	calls                  int
	spans, positions, gaps map[int]time.Duration
}

func (s *samplingTimeline) sample() (processTime, error) {
	s.calls++
	before := s.next + s.gaps[s.calls]
	span := time.Nanosecond
	if d, ok := s.spans[s.calls]; ok {
		span = d
	}
	s.end = before + span
	s.next = s.end + time.Microsecond
	return processTime{before: s.base.Add(before), wall: s.wall.Add(before + s.positions[s.calls]), after: s.base.Add(s.end), pid: 123}, nil
}

func samplingAuthority(t *testing.T) (*Authority, *fixture, *samplingTimeline) {
	t.Helper()
	f := validFixture(t)
	f.s.observation.ExpiresAt = f.s.observation.ObservedAt + 1
	s := &samplingTimeline{base: time.Now(), wall: time.Unix(f.s.observation.ObservedAt, 0).UTC(),
		spans: map[int]time.Duration{}, positions: map[int]time.Duration{}, gaps: map[int]time.Duration{}}
	c, err := newProcessClock(s.sample, "synthetic-sampling-epoch")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(f.p, f.s, c)
	if err != nil {
		t.Fatal(err)
	}
	return a, f, s
}

func samplingBoundary(a *Authority, phase Phase) func(context.Context, Request) (*Qualification, error) {
	if phase == Presign {
		return a.BeforeSign
	}
	return a.BeforeBuild
}

func TestSamplingExpiryAtPhaseBoundaries(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, point := range []struct {
			name string
			call int
		}{{"receipt", 3}, {"final", 4}} {
			for _, delayed := range []bool{false, true} {
				name := string(phase) + "/" + point.name + "/fresh"
				if delayed {
					name = string(phase) + "/" + point.name + "/expired"
				}
				t.Run(name, func(t *testing.T) {
					a, f, s := samplingAuthority(t)
					s.spans[point.call] = 250 * time.Millisecond
					if delayed {
						s.spans[point.call] = 2 * time.Second
					}
					q, err := samplingBoundary(a, phase)(context.Background(), f.r)
					t.Logf("calls=%d measured_end=%v expiry=1s qualification=%v error=%v", s.calls, s.end, q != nil, err)
					if s.end >= AuthorityBudget || len(f.s.queries) != 1 || f.s.queries[0].Phase != phase {
						t.Fatal("not a bounded independent source phase")
					}
					if delayed {
						if s.end < time.Second || q != nil || !errors.Is(err, ErrUnavailable) {
							t.Fatal("expiry inside sample did not refuse", err)
						}
					} else if err != nil || q == nil || q.CheckFreshness() != nil {
						t.Fatal("fresh delayed positive partner failed", err)
					}
				})
			}
		}
	}
}

func TestSamplingExpiryAtFreshness(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, delayed := range []bool{false, true} {
			name := string(phase) + "/fresh"
			if delayed {
				name = string(phase) + "/expired"
			}
			t.Run(name, func(t *testing.T) {
				a, f, s := samplingAuthority(t)
				q, err := samplingBoundary(a, phase)(context.Background(), f.r)
				if err != nil {
					t.Fatal(err)
				}
				s.spans[5] = 250 * time.Millisecond
				if delayed {
					s.spans[5] = 2 * time.Second
				}
				err = q.CheckFreshness()
				t.Logf("measured_end=%v expiry=1s freshness_error=%v", s.end, err)
				if len(f.s.queries) != 1 || s.end >= AuthorityBudget {
					t.Fatal("freshness changed source or budget")
				}
				if delayed {
					if s.end < time.Second || !errors.Is(err, ErrUnavailable) {
						t.Fatal("expiry during freshness read passed", err)
					}
				} else if err != nil {
					t.Fatal("fresh positive partner failed", err)
				}
			})
		}
	}
}

func TestSamplingReceiptAnchorAndStrictEndpoints(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		t.Run(string(phase), func(t *testing.T) {
			a, f, s := samplingAuthority(t)
			// Receipt's wall sample is 300ms after its leading endpoint and
			// 100ms before its trailing endpoint. Never pair that wall with end.
			s.spans[3], s.positions[3] = 400*time.Millisecond, 300*time.Millisecond
			q, err := samplingBoundary(a, phase)(context.Background(), f.r)
			if err != nil {
				t.Fatal("valid receipt interval refused", err)
			}
			if q.deadline != 700*time.Millisecond {
				t.Fatalf("receipt deadline extended: %v", q.deadline)
			}
			s.next = q.deadline - 2*time.Nanosecond
			if err := q.CheckFreshness(); err != nil {
				t.Fatal("one nanosecond before cap refused", err)
			}
			s.next = q.deadline - time.Nanosecond
			if s.wall.Add(s.next).Unix() >= f.s.observation.ExpiresAt {
				t.Fatal("not isolating monotonic cap")
			}
			if !errors.Is(q.CheckFreshness(), ErrUnavailable) {
				t.Fatal("trailing endpoint at cap passed")
			}
		})
	}
}

func TestSamplingAuthorityBudgetIncludesTrailingEndpoint(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, expired := range []bool{false, true} {
			name := string(phase) + "/within"
			if expired {
				name = string(phase) + "/over"
			}
			t.Run(name, func(t *testing.T) {
				a, f, s := samplingAuthority(t)
				f.s.observation.ExpiresAt = f.s.observation.ObservedAt + 300
				s.gaps[4], s.spans[4] = 29*time.Second, 500*time.Millisecond
				if expired {
					s.spans[4] = 2 * time.Second
				}
				q, err := samplingBoundary(a, phase)(context.Background(), f.r)
				if expired {
					var refusal *Refusal
					if q != nil || !errors.As(err, &refusal) || refusal.Predicate() != "authority_budget" {
						t.Fatal("trailing sample bypassed budget", err)
					}
				} else if err != nil || q == nil {
					t.Fatal("bounded positive partner failed", err)
				}
			})
		}
	}
}

func TestSamplingPreservesAuthorityRules(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, rule := range []string{"same_origin", "exact_journal_bytes", "complete_frontier", "future_observation"} {
			t.Run(string(phase)+"/"+rule, func(t *testing.T) {
				a, f, s := samplingAuthority(t)
				s.spans[3] = 250 * time.Millisecond
				switch rule {
				case "same_origin":
					f.s.observation.Lookup.Scopes[0].Origin = "foreign.invalid"
				case "exact_journal_bytes":
					f.s.observation.Lookup.Scopes[0].Events[0].Body += "\n"
				case "complete_frontier":
					f.s.observation.Lookup.Scopes[0].Coverage = Partial
				case "future_observation":
					f.s.observation.ObservedAt++
				}
				q, err := samplingBoundary(a, phase)(context.Background(), f.r)
				if q != nil || err == nil || len(f.s.queries) != 1 {
					t.Fatal("sampling relaxed authority rule", err)
				}
			})
		}
	}
}

func TestSamplingInvalidBoundsRefuse(t *testing.T) {
	for _, fault := range []string{"negative", "budget", "overflow", "wall_overflow", "overlap"} {
		t.Run(fault, func(t *testing.T) {
			f := validFixture(t)
			q := qualifyFixture(t, f)
			switch fault {
			case "negative":
				f.c.r.SampleSpan = -time.Nanosecond
			case "budget":
				f.c.r.SampleSpan = AuthorityBudget
			case "overflow":
				f.c.r.Monotonic = time.Duration(1<<63 - 1)
				f.c.r.SampleSpan = time.Nanosecond
			case "wall_overflow":
				f.c.r.Wall = time.Unix(1<<63-1, 0)
				f.c.r.SampleSpan = time.Second
			case "overlap":
				q.start.SampleSpan = time.Nanosecond
			}
			if !errors.Is(q.CheckFreshness(), ErrUnavailable) {
				t.Fatal("invalid interval passed")
			}
			if fault != "overlap" {
				for _, phase := range []Phase{Prebuild, Presign} {
					if got, err := samplingBoundary(f.authority(t), phase)(context.Background(), f.r); got != nil || !errors.Is(err, ErrUnavailable) {
						t.Fatal("invalid phase interval passed", err)
					}
				}
			}
		})
	}
}

func TestSamplingConservativeWallUpperBound(t *testing.T) {
	for _, phase := range []Phase{Prebuild, Presign} {
		for _, atExpiry := range []bool{false, true} {
			name := string(phase) + "/below_upper_expiry"
			if atExpiry {
				name = string(phase) + "/at_upper_expiry"
			}
			t.Run(name, func(t *testing.T) {
				a, f, s := samplingAuthority(t)
				// End is only 600ms into the lease. The wall sample is inside
				// that bracket, but the conservative wall upper bound reaches
				// expiry. This isolates wall uncertainty from monotonic expiry.
				s.spans[4] = 500 * time.Millisecond
				s.gaps[4] = 100*time.Millisecond - 3003*time.Nanosecond
				s.positions[4] = 400 * time.Millisecond
				if !atExpiry {
					s.positions[4] -= time.Nanosecond
				}
				q, err := samplingBoundary(a, phase)(context.Background(), f.r)
				if s.end != 600*time.Millisecond {
					t.Fatal("invalid bracket control", s.end)
				}
				if atExpiry {
					if q != nil || !errors.Is(err, ErrUnavailable) {
						t.Fatal("upper wall expiry accepted", err)
					}
				} else if err != nil || q == nil {
					t.Fatal("strictly below wall upper expiry refused", err)
				}
			})
		}
	}
}
