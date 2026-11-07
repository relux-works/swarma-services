package sourceauthority

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"time"
)

// ProcessClock implements Clock with process-local monotonic time and sampled
// wall-clock continuity. Construct it in the trusted composition layer, never
// from release input. It does not establish the host's absolute UTC accuracy or
// qualify a native clock. See docs/sourceauthority-clock.md for that boundary.
// A ProcessClock must not be copied after construction; its zero value refuses.
type ProcessClock struct {
	mu       sync.Mutex
	sample   func() (processTime, error)
	pid      int
	epoch    string
	origin   time.Time
	wall     time.Time
	lastWall time.Time
	lastEnd  time.Duration
	lower    time.Duration
	upper    time.Duration
}

type processTime struct {
	before, wall, after time.Time
	pid                 int
}

var _ Clock = (*ProcessClock)(nil)

// NewProcessClock starts a new, nonpersistent epoch. Qualifications cannot be
// restored across a restart or transferred to another instance. After unknown
// time or discontinuity the instance permanently refuses; recovery requires a
// new instance and complete source qualification, never a freshness fallback.
func NewProcessClock() (*ProcessClock, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, unavailable("clock")
	}
	return newProcessClock(readProcessTime, hex.EncodeToString(id[:]))
}

func readProcessTime() (processTime, error) {
	pid := os.Getpid()
	before := time.Now()
	wall := time.Now().UTC() // UTC strips the hidden monotonic value.
	after := time.Now()
	if os.Getpid() != pid {
		return processTime{}, unavailable("clock")
	}
	return processTime{before, wall, after, pid}, nil
}

func hasMonotonic(t time.Time) bool { return t != t.Round(0) }

func validProcessTime(s processTime) bool {
	return s.pid > 0 && !s.wall.IsZero() && s.wall.Unix() >= 0 &&
		hasMonotonic(s.before) && hasMonotonic(s.after) &&
		s.after.Sub(s.before) >= 0 && s.after.Sub(s.before) < AuthorityBudget
}

func newProcessClock(sample func() (processTime, error), epoch string) (*ProcessClock, error) {
	if sample == nil || !text(epoch, 256) {
		return nil, unavailable("clock")
	}
	s, err := sample()
	if err != nil || !validProcessTime(s) {
		return nil, unavailable("clock")
	}
	span := s.after.Sub(s.before)
	return &ProcessClock{sample: sample, pid: s.pid, epoch: epoch,
		origin: s.before, wall: s.wall.UTC(), lastWall: s.wall.UTC(),
		lastEnd: span, lower: -span, upper: 0}, nil
}

// Read serializes the three time samples and continuity state. The middle wall
// sample must fit the intersection of all observed wall/monotonic offset
// intervals. Sampling uncertainty is measured, not an added skew allowance.
// The leading endpoint anchors receipt deadlines conservatively. SampleSpan
// also carries the measured trailing endpoint so qualification and freshness
// cannot ignore time already spent completing this read.
func (c *ProcessClock) Read() (Reading, error) {
	if c == nil {
		return Reading{}, unavailable("clock")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	refuse := func() (Reading, error) {
		c.epoch = ""
		c.sample = nil
		return Reading{}, unavailable("clock")
	}
	if c.sample == nil || c.epoch == "" {
		return refuse()
	}
	s, err := c.sample()
	if err != nil || !validProcessTime(s) || s.pid != c.pid || s.wall.Before(c.lastWall) {
		return refuse()
	}
	before, after := s.before.Sub(c.origin), s.after.Sub(c.origin)
	elapsed := s.wall.Sub(c.wall)
	const maxDuration = time.Duration(1<<63 - 1)
	if before < c.lastEnd || after < before || elapsed < 0 ||
		before == maxDuration || after == maxDuration || elapsed == maxDuration {
		return refuse()
	}
	// All operands are nonnegative and below MaxInt64, so these differences
	// cannot overflow. A disjoint interval means lost clock continuity.
	lower, upper := elapsed-after, elapsed-before
	if lower > c.upper || upper < c.lower {
		return refuse()
	}
	if lower > c.lower {
		c.lower = lower
	}
	if upper < c.upper {
		c.upper = upper
	}
	c.lastWall, c.lastEnd = s.wall.UTC(), after
	return Reading{Wall: c.lastWall, Monotonic: before, Epoch: c.epoch, SampleSpan: after - before}, nil
}
