# Process clock source implementation

`sourceauthority.NewProcessClock()` supplies the existing trusted `Clock` seam.
The service composition constructs and retains its pointer outside request
handling, then supplies it to `New(policy, source, clock)`. There is no caller
clock, qualification flag, serialized clock state or persisted lease. No service
entrypoint, provider transport or native integration is added here.

Each instance generates a 256-bit random epoch and retains actual Go monotonic
timestamps and its process ID. A new process or instance has a new epoch. The
zero value, missing monotonic timestamps, invalid or backward wall time,
decreasing monotonic time, changed process identity and unknown samples refuse.
An error clears the epoch and permanently disables that instance. Recovery uses
a new instance and complete `BeforeBuild` / `BeforeSign` qualification, including
a new authenticated `Source.Read`; an old qualification cannot recover.

Each serialized read brackets a UTC wall sample with two monotonic samples. It
intersects the possible wall/monotonic offset interval with every prior sample.
A disjoint interval detects a wall discontinuity, including forward movement,
backward movement that still exceeds the previous wall reading, or a wall jump
during suspend when the target monotonic clock stops. No fixed drift or positive future tolerance is
introduced. Sampling uncertainty is the actual measured bracket, less than the
existing 30-second authority budget. `Reading.Monotonic` retains the leading
endpoint and `Reading.SampleSpan` carries the full measured bracket. Receipt
deadlines use the leading endpoint plus the remaining lifetime at the sampled
wall time. Final qualification and freshness compare the trailing monotonic
endpoint against that deadline, and the conservative upper wall bound
`Wall + SampleSpan` against UTC expiry. Pairing the trailing endpoint with the
earlier wall sample would extend the receipt deadline and is forbidden. A pause
inside a bracket can cross expiry even below the 30-second budget; that read
must refuse qualification/freshness. Sampling uncertainty can cause early
refusal. Duration saturation and arithmetic overflow cannot produce success.

The verifier keeps its existing rules: observed time cannot be in the future, lease
length is 1..300 seconds, the entire qualification has one absolute 30-second
budget, and fractional remaining lifetime is capped monotonically without
rounding upward. Budget checks include the trailing endpoint; future-observation
checks still use the sampled wall value with zero positive tolerance. Other
trusted clock adapters must supply their full `SampleSpan`, or zero only for a
point reading. `CheckFreshness` only tests that local lease. It cannot replace
the independent presign source read or current revocation/policy verification.

This is a source implementation, not target clock admission. Go's local wall
clock does not prove absolute UTC accuracy. Continuity is observed only at reads;
a step and compensating reversal between samples, or a change hidden inside the
measured sampling interval, is not independently detectable. NTP slewing can
eventually exhaust the intersected interval and cause conservative refusal. No
skew allowance, automatic reset or stale fallback hides that refusal. Target
clock resolution, suspend/rate behavior, external UTC trust and scheduling must
be qualified at the actual runtime boundary before effects. No host settings are
changed and no native Mac clock or build capability is asserted.

The implementation retains constant state and takes three clock samples and
process-ID checks per read under one mutex; construction also reads 32 bytes of
OS randomness. There is no polling, goroutine, file, socket, key or provider
access. The bracket limit detects a late sample after return; it is not a
preemptive scheduler or whole-process CPU/RSS bound. The focused controls use
synthetic timestamps for deterministic fault injection and a separate real
same-process constructor/read check. Neither establishes native qualification.
