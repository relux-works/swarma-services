# Unsigned builder artifact snapshots

`internal/artifactsnapshot` implements the byte-stream and unsigned snapshot part
of the existing [builder result contract](builder-wire-data-r2.md#result-variants-logs-and-streams).
It consumes the two consecutive artifact streams after a validated successful
result, checks each actual size and SHA-256, compares the private copies byte for
byte, and requires EOF without any trailing byte. The existing inclusive size
range is 1 through 268,435,456 bytes per artifact; hashes use 64 lowercase hex
characters. It uses fixed-size copy/comparison buffers and disk storage for both
copies rather than holding whole artifacts in memory.

The caller supplies the authenticated builder connection, the two decoded byte
receipts, and the original active job context. Before calling, the caller must
validate the complete result frame, operation/nonce/job binding, source, policy,
recipe, target and log metadata. This package cannot establish those facts from
two artifact receipts. Equal receipts alone are insufficient: both streams are
independently copied and hashed, and the copied bytes are also compared directly.

Each artifact read gets an absolute 60-second deadline capped by the original
job deadline. The final EOF wait retains the second deadline. A context without
a deadline, an expired context or a remaining budget greater than the existing
600-second job ceiling refuses. The original job start remains the caller's
responsibility; calling the verifier does not renew that budget. Cancellation
closes the connection to unblock reads. The trusted `net.Conn` adapter must
support real absolute read deadlines and concurrent close; this package does not
attest an adapter implementation or an authenticated transport. It consumes and
closes the exchange on both success and refusal.

The parent scratch directory comes from trusted signer configuration. It must be
absolute, owned by the running principal, mode 0700 and not itself a symlink.
Trusted custody of its ancestors and concurrent namespace changes remain host
adapter preconditions. The verifier creates one exclusive mode-0700 child and
two exclusive mode-0600 files; it accepts no builder path or descriptor. Refusal
closes the files and removes only that child. A storage or connection cleanup
failure reports `ErrCleanup` and returns no snapshot, allowing the operation
owner to retain the gate for recovery instead of claiming clean terminal refusal.
Cancellation waits for its connection-close callback to finish and retains that
first close's cleanup error even when a later close reports already closed.
Already-closed errors are benign only when every cause in their error tree is
benign; a joined independent cleanup failure retains its cause and `ErrCleanup`.
After all connection and callback cleanup finishes, the verifier reconciles the
original job context again. Cancellation or expiry closes and suppresses any
candidate snapshot, retaining the context error and cause alongside cleanup errors.

On success the first private copy is reopened read-only and both temporary names
are removed before the opaque `Snapshot` is returned. It exposes only a value
receipt, concurrent `ReadAt` and `Close`. Callers must close it to release its
storage. No writable descriptor or filesystem path is exposed. This is an
unsigned in-process handle; it does not survive a process exit and is not durable
native signing staging. A later native adapter must establish its own private
materialization, custody and durability under the admitted host contract.

The package performs no build, signature, admission, source-authority check,
audit append, client fetch or installation. Verified unsigned bytes may proceed
only through the existing independent authority/admission, durable intent,
native P-256 certificate/designated-requirement verification and durable outcome
gates. There is no service entrypoint or host qualification in this increment.

Focused controls cover a valid multi-buffer snapshot; short first/second streams;
altered first/second payloads; noncanonical or unequal receipts; trailing bytes;
direct copied-byte inequality; private-directory refusals; preservation of
unrelated files; cancellation during either stream and the EOF wait; absolute
deadline installation; and explicit cleanup failure. The maximum-size field
boundary is checked without claiming a full 256 MiB transfer or native capacity
qualification. Direct comparison controls use different real bytes, not a
fabricated SHA-256 collision.
