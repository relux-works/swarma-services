# Private source response acquisition

The source authority package contains a concrete private HTTPS response reader
for trusted evidence-source components. It returns owned bounded response bytes
and the HTTP status, or an error with no partial result. It does not implement
production `Source.Read`, construct observations, decode evidence, establish
coverage, normalize provider records, verify Git objects or qualify an installation.

Protected installation supplies a canonical provider identifier, one exact HTTPS
origin, a copied table of exact canonical paths and response classes, optional
copied public TLS roots, and explicit limits. Paths use a narrow ASCII subset;
queries, escaped paths, user information, fragments, path traversal and alternate
origins are unavailable. Generic acquisition discovers no credentials. Protected
GitHub composition can bind an opaque installation auth capability and an owned
connector; neither has a public issuer. No actual provider installation is
configured. Endpoint construction and
admission require authentic source-owned facts; this reader does not invent a
provider API mapping. A release request has no access to these private settings.

Each phase inherits the enclosing absolute deadline, which must have at most
30 seconds remaining. It never creates a new 30-second budget. Context values
are excluded from transport configuration while cancellation and the exact
deadline are preserved. An occupied reader refuses another phase immediately;
an active phase refuses another transfer. Closing a phase cancels active I/O and
retains its gate until synchronous TLS/I/O and the owned cancellation callback
have finished and the underlying socket has closed. There are no queued transfers,
refresh workers or automatic retries. A transfer error makes that phase unusable
for further transfers. The enclosing source must close every phase, share its
remaining reservations across its own readers and serialize its full read.

Configured limits are explicit positive ceilings, with maxima of 64 KiB headers,
16 MiB metadata body, 1 MiB raw commit body, 512 MiB aggregate body and 1,024
response attempts. A phase and each transfer also accept stricter remaining
reservations from the trusted component; maxima allocate no implicit quota.
Declared oversize is refused before body allocation. Unknown-length streams
use fixed 32 KiB scratch and bounded growth, with at most one overflow byte.
Every payload byte actually read, including error bodies and the overflow probe,
consumes the aggregate reservation. No unfunded probe is allowed: if framing
has not already proved EOF, an exactly exhausted reservation refuses. Response
attempts include failed exchanges. Buffer capacity never exceeds the selected
body limit; a growth step temporarily retains the previous buffer as well.

Each transfer owns one numeric TCP dial, a synchronous verified TLS handshake,
and a single HTTP/1 exchange. No HTTP Transport workers, connection pool, proxy
discovery, decompression, redirect following or retry are involved. The socket
uses the original absolute deadline. One cancellation callback closes that raw
socket; the transfer joins it before its active flag or adapter gate can release.
Cleanup closes the raw socket without a TLS close-notify timeout or body drain.
Admission and return also inspect the absolute clock, because a socket timeout
can precede delivery of the context timer callback.

Public resolver and failed-dial APIs do not supply a join handle for every
internal worker. The implementation conservatively retains the adapter gate
permanently after any hostname resolution or failed numeric dial. A hostname
transfer can finish, but another transfer or phase on that adapter refuses. It
never replaces the adapter or retries to bypass this containment. The protected
GitHub composition has a separate owned numeric connector with synchronous
nonblocking connect/select and no resolution or dial workers. It requires a
privately issued canonical-address capability; that issuer and its currentness
qualification are still missing. The old resolver path remains contained.
Successful numeric dials, including canceled TLS handshakes and body
reads, have the owned cleanup path and can release normally after phase close.

The header reservation covers parser representation and scratch, rather than
only wire bytes. Before the standard parser receives anything, a fixed-capacity
wire buffer charges 32 KiB for fixed/cold parser and diagnostic state, its full
capacity, eight bytes per wire byte for scalar copies and scratch, and 384 bytes
per physical field line for map growth and value descriptors. The buffer's
capacity is `(reservation - 32768) / 16`; every byte and field line is checked
before appending, and at most 128 physical field lines are admitted. Folded and
repeated fields count too. The conservative representation allowance covers
both old and new map storage, hint/value backing arrays, string descriptors and
framing metadata. The scalar allowance covers status/key/value strings, line and
fold scratch and bounded malformed-input diagnostics. The fixed allowance also
covers the two 64-byte reader buffers and cold standard-parser machinery.
A reservation at or below 32 KiB refuses before dialing. At the 64 KiB maximum,
the initial wire cap is 2,048 bytes; count/representation checks can refuse sooner.
These conservative refusals are intentional, including for valid HTTP below a
wire-only ceiling. The ceiling grants no implicit parser allocation.

The standard HTTP parser retains status, header syntax, folding, duplicate-length
and transfer-framing semantics. Only identity content encoding is accepted.
Informational responses, protocol switches, partial responses and content ranges
refuse. Trailer declarations refuse before parsing, including comma-separated
lists that could otherwise allocate a second map. Chunked bodies use the standard
chunk decoder directly; their terminal trailer section must be empty. A fixed
reader buffer inspects that terminator without entering an allocating MIME
trailer parser. All truncations and parser errors discard partial material.
No provider SDK buffers responses first.

The tests use synthetic loopback TLS in an isolated network namespace. They
exercise actual HTTP parsing, streamed and declared bounds, both real byte
ceilings and small boundary neighbors, stricter reservations, error bodies,
redirect refusal, encoding refusal, malformed framing, cancellation, attempted
late completion, gate reuse and process-local connection/goroutine/file-descriptor
cleanup. Fixture TLS trust is not source authentication, enforced read capability,
frontier qualification or native runtime admission. Independent source review and
installation qualification remain required before production use.
