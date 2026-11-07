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
origins are unavailable. The implementation accepts no credentials and discovers
none. No actual provider installation is configured. Endpoint construction and
admission require authentic source-owned facts; this reader does not invent a
provider API mapping. A release request has no access to these private settings.

Each phase inherits the enclosing absolute deadline, which must have at most
30 seconds remaining. It never creates a new 30-second budget. Context values
are excluded from transport configuration while cancellation and the exact
deadline are preserved. An occupied reader refuses another phase immediately;
an active phase refuses another transfer. Closing a phase cancels active I/O and
retains its gate until body cleanup completes. There are no queued transfers,
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

Each transfer uses a new non-pooling HTTP/1 transport with proxy discovery,
transparent decompression and redirects disabled. Only identity content encoding
is accepted. Informational responses, protocol switches, partial responses,
content ranges and trailers refuse. Half the header reservation bounds initial
headers; half bounds the HTTP/1 trailer read buffer. This conservative split can
refuse headers below the overall ceiling. The standard HTTP parser supplies
framing validation; body truncation, parser errors and cancellation discard bytes.
TLS verification stays enabled. No provider SDK buffers responses first.

The tests use synthetic loopback TLS in an isolated network namespace. They
exercise actual HTTP parsing, streamed and declared bounds, both real byte
ceilings and small boundary neighbors, stricter reservations, error bodies,
redirect refusal, encoding refusal, malformed framing, cancellation, attempted
late completion, gate reuse and process-local connection/goroutine/file-descriptor
cleanup. Fixture TLS trust is not source authentication, enforced read capability,
frontier qualification or native runtime admission. Independent source review and
installation qualification remain required before production use.
