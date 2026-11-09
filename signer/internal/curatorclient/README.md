# Curator request and response preparation

This pure component prepares the three version-1 client request frames. It fixes
the sign pairing to `curator` / `curator-core`, validates exact source and
correlation grammars, derives decimal attempt identifiers without leading zeros,
and returns a fresh opcode/length/JSON frame. The five-byte header carries a
big-endian body length; the 4096-byte request body limit excludes that header.
There is no caller principal, binary path, recipe, credential or approval field.

The caller supplies an already recovered attempt number. This API neither owns
nor advances it. The uint64 argument is a local representational bound, not a
change to the wire request-ID grammar. Inspect accepts the existing 1–64 byte
identifier grammar, including identifiers retained by another admitted client
implementation. The first Curator attempt is 1; a later attempt requires a
durably recorded refused summary for its predecessor. Lost responses, timeouts,
missing journals and an inspect `request_not_found` do not authorize new signing.

`DecodeResponse` accepts exactly one control frame with a body of 1–16384 bytes.
It implements C3's opcode 64 summary, 65 refusal and 66 fetch header, with exact
member sets, decoded duplicate detection, lossless UTF-8/UTF-16 validation and
canonical bounded integers. Unknown variants, codes, members and correlations
return only `ErrResponse`, with no partially decoded result or peer-controlled
error text. Legal escapes and whitespace are accepted within the frame bound.
It accepts no artifact bytes appended to a fetch header.

The caller supplies an `Exchange` snapshot from its retained request. `Session`
is a local exchange identity, checked against the identity of the receiving
exchange; it is never a wire field or proof of peer authentication. The caller
must supply that identity from its own exchange routing, authenticate the peer
before decoding, and serialize/deduplicate exchange consumption in its journal.
The decoder is stateless and does not detect replay of the same frame on the same
exchange. Sign/inspect may discover an operation ID on the first matching
summary; subsequent exchanges must bind the retained operation ID. Summaries
match the exact retained request ID and source. A fetch requires a retained
operation ID and an exactly matching complete success receipt.

Success decoding also requires independently admitted policy, recipe, toolchain,
input, certificate and requirement digests through `Pins`. The response cannot
supply those pins. Receipt hashes, sizes, target, source and audit bounds are
checked, but syntax and equality establish neither durable history nor artifact
or native identity. After decoding a fetch header, the caller still must receive
exactly the declared bytes, enforce EOF/deadlines, verify hash/size and native
policy, and retain verification before consumption. No fetched artifact is
released or consumed by this package.

A refusal's retry value is only a wire hint. In an opcode 64 summary,
`same_request` means inspect. A malformed or missing response remains an ambiguous
outcome. Opcode 65 does not prove that an earlier operation never existed; a
fetch refusal leaves retained success intact. No decoder result authorizes a new
signing attempt. Messages are bounded UTF-8 data, never machine predicates or
trusted logging text; the decoder cannot establish the service's literal origin.

This is an internal preparation seam with no installed client, transport,
persistence or native effect. It must not be wired to a socket before the complete
client contract and custody inputs are admitted. The delivery lane must persist
intent with principal bindings under an exclusive tuple lock before connecting,
verify the service against protected pins, enforce exchange deadlines and retain
UNKNOWN across ambiguous sends. Transport and durable recovery require their
actual host custody inputs. The [baseline protocol](../../docs/baseline-r5.md)
remains the upstream context; this package adds no wire opcode, response field or
error code. Contract acceptance and independent review of documentation do not
constitute review or operational admission of this component.
