# Proposed manifest capacity addendum r3

Status: design specification. Implementation, runtime qualification and activation remain pending. The integrated addendum controls its explicit deltas.

## Exact proposed delta

The maximum UTF-8 JSON BODY length for manifest opcode34 becomes4194304 bytes (4MiB), excluding its existing uint8-opcode/uint32-big-endian-length frame header. This applies at both existing acquisition-to-signer and signer-to-builder DATA boundaries. Reject declared34 length above4194304 before allocating a body buffer or parsing it. An incomplete/short/extra frame retains existing refusal and operation-owned cleanup semantics. No new opcode, field, reference, chunk or negotiated capacity.

Manifest34 keeps its existing ABSOLUTE10s phase. DATA keeps120s and its global600s job budget. Builder control16–20 remains16384B with its existing control deadlines; client control limits are unchanged. Entries remain nonempty/max8192, module records max512, regular file max67108864B, DATA max1073741824B, with overflow checks before allocation/addition. The JSON-byte and count limits are independent; no guarantee that every legal8192-entry/path combination fits4194304B. Oversized future inputs refuse, never auto-grow the cap, omit files or silently switch transport.

All other decoding, role/peer, graph/path/collision/symlink, mode, original-sum, authority, identity, hash and stream checks remain. The whole manifest graph is received/validated before materialization under existing rules; private operation-owned payload staging is not trusted build input until every required content/canonical-module check passes. No entry is used for build/signing from a partial or unqualified input. This capacity change never supplies missing metadata, original trust anchors or a verifier verdict.

## Exact bytes and completeness

Retain/hash/forward the actual manifest body bytes, including permitted member-order/whitespace/escape variations, with no trim, normalization or reserialization. No shared canonical encoder is introduced. Existing input_sha256/announcement manifest_sha256 retain their meaning: full actual manifest contents, not an unavailable digest-only surrogate. Existing original inline receipt/data binding remains. A digest-referenced manifest or chunks would be a separate explicit contract change, not a fallback admitted by this addendum. Opaque source archives retain their unchanged ordinary-file interpretation; no DATA extraction/compression.

Receipt-scope clarification for selected-but-unconsumed graph-only versions is a SEPARATE pending additive clause. Current r5 conditions remain until that clause is explicitly agreed from clean offline sufficiency/control evidence. The all22 compiled modules retain complete canonical contents and ORIGINAL module/go.mod h1. Missing an actually required original anchor refuses; sumdb/cache strings do not repair source trust. No source pin or go.sum edit is authorized here.

## Initial source qualification and headroom

Before accepting this capacity candidate for the initial source/recipe, obtain the genuinely complete eligible selected manifest, all required verified content and full agreed receipt, with exact actual body bytes/hash and membership. Measure B from the actual selected sender encoding, not an incomplete subset or sizing placeholders. Require4194304 >=2*B using overflow-safe arithmetic (B<=2097152). This is initial candidate-qualification evidence, not an extra per-message2MiB wire cap; proposed valid wire bodies up to4194304 are tested independently.

Current real known entries:1590943B/5931 entries/73324948 file bytes. Current known-subset manifest1598753B and conditional full-shape1602417B are expressly NOT complete eligible manifests. The latter uses8 absent file sizes at the existing maximum numeric width and placeholder hashes/h1/bindings; it demonstrates bounded sizing only. Neither satisfies this qualification. If the actual complete set fails2x margin, revise the candidate explicitly before freeze; assess bounded digest-reference next, then chunks. No silent capacity or trust change.

Actual4MiB allocation/parser/deadline behavior and complete offline/build/native/resource/custody qualification remain executable acceptance work, not inferred from this document. Larger raw buffers do not establish host enforcement or memory/latency guarantees.

## Paired acceptance expectations — NOT EXECUTED

| Legitimate positive fixture | Forbidden neighbor | Required claim |
| --- | --- | --- |
| Fully valid manifest34 body exactly4194304B, e.g. permitted interior JSON whitespace with the actual matching raw digest | Same valid semantic shape4194305B, declared accordingly | Exact-cap size pass versus intended oversize refusal before body allocation/materialization; no build/sign or forbidden partial effects. All other positive fixture trust/graph conditions remain independently valid. |
| Valid17KiB manifest34 within4MiB | Valid-shaped17KiB builder17 control | Separate manifest admission versus16384B control refusal; no blanket control-cap application to34. |
| Complete original-anchored selected data/receipt within capacity | Incomplete1598753B witness or substituted/reserialized digest | Byte size alone cannot admit missing identity/content/receipt; preserve intended completeness/hash refusal. |
| Permitted distinct JSON encodings, each independently size-bounded and raw-hashed | Hash of another encoding, changed forwarded bytes or extra data | Preserve legitimate encoding compatibility and reject wrong binding without normalization. |
| All entry/module/file/DATA limits pass | Any one original limit exceeded while JSON fits4MiB | Each independent intended limit refusal preserved; no capacity-derived waiver. |
| Complete initial eligible sender body withB<=2097152 | Actual initial complete body above2097152 | Accept stated2x qualification evidence versus hold/revise candidate; this is not claimed runtime wire acceptance/refusal evidence. |

The future checker must detect a deliberately bypassed length guard with these intended size outcomes, alongside a valid control; unrelated setup/JSON/trust failure is not the oversize-control result. Every selected lane reports its real outcome even after a failure. Contract expectations are not parser/runtime test passes. Fresh whole independent review binds the eventual integrated candidate; neither this direction nor counterpart sizing advice substitutes for it. No worker, OS/key/private operation, source implementation, native upgrade or deployment is launched.
