# Proposed exact-source authority adapter

Status: proposed, 2026-11-01. This specifies a component of the signer's independently movable module, with
separate process and credential custody. It does not establish an installed adapter, account, access grant or
Keychain item. Actual receipt parsing and target qualification remain required before executable admission.

## Credential and trust boundary

Only the evidence-adapter principal holds its own Matrix/GitHub read-access credentials. It is distinct from
the key-holding signer, keyless builder and requesting client. Neither another tool's credential nor an agent's
identity is borrowed. Adapter code uses only required read operations; actual server-enforced capabilities,
room membership and repository access are separate preflight facts. A token that can perform writes cannot be
described as intrinsically read-only because the adapter elects not to write.

The adapter reads its own Keychain item in process through Security.framework. Its item ACL admits only its own
signed executable's designated requirement, binding its own code identifier and pinned signing identity. No generic reader, including
`/usr/bin/security`, or team-OU-only requirement substitutes for that identity. Before that binary is signed and
admitted, same-UID/ad-hoc operation cannot claim this binary-specific isolation. Initial signed adapter delivery
and credential provisioning require the existing custody route; there is no bootstrap self-exemption in this
protocol. This proposal performs neither operation.

For the first slice, independent review identity is a configured Matrix homeserver-authenticated member sender,
distinct from the configured producer sender established by an authenticated exact-head producer handoff. A
hosting account that publishes a COMMENT can be the PR author's account; its name alone proves no independence.
The trusted policy binds repositories, owner signing keys, producer and allowed reviewer senders, Matrix origin
and allowed verdict rooms. A request cannot supply or widen these mappings.

This is the present trust model. It has no end-to-end sender signature: homeserver administration and compromised
member credentials can defeat attribution. Same-OS-user agent tokens also have limited isolation. Future signed
grants are a separate change and are not an additional prerequisite for this agreed MVP identity model.

## Exact review and source binding

An eligible platform review identifies the full candidate head, declares its verdict and contains one neutral
record digest. The exact line accepts either plain `Verdict record digest: sha256:<64 lowercase hex>` or the same
digest enclosed in one pair of Markdown backticks. Exactly one such line is required. Messaging room/event/sender
provenance remains private and is never added to product comments or PR descriptions.
The first supported platform text starts `Independent source review: **ACCEPT** for exact head ` followed by
the full head and base in Markdown code spans. Those values must match the provider record and admitted source;
an occurrence in a quotation, another head or an unrelated ACCEPT sentence does not qualify.

Hash UTF-8 bytes of the stored verdict body string after JSON decoding, without an added newline, trimming,
Unicode normalization or rendered-HTML substitution. The adapter searches only configured evidence scopes,
with the absolute 30s authority budget. The proposed qualifying interval starts 24h before the platform review
timestamp and ends 300s after it. Coverage is complete at authenticated per-scope read frontiers captured for
the observation; this proves no absence of future events and claims no atomic snapshot across scopes.
At most four configured scopes, 256 aggregate pages, 16384 events and 16 MiB of decoded bodies are read.
Exceeding a bound, incomplete coverage or unknown frontier refuses as authority unavailable. A local index may
accelerate a complete read but cannot manufacture coverage. Nonmatching private bodies are not retained in logs.

Exactly one matching stored body across the complete configured scope is required; zero or multiple matches
reject. Repeated pagination of the same event is not a second event. The adapter then verifies:

1. The evidence scope is admitted, the matched event is current and intact, and the sender is an allowed
   independent reviewer rather than the authenticated producer of that candidate.
2. The verdict binds the canonical repository, PR and full exact candidate head; it explicitly accepts that head
   with no unresolved blocking findings. Quoted acceptance, caller JSON or finding the word ACCEPT is insufficient.
3. The platform record and current PR head bind that same candidate; the exact signed commit is subsequently
   landed on the configured default branch without rewriting. Required checks and repository-scoped owner-key
   verification also pass for that exact commit. An unknown rule or unavailable inventory is not success.

Receipt grammar must be frozen against an actual forward-form verdict and COMMENT. A historical platform comment
without the digest is a negative witness for this binding, even if a separate
authenticated verdict establishes its historical provenance. Do not edit historical comments to manufacture a
passing control. A draft, running checks, reviewer assignment or an unlanded accepted candidate is ineligible.
Digest lookup establishes historical provenance only. Current check, landing, review-withdrawal and admission/
revocation evidence remain independent release gates; a bounded historical search cannot establish their absence.

## Protected local projection

The signer creates the evidence endpoint and both sides verify configured kernel peer UIDs. A bounded request
binds protocol version, service-generated operation ID and nonce, product/repository/exact commit, policy digest
and requested qualification phase. The adapter returns only a bounded projection for those exact values.
The signer rejects unsolicited, wrong-peer, stale, wrong-nonce, wrong-policy or mismatched-source projections.
An evidence peer cannot submit artifact bytes as a successful build.

The projection records canonical repository, commit and tree; PR and platform-review identities; verdict room,
event, authenticated sender, server timestamp and exact fetched body SHA-256; owner-signature verification;
bounded lookup scope/coverage/uniqueness evidence; check-policy/inventory/result references; observed default-branch head and landing relationship; acquisition
references; policy identity; observation and expiry times; and an explicit verdict with sanitized reason.
Identity/reference values are data, never commands or arbitrary network destinations. The maximum JSON result
size is 16384 bytes and authority refresh has the existing absolute 30s budget. Detailed bounded wire member
sets and receipt grammar remain part of the same freeze, not permissive free-form maps.

The signer copies the verified projection into its private operation journal before relying on it. Results and
logs exclude credentials, raw private event bodies and provider responses; body digests cover defined fetched
bytes rather than a reworded summary. A local authenticated principal is a trusted verifier, not cryptographic
proof that its projection is true. Host qualification must establish this custody boundary. Qualification leases
and current policy/revocation checks retain the execution contract's maximum 300s freshness and zero-byte refusal.

## Paired qualification controls

| Valid control | Intended refusal and post-state |
| --- | --- |
| Actual digest-bound verdict, complete unique lookup, admitted independent sender and exact eligible head | COMMENT alone, no digest, changed body, zero/multiple matches, quoted ACCEPT, producer sender, wrong source/head/PR: authority rejected, no sign |
| Complete configured-scope lookup within its finite budget | One match in partial/truncated history, unknown frontier or exhausted deadline: authority unavailable, no sign |
| Current exact-head evidence under the admitted policy | Missing event, unknown checks, unavailable provider, expired evidence: refuse without treating absence as acceptance |
| Bound projection from the configured adapter peer | Caller-forged projection, replayed nonce or another policy: refuse before build/sign |
| Adapter reads its own item through its pinned signed binary | Generic reader, another signing identity or team-OU-only match: item access must fail in an isolated fixture |
| Verified source/dependency data for the accepted commit | Binary substituted for source, missing closure or escaping archive: no compilation/signing |

These are acceptance expectations. No provider parser, Keychain control or runtime isolation has been executed
by publishing this document.
