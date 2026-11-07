# Source authority at effect boundaries

`internal/sourceauthority.NewEffectRunner` composes the existing verifier with
constructor-bound builder, signer and boundary-audit adapters. It is a source
composition seam. There is no installed service, production effect adapter,
provider client, credential reader or native operation in this component.

Construct it outside request handling with protected `Policy`, admitted `Source`
and `Clock`, installed recipe/toolchain/target correlation and distinct admitted
builder/signer endpoint identities. A digest alone does not establish available
policy or toolchain bytes. The adapters and their endpoint identities are trust
grants, just as `Source` is; a callback that echoes caller assertions is invalid.
`Peer` must authenticate the fixed channel used by the corresponding effect and
retain its identity throughout the call. This interface does not authenticate a
transport by itself. Real admission values are not supplied by the source.

`Run` takes only the existing immutable `UnqualifiedOpcode34Body` and the original
active job context. A context with no deadline, an expired/cancelled context, or
more than 600 seconds remaining refuses. The caller must start that original
budget at durable operation acceptance; supplying a newly extended context is
invalid. There is no per-request observation, nonce, policy, endpoint, callback
or qualification selector. The runner admits one active invocation and performs
no retry. Durable operation ownership, idempotency, cancellation/reconciliation
and retention of a gate after uncertain cleanup remain the service custodian's
responsibility; releasing the in-process runner slot is not a durable terminal
operation record.

The source sequence is:

1. Compare the immutable manifest's policy, recipe and toolchain bindings with
   installed configuration. Authenticate the fixed builder endpoint.
2. Generate a 32-byte cryptographically random service nonce and call the
   existing `BeforeBuild`. Check the qualified Git tree against the manifest.
3. Emit the existing opcode17 BODY with the exact operation, nonce, configured
   product/alias, commit/tree, policy, recipe, toolchain, target, raw manifest
   SHA-256 and qualified lease. Retain these actual bytes and their SHA-256.
   The existing opcode34 decoder is reused without a syntax extension; its raw
   bytes are passed unchanged. The 16 KiB job and 1 MiB manifest limits remain
   separate. There is no parser for caller-supplied opcode17 bodies here.
4. Record the neutral authority/correlation projection, recheck the original
   context and the existing local lease, then invoke the bound builder.
5. Retain the returned opaque unsigned snapshot. Authenticate the fixed signer
   endpoint, generate a different service nonce, and call `BeforeSign` for a
   **new `Source.Read`**, even when the build qualification is locally fresh.
6. Check the same tree, retain the original job/manifest/recipe/toolchain hashes
   and add the snapshot receipt to the presign projection. Record it, recheck
   context and lease, and invoke the bound signer. Close the snapshot on every
   subsequent outcome, including failure. Cleanup uncertainty remains a refusal.

Both source reads retain all existing policy, signature, landing, finite review
grammar, current check/delivery and clock predicates. There is no cached build
observation used for presign. Audit failure, changed/revoked source authority,
wrong endpoint, tree/configuration mismatch, entropy failure or local expiry
prevents the corresponding effect. Endpoint/provider errors are reduced to
finite refusals rather than exposing private diagnostics.

`BuildJob.RawBodyCopy` returns an owned copy, while `Manifest` retains the opaque
immutable decoder result. `SignJob` carries that original build job, the owned
unsigned snapshot and the new presign record. The neutral audit projection
contains no raw message bodies or Matrix room/event/sender provenance. Its peer
field is the installed local endpoint identity, not a transport credential.

The builder adapter must still enforce authenticated registration/ack/result
bindings to these exact job bytes, DATA/source/module closure verification,
current installed resource policy, immediate compile-start lease checks,
qualified keyless containment, original deadlines, log bounds, child cleanup
and both artifact streams. The signer adapter must still enforce native first
admission, immutable native staging, current signing policy, durable intent
before signature and durable outcome before release. A returned snapshot or a
successful audit callback establishes none of these missing facts. The runner
does not stream a released artifact and cannot qualify a backend.

The public `keylessexecutor.RunNative` and `keyvaultinput.NativeReadiness` remain
unconditional refusals. No production path constructs these effect adapters.
Source/provider/policy/delivery admission and target clock/native qualification
remain required before any real build or signature. No real key, principal,
membership, owner authority or deployment is selected by the synthetic tests.

The existing `signingaudit.Audit.Run` already orders a fresh
`TrustMetadata.Check(Presign, operation)`, durable intent, its `Signer.Sign`
callback and durable outcome. Its operation/input/replay model is unchanged.
`OpenAuditedSigner` now provides that concrete source adapter. It implements
`SignerEffect`, owns one existing `signingaudit.Audit`, and binds a fixed
`SnapshotSigner`, protected `AuditSignerPolicy`, current native `TrustMetadata`,
`Source` and `Clock` at construction. It is not installed by any runtime here.
The neutral boundary audit remains correlation only; no journal schema, wire
member, opcode or client action changes. `keylessexecutor` still has only a private synthetic controller
and an unconditional public native refusal; this change supplies no process
backend or new controller qualification switch.

Before acceptance, the adapter hashes the retained opcode17 BODY and actual raw
opcode34 BODY, checks their operation/commit/tree/configuration/nonce/lease
bindings against both qualifications, and rehashes the entire unsigned snapshot
through its read-only descriptor. Audit inputs bind those computed hashes, the
snapshot's exact size/hash, the presign summary digest and configured certificate
and requirement digests. The native callback receives that same snapshot and
the journal operation, not a caller hash or path. The snapshot is borrowed only
for the synchronous Sign call; the runner remains its owner and closes it on
return or panic.

`Audit.Run` calls the adapter's trust bridge before durable intent. That bridge
does a new `BeforeSign` with a fresh service nonce, checks exact tree identity,
then calls the configured current native trust checker. It rechecks both original
qualifications and the fresh qualification after that callback. Original context
cancellation and both original lease caps still apply after journal flush and
immediately before native callback entry. The successful fresh qualification is
retained on the exact operation binding with its audit phase. After durable
intent and endpoint authentication, Sign rechecks that qualification alongside
both original caps and the original context directly before backend entry.
Verify, Reconcile and Release apply the same gate after endpoint authentication
for their own phase. A failed refresh clears the previous successful check;
expiry never renews a lease or retries signing. Neither a fresh source observation nor
a replacement context renews the job constructed before Build.

Any error, panic, invalid native metadata or cancellation after intent remains
possible signing. Repeated `Sign` never resumes an existing journal request.
`Reconcile(requestID)` delegates only to the existing Audit recovery path and
the endpoint's non-signing reconciliation method. It refreshes current source
and native trust and must establish completed cleanup and verify existing private
staging; missing staging does not establish that signing never happened. `Fetch`
uses Audit's durable-success gate, independent endpoint verification and two
fresh trust checks, including the check after verification. Only the release
method may emit the already verified stored bytes. A transfer error can mean
partial delivery and leaves historical success unchanged. Neither path signs.
All methods serialize without waiting; Close refuses while a callback is active.

There is a deliberate restart limit. The existing journal retains the authority
digest, not original contexts, sampled-clock epochs, lease caps or raw bodies.
The adapter retains only scalar bindings, the original context and both opaque
qualifications in memory. After Close/reopen, Inspect remains available but
recovery/fetch for old operations refuse for lack of that binding. Sign also
refuses a previously accepted request, including a pre-intent pending operation.
No deadline or missing custody proof is fabricated from the digest. Restart
continuation needs an explicit contract for independently retained operation
custody and clock/lease reconstruction; this adapter does not add a second log,
extend a lease or silently adopt that contract. Native staging remains under
the endpoint's existing custody and is not deleted by adapter Close.

The focused controls in `effects_test.go` use synthetic signed Git observations,
the existing BODY decoder, two in-process artifact streams and in-memory effect
adapters. They check effect ordering, independently refreshed nonces, exact job
and raw-manifest hashes, audit correlation and cleanup, with adjacent failures
for presign revocation/withdrawal/check changes, clock/provider uncertainty,
foreign endpoints, changed inputs, audit failure, expiry, cancellation, entropy
failure and the original context bound. These are source controls, not native
execution or whole-service acceptance.

`auditedsigner_test.go` additionally composes the actual journal with inert
snapshot/signing/staging controls and a fixture durability profile performing
real local file/directory fsync. It checks exact-intent durability before callback
entry and outcome durability before any fixture release, acceptance/intent/outcome
flush faults, staged partial signing, never-signing reconciliation, revocation,
stale head, policy change, wrong certificate pin, expiry/epoch discontinuity,
late cancellation, replaced contexts, restart refusal, panic cleanup and active
writer custody. Local fsync and inert signed bytes qualify no native host,
production durability profile, real key, delivery or release receipt.

Refresh invalidates the matched operation's previous current qualification and
phase before either original lease/context check can fail. Operation request and
inputs must match before this invalidation; an unrelated operation cannot clear
another binding. A transient clock error therefore cannot leave a previous
successful refresh available to a backend entry. New authority is retained only
after all endpoint, source, native-trust and original/current freshness checks
succeed. This changes neither context nor lease bounds, and permits no re-sign.
