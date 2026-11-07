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
An actual signer adapter must compose that boundary with the retained operation,
job, manifest, unsigned snapshot and current protected admission; the new neutral
audit callback is not an alternative journal. There is no such runtime adapter
installed here. `keylessexecutor` likewise has only a private synthetic controller
and an unconditional public native refusal; this change supplies no process
backend or new controller qualification switch.

The focused controls in `effects_test.go` use synthetic signed Git observations,
the existing BODY decoder, two in-process artifact streams and in-memory effect
adapters. They check effect ordering, independently refreshed nonces, exact job
and raw-manifest hashes, audit correlation and cleanup, with adjacent failures
for presign revocation/withdrawal/check changes, clock/provider uncertainty,
foreign endpoints, changed inputs, audit failure, expiry, cancellation, entropy
failure and the original context bound. These are source controls, not native
execution or whole-service acceptance.
