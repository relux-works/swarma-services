# Curator first-client contract delta, proposed r1

Status: source-only design candidate. Provider and consumer acceptance is NOT RECORDED.
No client implementation, transport, production identity, release pin or native qualification is established.

Read [baseline r5](baseline-r5.md), [builder/DATA r2](builder-wire-data-r2.md),
[capacity r3](manifest-capacity-r3.md), [integrated r2](integrated-addendum-r2.md), then this delta.
The earlier documents retain their bytes and status. If accepted, this delta controls only the client
clarifications C1–C8 below. It introduces no opcode, field, error code, client broker or shared framework.
The [open agreement register](../../UNRESOLVED_QUESTIONS.md) remains open.

## C1 — Contract ownership and proposed boundary

The first consumer is Curator core, on darwin/arm64. The proposed logical pairing remains `curator` /
`curator-core`; these are configuration proposals, not evidence of allowlisting. The separate launcher and
later KEK broker remain outside this first integration. Preserve the baseline's
[broker compatibility inputs](baseline-r5.md#kek-broker-compatibility-inputs) without implementing them here.

The acceptance matrix in C8 names the exact accountable roles supplied by the open register. A role is an
acceptance owner, not an assertion that an individual is currently staffed. No supplied evidence identifies
an accepted production principal, actual policy bytes, certificate DER or native requirement blob. Their
values remain UNKNOWN. A document signature cannot fill any of those slots.

All numerical client limits below are carried forward from the baseline's
[finite protocol](baseline-r5.md#proposed-finite-release-signing-protocol) and
[execution contract](baseline-r5.md#framing-deadlines-and-operation-acceptance). They remain PROPOSED for
counterpart acceptance; none is promoted to a qualified deployed limit. No caller may increase a limit.

## C2 — Transport, origin and decoding

Use the proposed signer-created local Unix endpoint with kernel peer credentials in both directions.
The trusted installation binds the client principal, service principal, socket parent/endpoint custody,
allowed role and product/repository pairing. Exact UIDs, paths, ownership/permission and replacement/restart
rules are UNKNOWN: blocked by C8/T. Path possession, JSON identities, correlation IDs and same-UID executable
names do not authenticate a client. If individual executable identity is required, the custodians must admit
its enforcement separately; kernel UID alone provides no such guarantee.

Authentication precedes reading a client frame. Wrong/unknown peer, endpoint custody or role closes the
exchange without accepting work or disclosing operation existence. Do not invent an authentication-success
field or a new error code. An unauthenticated peer receives no operation/receipt/artifact. A client rejects
a response from an unverified service peer and retains any pending request identity for inspection.

The frame is opcode:uint8, body length:uint32 big endian, then exactly that many UTF-8 JSON bytes. Request
body maximum is 4096 bytes; response body maximum is 16384 bytes. These limits exclude the five-byte header.
Check declared length before allocation. Header and body each have an absolute 2-second budget; control
response write has 5 seconds. Four client connections are proposed; a partial connection never acquires the
single operation gate. Extra bytes, truncated frames and stalled peers close the exchange deterministically.

Each object has only its named members. Reject missing, null, wrong-type, unknown or duplicate members,
including duplicate decoded names such as `version` and `\u0076ersion`; reject invalid UTF-8/surrogates,
BOM, trailing JSON and noncanonical integer tokens. Bounds count decoded string UTF-8 bytes and encoded
frame bytes independently. Legitimate JSON escapes/whitespace within those bounds need no shared canonical
encoder. Compare decoded values for request identity; never compare reserialized bytes as authentication.
Malformed input causes `invalid_request`; a well-formed unsupported version causes `unsupported_version`.
If an authenticated bounded refusal frame cannot be sent safely, close; transport closure is not a durable
operation result and never proves no signature exists.

## C3 — Exact request and response projection

Client request member sets are unchanged:

| Opcode | Exact body members | Effect |
| --- | --- | --- |
| 1 sign | version, product_id, repository, commit, request_id | Request configured exact source, never upload a binary |
| 2 inspect | version, request_id | Read caller-scoped recorded state, no build/sign/release |
| 3 fetch | version, operation_id | Request caller's existing artifact under current release policy |

Every field below inherits the whole-frame/deadline bounds in C2. Owner/dependency labels refer to C8.

| Field or exact group | Type and finite bound | Trust origin and required refusal | Acceptance owner/dependency |
| --- | --- | --- | --- |
| version | JSON integer token `1` | Decoder; other version refuses, no effects | Services + Curator / W |
| product_id | Nonempty configured ASCII string, at most 128 bytes | Caller selector compared with protected pairing; not_allowlisted/admission_required, never caller admission | Service maintainer + signing custodian / A,W |
| repository | Nonempty configured ASCII alias, at most 64 bytes | Caller selector compared with pairing; no URL/path/branch or authority assertion | Service maintainer + Curator maintainer / A,W |
| commit | String, exactly 40 lowercase hexadecimal SHA-1 digits | Caller selects exact object; actual signature/review/check/landing from authority provider, not this string | Service + first-client delivery owner / S,W |
| request_id | String, 1–64 ASCII letters/digits/underscore/hyphen | Caller correlation scoped by authenticated principal; reused changed semantics yields request_conflict | Service + Curator / R,T,W |
| operation_id | Service-generated 128-bit random value as 32 lowercase hexadecimal characters | Durable caller-scoped index; foreign/absent ID yields non-disclosing request_not_found | Service + Curator / R,T,W |
| state | Exactly pending/succeeded/refused/uncertain | Durable journal projection; inconsistent or unavailable history cannot claim terminal success/absence | Signing custodian + service / D,W |
| source | Object exactly product_id, repository, commit, with bounds above | Retained accepted request, not a response-selected replacement; mismatch rejects consumption | Service + Curator / S,W |
| outcome.kind | Exactly the literal matching state | Journal-derived discriminant; any incompatible or extra variant member rejects response | Service + Curator / D,W |
| outcome.phase (pending only) | Exactly qualifying/acquiring/building/signing/reconciling | Recorded phase; never permission to invoke signing from client | Service + Curator / D,W |
| code | Exactly a code listed in C6, no free-form extension | Service-selected classification with effect constraints; unknown response code rejects consumption without retry signing | Service + Curator / W,R |
| retry | Exactly never/same_request/inspect/later | Service hint subordinate to C5, never fresh signing authority | Service + Curator / R,W |
| message | Service-selected UTF-8 literal, at most 256 bytes | Sanitized constant, no caller echo, private path, provider body or secret | Service + Curator / W |
| receipt | Exact object below | Durable verified outcome; syntax/hash strings alone prove no authority | Signing custodian + service + Curator / D,F,S,W |
| artifact_bytes | Integer 1–268435456, identical to receipt.signed_bytes | Service snapshot size, checked before receiving; mismatch rejects file | Service + Curator / F,W |

Opcode 64 operation summary has exactly `version, request_id, operation_id, state, source, outcome`.
Pending outcome has exactly `kind, phase`. Succeeded outcome has exactly `kind, receipt`.
Refused outcome has exactly `kind, code, retry, message` and requires established durable pre-sign refusal.
Uncertain outcome has exactly `kind, code, retry, message`, with kind=uncertain,
code=outcome_uncertain and retry=inspect. No artifact is released with pending/refused/uncertain.

Opcode 65 refusal has exactly `version, code, retry, message`, with no arbitrary request ID echo.
It covers decoder/lookup/busy rejection and current fetch refusal without erasing an existing operation.
Opcode 66 fetch header has exactly `version, operation_id, receipt, artifact_bytes` and precedes only the
successful artifact stream in C4. Response opcodes are invalid client inputs. Source, operation and receipt
must match the request and retained record; a syntactically valid cross-operation response is rejected.

Receipt members are exactly those below; no optional success flags or provider provenance are added:

| Receipt member group | Type/bound and origin | Refusal and owner/dependency |
| --- | --- | --- |
| product_id, repository, commit | Same scalar grammars as above; retained exact accepted source | Mismatch rejects receipt; service + Curator / S,W |
| policy_sha256, recipe_sha256, toolchain_sha256, input_sha256 | Each string exactly 64 lowercase hexadecimal digits; hashes of actual protected policy, recipe, full toolchain and retained input bytes | Missing actual bytes/pins is unavailable, not self-authentication; service + Curator build owner / B,S,A |
| target | String exactly darwin/arm64 | Other target refuses this slice; service + Curator / B,W |
| unsigned_sha256, signed_sha256 | Each string exactly 64 lowercase hexadecimal digits; signer-owned independently verified snapshots | Wrong hash rejects artifact; signing custodian + service + Curator / B,F |
| unsigned_bytes, signed_bytes | Canonical integers, each 1–268435456 | Zero/oversize/mismatch rejects artifact; signing custodian + service + Curator / B,F |
| certificate_sha256 | String exactly 64 lowercase hexadecimal digits, SHA-256 of exact admitted public certificate DER | Unknown/wrong actual pin rejects release/consumption; signing custodian + service / A,F |
| requirement_sha256 | String exactly 64 lowercase hexadecimal digits, SHA-256 of agreed native requirement blob | No inferred pin from a label or historical fingerprint; signing custodian + Curator / A,F |
| audit_sequence | Canonical integer 1–9223372036854775807, durable outcome/recovery sequence | Missing/inconsistent outcome withholds release; signing custodian + service / D |
| audit_digest | String exactly 64 lowercase hexadecimal digits, actual durable outcome record digest | Receipt not backed by durable history withholds release; signing custodian + service / D |

Counters use ordinary nonnegative decimal integer tokens with no sign, fraction, exponent or leading zero
except the token 0 where zero is allowed. The client receives no caller UID, private path, key, credential,
raw review body or room/event/sender provenance. This external summary is not serialization of internal Go
operation structs. Internal tree, nonce, authority and raw-manifest bindings remain required upstream under
the existing authority/builder/audit contracts and are not new client-selected fields.

## C4 — Immutable artifact handoff and current release authority

Fetch streams only the signer's existing verified snapshot. Following the complete opcode 66 header, send
exactly artifact_bytes raw bytes and close: no upload, path, descriptor, compression, redirect, chunk protocol
or trailing frame. Enforce the absolute 60-second transfer budget and 256 MiB size bound independently of
JSON limits. Interrupted/short/extra/hash-mismatched transfer is unusable; preserve history and fetch the
same operation again only after current qualification. It never starts another build or signature.

The client writes an exclusive private file under its admitted custody policy, verifies exact size and
SHA-256 plus the agreed native certificate/requirement/target policy, then publishes/consumes it. A receipt's
reported verification cannot replace the client's native verification. The actual client destination custody,
certificate DER, requirement bytes and verification procedure are UNKNOWN, blocked by C8/F and A.

Immediately before emitting any artifact byte, the provider checks ownership, historical durable success,
actual stored bytes and current trusted admission/revocation/policy and exact-source authority. A lease
has zero future tolerance and maximum age 300 seconds using a qualified clock. The audit component makes
fresh trust calls for each fetch; it is not a production adapter or a reusable restart lease. A stale lease
refreshes autonomously within the existing absolute 30-second authority budget. Unknown time, unavailable
evidence or revoked admission withholds every artifact byte on that new fetch decision. Historical inspect
success remains truthful. An authorized in-flight transfer retains its 60-second bound; revocation cannot
recall delivered bytes. No fetch result grants perpetual release eligibility.

The provider's immutable snapshot/transfer implementation, durability and native enforcement remain external
custody gates. The builder recipe, module graph, DATA/cache and double-build mechanisms are governed only by
the existing [integrated contract](integrated-addendum-r2.md#production-acceptance-and-diagnostic-separation--n5)
and the separately accepted builder/artifact delta when available. A parallel draft supplies no accepted pin.

## C5 — Acceptance, retries and UNKNOWN

Persist the Curator-side pending request identity before its first send, retaining principal mapping and the
semantic tuple (version, product_id, repository, commit, request_id). No timing event changes that tuple.
The actual client persistence/restart policy is blocked by C8/R. On the provider, authenticate, fully decode,
validate pairing/admission and deduplicate before acquiring the operation gate; durable acceptance precedes
qualification/build dispatch. A sign response is an asynchronous summary, not a socket held for the 600-second
build. Client compatibility with this behavior requires W acceptance.

Deduplicate by authenticated caller principal plus request_id and compare decoded semantic source values.
A matching sign retry returns the existing operation without trust/build/sign side effects. Retain the
original immutable policy/input/authority bindings: do not regenerate them from current policy to turn an
inspection retry into new work or a spurious new operation. Internal continuation is the provider's once-only
operation path. Different semantics or changed claimed retained bindings yield request_conflict; another
active request yields busy, with no queue. An uncertain operation holds the gate.

| Observed condition | Required consumer/provider behavior |
| --- | --- |
| Definitive local failure before any send | Keep the same request tuple for a permitted first transmission; no new ID is necessary |
| Sign response lost, malformed, timed out, or service disconnected/restarted | Outcome UNKNOWN; inspect the same caller/request. Never infer refusal or issue a fresh sign ID |
| Matching accepted request | Return pending/succeeded/refused/uncertain historical summary without another sign |
| inspect reports request_not_found after an ambiguous send | Absence of this lookup is not proof of absent signing. Hold; require authoritative custody/replay reconciliation before any new sign |
| Intent exists without durable verified outcome, native timeout/cancellation, unknown child cleanup, or missing staging | Keep uncertain and the operation gate; reconcile recorded staging only, never sign again |
| Durable successful outcome exists but fetch is revoked/expired/unavailable | Preserve historical success; release zero bytes for that decision; refresh/fetch may not rebuild or re-sign |
| Client identity changed or journal/index continuity is unavailable | Do not treat the new namespace as permission to repeat the release; signing custodian resolves mapping/history |

The component's retained record has no automatic pruning or retry-key expiry. No finite accepted retry
horizon is supplied: value UNKNOWN, owner C8/R. This delta proposes retaining deduplication for the lifetime
of the operation history; capacity refusal occurs before accepting new effects. An expired artifact or client
deadline never expires signing history. Any future retention, key reuse, identity migration or storage-recovery
contract must preserve evidence preventing duplicate signing. Missing/corrupt/torn history fails closed.
No timeout, retry hint, request_not_found, later retry, or new caller key authorizes a second signature after
an ambiguous outcome. Only positive custody reconciliation can establish the existing operation's result;
reconciliation itself never invokes signing. The client uses the baseline's finite per-exchange budgets;
overall retry/backoff/availability policy remains UNKNOWN under R, not an invented release SLA.

## C6 — Refusal classes and effect constraints

These are the baseline's existing finite codes. No error message is used as a machine predicate.

| Codes | Required meaning/effect | Proposed retry classification |
| --- | --- | --- |
| invalid_request, unsupported_version | No acceptance/build/sign; bounded sanitized reply only when safe | never |
| not_allowlisted, admission_required | Protected pairing/admission absent; no build/sign | never for unchanged configuration |
| request_conflict | Same caller/request with different semantics/bindings; no replacement effect | never |
| busy | Another active/uncertain operation; no queue/new effect | later, preserving pending identities |
| request_not_found | Authenticated scoped absence, including foreign IDs; disclose no existence | inspect after ambiguous send; never new-sign authority |
| authority_rejected, authority_unavailable | Exact authority not established; no sign; on fetch zero bytes, preserve history | inspect if accepted; same_request only with definitive pre-acceptance rejection |
| build_failed, build_isolation_failed, artifact_rejected | Established pre-sign build/isolation/snapshot refusal; no sign/release | inspect recorded refusal; no automatic new operation |
| audit_unavailable | No required durable intent means no signer entry; uncertain outcome means no release | inspect whenever acceptance/effect is possible |
| signature_failed | Failed native signing/verification means no release; signer-entry ambiguity remains uncertain | inspect, never blind re-sign |
| outcome_uncertain | Possible effect without verified durable outcome; gate retained, zero release | inspect |
| release_revoked, artifact_expired, artifact_unavailable | Current artifact release refused, zero artifact bytes; historical result retained | inspect or later fetch same operation, no signing |

The retry column is a proposed client mapping requiring W/R acceptance, subordinate to C5. A definite
non-success result from native signing is not enough to claim no effect; once signer entry is possible,
retain uncertain unless positive evidence establishes a durable verified outcome. `signature_failed` may
describe that failed attempt but cannot change uncertain to terminal refused. Only established durable
pre-sign refusal uses state=refused. A later fetch refusal uses opcode 65 and does not overwrite success.

## C7 — First admission and later release autonomy

The owner decision is already recorded in [required behavior](baseline-r5.md#required-behavior): owner
presence applies only to initial allowlisting of a tool that holds/binds secrets. Curator core is classified
secret-bearing. No evidence here establishes its actual initial admission. Missing that admission yields
admission_required. Protected policy and the custodian, never a request flag or client claim, bind the product,
repository, identity and first-confirmation record. Actual confirmation, policy-change/revocation and
re-admission semantics are UNKNOWN under C8/A; they must not be guessed from this draft.

After initial admission, reviewed qualified releases proceed autonomously through the existing authority,
build, artifact, audit and fetch gates. Add no per-release owner-presence, Touch ID, build-hash approval or
new owner signature on this path. Revocation may prevent release; it does not manufacture an additional
release-specific approval rule. Admission is not proof that this particular source/artifact meets the gates.

## C8 — Provider/consumer acceptance and blocked values

No row below is counterpart-accepted by this candidate. Known owner decisions and landed pure components
are facts with the narrow scopes indicated; new clarifications and production values remain proposed/open.
The row labels are local documentation references, not board elements or a new runtime policy language.

| Gate | Provider obligation / acceptance owner | Consumer or counterpart obligation / acceptance owner | Exact dependency and present blocked_by |
| --- | --- | --- | --- |
| W: wire/projection | Service maintainer accepts C2/C3/C6 exact variants, capacities and async responses | First-client maintainer (Curator) accepts decoding, persisted request correlation and positive/refusal/inspection behavior | baseline finite protocol + open-register request/result row; blocked_by independent exact-candidate design review and both maintainers' recorded acceptance |
| T: authenticated origin | Signing custodian + service maintainer accept actual service/client principal mapping and endpoint custody | macOS host custodian + Curator maintainer accept reverse authentication and same-UID trust limit | baseline proposed envelope/independent principals + open-register builder/isolation row; actual UID/socket/custody pins UNKNOWN, blocked_by those custodians' admission |
| A: admission/policy | Signing custodian and service maintainer under owner decision bind first confirmation, actual policy bytes, signing identifier, certificate DER, requirement blob, revocation/re-admission | Curator maintainer consumes those actual admitted pins and preserves later-release autonomy | baseline required behavior + open-register first-admission row; initial presence/later autonomy is existing decision, actual record/pins UNKNOWN; blocked_by custody acceptance, no per-release approval added |
| S: actual source authority | First-client delivery owner + service maintainer supply authenticated complete current source/review/check projection and qualified clock/profile | Curator maintainer binds exact requested release; signing custodian verifies at effect boundaries | sourceauthority-implementation.md trust-boundary section + open-register parser/lookup row; pure verifier exists, actual production adapter/owner pins/forward-form qualification UNKNOWN; blocked_by source/delivery acceptance |
| B: artifact dependency | Service maintainer + first-client build owner accept existing builder/artifact receipt and exact source/recipe/toolchain/closure | Curator build owner accepts actual release inputs and native compatibility | integrated-addendum-r2.md B1/N5 + open-register source/recipe and closure rows; blocked_by accepted builder/artifact contract and real pins/qualification; parallel builder draft is reference only |
| D: durable outcome | Signing custodian + service maintainer admit actual durability primitive, storage budget, checkpoint/recovery custody and once-only composition | Service/client maintainers accept persisted summary/UNKNOWN/recovery behavior | signingaudit-implementation.md operation contract + open-register durable-audit row; pure audit exists, native persistence/checkpoint/composition UNKNOWN; blocked_by those custodians' acceptance |
| F: transfer/verification | Signing custodian + service maintainer accept immutable retained snapshot/current fetch gate/expiry | Curator maintainer + macOS host custodian accept private destination and actual native verification | baseline fetch eligibility + open-register transport and native rows; actual transfer/custody/native procedure UNKNOWN; blocked_by T/A/D and counterpart acceptance |
| R: retry/retention | Signing custodian + service maintainer accept principal-scoped deduplication/history continuity and storage refusal | Curator maintainer accepts C5, durable client identity and recovery across lost responses/restart | baseline durable operation history + open-register retry/audit rows; finite horizon/backoff/storage custody UNKNOWN; blocked_by client/service/host retention acceptance, no expiry permitting second sign |

Independent review binds the exact candidate head/tree and requested reviewer model/effort. Provider and
Curator consumer acceptance then bind these clauses and each real policy/custody value; unresolved values
stay blocked. Source hygiene/marker and source-custodian delivery remain separate gates. Source drafting
completion closes none of implementation, whole-solution review, native qualification, installation or first-use
acceptance. No actual production provider invocation or key/service access is authorized by this document.

## Paired contract controls — specified, NOT EXECUTED

Each negative changes only the intended seam predicate in an otherwise admitted complete positive case.
Preserve actual commands, bounds, exits, times, failures and effect counts when a later gate authorizes
execution. A shape-only fixture cannot establish native/provider acceptance.

| Control | Valid case / intended negative | Required observation |
| --- | --- | --- |
| P1 origin | Admitted kernel peers and custody / wrong peer, replaced endpoint or JSON UID claim | Valid exchange / no accepted work, no operation disclosure or artifact |
| P2 decode | Exact version-1 sets within 4096/16384 bytes / extra or decoded-duplicate member, null, invalid surrogate, unsupported version, oversize or short frame | Intended decoder refusal before effect; absolute deadline, no gate leak |
| P3 operation | Accepted exact Curator source and protected pairing / caller binary/path/recipe, mutable/substituted artifact or wrong source/operation response | Correct summary / input refusal or rejected consumption; no substituted release |
| P4 authority | Fresh authenticated exact-source build/presign evidence / stale, wrong owner/head, partial check inventory or unknown clock | Intended authority refusal, no signing; green/empty unknown inventory is insufficient |
| P5 lost response | Durable accepted operation followed by response loss and same-ID inspect/retry / new ID or changed principal after ambiguity | Same operation, signing count at most one; unknown history holds |
| P6 uncertain | Intent plus possible native effect, then outcome failure/timeout / missing staging treated as absence | uncertain, zero release, gate retained; reconcile existing bytes only, no signer reentry |
| P7 fetch | Current admitted historical success with exact signed bytes / revocation, expiry, altered hash/size, interrupted/extra transfer | Verified client file or no consumption; new fetch requalifies, zero new signatures |
| P8 admission | Initial secret-bearing tool confirmation then later qualified release / client claims first admission or asks per-release presence | Initial missing admission refuses; later admitted release autonomous with all other gates |
| P9 history | Retained scoped index across restart / torn/corrupt/absent journal, exhausted budget or identity migration | No false not-found success or dedup expiry; refuse new effects, preserve evidence |

These are acceptance expectations for the existing service/client route, not another implementation, test
framework, live experiment, or claim that a native signature/build/client exchange has run.
