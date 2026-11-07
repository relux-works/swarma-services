# Protected GitHub provider implementation work packet

Status: PARTIAL source implementation; no qualified production provider.
`OpenProtectedGitHubPRSource` now composes protected policy loading, current
membership rereads, REST inventory and a concrete fixed-query authenticated
GraphQL POST transport. It returns the protected source accepted by the existing
authority/effect/audited constructors. Synthetic canonical-host TLS fixtures
exercise this exact public constructor through admission, build/sign/verify,
release and recovery, without replacing authority fields.

Current membership, original Git-object/ancestry and effective complete check
readers remain explicit custodian interface gaps, with synthetic readers only.
So do opaque auth-capability issuance/visibility and qualified numeric address
issuance/currentness. Neither opaque capability has a public issuer; zero,
missing or unqualified capabilities refuse without provider probes. Production
use is blocked until these source gaps are implemented and reviewed. Possessing
credentials alone would not complete this work.

The implemented composition API is
`OpenProtectedGitHubPRSource(ctx, ProtectedGitHubPRInstallation) (Source, error)`
in `internal/sourceauthority`, called only by the trusted service composition
root outside requests. It returns the exact protected `*githubPRSource` accepted
by `NewGitHubPR`, `NewWithPolicySource`, `NewEffectRunnerWithPolicySource` and
`OpenAuditedSignerWithPolicySource`. Do not export a generic observation mapper
or permit request-selected URLs, clients, queries, headers, credentials or trust.

The installation must bind these trusted dependencies once:

- A protected canonical policy source, explicit GitHub route and independently
  supplied accepted exact-byte digest. Preserve repository/key/scope validation,
  owner/reviewer separation, and the disabled empty Matrix route. An unchanged
  already accepted policy does not need another approval.
- A current policy and membership reader supplying digest, generation, state
  and the exact admitted account/member relation, with complete current reads
  at both ends of acquisition. Account IDs/logins correlate the signed original;
  only native reviewer public pins authorize its SSHSIG verdict.
- An opaque service-owned authentication capability already authorized for the
  canonical repository and required GraphQL/check visibility. It must keep
  credential bytes out of logs, errors, bodies and caller configuration. Missing
  visibility refuses. Implementation work does not authorize a new credential,
  scope expansion, platform mutation or alternate authentication route.
- An original-Git reader returning exact signed commit bytes, exact object
  identity, default-head state and bounded real parent ancestry. Preserve core
  signature/tree/ancestry verification; synthesized metadata is insufficient.
- A complete effective check-policy/inventory reader covering required rule and
  application identities, latest attempts, statuses and conclusions. No unknown,
  partial, hidden, stale or uncorrelated set may become `no_required` or complete.
- The admitted clock and a canonical TLS acquisition implementation with a
  proved resolver/dial/cancellation lifetime. A caller transport is not a trust
  substitute. Native SnapshotSigner, current native trust, certificate/DR pins
  and durability remain separately supplied audited dependencies.

GraphQL acquisition must issue exactly one POST per requested observation to
`https://api.github.com/graphql`, authenticated to that origin with verified
hostname and public TLS roots, no redirect, proxy, retry or origin fallback.
The JSON body contains exactly `query` and `variables`; `query` is the existing
`githubOriginalReviewQuery` literal and `variables` is exactly `{"id": Rnode}`.
`Rnode` is the exact original node ID bound by the discovered signed numeric R,
not a caller selector, repost or newly allocated review. Bound the request body
and node length before encoding; reject extra variables and arbitrary queries.
Return owned raw JSON, retaining missing/null/false distinctions for the existing
decoder. Any GraphQL errors or partial/null data refuse even with HTTP success.
Never interpret REST fields as never-edited integrity or substitute a history
journal. Existing pending-R allocation/sign/COMMENT submission is separate work;
this provider performs no mutation or reviewer signing.

Preserve the existing stricter bound at every layer, before allocation/return:

| Resource | Existing ceiling / required behavior |
| --- | --- |
| GraphQL response | 24,576 bytes, one response, exact fixed query and original node |
| Response headers | 65,536-byte reservation including parser/copy state; existing conservative parser accounting and 128 field-line ceiling |
| REST metadata | 16 MiB per response, additionally constrained by remaining aggregate budget |
| Raw signed commit | 1 MiB or the lower policy CommitBytes limit |
| Entire acquisition phase | 512 MiB and 1,024 attempted responses maximum; failures consume the budget |
| Policy collections | GitHub caps of 256 ancestry commits, reviews and check records, or smaller configured limits |
| Current REST reviews | Existing unpaginated coverage rule refuses a full 30-entry page; do not silently claim complete coverage or relax this limit |
| Time | Original caller context, absolute phase deadline of at most 30 seconds, sampled monotonic/wall lease and both older audited caps; no renewed deadline on reread |

Retain the existing signed-original decoder predicates: COMMENTED, exact signed
numeric R/node/repository/PR/head/base/ref/body/account and submitted timestamp,
explicit null lastEditedAt, explicit false includesCreatedEdit/isMinimized,
zero userContentEdits with empty nodes, false pagination and null cursors. Missing,
duplicate, case-aliased or malformed fields, dismissal, edit, deletion and copies
refuse. Full canonical installed bytes are reread after each blocking final
GraphQL read against the external digest, followed by time/cancel/lease checks.

All sockets, resolver/dial work, TLS workers, body/header parsing and cancellation
callbacks must finish or be joined before releasing the acquisition gate. Close
underlying sockets directly and retain the original absolute deadline. If the
chosen runtime API cannot prove join, preserve an uncertain/poisoned gate and
refuse subsequent use. Do not clear the present resolver gate merely to make
multiple REST reads work. A qualified solution may use an independently reviewed
owned resolver/connector with provable completion or a supervised acquisition
process whose full lifetime is reaped; its trust and budget contract must be
explicit. A Linux owned numeric connector is now implemented: one nonblocking
socket, synchronous connect/select with at most 5 ms cancellation polling under
the unchanged original deadline, no resolver, parallel racer, callback or retry.
Descriptor duplication into Go's poller occurs only after connection completion;
every failure closes the owned descriptor before returning. TLS and HTTP retain
the existing direct-close and joined cancellation callback. Existing resolver
and DialContext uncertainty containment remains unchanged on the old path.

The connector's numeric address is private, not supplied by a request or public
constructor. There is deliberately no address issuer: independent custody must
qualify canonical address provenance, currentness/expiry and refresh refusal
before issuing it. No DNS implementation or DNS cancellation qualification is
claimed. The new Linux connector requires independent review; its presence does
not admit a new host primitive or clear the old DNS gate.

Implemented transport tests include canonical hostname/public-root verification
(the offline test process has a synthetic public-root store), exact POST/query/
original-node variables and auth-origin binding, strict response and aggregate
bounds/attempt accounting, partial/error/deleted responses, current policy and
membership replacement/revocation, repeated successful inventory/final reads,
blocked kernel connect cancellation, and TLS/header/body cancellation followed
by gate reuse only after join. Original submission time is also correlated.
Remaining custodian readers must enforce shared acquisition budgets before
allocating or returning material; their concrete preallocation, remote-attempt
accounting and lifetime qualification remain unimplemented and block readiness.

Acceptance for this separate unit requires offline synthetic HTTP/TLS controls
for exact POST/query/variables/auth-origin binding, allocations/headers/body and
aggregate bounds, complete current-port rereads, replacement/revocation, HTTP
and GraphQL errors, cancellation during resolution/dial/handshake/headers/body,
and proved gate lifetime across successful repeated reads and all failures.
Run the actual protected constructor through admission and build/sign/verify/
release/recovery with adjacent refusals and no private authority substitution.
Independent exact-head review must cover the complete implementation, not a
half-provider. Fresh installation/admission/runtime evidence then separately
establishes actual credential visibility, provider readiness, target native
endpoints/source closure and the first-run marker. No such live actions are
authorized or claimed by this work packet.
