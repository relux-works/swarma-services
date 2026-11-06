# Signer contract baseline, revision 5

Status: design specification. Implementation, source/recipe admission and runtime qualification remain pending.
Read this baseline with [builder/DATA](builder-wire-data-r2.md), [capacity](manifest-capacity-r3.md) and
[integrated addendum](integrated-addendum-r2.md), in that order. The integrated addendum controls its explicit deltas.

## Review and receipt rules

Product review records carry the exact head, verdict and neutral verdict-body SHA256; messaging room, event and sender provenance remains outside product records.
The configured authenticated Matrix reviewer must differ from the authenticated producer and bind the exact head and pull request. The lookup interval is 24 hours before to 300 seconds after the platform-review time. Require complete per-scope frontier coverage, exactly one digest match and a 30-second budget. Unknown-scope discovery and substring trust are forbidden. Zero or multiple matches, partial/truncated/deadline/unknown coverage refuse. Future events and atomic cross-scope snapshots are not claimed. Private journals retain minimum provenance; product receipts expose none.
Module receipts contain actual inline original source mod/sum hashes, bounded path/version/checksum/directory records and streamed dependency content. Original source go.sum verification and offline closure are required; cache-integrity self-checks cannot replace them.
The first client is the core tool. For tools that hold or bind secrets, owner presence applies only to first allowlist admission; later qualified releases are autonomous. The commit-derived label, separate credential adapter, signer and keyless builder, P-256, audit/recovery and current fetch gates remain required.

The baseline's 52 declarative expectations comprise 13 request, 17 authority, 15 DATA and 7 module cases. JSON serialization, links and whitespace are checked only; these expectations are not executable parser, runtime or security tests.

---

Source: signer/docs/contract-v1.md

# Release signing contract, version 1

Status: proposed, 2026-11-01. Client and host parameters listed below remain open. This is a source contract
proposal, not evidence of counterpart acceptance, deployment, key access or installation authority.

The first usable slice serves Curator on `darwin/arm64`, accepts SHA-1 repository object IDs and runs one signing
operation at a time. Broker compatibility is recorded now; second-client implementation follows Curator rollout
and dogfooding. Other targets, object formats and parallel signing are outside this slice.

## Required behavior

The service accepts a configured repository alias and an exact commit for an allowlisted product identifier.
It never accepts a caller's binary. The exact commit must be signed by an admitted owner key, independently
reviewed, checked and landed. A separate keyless builder builds the source. The signing account never builds.
The existing signing identity uses ECDSA P-256. A prepared identity alone is not a running service.

Owner decision, 2026-11-01: owner presence is required only at the first allowlist admission of a tool that
holds or binds secrets. Subsequent qualified releases are autonomous. No release-specific presence approval,
build-hash approval or Touch ID prompt is added to that later-release path.

The owner's words on 2026-11-01 were «чтоб не мне каждый раз подписывать а ты сам» and, about presence once for
a new tool, «да ок, пока можно оставить я пер новый тул». The earlier 2026-10-30 boundary was
«тач айди только для тулов с секретом».

Admission and artifact integrity serve different purposes. The trusted admission record binds the configured
product/repository identity and admitted policy; build and signing receipts bind each release's exact bytes.
The admission confirmation mechanism and policy-change/revocation behavior require custody agreement before
implementation. The caller cannot declare a tool admitted or non-secret-bearing.

The first Curator core candidate is classified as secret-bearing: its source already resolves Git credentials,
accepts login tokens and supplies registry authorization. This classification does not assert that a particular
installation contains a secret or that its first admission has occurred. The separate launcher remains a later
artifact. The [first Curator build proposal](baseline-r5.md#first-curator-build-proposal) records the source and recipe boundary.

## Independent service boundary

The signer is a separately movable Go module with its own README and shipped skill when executable tooling
exists. It shares no internal packages with other services or clients. Curator signing/OAuth and the proxy KEK
broker integrate through a versioned external contract and configuration seams. Their standalone MVPs do not
depend on a new shared framework. This interface neither reads nor returns OAuth tokens, KEKs or private keys.

The network proxy application and its separately provisioned KEK broker are distinct products. An application
repository, identifier, build recipe or historical ad-hoc pilot signature cannot establish the broker's source,
allowlist admission or production signing policy. Broker facts come from the actual broker source and custodian.
The proxy consumer's existing private-store and failure-before-listener guarantees remain its own contract;
a signing receipt does not establish broker deployment, envelope migration or private-host qualification.
The [broker compatibility inputs](baseline-r5.md#kek-broker-compatibility-inputs) record its known source boundary and remaining
recipe and installation limits.

## Proposed request and result envelope

Version 1 is a finite local request/result protocol. A Unix socket with kernel-provided peer credentials is the
proposed transport. Both endpoints verify configured peer UIDs. A claimed JSON UID, socket-path possession or
correlation identifier is not authentication; a kernel UID does not identify an individual executable among
same-UID processes. Exact principal mappings, socket custody, framing and final bounds require agreement before
freezing the wire schema.
The [proposed execution contract](baseline-r5.md#proposed-execution-and-artifact-release-contract) specifies the separate builder process, bounded byte-stream
handoff, IO budgets, acceptance boundary, journal recovery and artifact-release eligibility.

| Request member | Proposed type and meaning |
| --- | --- |
| `version` | Integer `1`; other versions refuse |
| `product_id` | Configured exact identifier; no caller-selected signing identifier |
| `repository` | Configured alias paired with that identifier; no URL or path |
| `commit` | Full exact lowercase 40-character SHA-1 object ID; other repository formats are unsupported in this slice |
| `request_id` | Client-scoped correlation and retry key; grammar/length pending client evidence |

Objects reject duplicate or unknown members, missing/null/wrong-type values, trailing content and oversized
frames before any build or sign effect. Bounds apply before unbounded allocation. The request contains no binary,
artifact path, branch, command, recipe, toolchain, certificate, entitlement or secret-bearing override.
Examples from both real clients will fix accepted grammars and limits; an invented identifier is not admission.

Every accepted exchange has a version and correlation identifier. Success returns the configured product and
repository, exact source commit, policy/recipe/toolchain identities, target, unsigned SHA-256 and size, signed
SHA-256 and size, certificate pin, designated-requirement verification and durable audit receipt. The agreed
transport delivers the immutable signed artifact corresponding to that receipt; an arbitrary output path is not
authority. Clients verify the signed hash/size and signature evidence before consuming it.

Refusal returns a stable machine-readable code, sanitized explanation, retry classification and known operation
state. A malformed request with no valid correlation identifier must not echo arbitrary input. Logs and results
exclude private paths, credentials, raw provider responses and key material. The precise JSON result schema and
artifact transfer method remain unaccepted.

| Proposed code | Meaning and required effect |
| --- | --- |
| `invalid_request`, `unsupported_version` | Input rejection; no build/sign |
| `not_allowlisted`, `admission_required` | Unknown pairing or missing first admission; no build/sign |
| `authority_rejected`, `authority_unavailable` | Exact signature/review/check/landing not established; no sign |
| `build_failed`, `build_isolation_failed` | Trusted build or isolation failed; no sign/release |
| `artifact_rejected` | Receipt/snapshot/hash/size/rebuild mismatch; no sign/release |
| `audit_unavailable` | Required durable intent/outcome unavailable; withhold release |
| `signature_failed` | Native signing or verification failed; no release |
| `request_conflict` | Retry identifier reused for a different semantic request; no new effect |
| `busy` | A different operation is active or awaiting reconciliation; no new build/sign |
| `release_revoked`, `artifact_expired` | Historical outcome retained; no artifact bytes or new signing on fetch |
| `outcome_uncertain` | Signature may exist in private staging; no release or automatic blind re-sign |

These codes are proposals for client agreement, not promises about an existing executable.

## Source authority and trusted policy

Installed trusted policy selects the repository URL/default branch, product pairing, admitted owner key,
independent review evidence adapter, required checks, build recipe, target, signing certificate pin and
entitlements. The caller selects none of these. Policy and evidence receipts have explicit identities.
Owner-key admission is repository-scoped: an automation key admitted for another repository cannot qualify a
client release here. An unrelated signers file or repository's own declaration cannot widen the trusted key set.

Resolve the current canonical default branch from the configured authority and verify that the exact requested
commit is landed there. Verify the commit's cryptographic signature against the configured owner key and obtain
actual independent acceptance and required successful checks for that exact candidate. Missing, unknown, stale,
wrong-head or unavailable evidence refuses. Caller assertions, tags, commit trailers and a producer's own
review comment cannot establish independent acceptance. Provider records must match the actual delivery
mechanism; no approval-only adapter is assumed.

A legitimate delivery form can record an independently received exact-head verdict in a GitHub COMMENT review
when the publishing account cannot approve its own PR. The service must also verify the independent verdict's
provenance and exact candidate binding; the COMMENT alone is insufficient. For the first adapter, an eligible
COMMENT carries the exact head, verdict and one stored-verdict-body SHA-256 digest. Messaging provenance stays
in private process evidence. The adapter proves a unique exact digest match within configured bounded evidence
scopes, then checks the authenticated independent sender, exact source head, PR and explicit acceptance without
unresolved blocking findings. Incomplete coverage never establishes uniqueness. Historical comments without
the digest do not pass this forward requirement.
The [authority adapter contract](baseline-r5.md#proposed-exact-source-authority-adapter) defines the separate credential principal, protected projection
and present trust limits. A successfully read, empty inventory
of checks under an independently established no-required-check policy is distinct from green CI. Unknown rules,
unavailable inventory or missing required checks cannot be interpreted as that empty case. Exact parsing must
be qualified against the actual forward-form receipt before freeze; no shared review framework is required.
The [finite protocol proposal](baseline-r5.md#proposed-finite-release-signing-protocol) specifies request/result variants, protected projections and
bounded source DATA, including supplied module-receipt content rather than a digest of unavailable data.

Recheck authority and admission immediately before build and before sign, with explicit freshness and revocation
rules. The accepted adapter must define how an exact reviewed signed head remains attributable after a permitted
nonrewriting landing. Freeze those evidence forms with clients before writing the admission implementation.

## Keyless build and immutable handoff

The builder is a distinct unprivileged account with no signing key or signer-home access. It uses a clean exact
commit, a trusted pinned recipe/toolchain, bounded resources, and a sanitized environment without inherited
authentication. Source/dependency acquisition with any provider credentials occurs in the separate authority
adapter, which supplies verified bounded source data rather than executable build output. The builder receives
no token, credential helper, SSH agent or credential-bearing URL and runs offline with approved dependency inputs.
Go recipes use `GOTOOLCHAIN=local`, `-mod=readonly`, `-trimpath` and verified dependency sums;
they do not run caller commands or `go generate`. Exact client architectures, dependency/network policy and
deterministic build inputs remain to be confirmed.

Account separation alone is not a general filesystem sandbox. The host contract must demonstrate that a build
cannot read the signer home/keychain or secrets exposed elsewhere on the host. Isolation controls run in safe
fixtures; source tests never authorize probing live keys or user data.

The builder emits a bounded regular artifact and receipt binding product, repository, commit, recipe/toolchain,
target, unsigned SHA-256 and exact byte size. The signer opens the input without following links, creates its
own private immutable snapshot, and independently verifies size/hash and receipt. It refuses links, replacement,
truncation, mutation or mismatch. The builder cannot alter the snapshot or trusted signing policy. The unsigned
artifact must reproduce byte for byte in two independent clean workspaces under the same recorded deterministic inputs;
a mismatch refuses signing. Recipes must bind version, date, VCS and other build inputs instead of inheriting
ambient values. The exact pinned recipe and independent rebuild procedure remain to be agreed before building.

## Signing, audit and recovery

The signer signs only its verified snapshot using the admitted P-256 identity. Native verification must establish
the actual selected certificate pin and designated requirement. Ad-hoc output, a different certificate or a
failed verification cannot succeed. Signing changes bytes: unsigned and signed hashes are separate fields.

The ordered release boundary is:

1. Establish request, allowlist admission, exact source authority and verified build snapshot.
2. Durably append an intent binding the operation and all release inputs before signing.
3. Sign the private snapshot and verify the resulting signature, identity and final hash/size.
4. Durably append the outcome and its artifact identity before releasing the artifact.
5. Release only the artifact bound to the successful outcome and return its receipt.

The log is append-only, inaccessible to the builder, integrity chained and externally checkpointed. Chaining
alone does not establish resistance to root or signing-account compromise. The checkpoint custodian, durability
primitive, concurrency ordering and retention policy require agreement. An audit failure before intent prevents
signing; failure after signing withholds the artifact in private staging and truthfully reports its known state.

A client scopes `request_id` within its authenticated identity. The semantic request includes version, product,
repository and commit. Reuse for different inputs refuses. A matching retry returns the existing operation's
state/result; policy and authority changes must never be hidden by retry. Stored policy identity and retry
freshness behavior remain to be specified before implementation.

Only one signing operation may be active. A matching retry inspects/returns its persisted state; a different
request receives `busy` without starting a new build/sign or an implicit queue. An interrupted operation with an intent
and no durable outcome remains uncertain until recovery reconciles private staging and verification evidence.
It retains the active-operation gate and must neither release nor blindly sign again. Recovery records append to
the audit instead of rewriting it.
An uncertain result is not a claim that no signature was created. Audit retention must cover the retry horizon.
Historical success does not override current admission, revocation or evidence freshness on a later fetch.
Inspection may still report that historical outcome while artifact release refuses with zero artifact bytes.

## Acceptance controls

Each forbidden case has a nearby valid control and asserts the intended refusal and post-state. Live destructive
plants and real private-key reads are excluded; runtime isolation evidence needs its separately authorized lane.
Every selected test lane runs and reports even if an earlier lane fails.

| Surface | Valid control | Forbidden case and observable invariant |
| --- | --- | --- |
| Envelope | Current client's complete request; broker compatibility retained for later integration | Binary/path/command injection, duplicate/unknown/oversize fields; no build/sign |
| IPC | Configured kernel peer UID on both endpoints | Forged JSON UID or wrong kernel UID refuses before private-key use |
| Admission | First confirmed secret-tool admission; later qualified release | Missing admission/unknown identifier; no build/sign. Later release has no presence prompt |
| Authority | Exact owner-signed independently reviewed checked landed commit | Wrong signer or key admitted only for another repo, unlanded, unreviewed, wrong-head review, missing/unknown checks; no sign |
| Builder | Real trusted exact-source build | Signer builds or builder reaches signing secrets; intended isolation refusal, no release |
| Snapshot | Matching immutable artifact/receipt and independent unsigned rebuild | Symlink, substitution, truncation, hash or reproducibility mismatch; no sign |
| Signature | Pinned P-256 identity and native verification | Ad-hoc/wrong identity/DR mismatch; no release |
| Audit | Durable intent then signature then durable outcome | Missing intent prevents sign; failed outcome withholds artifact without claiming no signature |
| Recovery | Same completed request returns its result; pending retry returns its state | Changed-input retry conflicts; different active-operation request is busy; interrupted retry cannot duplicate signing or release uncertain output |

Instrument controls must demonstrate a known forbidden effect is detected for the intended reason. Source
fixtures prove only the paths they exercise; they do not establish host account isolation or deployment success.

## Open agreement points

The [open agreement register](../../UNRESOLVED_QUESTIONS.md) names the missing client and custody facts. Building
starts only after the request/result/data/error/refusal, authority, build/handoff, admission, audit/recovery and
acceptance contracts are agreed. A later installer must enumerate exact write targets, preflight, rollback and
one absolute maintenance entrypoint. Host execution remains a separate exact-operation decision.

---

Source: signer/docs/execution-v1.md

# Proposed execution and artifact-release contract

Status: proposed, 2026-11-01. These are source mechanisms for the Curator-first slice. No process, principal,
socket, directory or policy described here is asserted to exist or authorized for installation.

## Principals and data custody

The signer runs under its configured signing principal and binds its own sockets. A separately launched,
unprivileged builder process runs under the configured distinct keyless principal. A separate evidence-adapter
process runs under its own configured unprivileged principal, distinct from signer, builder and requesting client.
It owns provider-read credentials and returns authenticated authority projections and verified source inputs;
its [authority contract](baseline-r5.md#proposed-exact-source-authority-adapter) preserves the signer's credential-free boundary. These processes belong
to the signer's one module and communicate through external role interfaces. A reviewed service launcher
can start each process as its own UID; the signer does not switch UID, execute builds or provide a root command
runner. Principal UIDs/GIDs and narrowly enumerated socket-group memberships are mandatory trusted deployment
inputs. Unknown host state is neither absence nor permission to create or repurpose an account.

Proposed paths are `/var/run/relux-signer/{requests,builder,evidence}.sock`, protected policy/admission records under
`/Library/Application Support/relux/swarma-signer`, signer-private journal/snapshots under `/var/db/relux-signer`,
and builder-private workspaces under `/var/tmp/relux-signer-build`. The runtime socket directory is signer-owned
0755; sockets are signer-owned 0660 with distinct configured client/build/evidence groups. Policy records are root-owned
0644; signer state and builder workspace directories are each 0700 under their separate principals.

Both endpoints verify kernel peer UIDs for the configured role. Group access, socket possession and JSON UID
claims do not authorize work. Same-UID executable identity is not attested by peer UID. Isolation must additionally
exclude signer secrets from build groups, environment, mounts and descendants. Exact Darwin peer semantics and
filesystem isolation require target qualification in safe fixtures.

## Source acquisition before the offline build

The evidence adapter uses only the configured repository and dependency authority routes. The request cannot
add a repository URL, helper, filter, hook, submodule or replacement outside that trusted policy. Acquisition
never runs source commands, build scripts or module tools with the adapter's credentials. Actual provider access
and repository/dependency closure must be qualified; a read-only code path is not proof of a read-only token.

The adapter supplies bounded content-addressed source and dependency data with an acquisition receipt binding
the canonical repository, exact commit and tree, bundle hashes/sizes, module sums and policy. It does not supply
a compiled artifact. The signer authenticates its configured peer, copies the bounded data into its own custody
and binds their digests to the operation before handing the same verified bytes to the builder. A bundle that
cannot establish the requested object/tree or dependency closure refuses; authentication alone is insufficient.
Extraction must reject traversal, escaping links and writes outside the private workspace. Source-data framing,
capacity and the exact dependency closure remain qualification inputs; none is an unbounded upload allowance.
The [finite protocol](baseline-r5.md#proposed-finite-release-signing-protocol) supplies a proposed inline module receipt and exact bounded DATA format.
Whole source can contain links or Gitlinks outside the accepted transport subset. The actual target's necessary
input closure must be qualified explicitly; unsupported required inputs cannot be silently omitted or transformed.

The builder verifies those inputs, creates two clean workspaces from them and has no network or credential
access. Dependencies are preverified read-only inputs to both builds; the compiler cannot fetch missing modules
or a toolchain. Failure to establish the isolated offline environment refuses before compilation. No secret
is copied into an environment merely to make a private source build work.

## Builder job and byte-stream result

The builder connects to the signer-created builder endpoint. Its bounded versioned registration binds the
configured recipe-policy digest. The signer dispatches one finite job only for the accepted active operation:
operation ID, service-generated nonce, configured repository alias, exact source commit, trusted recipe identity
and digest, verified source/dependency input digests, toolchain/target identities, and installed resource limits.
No client-selected URL, shell command,
environment, output path or binary is accepted. The builder independently selects that installed recipe and
refuses a policy/job mismatch. Registration and idle reconnection are bounded; they do not create a signing job.

The builder acknowledges the exact job, builds in two clean private workspaces, and returns a bounded result
receipt binding the job/nonce, source/policy/recipe/toolchain/target, two unsigned hashes and sizes, and bounded
build-log evidence. It then streams exactly those two artifact byte sequences on the authenticated connection.
Unsolicited output, a wrong operation/nonce, extra fields including arbitrary paths, over-limit or short streams,
and mismatched source/recipe identities refuse without signing.

The signer never traverses the builder's 0700 workspace or treats a builder path/descriptor as immutable input.
It creates exclusive private staging files and copies both bounded streams, computing its own hashes and sizes.
Both actual copied artifacts must match their receipts and each other byte for byte. Only the verified
signer-controlled snapshot may proceed to signing. The builder cannot reopen or mutate that snapshot. An
authenticated builder peer alone does not authorize arbitrary bytes independently of the accepted source job.

## Framing, deadlines and operation acceptance

The proposed frame header is one opcode byte and a four-byte network-order JSON length. Client opcodes are
sign, inspect and fetch; the builder endpoint has separate registration/job/acknowledgement/result messages.
Each opcode has its own exact member set and role. The sign request is the finite envelope in the main contract;
inspect identifies the authenticated caller's request, and fetch identifies its recorded operation. Result JSON
is length-prefixed. Only a successful authorized fetch carries a server-to-client artifact stream. There is no
client-to-service binary upload operation.
Client opcode values are 1/2/3 respectively; builder registration/job/acknowledgement/result use 16/17/18/19,
and an idle builder response uses 20. A builder idle response closes the channel; bounded reconnect is 1s–10s.

Proposed trusted limits for first-client agreement are:

| Boundary | Proposed bound |
| --- | ---: |
| Client / builder / evidence-adapter connections | 4 / 1 / 1 |
| Header / JSON body read | 2s / 2s |
| JSON request / result size | 4096 bytes / 16384 bytes |
| JSON response write | 5s |
| Authority refresh | 30s |
| Builder acknowledgement / complete build job | 5s / 600s |
| Builder idle registration wait before clean close/reconnect | 30s |
| Native signing / native signature verification | 60s / 30s |
| Managed child termination/reap after timeout | 10s |
| Each artifact stream read or write | 60s |
| Each unsigned or signed artifact | 256 MiB |

Deadlines are absolute budgets for the whole phase, not sliding per-byte resets. Trusted policy may select
different finite limits after client qualification; callers cannot extend them. An unresponsive native signer
cannot be treated as proof that no signing effect occurred. Termination targets only recorded child PIDs; if
termination/reap cannot be established within its budget, return uncertain and keep the gate closed to new work.

Authenticate, read the complete bounded frame, decode/validate it, check pairing/admission and deduplicate before
acquiring the active-operation gate. Persist acceptance before dispatching source qualification or builder work.
An unparsed connection never holds that gate. A matching retry returns the recorded state; a different request
receives busy without an implicit queue. The gate covers the operation through its terminal or uncertain state.

Close malformed, stalled or over-limit connections deterministically. Before acceptance there is no build/sign
effect or retained operation gate. A response timeout after acceptance preserves the operation's journal state;
a reconnect can inspect it instead of inventing a new request. Pre-sign job/stream failure cleans up private
partial output without key use. Any timeout after a possible signing effect retains uncertain/reconciliation
semantics and cannot release or blindly sign again. Client fetch interruption does not start another build/sign.

## Durable operation history

One protected-writer append-only journal is the authoritative operation history and replayed request index.
Bounded records bind schema, sequence, previous digest, caller/request/operation, exact source/policy/recipe,
snapshot and transition. A complete intent must pass the qualified durable-flush boundary before native signing;
the verified signature outcome, signed hash/size and certificate/DR evidence must pass it before release.
File creation, segment transitions and staging publication require the target-qualified directory-persistence
protocol too. Buffered writes and unqualified renames are insufficient. The implementation must refuse an
unavailable durability profile; no power-loss guarantee follows from source fixtures alone.

After intent without a durable outcome, retain the gate and reconcile signer-private staging against the
recorded operation, native signature and current authority/admission. Append a recovery outcome only when those
claims are established. Otherwise retain uncertainty with no release or new signing. Preserve torn-tail bytes
and seal the old segment; a linked recovery segment binds the full predecessor and its last complete record.
Never truncate or overwrite evidence to make replay succeed. Unreconcilable history refuses further effects.

This is application append-only custody, not OS-enforced immutability or protection from root/signer compromise.
Outcome sequence/digest receipts support an agreed external checkpoint custodian. The signer gets no messaging
credential. No automatic audit/idempotency pruning is proposed for the first slice. A trusted storage budget
must refuse new work before effects rather than delete evidence; retention and capacity must be agreed with
the client and host. No periodic checkpoint job is claimed to be armed.

## Fetch eligibility and historical success

Historical operation success and current artifact-release eligibility are separate. Inspect may truthfully
report recorded success after a later revocation or artifact expiry. Fetch additionally authenticates the caller,
verifies the stored bytes/receipt, and applies the current trusted admission/policy and evidence-freshness rule
before emitting any artifact byte. A past success receipt is not perpetual release authority.

The proposed freshness rule uses a versioned protected local admission/policy snapshot and an independently
verified qualification lease bound to the exact source/evidence/policy, with maximum age 300s. A still-current
lease needs no per-fetch network lookup. A stale lease is refreshed autonomously through the actual authority
adapter within its finite budget, without rebuilding/signing or owner presence; unavailable evidence refuses
release. Missing or revoked admission refuses release regardless of a valid historical lease.

The release decision binds the validated policy snapshot immediately before streaming starts. An already
authorized in-flight transfer is bounded by its artifact deadline; bytes already delivered cannot be recalled.
New fetch decisions under the applicable revoked policy emit zero bytes. The client must agree this freshness
and invalidation boundary before freeze. Retention/expiry is a separate decision and never silently triggers
another signature. Refusal preserves the historical outcome and records the current release reason separately.

## Paired acceptance controls

Run target-qualified controls with separate fixture principals and private directories, without live keys:
valid jobs deliver both unsigned outputs despite builder0700, while path-only/forged-job/wrong-peer/mutated-stream
results refuse without signing. A complete timely frame passes while zero/partial headers, short bodies and
stalled readers close at their intended boundary without pre-acceptance effects or leaked snapshots. An
accepted lost-response operation remains inspectable and never signs twice. Native timeout or missing outcome
remains uncertain. A current authorized fetch returns the recorded bytes without new signing; a fetch invalidated
by applicable revocation returns zero artifact bytes despite the same caller and historical receipt.

---

Source: signer/docs/authority-v1.md

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

---

Source: signer/docs/curator-build-v1.md

# First Curator build proposal

Status: proposed, 2026-11-01. This selects one candidate unsigned recipe for agreement and later qualification.
It is not a qualified release, toolchain installation, allowlist admission or permission to execute a build.

## Product and source

| Input | First-slice selection or known limit |
| --- | --- |
| Logical product / repository alias | `curator` / `curator-core` proposed trusted configuration |
| Canonical source / branch | `https://github.com/relux-works/curator` / `main` |
| Module / entrypoint / executable | `github.com/relux-works/curator` / `./cmd/curator` / `curator` |
| Target | `darwin/arm64` only |
| Reported source baseline | `12b2d57e4b349a93eb3624709b48cdb3ee994d6c`; not a qualified release selection |
| Source Go minimum | `1.25.5`; a minimum is not a pinned toolchain |
| Proposed compiler version | Go `1.25.14`; complete toolchain manifest/digest still required |
| Secret-bearing policy | Yes: core resolves credentials, accepts login tokens and uses registry authorization |
| macOS signing identifier / DER pin / designated requirement | Must be fixed in trusted signing policy; the logical product name supplies none of them |
| Entitlements | Proposed empty set; actual native compatibility still requires qualification |

The separate `curator-run` launcher is a different repository/artifact and later policy entry. Unpublished
launcher OAuth work neither qualifies this core source nor removes the core's existing secret-handling behavior.

## One unsigned recipe

Select a whitespace-free version label `commit-` followed by the full lowercase 40-character requested commit.
The examined core version consumers return and print a nonempty linker value verbatim. This establishes those
consumers' compatibility; it does not establish every external installer or protocol version parser's behavior.

The proposed trusted command is the fixed Go build entrypoint with these arguments, substituting only the
already verified commit into the label and a builder-private output location:

```text
go build -mod=readonly -trimpath -buildvcs=false
  -ldflags="-s -w -buildid= -X github.com/relux-works/curator/internal/version.value=commit-<full-commit>"
  -o <private-output>/curator ./cmd/curator
```

The invocation uses a pinned absolute compiler path and a cleared, explicitly reconstructed environment:
`GOTOOLCHAIN=local`, `GOWORK=off`, `GOOS=darwin`, `GOARCH=arm64`, `CGO_ENABLED=0`, `GOPROXY=off`,
`GOSUMDB=off`, empty `GOFLAGS`, and fixed trusted Go roots/cache paths. Fresh private HOME/TMPDIR/build caches
contain no host credentials; dependency inputs are verified read-only data. Disabling online sum lookup requires
prior approved module-sum verification, not bypassing it. No shell, Make target, generator, network download or
repository-selected credential helper runs in the builder. The exact environment and every toolchain input
must be represented in the recipe/toolchain manifests before this command is executable policy.

This differs deliberately from the current GoReleaser `v<Version>` recipe and its optional Developer ID,
notarization, archive and checksum steps. A service P-256 signature does not establish those distribution claims.
The existing release recipe's CGO-disabled core target is source evidence for this proposal, not proof that this
new recipe builds, reproduces or preserves all runtime behavior.

## Qualification boundary

Two clean offline workspaces receive the same verified exact-commit source/dependency inputs and pinned complete
toolchain. Both outputs must be byte-equal and bind the recipe, full source commit and toolchain manifest. A
single `go` executable hash or version string is insufficient: compiler tools, standard-library inputs and all
other effective build inputs must be covered. Ambient time, VCS metadata and downloaded toolchains are excluded.

Nearby valid controls must show that a complete approved closure builds and prints the selected label. Missing
dependencies/toolchain pins, forbidden network/helper execution, changed inputs, a wrong label or differing
unsigned bytes refuse before signing. Target-qualified signature/entitlement and normal CLI behavior checks
remain required; source inspection and a local tool-version readback do not satisfy them.

The proposed transport entry/type limits are not qualified for the whole observed source/cache inventory. The
necessary-and-sufficient `./cmd/curator` closure, including embedded assets and dependencies, remains unknown.
Bind every inclusion and exclusion in the recipe manifest and verify the actual closure. Source links/Gitlinks
cannot be silently discarded; if a required input is outside the finite subset, revise that contract explicitly
before building. A warm-cache binary built with other flags does not qualify the new recipe or its time budget.

---

Source: signer/docs/broker-compatibility-v1.md

# KEK broker compatibility inputs

2026-11-01. Source facts inform the proposed version 1 signer contract. They do not admit a broker release,
freeze a build recipe, qualify an installed broker or authorize key/installation changes.
Broker integration follows the first Curator rollout; these inputs preserve that later compatibility boundary.

| Input | Retained source fact |
| --- | --- |
| Repository and default branch | `https://github.com/relux-works/mac-infra`, `main` |
| Module | `github.com/relux-works/mac-infra` |
| Product identifier | `works.relux.mac-infra.keyvault-kek` |
| Entrypoint | `./cmd/mac-keyvault-kek` |
| Go directive | `go 1.25.5`; a minimum, not an exact toolchain pin |
| Existing shared setup arguments | `-trimpath`; shared ldflags name `main.Version`, `main.Commit`, `main.BuildDate`, which does not establish mutable metadata in this broker |
| Existing signing options | `runtime,library`; options are distinct from entitlements |
| Existing signing identity | `--sign -`, ad-hoc; cannot satisfy genuine P-256 release identity verification |

The retained setup recipe was inspected at source commit `13c4dd484cfd35cd8a43fbec476f6380f920d028`.
That is a source compatibility witness, not a newly qualified release or a fresh remote-head assertion.
The network proxy application has a different repository, identifier and entrypoint; its pilot artifact and
recipe cannot stand in for any of these broker inputs.

The shared setup derives version from `git describe --tags --always` and date from current UTC time. The broker
itself has a compile-time `Version = "0.1.0"`, emitted as the audit Tool value `mac-keyvault-kek/0.1.0`. It has no
mutable `Commit` or `BuildDate` field and no release `--version` command. Its `pub --version` selects a key
generation; the client envelope/payload protocol version is also separate. Preserve these values for an
unchanged-source release. Keep exact commit and commit-derived date in service build/release/audit receipts;
do not replace the product constant or introduce a new broker field merely to stamp a release.

Production requires `darwin` with CGO, Security.framework, CoreFoundation.framework and libbsm. The non-darwin
or non-CGO implementations refuse native operations; a successful compile with `CGO_ENABLED=0` cannot qualify
the production broker. Pin the C compiler, Xcode or CLT SDK, native flags and target alongside Go. Exact versions,
dependency/network policy, final entitlements and a qualified release target remain open. `darwin/arm64` is a
compatible proposed first target, not a tested release matrix. The setup invocation alone establishes neither
reproducibility nor which shared metadata arguments affect broker bytes. Require independent byte-equal unsigned
rebuilds under the accepted full native recipe. Preserve the identifier, entrypoint and agreed runtime signing
semantics while replacing the ad-hoc identity with the admitted real identity.

The existing setup preserves an installed broker unless rebuilding is explicitly selected, because existing
keys trust that exact binary. The service produces a release artifact and receipt. It must not silently replace
the installed binary, create a store or key, run rebind, change key ACLs or migrate envelopes. Those operations
retain their separate custody and exact-operation decisions. Signing success does not prove that a broker was
installed or that it can read existing keys.

The proxy consumer requires an explicit absolute broker path and an existing provisioned store. Its private
envelope/socket and failure-before-listener guarantees remain consumer-owned. Accepting this source boundary
does not claim current installed/test qualification or change those guarantees.

---

Source: signer/docs/protocol-v1.md

# Proposed finite release-signing protocol

Status: proposed, 2026-11-01. This specifies finite request/result/projection and source-DATA subsets for the
Curator-first slice. It is not an implemented parser, accepted client API or target qualification. The actual
first-client input closure does not yet establish that the proposed capacity/type subset is sufficient.

## Common decoding and identifiers

Control frames retain opcode:uint8 plus JSON-length:uint32 big endian, then exactly that many UTF-8 JSON bytes.
Decode only the opcode's exact object member set; reject duplicates, unknown members, null, wrong types, BOM,
trailing content and noncanonical integer spellings. All lengths are encoded byte lengths and checked before
allocation. Client bodies <=4096B; every result/projection <=16384B. No nesting beyond the named objects below.
The source manifest is a distinct internal-role frame with its own <=1048576B limit, never a client opcode.

All version fields are integer1. request_id remains1..64ASCII alnum/underscore/hyphen. product_id/repository
remain configured ASCII <=128/64B. Commit/tree use40lowercasehex SHA1. SHA256 uses64lowercasehex. operation_id
and transfer_id are service-generated128-bit random values encoded as32lowercasehex; nonce is256-bit random
encoded as64lowercasehex. An ID is a correlation value, not authority. Counters/times are canonical nonnegative
integers <=9223372036854775807; audit sequence starts at1. Time values are UTC Unix seconds, never a caller clock.
URI-like evidence references are typed configured-provider identifiers, never arbitrary fetch destinations.
Evidence room/event references are nonempty UTF-8 <=512B; sender IDs <=255B; policy/key references nonempty
configured ASCII <=256B; all reject NUL/newlines. PR is exactly repository/number: repository is the configured
alias, number a positive integer. These fields are compared with authenticated provider records and trusted
configuration, not interpreted as user-selected network addresses.

Role authentication precedes frame decoding. Only the named endpoint/peer role can send its opcodes; extra or
unexpected bytes close the exchange. The existing absolute2s header/body and5s control-response deadlines apply.
Manifest reception is a separate absolute10s phase; DATA is separate below, not an extension of a JSON deadline.
No partial frame holds the single active-operation gate. Decoder rejection permits no build/sign effect.

## Client requests and operation responses

| Opcode | Exact members | Meaning |
| --- | --- | --- |
| 1 sign | version, product_id, repository, commit, request_id | Request the configured exact-source product |
| 2 inspect | version, request_id | Inspect caller-scoped operation; unknown ID returns request_not_found |
| 3 fetch | version, operation_id | Fetch caller's recorded bytes only after current release qualification |

Signer-to-client response opcodes are64 operation summary,65 refusal and66 successful fetch header; they are
invalid as client requests. The sign response follows durable acceptance; it does not hold a client socket open for a600s build. It returns
an operation summary. A matching retry returns the existing summary; a different active request gets busy,
with no implicit queue. This asynchronous result semantic is a proposal needing current-client compatibility.

An operation summary has exactly version, request_id, operation_id, state, source, outcome. source is exactly
product_id/repository/commit. state is pending/succeeded/refused/uncertain. outcome is a named variant:
- pending: exactly kind=pending, phase; phase is qualifying/acquiring/building/signing/reconciling.
- succeeded: exactly kind=succeeded, receipt. Historical success says nothing about current fetch eligibility.
- refused: exactly kind=refused, code, retry, message; only established pre-sign refusal gets this terminal state.
- uncertain: exactly kind=uncertain, code=outcome_uncertain, retry=inspect, message; no release/new sign.

A decoder/authentication/lookup/busy refusal with no accepted operation has exactly version, code, retry, message.
It echoes no arbitrary identifier, path or caller text. message is a service-selected UTF-8 literal <=256B.
retry is never/same_request/inspect/later. Error codes retain the main contract and additionally request_not_found
and artifact_unavailable for an authenticated absent operation/artifact. Wrong-caller IDs disclose no existence.
An internal record already accepted remains inspectable even when a later release check fails.

A successful fetch header is exactly version, operation_id, receipt, artifact_bytes; bytes match the signed size.
After the complete <=16384B header, stream exactly artifact_bytes raw bytes, then close. No chunk headers,
compression, redirects, output paths or trailing response frame. A release refusal sends only the finite error
object and zero artifact bytes. The existing absolute60s/256MiB artifact bounds apply. The client writes to its
own exclusive private file, checks size/hash and native policy, and only then consumes/publishes that file.

receipt is exactly product_id, repository, commit, policy_sha256, recipe_sha256, toolchain_sha256, input_sha256,
target, unsigned_sha256, unsigned_bytes, signed_sha256, signed_bytes, certificate_sha256, requirement_sha256,
audit_sequence, audit_digest. target is darwin/arm64. Each artifact size is1..268435456. certificate_sha256 hashes
exact public certificate DER; requirement_sha256 hashes the agreed native requirement blob, not an arbitrary
reworded string. Actual policy bytes/pins must come through custody; the retained historical SHA1leaf is not a
newly invented SHA256pin. A returned digest is not a substitute for client native verification.

## Evidence request and projection

Internal evidence opcodes32/33 are qualification request/result;34/35 are source manifest/DATA announcement.
They are invalid when sent by a client or builder. The signer-to-builder source handoff uses the same34/35 data
format as server-sent input after the existing trusted builder job17/ack18; it is not builder authority evidence.
Builder-produced unsigned outputs retain result19 and the two separately bounded artifact streams from r4.

Request32 has exactly version, operation_id, nonce, phase, product_id, repository, commit, policy_sha256.
phase is prebuild/presign/fetch. The first can request source acquisition under trusted policy; the latter two
refresh authority only and cannot start a new build/sign. The signer binds every response to all request values.

Success33 has exactly version, operation_id, nonce, phase, product_id, repository, commit, policy_sha256,
observed_at, expires_at, tree, owner, review, lookup, checks, landing, acquisition. expires_at-observed_at is1..300s;
future observations outside the target-qualified clock-skew policy refuse. The signer uses its own clock and
current policy; adapter timestamps cannot extend a lease after restart/clock discontinuity.
- owner: exactly commit, key_fingerprint. The fingerprint must be repository-admitted; no new key is supplied.
- review: exactly pr, platform_review_id, producer_room_id, producer_event_id, producer_sender, verdict_room_id,
  verdict_event_id, reviewer_sender, verdict_server_at, verdict_body_sha256. Each event/room is a configured-origin
  identifier, not a URL. Distinct producer/reviewer must match the trusted policy and exact-head authenticated
  events. PR is canonical configured repo + positive PR number. No free-form verdict text is accepted in this IPC.
- checks: exactly policy_ref, inventory_sha256, verdict; verdict is required_passed/no_required_and_none_present.
  The second requires an independently known no-required policy AND a successful complete empty inventory.
- landing: exactly default_branch, default_head, relationship. relationship is equal/ancestor and must be verified
  from canonical current branch evidence; branch name is the configured one, never request-selected.
- acquisition: exactly state, manifest_sha256. state is ready/retained/not_requested; digest binds the approved
  manifest or the retained original input. not_requested is allowed only for a known retained prebuild receipt
  at presign/fetch; it does not erase that receipt or bless a different source bundle.

The projection represents ACCEPT only if all these checks succeeded. Failure33 is a disjoint exact object:
version, operation_id, nonce, phase, code, retry, message; authority_rejected/unavailable never carry success fields.
The actual supplied format witness fixes body-byte hashing: UTF-8 of the stored JSON-decoded body string, no
added newline, trimming, normalization or rendered-body substitution. The neutral platform digest line and
bounded lookup are defined in the [authority contract](baseline-r5.md#proposed-exact-source-authority-adapter). Raw private body, credentials and provider
responses never cross this role interface; the source verifier retains private provenance evidence. Digest
agreement alone is not live-provider authentication, complete uniqueness, or full release authority.

lookup is exactly window_start, window_end, observed_at, scopes, matching_events, coverage_sha256. scopes has
1..4 entries with exactly scope_id, frontier_sha256, complete; IDs must match the complete configured scope set,
never a caller-selected subset. complete must be true and matching_events exactly1 for success. The interval is
platform-review time minus24h through plus300s; observation binds authenticated per-scope frontiers. It proves
coverage at those frontiers, not absence of future events or an atomic cross-scope read. The existing30s total,
256 aggregate pages,16384events and16MiB decoded-body budgets are absolute. Exhaustion/partial coverage refuses;
zero/multiple exact-body matches reject. Pagination duplicates of the same event are deduplicated by private
identity. Retain no nonmatching raw private bodies in logs.

The first text grammar requires an unquoted initial ACCEPT declaration for an independent source review, one
canonical PR line and one exact-head/base line matching authenticated provider values. Only the configured,
versioned format is recognized. Acceptance is the reviewer's explicit no-blocking verdict; descriptive prose is
not classified by substring search. Quoted/fenced ACCEPT, contradictory verdicts, blocking markers, wrong or
ambiguous PR/head fields, unknown format and an assignment without a verdict refuse. The actual witnessed
non-blocking notes/limits are not full-suite, hosted-check or landing success. Required current qualification
and revocation remain separate from this historical provenance lookup.
The initial declaration starts exactly `ACCEPT: independent source review of ` with the configured repository
name and matching PR number. The authoritative lines are exactly `PR <canonical PR URL>` and
`Exact head <full head>, base <full base>.`, each occurring once. No matching text inside quotations or code
fences qualifies. An unquoted line starting `REJECT:`, `CHANGES_REQUESTED:`, `Blocking findings:` or `Blocking:`
contradicts acceptance and refuses. The authenticated reviewer's ACCEPT declares no blocking findings; the
adapter does not pretend to independently interpret arbitrary prose as a technical review.

## Bounded source/dependency DATA

One authenticated manifest34 has exactly version, operation_id, transfer_id, commit, tree, policy_sha256,
recipe_sha256, toolchain_sha256, entries, module_receipt, data_bytes. It is bound to acquisition evidence
and the same trusted job. It supplies source/dependency DATA only, never a compiled artifact or shell command.
The signer copies/verifies its own manifest and streams before dispatching the same recorded bytes to builder.

entries is a nonempty array <=8192 items, sorted by root then exact UTF-8 path bytes, with no duplicate/colliding
materialized paths. Each entry is exactly root, path, kind, mode, size, sha256, link_target.
root is source/modules. path is nonempty relative UTF-8 <=1024B, no NUL/backslash/absolute/drive prefix, no empty,
dot or parent segment. Segment/path equivalence and forbidden native names must be checked under the qualified
Darwin filesystem semantics; no silent normalization or overwriting. Implied directories have no record.
kind/mode pairs are file/100644, file/100755 or symlink/120000. No hard link, device, socket, FIFO, setuid or
arbitrary numeric permissions. File link_target is the empty string; source symlink link_target is relative UTF-8
<=1024B with size/hash of its exact encoded target. Module inputs have no symlinks or executable entries.

Before writing, validate the entire graph: a source symlink must resolve within the same source root, with no
cycle/dangling target/escaping target; no entry can be materialized through a symlink ancestor. Write exclusive
regular files into a fresh private root, then validated symlinks last; do not extract over existing state. Preserve
source executable bits without granting extra authority; make verified inputs read-only before compilation.
This finite subset requires actual-source qualification; an unsupported legitimate tree is reported, never
silently transformed to make a build pass. The receipt attests verified canonical source/commit/tree acquisition;
matching a stream hash alone does not independently prove its relationship to a Git commit.

Each file <=67108864B; total streamed file bytes <=1073741824B and exactly data_bytes. Manifest JSON <=1048576B
independently of entry count. Reject overflow before addition/allocation. A size/count exceeding this proposed
capacity requires an explicit finite recipe-contract revision, not an unbounded fallback.

Announcement35 is exactly version, operation_id, nonce, transfer_id, manifest_sha256, data_bytes. nonce binds
the current evidence request or builder job, respectively. The immutable manifest excludes that per-exchange
nonce; the receiving trusted job binds its exact manifest digest. Forwarding rewrites only this transport
envelope for the new role nonce, preserving the manifest and data bytes. Announcement35 is followed
by file payloads in manifest order (symlink targets are already manifest data), with exactly the declared bytes;
no compression, nested archives, arbitrary descriptors, filenames in stream or per-byte deadline extension.
Absolute DATA phase budget120s, global acquisition/build job budget600s remains unchanged. Every receipt entry
hash and stream size is recomputed; interruption, extra/short bytes, wrong peer/nonce/manifest or changed data
refuse and clean only that operation's private partial files. No signing occurs before all inputs qualify.

module_receipt is an inline exact object: source_go_mod_sha256, source_go_sum_sha256, modules. The full raw
manifest hash binds these actual serialized receipt bytes; there is no digest standing in for missing content.
The source root must contain the matching regular go.mod/go.sum files for this recipe. modules has0..512 entries
strictly sorted by path/version; each is exactly path, version, directory, go_mod_h1, module_h1. path is a valid canonical
Go module path <=1024UTF-8 bytes; version is its canonical Go module version <=128ASCII bytes. directory is the
relative modules-root data directory m/<SHA256(path + NUL + version)>. All ordinary path/collision checks apply;
it is data input, not a caller-selected destination or Go cache path.

Each directory supplies its actual go.mod and, when module_h1 is nonempty, the complete expanded module source.
go_mod_h1 is an exact47ASCII-byte h1 checksum; module_h1 is the same format or the empty string for metadata-only
input. Both nonempty sums must equal the corresponding entries in this exact source's go.sum. A module version
needed for compilation cannot use metadata-only input. Missing sums/metadata, inconsistent graph/version, extra
unclaimed module directories or unsupported replacements refuse before compilation. Source go.sum is never
amended, no online checksum fallback occurs, and a module-cache receipt cannot supply its own trust anchor.

Before compilation, the builder's pinned module-format verifier recomputes the standard Go h1 sums from the
actual supplied go.mod/module source, checks them against source go.sum, and resolves the selected graph offline.
The complete closure must be sufficient for that graph/target and exact entrypoint, including embedded assets.
The manifest carries all actual module bytes with each stream hash, in addition to these semantic sums. The
builder may create its fresh Go cache layout and hash metadata only from those verified inputs, then makes
module inputs read-only. It never imports a mutable host cache. Actual verifier/toolchain manifests still need
qualification; this is not permission to run source commands with provider credentials.

Go's [module reference](https://go.dev/ref/mod#go-mod-verify) distinguishes cache-integrity verification from
checking content against source go.sum. go mod verify alone does not establish the latter; it can also need
module metadata. The admitted verifier must demonstrate both original-sum matching and offline closure, not
merely print a cache-integrity success. No credential, helper, network or automatic toolchain download is allowed.

The first client's whole observed source/cache inventory exceeds this proposed entry bound and includes a
Gitlink outside the accepted kinds. Its necessary target closure remains unqualified. Do not drop required inputs
or claim that a capacity increase establishes completeness. Bind explicit inclusion/exclusion and verify actual
source/dependency/embedded inputs; revise finite limits/kinds if that evidence requires it before any build.


## Qualification

The [contract counterexamples](examples/contract-cases-v1.json) are non-executable proposed expectations. They
record nearby valid shapes and intended forbidden outcomes, not parser/runtime/security evidence. Actual provider
lookup, original-sum verification, full closure, native isolation/durability, deterministic double-build and client
behavior remain qualification gates. Source fixtures cannot establish installed authority or release success.

---

Source: signer/docs/examples/contract-cases-v1.json

{
  "status": "NON_EXECUTABLE_PROPOSED_EXPECTATIONS",
  "scope": "Synthetic shape/contract expectations only; no example is real release authority, runtime or host-isolation evidence.",
  "request_cases": [
    {
      "name": "complete_five_fields",
      "input_utf8": "{\"version\":1,\"product_id\":\"curator\",\"repository\":\"curator-core\",\"commit\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"request_id\":\"fixture_1\"}",
      "expected_decode": "accept_shape",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "unknown_path",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"fixture_1\", \"path\": \"/tmp/caller-binary\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "duplicate_version",
      "input_utf8": "{\"version\":1,\"version\":1,\"product_id\":\"curator\",\"repository\":\"curator-core\",\"commit\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"request_id\":\"fixture_1\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "wrong_version",
      "input_utf8": "{\"version\": 2, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"fixture_1\"}",
      "expected_decode": "unsupported_version",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "null_commit",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": null, \"request_id\": \"fixture_1\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "short_commit",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"fixture_1\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "uppercase_commit",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\", \"request_id\": \"fixture_1\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "empty_request_id",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "oversize_request_id",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "exponent_version",
      "input_utf8": "{\"version\":1e0,\"product_id\":\"curator\",\"repository\":\"curator-core\",\"commit\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"request_id\":\"fixture_1\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "trailing_object",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"fixture_1\"}{}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "bom",
      "input_utf8": "﻿{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"fixture_1\"}",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    },
    {
      "name": "over_4096_bytes",
      "input_utf8": "{\"version\": 1, \"product_id\": \"curator\", \"repository\": \"curator-core\", \"commit\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"request_id\": \"fixture_1\"}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 ",
      "expected_decode": "invalid_request",
      "required_effect": "No build/sign during decode; source authority is a separate gate."
    }
  ],
  "authority_cases": [
    {
      "name": "exact_digest_complete_unique_lookup_and_independent_sender",
      "fixture_facts": {
        "authenticated_reviewer": "fixture-reviewer",
        "authenticated_producer": "fixture-producer",
        "same_head": true,
        "same_pr": true,
        "explicit_accept_without_blockers": true,
        "owner_signed": true,
        "checks_qualified": true,
        "landed": true,
        "has_digest": true,
        "complete_lookup": true,
        "matching_events": 1
      },
      "expected_authority": "eligible_if_all_real_evidence_verified"
    },
    {
      "name": "comment_without_neutral_digest",
      "fixture_facts": {
        "has_digest": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "producer_is_reviewer",
      "fixture_facts": {
        "authenticated_reviewer": "fixture-producer",
        "authenticated_producer": "fixture-producer"
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "wrong_head",
      "fixture_facts": {
        "same_head": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "wrong_pr",
      "fixture_facts": {
        "same_pr": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "quoted_accept_only",
      "fixture_facts": {
        "explicit_accept_without_blockers": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "empty_inventory_unknown_policy",
      "fixture_facts": {
        "inventory_empty": true,
        "policy_known_no_required": false
      },
      "expected_authority": "authority_unavailable"
    },
    {
      "name": "reviewer_assigned_not_verdict",
      "fixture_facts": {
        "reviewer_accepted_assignment": true,
        "actual_verdict": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "signed_and_accepted_but_draft_unlanded",
      "fixture_facts": {
        "owner_signed": true,
        "independent_accept": true,
        "landed": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "replayed_projection_nonce",
      "fixture_facts": {
        "nonce_matches": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "expired_or_clock_unknown",
      "fixture_facts": {
        "lease_current": false
      },
      "expected_authority": "authority_unavailable"
    },
    {
      "name": "changed_verdict_body",
      "fixture_facts": {
        "body_digest_matches": false
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "zero_digest_matches",
      "fixture_facts": {
        "complete_lookup": true,
        "matching_events": 0
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "multiple_digest_matches",
      "fixture_facts": {
        "complete_lookup": true,
        "matching_events": 2
      },
      "expected_authority": "authority_rejected"
    },
    {
      "name": "one_match_in_partial_history",
      "fixture_facts": {
        "complete_lookup": false,
        "matching_events": 1
      },
      "expected_authority": "authority_unavailable"
    },
    {
      "name": "lookup_deadline_exhausted",
      "fixture_facts": {
        "complete_lookup": false,
        "deadline_exhausted": true
      },
      "expected_authority": "authority_unavailable"
    },
    {
      "name": "wrong_product_or_configured_scope",
      "fixture_facts": {
        "product_matches": false,
        "scope_configured": false
      },
      "expected_authority": "authority_rejected"
    }
  ],
  "source_cases": [
    {
      "name": "bounded_regular_source_data",
      "entry": {
        "root": "source",
        "path": "cmd/curator/main.go",
        "kind": "file",
        "mode": "100644",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "accept_shape_only_not_source_authority"
    },
    {
      "name": "path_escape",
      "entry": {
        "root": "source",
        "path": "../outside",
        "kind": "file",
        "mode": "100644",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "reject_path_before_write"
    },
    {
      "name": "absolute_path",
      "entry": {
        "root": "source",
        "path": "/outside",
        "kind": "file",
        "mode": "100644",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "reject_path_before_write"
    },
    {
      "name": "backslash_path",
      "entry": {
        "root": "source",
        "path": "cmd\\outside",
        "kind": "file",
        "mode": "100644",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "reject_path_before_write"
    },
    {
      "name": "special_file",
      "entry": {
        "root": "source",
        "path": "cmd/curator/main.go",
        "kind": "device",
        "mode": "100644",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "reject_entry_before_write"
    },
    {
      "name": "setuid_mode",
      "entry": {
        "root": "source",
        "path": "cmd/curator/main.go",
        "kind": "file",
        "mode": "104755",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "reject_entry_before_write"
    },
    {
      "name": "oversized_file",
      "entry": {
        "root": "source",
        "path": "cmd/curator/main.go",
        "kind": "file",
        "mode": "100644",
        "size": 67108865,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "reject_bound_before_allocation"
    },
    {
      "name": "hash_mismatch",
      "entry": {
        "root": "source",
        "path": "cmd/curator/main.go",
        "kind": "file",
        "mode": "100644",
        "size": 13,
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a",
      "expected_shape": "reject_stream_before_build"
    },
    {
      "name": "symlink_escape",
      "entries": [
        {
          "root": "source",
          "path": "link",
          "kind": "symlink",
          "mode": "120000",
          "size": 10,
          "sha256": "62ca1d92c4a3fc44a5fa30d1ddc593be1a9945ca21c0821af53d4f2b604075e7",
          "link_target": "../outside"
        }
      ],
      "expected_shape": "reject_graph_before_write"
    },
    {
      "name": "symlink_ancestor",
      "description": "A validated link at pkg and a file pkg/main.go must never be extracted through that link.",
      "expected_shape": "reject_graph_before_write"
    },
    {
      "name": "short_stream",
      "entry": {
        "root": "source",
        "path": "cmd/curator/main.go",
        "kind": "file",
        "mode": "100644",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e",
      "expected_shape": "reject_stream_before_build"
    },
    {
      "name": "extra_stream",
      "entry": {
        "root": "source",
        "path": "cmd/curator/main.go",
        "kind": "file",
        "mode": "100644",
        "size": 13,
        "sha256": "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47",
        "link_target": ""
      },
      "stream_hex": "7061636b616765206d61696e0a78",
      "expected_shape": "reject_stream_before_build"
    },
    {
      "name": "internal_source_symlink",
      "description": "A regular source main.go and a sibling link to main.go, no link ancestor or escape.",
      "expected_shape": "accept_graph_shape_only_not_source_authority"
    },
    {
      "name": "unsupported_required_gitlink",
      "entry": {
        "root": "source",
        "path": "skills/example",
        "kind": "gitlink",
        "mode": "160000",
        "size": 0,
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "link_target": ""
      },
      "expected_shape": "reject_unsupported_kind_before_write_no_silent_omission"
    },
    {
      "name": "inventory_over_entry_limit",
      "entry_count": 8264,
      "expected_shape": "reject_bound_no_claim_about_minimum_target_closure"
    }
  ],
  "required_post_state": {
    "decode_rejection": "no accepted gate/build/sign",
    "authority_rejection": "no build/sign; preserved rejection record permitted",
    "source_rejection": "no compilation/sign; remove only private partial data",
    "possible_signing_effect": "uncertain, withhold release and never blindly re-sign"
  },
  "module_cases": [
    {
      "name": "inline_receipt_zero_external_modules",
      "receipt_shape": {
        "source_go_mod_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "source_go_sum_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "modules": []
      },
      "expected_shape": "accept_shape_only_given_matching_source_files_and_empty_selected_graph"
    },
    {
      "name": "receipt_digest_without_content",
      "expected": "reject_missing_receipt_before_compile"
    },
    {
      "name": "source_sum_mismatch",
      "expected": "reject_original_sum_mismatch_before_compile"
    },
    {
      "name": "mutated_module_with_self_consistent_cache_hash",
      "expected": "reject_against_source_go_sum_before_compile"
    },
    {
      "name": "missing_selected_module_or_metadata",
      "expected": "reject_incomplete_offline_closure_no_download_or_sum_write"
    },
    {
      "name": "metadata_only_for_compiled_module",
      "expected": "reject_missing_module_source_before_compile"
    },
    {
      "name": "module_directory_outside_receipt",
      "expected": "reject_unclaimed_input_before_compile"
    }
  ]
}

---

Source: UNRESOLVED_QUESTIONS.md

# Open agreement points

2026-11-01. Agreement fields and later acceptance evidence remain open below. Agree the contracts and their
expected controls before implementation/build; runtime qualification is demonstrated by executing the agreed
candidate at its applicable gate. A runtime result is not a prerequisite for specifying the test that measures it.

| Question | Required source | Effect while open |
| --- | --- | --- |
| Curator exact qualified source release, signing identifier, complete toolchain/recipe and source/dependency manifests, entitlements and runtime compatibility | Curator maintainer and service maintainer | Repo/branch/entrypoint/target and secret-bearing classification are known; one commit-labelled recipe is proposed, not qualified |
| Later broker release candidate, native deterministic recipe, toolchain/SDK digests, dependency policy and entitlements | Broker source maintainer and service maintainer | Repo/identifier/entrypoint, required CGO/native frameworks and constant-version constraints are known; broker integration follows Curator rollout |
| Actual forward-form parser, bounded complete digest lookup, check policy, freshness and revocation qualification | First-client delivery owner and service maintainer | Real body/digest/platform format witness received; live authenticated complete lookup is unqualified. Product records carry neutral digest; provenance stays private |
| Request/result JSON bounds and grammars, transport authorization, artifact transfer, timeout and retry horizon | First-client maintainer and service maintainer; broker compatibility retained for later integration | Version 1 envelope remains proposed; second-client qualification does not block the first slice |
| First-admission confirmation record and identity binding; policy changes, revocation and re-admission semantics | Signing custodian and service maintainer under the owner decision | No release-specific approval requirement added |
| Builder account/isolation, source access, immutable IPC custody, signer snapshot ownership and reproducibility envelope | macOS host custodian and actual Curator/broker build owners | No host writes or assertion that UID separation alone protects all host secrets |
| Exact target input closure, manifest capacity and required link/Gitlink handling | First-client build owner and service maintainer | Whole observed source/cache inventory does not fit the proposed subset; minimal required closure is not yet measured or qualified |
| Separate evidence principal's actual provider access, own signed binary/DR, Keychain custody and bounded source/dependency transfer | Evidence and signing custodians with service maintainer | Selected credential placement is not an account, enforced token scope or bootstrap exemption |
| Durable audit primitive, checkpoint custodian, retention, recovery and concurrent/retried operation semantics | Signing custodian and service/client maintainers | No artifact release without durable outcome; uncertainty stays explicit |

No service, user, key, ACL, Keychain, sudo, daemon or private broker operation is authorized by this proposal.

The original requirements, current first-admission-only amendment and broker compatibility addendum have been
received. Historical per-release-presence wording remains superseded. The known source boundary is documented
in [broker compatibility inputs](baseline-r5.md#kek-broker-compatibility-inputs); it is not runtime acceptance.
