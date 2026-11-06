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
bounded lookup are defined in the [authority contract](authority-v1.md). Raw private body, credentials and provider
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
