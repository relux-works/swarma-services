# Shared builder duties and Curator second-client recipe/custody proposal

Status: proposed additive contract for counterpart and independent review. This is a documentation candidate,
not an accepted recipe, executable builder, qualified manifest, Mac admission or permission to build or sign.
Read the [baseline](baseline-r5.md), [builder wire contract](builder-wire-data-r2.md),
[capacity specification](manifest-capacity-r3.md) and [integrated addendum](integrated-addendum-r2.md) first.
They retain their bytes and precedence. This delta narrows the remaining recipe/cache/custody seam; it adds
no opcode, wire member, client response, dependency solver or authority-verification mechanism.

## Contract boundary and status

The evidence adapter provides source DATA, the signer owns the accepted job and immutable input copy, and the
distinct keyless builder validates and builds. The signer independently copies and checks both unsigned
artifacts. A source signature on this document admits none of those runtime roles or product owner keys.
Source authority still follows the baseline's [independent authority boundary](baseline-r5.md#source-authority-and-trusted-policy).
The separate client request/result contract consumes this seam; this delta does not redefine it.

The existing pure `manifestbody` result is explicitly unqualified; `moduleinput.Verified` proves integrity of
the supplied subset only. Neither establishes acquisition, target closure, graph completeness, cache isolation,
native resources or authority. Reuse those packages unchanged. Native integration remains blocked on the
acceptances below, even where a pure source component has already passed review and landed.

G1 denotes exact recipe/toolchain/source and graph/cache sufficiency; G2 denotes the two fixed offline builds
and unsigned equality; G3 denotes actual distinct-principal isolation and immutable handoff. These are separate
proof obligations. A G1 paper agreement, G2 artifact hash or G3 fixture alone cannot satisfy the other two.

## Shared obligations and selected clients

The G1/G2/G3 duties, receipt-only cache rules, bounds and unsigned-artifact custody requirements below
are shared obligations. Recipe selection and source sufficiency remain client-specific. The selected first
keyless source-input client remains `mac-keyvault` / `swarma-keyvault`, canonical repository
`https://github.com/relux-works/swarma-keyvault`, at commit `cc1aa20c551f5d2e4ed9785d844dd036ae8716ed`
and tree `31c46e09909ba3c53b1b806d3eb74c2a7c5ffbbd`, targeting `darwin/arm64` through
`./cmd/mac-keyvault` with `CGO_ENABLED=1`. Its exact existing
[recipe.json](first-client-keyvault/recipe.json) bytes retain SHA256
`74c1e365d9edac891671ff036bb55bf4aa917f2561da4c6289c25b221cf23344`.
The [first-client source-input contract](first-client-keyvault/source-input-implementation.md) retains all
existing exact source, closure, dependency, Go/verifier inventory and original-anchor bindings, including
its cgo/Apple tool inputs and native-readiness refusal. Those source-validation bindings are not UNKNOWN
Curator slots and do not establish native or installed qualification.

Curator is the second client. Only the next slot table, its UNKNOWN values, fixed invocation/environment
and Curator counterpart rows propose the second-client `curator` / `curator-core` recipe. They neither
replace the first-client recipe nor describe existing code as accepting a generic Curator recipe.
The shared G1/G2/G3 duties still require each client's own admitted inputs and actual evidence.

## G1: Curator second-client installed recipe and input slots

For the Curator second-client proposal, the following are required slots in the installed recipe/policy/toolchain and retained job evidence,
not a new transport object or caller-supplied manifest format. Endpoints must possess actual immutable bytes,
not just hashes of unavailable records. Their serialization, finite storage bounds and real values must be
accepted by the named provider and consumer before execution; unresolved slots fail closed. No zero digest,
historical example or version string is a qualified value.

| Slot, type and bound | Trust origin and validation | Missing acceptance / blocked_by |
| --- | --- | --- |
| Product/repository: configured ASCII strings at most 128/64 bytes respectively; target exactly `darwin/arm64` | Installed positive policy, compared at registration/job/DATA; proposed second-client pairing is `curator` / `curator-core`, canonical Curator repository and entrypoint from the baseline | Services source custodian + Curator build owner: actual pairing and selected source release; `gate:curator-exact-recipe-and-manifests` |
| Source identity: exact 40-lowercase-hex commit and tree; source `go.mod`/`go.sum` each bound by 64-lowercase-hex SHA256 | Independently qualified canonical acquisition and exact source bytes, checked against the job and inline receipt; no caller URL or cache self-authentication | Curator build owner supplies exact source/closure; Services authority-adapter custodian supplies acquisition; `gate:curator-exact-recipe-and-manifests` |
| `recipe_sha256`, `toolchain_sha256`, `policy_sha256`, `input_sha256`: each 64-lowercase-hex SHA256 | Existing job17 binds actual installed recipe/toolchain/policy bytes and exact retained raw manifest34; `input_sha256` is not proof of Git acquisition | Services source custodian with Curator build owner: complete accepted bytes and their digests; `gate:curator-exact-recipe-and-manifests` |
| Compiler/verifier identity: pinned absolute executable locations, exact bytes/digests and complete effective tool inputs | Installed toolchain/recipe manifest covers compiler tools, standard library, verifier implementation/dependency pins and any effective target inputs; executable hash or `go version` alone is insufficient | Curator build owner + Services source custodian: full manifest, exact paths, finite manifest-size bound and qualification; `gate:curator-exact-recipe-and-manifests` |
| Recipe invocation/environment: fixed argv and closed reconstructed environment below; output location is operation-owned | Installed recipe bytes, never client commands, shell expansion, Make target, generator or inherited environment | Services builder integrator + Curator build owner: exact path mapping/environment bytes and full closure; `gate:curator-exact-recipe-and-manifests` |
| Source inclusion/exclusion and required compiled modules/assets: finite entry set under DATA bounds below | Curator build owner binds every necessary input to the exact source/entrypoint/target; DATA verification establishes those actual bytes, and the native graph checks metadata sufficiency | Curator build owner + Services builder integrator: accepted complete closure and precompile required-content controls; `gate:curator-exact-recipe-and-manifests` |
| Enforcement profile: finite CPU, memory, processes, wall time, concurrency, workspace, aggregate logs and cleanup limits | Existing installed policy/recipe bytes; both endpoints verify available content and actual enforcement, not a peer resource override | macOS host/signing custodian + Services integration owner, owners retain policy decisions; `gate:mac-keyless-custody` |

For this Curator proposal, actual source release, absolute compiler path, complete toolchain/verifier manifest,
closure and enforcement values remain UNKNOWN. Shared native enforcement remains unqualified for both clients.
The baseline's historical Curator source and proposed Go `1.25.14` are reference choices,
not promoted pins. This delta selects no replacement version and changes no dependency. Services delivery
signatures do not admit a key as Curator's release owner.

### Curator second-client fixed recipe and environment disposition

For Curator only, retain the baseline's proposed unsigned recipe: pinned absolute Go executable, argv `build`,
`-mod=readonly`, `-trimpath`, `-buildvcs=false`, one `-ldflags` argument with
`-s -w -buildid= -X github.com/relux-works/curator/internal/version.value=commit-<full-commit>`,
`-o`, the builder-private `curator` output, and `./cmd/curator`. Substitute only the already verified full
commit and the operation-owned private output location. These are argv values, not a shell command.
Version consumers must return that exact nonempty label; target/CLI compatibility remains actual qualification.

For this Curator recipe, reconstruct from an empty environment: `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`, `GOOS=darwin`,
`GOARCH=arm64`, `CGO_ENABLED=0`, `GOPROXY=off`, `GOSUMDB=off`, `GOVCS=*:off`, `GOAUTH=off`;
set `GOROOT`, `GOMODCACHE`, `GOCACHE`, `HOME` and `TMPDIR` to exact recipe-bound private/tool paths.
No host HOME/cache, authentication variables, helpers, agents, sockets or inherited search path enter the job.
Any required additional environment variable needs an explicit finite recipe amendment and counterpart acceptance.

For the Curator graph phase use that pinned Go executable with argv `mod`, `graph`, and explicitly set
`GOFLAGS=-mod=readonly`, as the existing first-unit graph requirement specifies. For each fixed build retain
the baseline's empty `GOFLAGS`, with explicit `-mod=readonly` in argv. This distinguishes the graph requirement
from the build environment rather than silently inheriting one phase's flags into the other. No saved graph,
`go list` diagnostic, `go mod verify` result or accepted error string can replace the actual graph/build gates.

## G1: DATA to graph and derived cache handoff

1. Authenticate configured role peers before decoding. The signer retains actual job17 bytes; `job_sha256`
   hashes those exact bytes. Manifest34 and DATA enter signer-owned custody and are forwarded unchanged;
   only announcement35's exchange nonce changes. Bind operation, transfer, commit/tree, all installed digests
   and actual `input_sha256`. Preserve permitted JSON encodings; no trim, normalization or reserialization.
2. Validate the complete manifest graph before materialization: exact root/path byte order (`modules`, then
   `source`), decoded uniqueness and native collisions, allowed modes, bounded contained source symlinks,
   and no symlink ancestor. Use fresh private roots, exclusive regular writes and validated symlinks last.
   Recompute each actual DATA size/hash and total; no missing/extra bytes or partial accepted graph.
3. Compare original source `go.mod`/`go.sum` bytes and receipt digests; invoke the unchanged supplied-module
   verifier on stable owned bytes. Every supplied record, including unused records, must pass original-anchor,
   canonical layout and standard h1 checks. Never insert, repair or deduplicate original source bytes.
4. Create each build's fresh module/cache state solely from those verified inputs under the accepted pinned
   standard-Go derivation. Retain a bounded derivation ledger mapping each derived file to its source record,
   verified input hashes, exact tool/recipe and derived size/hash; the ledger's finite byte budget belongs to
   the installed resource profile. Ledger metadata and derived hashes cannot supply missing original anchors.
   Never import host/provider cache `.zip`, `.list` or `.info`, or synthesize `.info` from historical Time.
   An authenticated ordinary `.info` file in canonical content remains ordinary content, not auxiliary metadata.
5. Run the pinned receipt-only offline `go mod graph` in each independent source/cache workspace. Require
   actual exit 0 with no graph error/stderr. A requested historical/selected `go.mod` must be supplied and
   originally anchored. An absent selected body is permissible only if this exact graph succeeds without it;
   metadata success cannot establish sufficiency for compilation. No online lookup or source-sum write.
6. Before compilation require all accepted target-required complete compiled-module/source/embedded content,
   exact source and toolchain bindings and current native/resource/authority qualifications. Required-content
   determination and its accepted closure remain with the selected client's build owner and Services integrator; the
   pure supplied-subset verifier is not that determination. Missing closure evidence blocks execution; a later
   build error is not a substitute for the required precompile refusal control.

Metadata-only layout remains exactly one ordinary `100644` `go.mod` with mandatory standard `go_mod_h1` and
empty `module_h1`. Full compiled modules require the complete canonical tree including its own root `go.mod`,
mandatory original `/go.mod` anchor and original full-module anchor. No generated `go.mod` may repair a
canonical tree missing one. Module symlinks/executables remain forbidden. Standard h1 values are exactly
47 ASCII bytes with canonical spelling; identity/directory derivation and both checksum domains retain the
existing `moduleformat`/`moduleinput` predicates. Unsupported replacement/layout or a needed unanchored body
refuses; no custom solver, auxiliary DATA channel or implicit acquisition is introduced.

Module inputs become read-only before compilation. Derived writable state, if required by the pinned tools,
is private to its one workspace and ledgered under the accepted profile; it cannot mutate verified inputs,
cross-feed the second build or become a trust source. The original opaque embedded source archive remains one
ordinary exact-byte file; DATA never extracts it. A recipe need outside these rules returns for an explicit
contract amendment, not a transport or cache exception.

### Bounds and policy status

| Boundary | Existing bound / status; refusal consequence |
| --- | --- |
| JSON and identities | Existing closed schemas; reject missing/extra/duplicate/null/wrong-type members, invalid integers/UTF-8; version integer 1, commit/tree 40 lowercase hex, digests 64 lowercase hex, operation/transfer 32 lowercase hex, nonce 64 lowercase hex. Counters/UTC Unix seconds are canonical nonnegative integers at most 9,223,372,036,854,775,807; no caller clock/path/env/command field |
| Manifest34 | Current public BODY maximum **1,048,576 bytes**. Integrated **4,194,304-byte** candidate remains inactive until its parser/headroom/native activation gates; initial complete eligible body must satisfy `B <= 2,097,152` for 2x candidate headroom. Historical sizing witnesses do not satisfy it |
| DATA/material | Nonempty entries at most 8,192; receipt records at most 512; decoded entry/module paths and link targets at most 1,024 UTF-8 bytes; version at most 128 ASCII bytes; each regular file at most 67,108,864 bytes; total at most 1,073,741,824 bytes. Existing module verifier additionally caps a full canonical module at 500 MiB and go.mod/root LICENSE at 16 MiB |
| Phases | Builder control16–20 at most 16,384 bytes; control header/body 2s, control write 5s; manifest34 absolute 10s, DATA 120s, acknowledgement 5s, whole job 600s, each artifact stream 60s, recorded-child termination/reap 10s. Bounds are absolute and nested in the original job budget, not reset per build/byte/retry |
| Artifact/logs | Each unsigned artifact 1..268,435,456 bytes. Logs use existing exact `{sha256, bytes, complete}` metadata, canonical counts and actual retained-byte digest; empty log has actual empty-byte SHA256. Aggregate log budget must be available in installed policy; success requires both streams complete and in budget |
| Storage allocation | Existing accepted policy: workspace 20 GiB, artifacts 20 GiB, audit/idempotency 2 GiB, logs 1 GiB; independent APFS free floor 100 GB decimal. These allocations do not qualify enforcement, reserve capacity or override smaller per-job/stream limits; no automatic pruning, capacity exhaustion refuses new effects |

Check overflow and declared lengths/counts before addition/allocation. No automatic capacity increase,
input omission, partial success, compression/chunk/reference fallback or client-controlled resource selection.
The resource profile still needs concrete CPU/RSS/process/concurrency/ledger/log bounds and genuine bounded
termination/cleanup qualification. A 1 GiB input allowance and algorithmic complexity bounds are not a memory
or wall-time guarantee. An unaccepted bound or unavailable enforcing policy blocks compilation.

## G2 and G3: two builds and immutable unsigned artifact custody

After G1 and actual G3 admission, construct two independent clean source/output/HOME/TMP/module/build-cache
workspaces from the same immutable verified inputs and complete toolchain. No warm cache or output from the
first build seeds the second. Run exactly the fixed recipe twice inside the original job budget; retain actual
argv/environment identity, start/end times, exit/status, bounded log evidence and output type/size/hash for each.
Both fixed builds must exit 0 and produce the required regular `darwin/arm64` artifact and version behavior.
Truncated logs, failed/skipped lanes, a metadata-only diagnostic or agreeing receipt claims are not success.

Existing result19 success binds operation/nonce/`job_sha256` and exactly `first`, `second`, `logs` under the wire
contract. The retained exact job supplies source/tree/policy/recipe/toolchain/manifest identity transitively;
do not add fields or accept unavailable job bytes. Each artifact has exact SHA256 and byte count, within the
bound above. Builder sends first bytes then second bytes and closes; refusal sends zero artifact bytes.

The signer never traverses a builder workspace or accepts its paths/descriptors as the immutable handoff.
It independently copies both streams into exclusive signer-private regular staging, recomputes size/hash,
rejects short/extra bytes and compares the actual two snapshots byte for byte. Links, mutation/replacement,
digest/size mismatch, unequal bytes, wrong binding or deadlines withhold signing. Only the signer-owned
verified immutable snapshot may enter the separately gated signing/audit boundary; builder cannot reopen it.

Actual distinct Mac principals, kernel peer-role checks, filesystem/descendant isolation, signer-home/Keychain
and other-host-secret denial, network denial and enforced cleanup remain G3. Same-UID confinement fixtures,
account separation alone or a new key do not amend that requirement. Native admissions, first owner presence,
certificate/DER/designated requirement, signed tool/entitlements and installation are separate owner-controlled
inputs; this document requests no key, service, account or native operation.

Use the existing internal refusals: input/graph/cache-invalid -> `input_invalid`, installed mismatch ->
`policy_mismatch`, stale/unknown authority -> `authority_expired`, failed recipe -> `build_failed`, exceeded
resource -> `resource_exhausted`, artifact stream/equality failure -> `output_invalid`. Existing public mapping
remains `build_failed`, except authority -> `authority_unavailable`, output -> `artifact_rejected`; separately
established isolation failure remains `build_isolation_failed`. A trustworthy result frame requires the current
binding; otherwise close and retain the internal classification. Never echo raw input/logs as a refusal.
Cancellation or lost signer IPC terminates/reaps only recorded job children within the existing 10s bound;
unknown cleanup retains the operation gate and uncertainty. Client disconnect does not cancel durable work.
No timeout, retained artifact, lost result or retry authorizes duplicate build/sign or artifact release.
Any separately permitted same-operation pre-sign re-dispatch still requires established prior child cleanup,
a fresh exchange nonce and remaining time inside the original job budget, as the wire contract requires.

## Curator second-client counterpart acceptance and blocked values

Every row below is PENDING for the Curator second-client proposal. These rows do not revoke or relabel the
first-client source bindings; shared native G1/G2/G3 proof obligations remain open independently.
Owners below are accountable functional counterparts from the existing
contract/reconciliation; no named person's new acceptance or active assignment is asserted. Exact individual
assignment, where absent, remains for the source custodian to record. Acceptance must name this exact candidate
head/tree and clauses; a producer signature, local check or paper acceptance never supplies native evidence.
The `gate:` labels below refer to the existing builder successor's blocked inputs, not new board elements or
extra approval gates. Their required source, toolchain, closure, manifest and actual Mac evidence remain distinct.

| Clause / provider -> consumer | Required acceptance and blocked_by | Evidence disposition |
| --- | --- | --- |
| G1 source/recipe/closure: Curator build owner -> Services source custodian / builder integrator | Actual source release and closure, recipe/complete toolchain/verifier bytes, paths/environment and their finite bounds; `gate:curator-exact-recipe-and-manifests` | UNKNOWN real pins; historical source/compiler and sizing remain reference only |
| G1 acquisition/DATA: Services authority-adapter custodian -> signer and Services builder integrator | Qualified exact-source acquisition and original anchors, raw-byte custody, full graph/path/DATA checks; `gate:curator-exact-recipe-and-manifests` | Pure decoder/subset acceptance retained; actual acquisition/graph/cache integration unestablished |
| G1 cache/graph: Services builder integrator -> Curator build owner and signer integration owner | Accepted derivation ledger/profile and real clean receipt-only native graph plus required-content controls; `gate:curator-exact-recipe-and-manifests`, `gate:mac-keyless-custody` | No graph or build executed by this candidate |
| G2 rebuilds: Services builder integrator + Curator build owner -> signer integration owner | Two actual fixed offline builds and independently copied equal artifacts, exact commands/times/exits/hashes/label/target; G1 acceptances and `gate:mac-keyless-custody` | No real production pair, equality or native acceptance established |
| G3 custody/enforcement: macOS host/signing custodian + Services integration owner -> builder and signer integration owners | Actual distinct-principal policy, peer/secret denial and resource/cleanup/immutable-IPC controls; owners retain account/key/policy decisions; `gate:mac-keyless-custody` | UNKNOWN admission/enforcement; reported fixture isolation is not product-profile qualification |
| Independent design and counterpart disposition: Services/Curator independent architect/whole-solution route -> source custodian | Fresh exact-head/tree review plus applicable marker and all provider/consumer acceptances; `gate:services-builder-contract-accepted` | PENDING. Source custodian retains publication/landing; execution remains separately blocked |

## Paired acceptance cases — expectations, not runs

| Valid neighbor | Forbidden neighbor | Required observation |
| --- | --- | --- |
| Exact approved job and available complete recipe/toolchain/policy | Caller-selected command, altered source anchor, digest without actual bytes or unsupported tool input | Intended binding/policy/input refusal before compilation; no build/sign |
| Every supplied record valid, including harmless anchored unused material | Unused but unanchored/wrong-h1 record; metadata-only substituted for compiled content | Original-anchor/layout/required-content refusal, not graph-selection by caller assertion |
| Native graph succeeds from verified receipt-only fresh cache | Remove requested historical go.mod or use host cache to conceal it | Intended precompile `input_invalid`, preserved actual stderr/exit and zero compile/sign; no sum repair |
| Complete canonical module and permitted opaque source archive | Generated go.mod inserted into no-go.mod tree, auxiliary cache .info, DATA extraction or omitted required asset | Intended layout/closure refusal; unchanged source/DATA bytes and no compile/sign |
| All independent caps and approved enforcement available | Each cap+1, unavailable CPU/RSS/cleanup policy, proposed 4 MiB treated as active | Correct bound/policy refusal; no allocation/capacity waiver or resource qualification claim |
| Two clean fixed builds succeed and real snapshots compare equal | One failed/skipped lane, different flags/toolchain, warmed second cache, wrong version/target or agreeing claims with unequal bytes | Failed build/profile/output classification with actual evidence; no successful artifact or sign |
| Admitted distinct Mac roles and signer-owned bounded copy | Self-asserted UID, same-UID fixture substituted, signer-home/key/socket access, mutable path or replaced/short/extra stream | Role/isolation or output refusal at its actual boundary; no key access/release; unknown cleanup stays gated |
| Known cleanup, current authority and retained operation on retry | Expired lease, lost IPC treated as clean stop, uncertain native state treated as safe retry | Existing bounded cancellation/uncertainty semantics; no renewed deadline or duplicate sign |

Future controls start from an otherwise valid admitted fixture, change one predicate, retain its valid neighbor
and report all actual outcomes/times/exits. An unrelated setup failure or arbitrary error is not the intended
refusal. Preserve originals and all failures; no runtime results, whole-solution acceptance or completed original
builder requirement are claimed by this documentation candidate.
