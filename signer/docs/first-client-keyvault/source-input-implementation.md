# mac-keyvault source-input composition

Status: local implementation candidate for independent review. The first keyless
source-input client is `mac-keyvault`; Curator is the second client. This changes
the selected source/recipe slots for this slice, without changing client wire
schemas, signing custody, native admissions, or the G1/G2/G3 proof obligations.

The implementation is `signer/internal/keyvaultinput`. Its installed pairing is:

| Slot | Exact selection |
| --- | --- |
| Product / repository alias | `mac-keyvault` / `swarma-keyvault` |
| Canonical repository / default branch | `https://github.com/relux-works/swarma-keyvault` / `main` |
| Source commit | `cc1aa20c551f5d2e4ed9785d844dd036ae8716ed` |
| Source tree | `31c46e09909ba3c53b1b806d3eb74c2a7c5ffbbd` |
| Entrypoint / target | `./cmd/mac-keyvault` / `darwin/arm64`, cgo enabled |
| Recipe | Exact existing [recipe.json](recipe.json) bytes, SHA256 `74c1e365d9edac891671ff036bb55bf4aa917f2561da4c6289c25b221cf23344` |

These constants select a source-validation case. They do not install a protected
allowlist or admit a signing identifier, key, grant, owner, certificate, native
executable or client principal. A subsequent source release needs its own exact
reviewed source/closure binding; this implementation refuses changed source.

## G1 source-input path

`New(Manifests)` requires the exact installed recipe, source closure, dependency
closure, Darwin Go inventory and Linux verifier inventory already supplied with
this tuple. Each byte hash is pinned before parsing. These source-owned artifacts
are not request parameters; changing even one artifact byte refuses construction.
Their inventories do not include the absent Apple effective native tool inputs.

The integrating signer/evidence path retains and authenticates the actual job17
and transfer bytes, then supplies their internal `Binding` projection. It remains
responsible for the original exact job schema, nonce, authority lease, qualified
clock, durable acceptance and endpoint authentication. `Binding` is not a new
wire object, authority observation, provider callback or client request.

`Prepare(binding, rawManifest34, DATA)` then:

1. Requires the fixed pairing, source and recipe, bounded correlation fields,
   and the retained job's exact raw manifest digest.
2. Calls the unchanged public `manifestbody.DecodeOpcode34BodyShape`, retaining
   its active 1 MiB bound, exact decoded schemas, canonical integer grammar,
   ordering and raw-byte identity. Valid whitespace/member-order encodings keep
   their own actual digests; no shared canonical JSON encoding is required.
3. Checks all manifest/job operation, transfer, source, policy, recipe and
   toolchain correlations. Policy/toolchain correlation is not qualification of
   unavailable installed bytes or source authority.
4. Requires the selected complete set: 35 ordinary source/anchor files and 925
   canonical module files, plus exactly the four original receipt records. The
   two compiled modules remain full; the two graph-only records remain metadata
   only. Missing content, a metadata downgrade, changed anchor, extra cache
   material or a changed source/hash/mode refuses before any compilation.
5. Verifies exact DATA length, entry sizes/hashes and final consumption, then
   calls the unchanged `moduleinput.Verify` on owned original go.mod/go.sum,
   receipt records and module bytes. Its original anchors, canonical layout,
   standard h1 domains, collision predicates and finite bounds remain in force.
6. Returns immutable owned raw BODY, source and existing verified-module
   snapshots. Accessors give copies. No path is opened, file materialized,
   graph/compiler invoked, or partial success exposed on refusal.

This fixed source case accepts only its exact selected closure. It does not
change the general module verifier's treatment of valid additional supplied
records, the DATA transport, or other source recipes. It supplies no cache .info,
.list, foreign cache or generated replacement go.mod.

`GraphCommand` and `BuildCommand` return copies of the exact recipe's argv,
absolute executable/cwd and a sorted, closed environment. An eventual executor
must assign this environment directly from an empty process environment, with
read-only verified source/module/tool roots and separate private 0700 state for
each of the two builds. The graph has `GOFLAGS=-mod=readonly`; the build has empty
`GOFLAGS` and the explicit argv flag. There is no shell or inherited environment.
These are invocation descriptions; the component has no execution entry point.

`NativeReadiness` always returns `native_runtime_inputs_missing`. There is no
caller boolean or invented hash that can change that result in this source-only
slice. Missing actual runtime inputs remain:

- Apple Xcode 16.4/macOS SDK 15.5 compiler, linker, frameworks and runtime bytes,
  complete effective toolchain inventory, and exact installed comparison.
- Actual protected policy, source-owner pins, admitted delivery profile/adapter,
  qualified clock and fresh `sourceauthority.BeforeBuild` qualification.
- Admitted native isolation, read-only materialization, finite CPU/RSS/process/
  log/cleanup enforcement and receipt-only cache derivation ledger.
- Actual clean offline graph, two independent native builds, byte equality and
  distinct-principal immutable handoff. Linux source tests prove none of these.

No zero/example digest, Go distribution inventory, source-test result or package
signature substitutes for those inputs. The later `BeforeSign` must obtain its
own fresh observation using the existing `sourceauthority` component. Presign,
native owner admission and signing/audit/fetch remain outside this slice.

## C1–C8 disposition

| Seam | Effect of this implementation |
| --- | --- |
| C1 pairing | Selects the exact source-input pairing above; Curator remains second |
| C2 authenticated transport | Unchanged and unimplemented here; internal bindings are not peer authentication |
| C3 request/receipt projection | No opcode, member, external receipt or result variant added |
| C4 immutable handoff | Source snapshots are owned; native artifact handoff and current fetch authority remain required |
| C5 retry/UNKNOWN | No operation, retry ID, deduplication or signing state machine introduced |
| C6 refusals | Sanitized local errors; the integration maps them to existing internal input/policy refusals |
| C7 admission/autonomy | Initial live secret-tool admission remains separate; no per-release owner-presence gate added |
| C8 acceptance | Independent exact-candidate review/marker remain pending; native values and custody are not admitted |

The offline controls use the original public source tar and canonical module
ZIP/.mod files, plus the independent original DATA entry-set oracle. They exercise
real source/module validation and causal refusals. Synthetic job policy/toolchain
correlation strings are labelled fixtures, never native policy/SDK evidence.
Set `KEYVAULT_FIXTURES` to the supplied review fixture directory and run
`go test -mod=readonly ./internal/keyvaultinput`. Default tests require the pinned
installed manifests; real-source controls explicitly skip when their public
fixture artifacts are absent. No native Mac command is executed by these tests.
