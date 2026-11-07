# Contributor source-authority adapter

The implemented seam is [`Source` and `Clock`](../../../../signer/internal/sourceauthority/types.go), wired once by [`sourceauthority.New(policy, source, clock)`](../../../../signer/internal/sourceauthority/authority.go). These packages are internal to the signer Go module. Implementations belong in that module's import-path tree; this is not an external plugin API.

## Write and wire

Implement `Source.Read(context.Context, Query) (Observation, error)` and `Clock.Read() (Reading, error)`. Pass those implementations with protected installed `Policy` to `New`, outside request handling. For current-file custody on Linux, construct `NewProtectedPolicySource` with the custodian's fixed absolute path and expected UID, then pass the admission-record digest at launch to `NewWithPolicySource` or `NewEffectRunnerWithPolicySource`. The [local Policy contract](../../../../signer/docs/protected-policy.md) defines CCJ-1 bytes without an embedded digest, exact-byte admission, explicit route guards, permissions and atomic reinstall rules. The Matrix verifier refuses unset Matrix identities. Explicit GitHub policy snapshots remain unbound to an authority until the separately owned mapper and reviewer contract are composed. Exact-byte acceptance and installation remain external; no example values establish admission. There is no plugin registration command, discovery directory or provider implementation to install.

`Source` is a privileged acquisition and normalization boundary. A real adapter must acquire only configured canonical authorities, authenticate provider records and message origins, establish complete bounded pagination and current review/check policy, obey the context, bound allocations before returning, and transfer stable observations. Request fields and caller-provided observations cannot grant that trust. `Clock` needs a qualified same-process clock and discontinuity detector; a fixed fixture clock cannot qualify a host. Both implementations must be concurrency safe when shared by concurrent callers.

Use `BeforeBuild` and a separately refreshed `BeforeSign` with fresh service-generated nonces. Never reuse a fixture, prior phase observation or a locally fresh lease as current provider authority. Read [the source-authority implementation contract](../../../../signer/docs/sourceauthority-implementation.md#trust-boundary-and-remaining-dependencies) before implementing an actual adapter. Provider normalization, installed policy/key custody and host qualification remain separate missing production inputs.

## Process clock

For the implemented same-process clock, call [`sourceauthority.NewProcessClock()`](../../../../signer/internal/sourceauthority/clock.go), handle its error, and retain the returned `*ProcessClock` for injection into `New(policy, source, clock)` outside request handling. Do not copy it after construction. Concurrent reads are serialized; its zero value refuses. Construction starts a random, nonpersistent epoch, not a restored lease or caller-selected clock.

An unknown sample, discontinuity or process-identity change permanently disables that instance. Do not retry it as recovery, silently reset it, substitute the fixture clock, or continue with an old qualification. Construct a new instance and perform complete `BeforeBuild` / `BeforeSign` qualification, including a fresh authenticated `Source.Read`. A new process or instance cannot inherit the previous epoch's qualification. `CheckFreshnessContext` checks the local lease and, on the protected route, current installed digest; pass the original job context. It cannot replace the independent presign read.

Read the [process-clock contract](../../../../signer/docs/sourceauthority-clock.md) for measured `SampleSpan`, conservative expiry and refusal rules before implementing another clock adapter. The landed clock does not attest absolute UTC accuracy, suspend/rate behavior or target host admission. Existing [clock controls](../../../../signer/internal/sourceauthority/clock_test.go) include real same-process construction/concurrent reads and synthetic latched-fault/requalification cases; they do not qualify a native host.

## Run the inert fixture and its nearby refusal

[`signer/examples/source-adapter/main.go`](../../../../signer/examples/source-adapter/main.go) implements and wires an in-memory refusing source and fixed clock. Its policy, public test-vector bytes, aliases, hashes and limits are synthetic; none selects a real owner, provider or repository. It reads no files, generates no private keys, opens no sockets, spawns no child process and performs no build, signing or native operation itself.

Within an offline sandbox with read-only source/tools, an empty environment and fresh private 0700 absolute HOME/TMP/cache directories, run from the repository root:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off \
  timeout 120s go -C signer run -mod=readonly ./examples/source-adapter
```

Go's compilation writes only the sandbox's private build/cache state. The source-authority package now also imports the existing BODY decoder through its effect-boundary composition; its transitive dependencies include the module's pinned `golang.org/x/mod` and `golang.org/x/text`. Supply those exact public artifacts with both canonical h1 domains verified in the private sandbox before this offline command; no dependency upgrade is required. Reading the skill does not request execution. Do not run the native durability runner as an example.

Exit 0 prints:

```text
fixture adapter wired; source_read refused; request_binding refused
```

Successful construction proves fixture interface wiring only. The first call returns nil qualification and `authority_unavailable: source_read` after exactly one adapter call. Changing only the request repository alias then returns nil qualification and `authority_rejected: request_binding` without another adapter call. The executable checks the error classes, predicates and read count; an unexpected outcome fails. Neither refusal yields authority or reaches a downstream effect.

For broader contributor checks, the existing `internal/sourceauthority` tests pair synthetic accepted observations with wrong bindings, provider failure, incomplete coverage and clock/refreshed-phase refusals. Run only requested lanes in the same confinement; fixture acceptance does not establish actual provider access, a qualified clock, a native Mac build or signing readiness. There is no production adapter or installed plugin to test through a service CLI.
