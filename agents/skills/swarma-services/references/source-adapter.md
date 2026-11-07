# Contributor source-authority adapter

The implemented seam is [`Source` and `Clock`](../../../../signer/internal/sourceauthority/types.go), wired once by [`sourceauthority.New(policy, source, clock)`](../../../../signer/internal/sourceauthority/authority.go). These packages are internal to the signer Go module. Implementations belong in that module's import-path tree; this is not an external plugin API.

## Write and wire

Implement `Source.Read(context.Context, Query) (Observation, error)` and `Clock.Read() (Reading, error)`. Pass those implementations with protected installed `Policy` to `New`, outside request handling. That constructor call is the existing wiring mechanism. There is no plugin file format, registration command, discovery directory or provider implementation to install.

`Source` is a privileged acquisition and normalization boundary. A real adapter must acquire only configured canonical authorities, authenticate provider records and message origins, establish complete bounded pagination and current review/check policy, obey the context, bound allocations before returning, and transfer stable observations. Request fields and caller-provided observations cannot grant that trust. `Clock` needs a qualified same-process clock and discontinuity detector; a fixed fixture clock cannot qualify a host. Both implementations must be concurrency safe when shared by concurrent callers.

Use `BeforeBuild` and a separately refreshed `BeforeSign` with fresh service-generated nonces. Never reuse a fixture, prior phase observation or a locally fresh lease as current provider authority. Read [the source-authority implementation contract](../../../../signer/docs/sourceauthority-implementation.md#trust-boundary-and-remaining-dependencies) before implementing an actual adapter. Provider normalization, installed policy/key custody and host qualification remain separate missing production inputs.

## Run the inert fixture and its nearby refusal

[`signer/examples/source-adapter/main.go`](../../../../signer/examples/source-adapter/main.go) implements and wires an in-memory refusing source and fixed clock. Its policy, public test-vector bytes, aliases, hashes and limits are synthetic; none selects a real owner, provider or repository. It reads no files, generates no private keys, opens no sockets, spawns no child process and performs no build, signing or native operation itself.

Within an offline sandbox with read-only source/tools, an empty environment and fresh private 0700 absolute HOME/TMP/cache directories, run from the repository root:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off \
  timeout 120s go -C signer run -mod=readonly ./examples/source-adapter
```

Go's compilation writes only the sandbox's private build/cache state. This example and its imported package use only the standard library; no module download or dependency upgrade is required. Reading the skill does not request execution. Do not run the native durability runner as an example.

Exit 0 prints:

```text
fixture adapter wired; source_read refused; request_binding refused
```

Successful construction proves fixture interface wiring only. The first call returns nil qualification and `authority_unavailable: source_read` after exactly one adapter call. Changing only the request repository alias then returns nil qualification and `authority_rejected: request_binding` without another adapter call. The executable checks the error classes, predicates and read count; an unexpected outcome fails. Neither refusal yields authority or reaches a downstream effect.

For broader contributor checks, the existing `internal/sourceauthority` tests pair synthetic accepted observations with wrong bindings, provider failure, incomplete coverage and clock/refreshed-phase refusals. Run only requested lanes in the same confinement; fixture acceptance does not establish actual provider access, a qualified clock, a native Mac build or signing readiness. There is no production adapter or installed plugin to test through a service CLI.
