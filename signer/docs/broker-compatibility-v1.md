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
