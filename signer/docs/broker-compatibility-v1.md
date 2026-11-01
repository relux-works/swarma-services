# KEK broker compatibility inputs

2026-11-01. Source facts inform the proposed version 1 signer contract. They do not admit a broker release,
freeze a build recipe, qualify an installed broker or authorize key/installation changes.

| Input | Retained source fact |
| --- | --- |
| Repository and default branch | `https://github.com/relux-works/mac-infra`, `main` |
| Module | `github.com/relux-works/mac-infra` |
| Product identifier | `works.relux.mac-infra.keyvault-kek` |
| Entrypoint | `./cmd/mac-keyvault-kek` |
| Go directive | `go 1.25.5`; a minimum, not an exact toolchain pin |
| Existing build arguments | `-trimpath`, `-ldflags` setting `main.Version`, `main.Commit`, `main.BuildDate` |
| Existing signing options | `runtime,library`; options are distinct from entitlements |
| Existing signing identity | `--sign -`, ad-hoc; cannot satisfy genuine P-256 release identity verification |

The retained setup recipe was inspected at source commit `13c4dd484cfd35cd8a43fbec476f6380f920d028`.
That is a source compatibility witness, not a newly qualified release or a fresh remote-head assertion.
The network proxy application has a different repository, identifier and entrypoint; its pilot artifact and
recipe cannot stand in for any of these broker inputs.

The existing setup derives version from `git describe --tags --always` and build date from current UTC time.
It does not fix a release architecture matrix, an exact toolchain executable/digest or a final entitlements
policy. Before signing-service builds, agree deterministic version/date/VCS inputs, exact toolchain and
dependencies/network policy, CGO policy, target and independent unsigned rebuild procedure. The current
invocation alone cannot establish reproducibility. Preserve the legitimate identifier, entrypoint and agreed
runtime signing semantics while replacing the ad-hoc identity with the admitted real identity.

The existing setup preserves an installed broker unless rebuilding is explicitly selected, because existing
keys trust that exact binary. The service produces a release artifact and receipt. It must not silently replace
the installed binary, create a store or key, run rebind, change key ACLs or migrate envelopes. Those operations
retain their separate custody and exact-operation decisions. Signing success does not prove that a broker was
installed or that it can read existing keys.

The proxy consumer requires an explicit absolute broker path and an existing provisioned store. Its private
envelope/socket and failure-before-listener guarantees remain consumer-owned. Accepting this source boundary
does not claim current installed/test qualification or change those guarantees.
