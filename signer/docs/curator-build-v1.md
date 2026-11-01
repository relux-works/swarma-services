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
