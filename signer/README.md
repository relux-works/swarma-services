# swarma-signer

Release signer. It signs tool binaries so that macOS can bind secrets to a tool's own signature (a Keychain item that
only that signed tool can read).

It signs only a repository and a commit, never a binary handed to it. The commit must be reviewed, signed by the owner
and landed. The signer builds the artifact itself, under a separate account that has no access to the signing key,
with a pinned toolchain. It signs only identifiers on its allowlist and keeps an append-only log. For tools that hold
or bind secrets, the owner's presence (Touch ID) is required only when the tool is first admitted to the allowlist.
Later releases run autonomously after signature, review, checks and landing verification. Artifact hashes remain
bound to the build, signing and audit receipts.

The signing identity is an ECDSA P-256 certificate held by a dedicated service user. The developer keys in the login
keychain are not used.

The first client is Curator core, which already resolves credentials and uses authorization tokens. Its separate
launcher follows later. The network proxy's KEK broker is the second client after Curator rollout and dogfooding.

Owner, 2026-11-01: «так ты говоришь нет подписи у куратора ну так давай подписывать».

## Implementation status

The independent Go module currently implements `internal/moduleinput`, a pure verifier of supplied module material.
It takes ordered typed records and file entries, checks finite bounds, copies an immutable snapshot, binds the exact
source bytes and verifies original `go.sum` anchors and standard Go checksums. It checks every supplied record,
including records unused by a later build. Returned content has no mutable aliases to caller buffers.

A verified supplied subset does not establish source authority, graph completeness or the sufficiency of omitted
material. Raw manifest parsing, whole-manifest accounting, cache synthesis, production builds, signing and service
installation remain to be integrated and qualified. There is no service entrypoint or installation command yet.

The version 1 design comprises the [baseline](docs/baseline-r5.md),
[builder and DATA contract](docs/builder-wire-data-r2.md),
[manifest capacity specification](docs/manifest-capacity-r3.md) and
[integrated addendum](docs/integrated-addendum-r2.md), read in that order. The integrated addendum controls
its explicit changes to earlier text, including module receipts and the proposed manifest capacity.
The baseline defines the independent source, evidence adapter, builder, signer and client boundaries.
The [open qualification register](../UNRESOLVED_QUESTIONS.md) records the remaining source and host inputs.

The current admitted manifest limit remains 1 MiB. The proposed 4 MiB limit requires its specified parser,
headroom and activation checks. The [contract cases](docs/examples/contract-cases-v1.json) and specification
tables remain declarative expectations. Executable pure-package tests cover only their applicable typed subset;
they do not establish parser, production build or native isolation qualification.

## Tools

Use Go 1.24 or newer for development. Dependencies are pinned in this module's `go.mod` and `go.sum`.
From the repository root, run each selected lane and inspect every exit code:

```sh
mkdir -p .temp/signer-tests
GOTOOLCHAIN=local go -C signer test -count=1 ./... > .temp/signer-tests/unit.log 2>&1
GOTOOLCHAIN=local go -C signer test -race -count=1 ./... > .temp/signer-tests/race.log 2>&1
GOTOOLCHAIN=local go -C signer vet ./... > .temp/signer-tests/vet.log 2>&1
```

These commands compile and check the pure package; they do not run a signer or qualify a production toolchain.
Tests use owned temporary directories for writes and read fixed checksum vectors from `internal/moduleinput/testdata`.
Go manages its normal module and build caches; the example logs and other temporary project evidence stay in ignored
`.temp/`.

Use `git diff --check` from the repository root to check patch whitespace. Python 3 can check that the declarative
fixture file is valid JSON:
`mkdir -p .temp && python3 -m json.tool signer/docs/examples/contract-cases-v1.json > .temp/contract-cases-v1.json`.
That command validates JSON serialization only.
