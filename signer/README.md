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

Status: preparation.

The version 1 design comprises the [baseline](docs/baseline-r5.md),
[builder and DATA contract](docs/builder-wire-data-r2.md),
[manifest capacity specification](docs/manifest-capacity-r3.md) and
[integrated addendum](docs/integrated-addendum-r2.md), read in that order. The integrated addendum controls
its explicit changes to earlier text, including module receipts and the proposed manifest capacity.
The baseline defines the independent source, evidence adapter, builder, signer and client boundaries.
The [open qualification register](../UNRESOLVED_QUESTIONS.md) records the remaining source and host inputs.
These documents describe a design; no signer implementation, installation or runtime qualification is shipped.

The current admitted manifest limit remains 1 MiB. The proposed 4 MiB limit requires its specified parser,
headroom and activation checks. The [contract cases](docs/examples/contract-cases-v1.json) and specification
tables are declarative expectations, rather than executed parser, checksum, build or isolation tests.

## Tools

This subproject currently contains documentation only. No build, signing or installation command is shipped yet.
Use `git diff --check` from the repository root to check documentation patches. Build and verification artifacts
belong in the ignored `.temp/` directory until the service defines its own supported output paths.
Python 3 can check that the declarative fixture file is valid JSON:
`mkdir -p .temp && python3 -m json.tool signer/docs/examples/contract-cases-v1.json > .temp/contract-cases-v1.json`.
That command validates JSON serialization only.
