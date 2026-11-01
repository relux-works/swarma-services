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

The [proposed version 1 contract](docs/contract-v1.md) defines the source, builder, signer and client boundaries.
Client parameters and host custody are awaiting confirmation; this document does not describe an installed service.
The [authority adapter](docs/authority-v1.md) keeps evidence credentials outside the signer and builder; the
[first Curator build proposal](docs/curator-build-v1.md) separates known source facts from unqualified recipe inputs.

## Tools

This subproject currently contains documentation only. No build, signing or installation command is shipped yet.
Use `git diff --check` from the repository root to check documentation patches. Build and verification artifacts
belong in the ignored `.temp/` directory until the service defines its own supported output paths.
