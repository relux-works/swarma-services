# swarma-signer

Release signer. It signs tool binaries so that macOS can bind secrets to a tool's own signature (a Keychain item that
only that signed tool can read).

It signs only a repository and a commit, never a binary handed to it. The commit must be reviewed, signed by the owner
and landed. The signer builds the artifact itself, under a separate account that has no access to the signing key,
with a pinned toolchain. It signs only identifiers on its allowlist and keeps an append-only log. For tools that hold
or bind secrets, each release also needs the owner's presence (Touch ID). The approval is bound to the build output
hash.

The signing identity is an ECDSA P-256 certificate held by a dedicated service user. The developer keys in the login
keychain are not used.

First clients: Curator, which will read the Claude setup token from the Keychain, and the network proxy's KEK broker.

Owner, 2026-11-01: «так ты говоришь нет подписи у куратора ну так давай подписывать».

Status: preparation.
