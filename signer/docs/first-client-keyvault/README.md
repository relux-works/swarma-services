# First secret-bearing Go client: mac-keyvault

Status: local source proposal for independent review. The paired
[source-input implementation](source-input-implementation.md) selects this
client for the keyless G1 source slice and preserves the C1–C8 boundaries.
This chooses one first
client and provides its immutable source/module inputs. It does not admit an
executable builder, a signing policy, a key, an installed client or a release.

The choice is `relux-works/swarma-keyvault`, `./cmd/mac-keyvault`, commit
`cc1aa20c551f5d2e4ed9785d844dd036ae8716ed`, tree
`31c46e09909ba3c53b1b806d3eb74c2a7c5ffbbd`, target `darwin/arm64`, cgo enabled.
The production command directly manages non-extractable P-256 private signing
keys in the login Keychain. Its `sign` path reaches `SecItemCopyMatching` for a
private-key reference and `SecKeyCreateSignature`; this is a secret-bearing
application, rather than merely a client of another process. No existing key,
service/purpose label or owner identity is selected by this proposal.

## Why this client

A source-backed comparison of three commands at that same commit found:

| Command | Target source files / bytes | External compiled modules |
| --- | ---: | ---: |
| `mac-keyvault` | 33 / 336252 | 2 |
| `mac-keyvault-kek` | 41 / 348088 | 2 |
| `swarma-keyvault` | 109 / 701029 | 4 |

The selected command has the smallest complete target closure in this shortlist.
The KEK command also adds native code-inspection and libbsm dependencies. Services
and Pulse source snapshots have no direct Keychain-secret implementation, so they
were excluded. This comparison is bounded; it claims no global search of every
repository. Existing Alexis-side KeyVault and Mac custody remains in place.
Services source custody does not transfer a private key or installed KeyVault.

## Available immutable inputs

- `tuple.json` binds the repository, commit/tree, entrypoint, secret call chain,
  custody, all artifact digests, concrete native prerequisites and remaining gates.
- `recipe.json` fixes one declarative argv/environment and two clean unsigned
  native builds. It invokes no generator, installer, signer or client deployment.
  Paths are installed recipe choices and are never caller inputs.
- `source-closure.json` contains all 35 required source/anchor files, with hashes.
  The two module anchors retain their exact original source bytes.
- `dependencies.json` contains two complete canonical compiled module trees
  (`x/crypto v0.55.0`, `x/sys v0.47.0`) and the original, anchored `go.mod`
  metadata for the exact envelope and registrar versions required by the graph.
  There are 925 module-content entries; no `.info` or `.list` cache metadata is
  imported. Unused x/term, x/net and x/text bodies are not required by the actual
  pinned offline graph and selected package list. Their omission was checked with
  a separate minimal input tree, not inferred from go.sum or a failed build.
- `go-toolchain.json` inventories every regular file in the official Go 1.26.10
  Darwin/arm64 archive and binds its official archive size/hash and public origin.
  `go-verifier-linux.json` binds the complete Linux verifier distribution used for
  the actual source/module checks. These are installed-tool manifests, not DATA
  entries under the 8192-entry material cap.

Canonical public module ZIP and separate go.mod bytes were acquired at their
existing versions. Standard h1 calculations match the original source go.sum;
Go 1.26.10 `go mod verify`, offline `go mod graph` and target `go list -deps` pass
on the reduced input set. No source anchor was added and no dependency upgraded.
These checks establish supplied integrity and target metadata sufficiency, not
native compilation or production authority. Services `moduleinput` and
`manifestbody` remain unchanged and are not requalified by these checks.

Two clean Linux/amd64 cgo-disabled builds of this command produced equal bytes.
That command uses a refusing Security.framework stub on Linux; its equality is
only a portable diagnostic. There was no Darwin cross-build, native Keychain
access or execution of a Darwin artifact.

## Concrete native prerequisites and first-run blockers

The proposed native C input is Apple Xcode **16.4**, including the macOS **15.5**
SDK, from Apple's own distribution. Apple documents that pairing in the
[Xcode release notes](https://developer.apple.com/documentation/xcode-release-notes/xcode-16_4-release-notes)
and [SDK notes](https://developer.apple.com/documentation/macos-release-notes/macos-15_5-release-notes).
The pinned Go Darwin archive is available and inventoried. No Apple SDK bytes,
Clang/ld bytes or native OS/framework manifest are present in this packet. Their
hashes remain absent. A version or origin URL cannot stand in for those bytes.
Before the first native build, its custodian must supply the actual immutable
SDK/compiler/linker/runtime manifest and qualify the exact fixed recipe, including
unsigned output flags, on a native arm64 Mac. This is the genuine missing part of
the complete *effective native* closure; the source/module closure is supplied.

The Services custodian and KeyVault source counterpart must accept the exact
client pairing and recipe replacement in the existing G1 and C1-C8 seams, which
currently name Curator. These files do not silently amend that baseline or define
a new protocol. Actual protected policy bytes, manifest34/job bindings,
receipt-only auxiliary cache derivation, precompile required-content refusal,
finite native enforcement, G2 double-build equality and G3 principal/isolation/
immutable handoff still need their existing qualification. The two clean builds
must use separate private writable cache state and identical reconstructed paths;
canonical module/source/tool input trees remain read-only.

Owner presence, native certificate/requirement/allowlist pins and initial
secret-tool admission are relevant to a later authorized signing/deployment run,
not gates for reviewing this source proposal. No live admission is asserted here.
Curator remains the second client after its own tag/recipe question. Its milestone,
a generic client framework and per-release owner approval are not added gates.
Existing later-release autonomy and all once-only/custody rules remain intact.

The source proposal is ready for fresh exact-head independent review and the
normal source marker check. Publication and all runtime effects remain separate.
