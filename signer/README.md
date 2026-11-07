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

The first keyless source-input client is `mac-keyvault`, a Go tool with a login-Keychain signing path.
Its [fixed source/recipe tuple and implementation](docs/first-client-keyvault/source-input-implementation.md)
cover source preparation only. Curator follows as the second client after its recipe inputs are available.
The separate Curator launcher and network proxy KEK broker remain later integrations.

Owner, 2026-11-01: «так ты говоришь нет подписи у куратора ну так давай подписывать».

## Implementation status

The independent Go module implements pure packages for unqualified manifest BODY decoding and supplied-module
verification. `internal/manifestbody` accepts the complete opcode34 JSON body, checks its closed schema and
finite shape/accounting bounds, and retains owned exact raw bytes with an eagerly computed SHA256. It uses a
bounded custom tokenizer, validates raw UTF-8 before traversal, and rejects decoded duplicate member names.
Success returns only `UnqualifiedOpcode34Body`; matching its separately compared raw digest establishes no authority.
Raw and manifest accessors return independent copies and support concurrent reads. Downstream integration must
carry the opaque body plus its raw digest, rather than treating mutable `ManifestCopy` fields as trusted input.

`internal/moduleformat` supplies the single identity, canonical h1 and directory derivation predicates under the
unchanged module pins. `internal/moduleinput` delegates to them while preserving its supplied-subset verifier.
It binds exact original source bytes, checks original `go.sum` anchors, canonical material/layout, portable
module-path collisions and both standard Go checksum domains, then publishes an immutable snapshot.
The collision index uses bounded segment keys; its [resource contract](docs/moduleinput-resources.md)
describes the algorithmic bound and the native caller budgets still required before integration.

`internal/keyvaultinput` composes these existing packages for the exact selected mac-keyvault source.
It binds retained job/manifest values, verifies the complete fixed source/module DATA closure and original
h1 anchors, and returns immutable snapshots plus fixed closed-environment recipe descriptions. Native
readiness always refuses pending actual SDK/toolchain/policy/isolation inputs; it has no execution entry point.
Other recipes and general native/source-graph qualification retain their existing boundaries below.

`internal/artifactsnapshot` verifies both bounded unsigned builder streams against
their receipts and each other, refuses trailing data, and returns an opaque
read-only snapshot with explicit cleanup. Its [caller contract](docs/artifact-snapshot.md)
preserves the original job and stream deadlines and the separate result-authentication,
host-custody, native signature and durable audit gates. This component does not
implement a builder exchange, signing service or durable native artifact staging.

`internal/sourceauthority.NewEffectRunner` supplies a
[source composition at build/sign boundaries](docs/sourceauthority-effects.md):
fresh service nonces and separate source reads, fixed endpoint checks, exact
job/manifest correlation and neutral pre-effect audit records. Its trusted
effect adapters have no production implementation. Source controls do not admit
policy, peers, native builders, signing or durable operation recovery; the
existing native readiness refusal remains unchanged.

`OpenAuditedSigner` implements the concrete `SignerEffect` bridge to the existing
`signingaudit` journal. It computes exact body and snapshot bindings, refreshes
current trust before durable intent, separates durable outcome from fetch, and
never signs during reconciliation. It retains original contexts/leases in memory;
old operations refuse recovery/fetch after restart without an agreed custody
contract. Native endpoint, admission and durability qualification remain required.

The public decoder admits at most 1,048,576 actual BODY bytes. Entries are nonempty and at most 8,192; receipt
records are at most 512; regular files are at most 64 MiB and their checked sum at most 1 GiB. Decoded entry paths,
link targets and module paths are bounded at 1,024 UTF-8 bytes; module versions at 128 ASCII bytes. Source symlink
size and SHA bind the exact decoded target bytes; regular-file payload hashes, including empty files, belong to a
later DATA verifier. An unexported capacity seam exists only for explicitly labelled inactive 4 MiB white-box tests.
There is no public capacity selector or 4 MiB activation. The 8,192/8,193 count pair exceeds the public raw cap.

Local refusal reasons preserve encounter order rather than globally prioritizing JSON syntax. In an integer
field, a number-like token such as `1e+` reports `integer_spelling`; in a wrong-type position, the same malformed
token reports `json_syntax`. Valid JSON fractions and exponents in a wrong-type position report `value_type`;
they are never admitted integer values. At an array maximum, an extra element beginning like a JSON value
can report `scalar_bound` before its malformed or truncated contents are parsed, including `,tru`, `,-`, `,1x`,
`,"abc` and `,{`. Punctuation or EOF immediately after a comma reports `json_syntax`, including at the maximum.
Tests pin these existing reasons; they do not change the decoder or establish a wire-error precedence policy.

Decoded module directories are checked against their path/version derivation before duplicate-directory lookup.
A copied directory on a distinct identity therefore reports `receipt_shape`, including escaped aliases; a repeated
identity reports `module_order_or_duplicate` before that lookup. Reaching the later duplicate-directory map guard
through otherwise valid public input would require distinct ordered identities with the same SHA-256 derivation.
That branch remains without practical public-contract coverage; tests do not bypass derivation or invent a collision.

Body-positive module entry layout and record membership remain unqualified until `moduleinput.Verify` checks
`Layout`; interior-colon module filenames meet a separate later `Path` refusal. Source Unicode/native equivalence,
symlink graph/containment, source receipt-to-DATA correspondence, required graph/compiled-content completeness,
framing/roles/deadlines, acquisition, cache synthesis, resource enforcement, durability, production builds, signing
and installation remain separate integration and qualification work. There is no service entrypoint or installation
command. A verified supplied subset does not establish authority, graph completeness or the sufficiency of omissions.

The version 1 design comprises the [baseline](docs/baseline-r5.md),
[builder and DATA contract](docs/builder-wire-data-r2.md),
[manifest capacity specification](docs/manifest-capacity-r3.md) and
[integrated addendum](docs/integrated-addendum-r2.md), read in that order. The integrated addendum controls
its explicit changes to earlier text, including module receipts and the proposed manifest capacity.
The baseline defines the independent source, evidence adapter, builder, signer and client boundaries.
The proposed [shared builder duties and Curator second-client recipe/custody delta](docs/builder-recipe-custody-delta.md)
separates shared graph/cache and two-build handoff duties from Curator-specific missing recipe inputs; native gates remain open.
The [open qualification register](../UNRESOLVED_QUESTIONS.md) records the remaining source and host inputs.

The current admitted manifest limit remains 1 MiB. The proposed 4 MiB limit requires its specified parser,
headroom and activation checks. The [contract cases](docs/examples/contract-cases-v1.json) and specification
tables remain declarative expectations. Executable pure-package tests cover body shape and the applicable supplied-module subset;
they do not establish production build, whole-input or native isolation qualification.

## Tools

The module requires Go 1.24 or newer; qualification uses its separately admitted exact toolchain and environment.
Dependencies are pinned in this module's `go.mod` and `go.sum`.
From the repository root, run each selected lane and inspect every exit code:

```sh
mkdir -p .temp/signer-tests
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go -C signer test -count=1 ./... > .temp/signer-tests/unit.log 2>&1
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go -C signer test -race -count=1 ./... > .temp/signer-tests/race.log 2>&1
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go -C signer vet ./... > .temp/signer-tests/vet.log 2>&1
```

These commands compile and check the pure packages; they do not run a signer or qualify a production toolchain.
Tests use owned temporary directories for writes and read fixed standard-Go checksum vectors from
`internal/moduleinput/testdata` plus the separately documented grammar corpus in `internal/moduleformat/testdata`.
Each grammar expectation has a fixed documented or retained standard-Go basis; checksum vectors alone are not a
complete grammar corpus. Private-capacity tests never count as public admission or source-headroom evidence.
Use the admitted isolated HOME, TMPDIR, module and build caches with the exact pinned dependency closure.
Example logs and other temporary project evidence stay in ignored `.temp/`.

Use `git diff --check` from the repository root to check patch whitespace.
