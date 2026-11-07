# First-run policy and signed GitHub review contract

Status: architectural proposal for a lab-only first run. No installed policy,
accepted format change, successful first run or release authority is asserted.

## Selected signature format

Use SSHSIG version 1, SSH Ed25519, namespace `swarma-source-review`, empty reserved
bytes and hash algorithm `sha512`. Do not introduce another signed envelope or
use envelope/2 on this path. Source-authority already implements SSHSIG framing,
SSH Ed25519 key decoding, SHA-512 hashing and Ed25519 verification in
`internal/sourceauthority/git.go` (`sshReader`, `sshEd25519Public`, `verifyOwner`).
Its current `verifyOwner` accepts only namespace `git` and Git commit payloads;
it does **not** verify a reviewer verdict. A separately reviewed change must
reuse those primitives with an explicit reviewer domain and pinned reviewer
role. Do not relax the Git namespace check or put reviewer keys in OwnerKeys.

The public producer pin for `https://github.com/relux-works/swarma-keyvault` is:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICSRUhYcN24vm72whIm2Mu7pmYNTpsW6QZy2TQ4+MOY9
SHA256:+8CC4oJ0iYApdxtBAFOfp7x1wry/GONh0Gn75d4CG/U
```

The distinct, lab-only public reviewer pin is:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJukNnwVDV44lMsuGDj1vmpMWzUUE+anC7pgL8mZx26W
SHA256:Zxudm2sMaXlQcNcbubgt9ThGhPBhTDImoDCmePR+QxA
```

Fingerprints hash the complete 51-byte binary SSH encoding, not the raw 32-byte
Ed25519 key. Compare both exact public bytes and full fingerprints. Reject an
absent signature, an unpinned key, a producer-key signature, and a configuration
whose reviewer key equals any admitted producer key. This equality refusal is
in addition to successful cryptography. The posting GitHub login may be
`reluxzion`; login, author display name and commit author are not reviewer trust.
Both keys share a Unix user: independence is procedural, not OS isolation.
Signing by this reviewer key is permitted only for the independently assigned
reviewer; publication by the producer does not authorize producer use of it.

## Exact signed bytes and COMMENT transport

Let H and B be the lowercase 40-hex exact GitHub PR head and base, and N the
positive decimal PR number, without a leading zero, at most 9223372036854775807.
Let S be the single admitted existing scope. There is currently no qualifying S
in the inspected core; the scope conflict below blocks instantiation. These are
substitutions in existing verdict text, not a JSON or envelope schema.

The signed byte sequence V is exactly the following four lines in this order,
UTF-8 ASCII, LF only, including exactly one LF after the final period:

```
ACCEPT: independent source review of relux-works/swarma-keyvault PR #N
PR https://github.com/relux-works/swarma-keyvault/pull/N
Exact head H, base B.
Scope S.
```

No BOM, CR, blank line, note, Markdown container, trimming, normalization,
reserialization or optional punctuation is allowed in V. S must exactly equal
the single configured scope and use printable ASCII without whitespace,
at most 512 bytes; a scope outside this finite subset is unsupported.
No placeholder S is admitted. Product and canonical repository are fixed by
the policy and the exact first two lines. H, B, N and S bind the verdict to the
candidate and authority scope. Changing any byte requires a new signature.

Set D to lowercase hex SHA256(V). The COMMENT body C is the exact concatenation:

1. `Independent source review: **ACCEPT** for exact head ` followed by H in
   backticks, ` (base ` followed by B in backticks, then `).` and LF;
2. `Verdict record digest: ` followed by `sha256:D` in backticks and LF;
3. one LF;
4. V;
5. one LF;
6. one canonical OpenSSH `SSH SIGNATURE` PEM block, ending in LF.

The first line therefore retains the existing `platformDigest` spelling.
The three existing verdict declaration/repository/head lines retain the
`verdictBody` spelling. The additional scope line and detached signature are
an explicit transport/verification delta: the existing Matrix digest lookup
cannot be described as already supporting this GitHub-only construction.
The adapter extracts exact V bytes; it never reconstructs V from parsed values.
It verifies D against those bytes, then the signature, then semantic bindings.
The signature armor and COMMENT prefix are not part of V and do not create a
self-reference. COMMENT must contain exactly one V and one signature, with no
other text, quotations, fences, attachments or trailing bytes.

SSHSIG cryptography is the existing OpenSSH construction. Define string(x) as
uint32 big-endian byte length followed by x. The Ed25519 signed message is
`SSHSIG || string(namespace) || string(empty) || string(sha512) ||
string(SHA512(V))`. The detached binary container is `SSHSIG || uint32(1) ||
string(public51) || string(namespace) || string(empty) || string(sha512) ||
string(string(ssh-ed25519) || string(signature64))`. The public51 must be the
reviewer pin. No `git`, `file` or other namespace is accepted for reviews.

Canonical armor uses the exact BEGIN/END SSH SIGNATURE markers, LF, standard
base64 without intra-line whitespace, 70 columns except the final nonempty line,
and no PEM headers. Re-encoding must equal the supplied block byte for byte.
One final LF is required. Refuse extra blocks, suffixes, malformed lengths,
unknown versions/algorithms, nonempty reserved bytes and any unconsumed bytes.

## Finite bounds and current-state requirements

Before allocation, cap each COMMENT at 8192 decoded UTF-8 bytes, V at 2048,
armor at 2048, decoded SSHSIG at 512, namespace at its exact configured length,
public key at exactly 51, and Ed25519 signature at exactly 64. Bound every SSH
length against remaining input using the existing checked reader. The admitted
SSHSIG above has fixed-size fields; longer aliases do not pass. Parse no JSON
within V or armor and never recurse. The policy remains at most 65536 bytes,
CCJ-1 depth at most 16, with the adopted commit limit 1048576, ancestry 256,
reviews 256 and check records 256. Review aggregate bytes stay at most 16 MiB.
All source reads and cryptography share the existing 30-second phase budget;
the observations retain the existing maximum 300-second lease. Bound raw
provider pagination before normalization, using the adapter's finite page cap;
overflow, missing coverage and unknown rules are unavailable, never empty.

Select one active COMMENT by trusted adapter selection over the complete
current exact-PR review inventory, not a release caller's ID. Require unique
selection and current head/base, positive PR, canonical repository, effective
state and checks. An active blocking review or dismissed/changed selected
review refuses. Do not salvage an old unsigned or differently formatted review.
The historical review numbered 5809500881 is not a signed positive.

BeforeBuild and BeforeSign independently reread installed policy, repository,
exact PR tuple, complete effective reviews, required-check rules and complete
check inventory. A producer-signed Git commit is necessary but not reviewer
approval. Missing/unsigned/producer-signed reviewer verdicts, unadopted producer
keys, changed head/base/repository/PR/scope, changed policy and unavailable
provider state refuse before effects. Preserve merged/nonrewriting landing and
fresh nonce/operation bindings. Do not claim an open PR is a landed candidate.

## Policy representation and scope conflicts

The inspected native Policy has Product, Alias, CanonicalRepository,
RepositoryName, DefaultBranch, SHA256, MatrixOrigin, ProducerSender,
ReviewerSenders, Scopes, OwnerKeys and Profile. OwnerKey has Repository,
Fingerprint and PublicKey. It has no ReviewerKeys member or reviewer key role.
Reusing OwnerKeys would admit the reviewer as a commit owner; encoding a key in
ReviewerSenders would misrepresent a Matrix member ID. Neither is acceptable.

More decisively, `internal/sourceauthority/types.go` defines each scope as a
configured room at MatrixOrigin, and `review.go:lookupVerdict` treats Scopes as
complete Matrix evidence lookup scopes. `authority.go:validPolicy` checks only
nonempty unique strings and a count of 1..4; it supplies no build/sign action
scope vocabulary. No existing scope in this core is defined to cover both a
lab build and sign of swarma-keyvault. Exactly one qualifying scope therefore
cannot honestly be named. Do not substitute a room, a grant proposal's scope,
`prebuild`/`presign` phases or an invented action identifier. This is an explicit
contract conflict requiring disposition, not a missing Matrix-ID blocker.

Consequently the accompanying known-field CCJ bytes and public bindings are
not a complete policy and their hashes are not installation policy digests.
No complete `policy.ccj.json` can be emitted under the unchanged field contract.
Do not accept or install a partial payload or a template with placeholders.

## Minimal loader and PR-adapter deltas

The loader owner must implement the authenticated nonrecursive mapping:
omit native SHA256 from serialized bytes, compute SHA256 of the entire exact
canonical file, compare to the expected digest supplied from the admission
record at launch, and populate runtime Policy.SHA256 from that derived digest.
There must be one digest, not an arbitrary native ID plus a second install hash.
Do not put an empty, zero or previous digest into the payload. Reject a digest
mismatch before constructing authority; repeat comparison at both phase reads
and effect freshness checks. Preserve protected no-follow descriptor reads,
0600 single-link file ownership, directory custody and bounded snapshots.

On the explicitly configured GitHub-PR route, native MatrixOrigin and
ProducerSender are empty strings and ReviewerSenders is an empty array (unset,
not synthesized). The Matrix route must refuse when any required Matrix field
is unset; never infer a route, member, room or origin from absent values. Keep
route selection constructor-bound, outside caller input. Serialize empty
native fields consistently; reject null aliases and unknown fields.

The PR-adapter/core owner must add role-separated reviewer-pin configuration
and verification. The smallest proposed native extension is ReviewerKeys using
the existing OwnerKey triple shape, with one repository-bound reviewer pin;
this is a proposed **core field delta**, not an already existing field or a new
wire envelope. The policy codec owner must mirror the final reviewed core
shape exactly. Until that delta is accepted and implemented, keep public
reviewer bindings in this proposal only and emit no installable alternative.

The PR adapter derives handoff from actual repository/head/base/PR provider
records, without fabricated ProducerHandoff Matrix fields or event evidence.
It replaces only the explicitly selected GitHub route's Matrix verdict lookup
with the exact signed COMMENT verification above. Matrix route predicates
remain unchanged. Signature identity supersedes the earlier GitHub-login
distinctness requirement for this lab route; unsigned self-review still
refuses, including a COMMENT posted by reluxzion without the reviewer signature.

The scope conflict requires its own explicit disposition and reviewed core
semantics before a final one-scope configuration can exist. Do not make the
loader silently redefine Scopes or accept arbitrary strings as authority.
Once the core supports the accepted scope and role pin, produce one complete
CCJ-1 file from those native fields, hash its exact bytes with no trailing LF,
and obtain acceptance of those bytes. The installer records the observed
installed-byte digest on the admission element; launch consumes that expected
digest from the trusted record. No install precedes exact-byte acceptance.

This format/config proposal requires fresh independent review. It authorizes
no implementation in another workbench, no installation, public publication,
release-key use, native execution, runtime activation or dogfooding success.
