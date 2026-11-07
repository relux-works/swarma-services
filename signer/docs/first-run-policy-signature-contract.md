# First-run policy and signed GitHub review contract

Status: revised architectural contract for a lab-only first run. The source owner
has accepted the exact repository scope and native ReviewerKeys configuration
below. Implementation, complete policy bytes, independent review of this revision,
a new admission marker and installation remain separate requirements. This
document asserts no successful first run or release authority.

## Accepted scope and reviewer role

The GitHub-PR route has exactly one first-run scope:
`github.com/relux-works/swarma-keyvault@main`. It means the actual repository
`https://github.com/relux-works/swarma-keyvault` and PR base branch `main`.
A PR in another repository or targeting another base branch refuses. Matrix
room IDs remain the Matrix route's scope vocabulary. This scope is source-owned
configuration, not an action grant, new wire format or replacement grant format.

Native Policy gains ReviewerKeys, a slice of 1..4 repository-bound SSH Ed25519
pins using the existing OwnerKey triple (Repository, Fingerprint, PublicKey).
ReviewerKeys is a separate role; never put reviewer pins in OwnerKeys or encode
them in ReviewerSenders. Verify verdicts using SSHSIG version 1, namespace
exactly `swarma-source-review`, empty reserved bytes and hash algorithm `sha512`.
Git commit signatures continue to require namespace `git` and producer OwnerKeys.

The public producer pin for the canonical repository is:

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
Ed25519 key. Validate exact encoding, fingerprint and repository binding for
every pin; refuse duplicates and a reviewer key equal to any admitted producer
key at policy construction/load, even across different repository labels.
The posting GitHub account may be shared. Its login, author name, association
and platform permissions confer no reviewer authority. Only the separately
assigned reviewer's pinned signature does. Same-Unix-user independence remains
procedural; publication never permits producer use of the reviewer key.

## Exact signed bytes and original delivery identity

Let H and B be the lowercase 40-hex exact PR head and base commit, N its positive
decimal number, and R the original GitHub pull-request review's positive decimal
database ID. N and R have no leading zero and are at most 9223372036854775807.
Let S be exactly `github.com/relux-works/swarma-keyvault@main`.

V consists of exactly these five ASCII lines, in order, LF only, with one LF
after the final period. Substitute values without angle brackets or placeholders:

```
ACCEPT: independent source review of relux-works/swarma-keyvault PR #N
PR https://github.com/relux-works/swarma-keyvault/pull/N
Exact head H, base B.
Scope S.
Original delivery https://github.com/relux-works/swarma-keyvault/pull/N#pullrequestreview-R.
```

No BOM, CR, blank line, note, Markdown container, trimming, normalization or
reserialization is allowed inside V. The signature authenticates the entire
original delivery selector (platform, canonical repository, PR and R), as well
as H, B and S. R is not a caller-selected replacement. A URL printed by the
producer is not an authenticated delivery record. The reviewer must independently
authenticate the actual preallocated platform object as described below before
signing its identity. Unknown or unsupported identity encodings refuse.

Set D to lowercase hex SHA256(V). COMMENT body C is exactly:

1. `Independent source review: **ACCEPT** for exact head ` followed by H in
   backticks, ` (base ` followed by B in backticks, then `).` and LF;
2. `Verdict record digest: ` followed by `sha256:D` in backticks and LF;
3. one LF;
4. V;
5. one LF;
6. one canonical OpenSSH `SSH SIGNATURE` PEM block, ending in LF.

Extract and hash the exact V bytes, verify the pinned reviewer signature, then
check all semantic bindings against actual provider records. Never reconstruct
V before verification. C contains exactly one V and one signature, without
quotations, fences, attachments, extra blocks or trailing bytes. The existing
platformDigest prefix and verdict declaration/repository/head lines remain;
the signed scope and original-delivery lines are a GitHub-only verdict-text
delta in this contract, not a second envelope or authority journal.

Define string(x) as uint32 big-endian byte length followed by x. The Ed25519
signed message is `SSHSIG || string(namespace) || string(empty) ||
string(sha512) || string(SHA512(V))`. The detached binary container is
`SSHSIG || uint32(1) || string(public51) || string(namespace) || string(empty) ||
string(sha512) || string(string(ssh-ed25519) || string(signature64))`.
public51 must match an admitted ReviewerKeys pin for this repository.

Canonical armor has exact BEGIN/END SSH SIGNATURE markers, LF, standard base64
without intra-line whitespace, 70 columns except the final nonempty line, and
no PEM headers. Re-encoding must equal the supplied block byte for byte. Require
one final LF; refuse unknown versions/algorithms, nonempty reserved bytes,
malformed lengths and unconsumed bytes. Never relax verifyOwner's Git domain.

## Producible preallocation, signing and submission

This is a required future flow, not an instruction to create a review now.
Use existing GitHub review operations; no ID is known before preallocation and
neither a future submission time nor the signature's own bytes are signed.

1. The independently assigned reviewer reads the exact PR and repository through
   the trusted GitHub client, authenticating canonical repository, number, H, B
   and base ref `main`. The reviewer completes the independent exact-candidate
   review. Using its authorized platform session, the reviewer creates a pending
   review with `POST /repos/relux-works/swarma-keyvault/pulls/N/reviews`, explicit
   `commit_id: H`, no event and no acceptance body. No inline comments are needed.
   A pending review is not an approval and cannot qualify.
2. The reviewer takes R from the actual successful platform response, then
   independently rereads `GET /repos/relux-works/swarma-keyvault/pulls/N/reviews/R`
   and the PR. Require the same R, correct review resource/PR/repository,
   commit_id H, pending state, unchanged H/B/base ref and no previously submitted
   body. Authenticate transport/provider provenance, not a producer-supplied JSON
   copy or an account name. If the authorized session cannot see its pending
   object, or there is an existing pending review conflict, stop; do not guess R,
   borrow credentials, silently reuse an object or substitute an active review.
3. The reviewer constructs V with this R and the independently observed tuple,
   and signs it with its assigned reviewer key in the stated namespace. The
   signature now authenticates the original-delivery selector before publication.
   This contract generates no signature and grants no additional key access.
4. Submit this SAME pending review with
   `POST /repos/relux-works/swarma-keyvault/pulls/N/reviews/R/events`, `event:
   COMMENT` and exact body C. Supplying C at submission avoids an intermediate
   active placeholder and avoids an edit of an already submitted acceptance.
   Publication may be performed by an authorized publisher able to submit that
   pending object; the publisher acquires no reviewer signing authority. A shared
   platform login does not change signer-key separation. If submission fails,
   reread R; never create a replacement review carrying the old signed bytes.
5. Reread the submitted review, exact PR, complete review inventory and integrity
   evidence. Require C unchanged, commit_id H, actual COMMENTED state and a valid
   submitted_at; normalize COMMENTED to Kind COMMENT, State active only after all
   integrity checks. Any intervening PR change or inability to establish the
   original submitted body's integrity refuses. No pending object qualifies.

These operations are documented in the [GitHub review REST API](https://docs.github.com/en/rest/pulls/reviews).
The [PullRequestReview GraphQL fields](https://docs.github.com/en/graphql/reference/pulls#pullrequestreview)
include current state, submittedAt, lastEditedAt and userContentEdits. They are
possible integrity inputs, not proof that the sealed adapter already exposes
complete history. Provider permissions, retained revisions and pagination must
actually support the following requirements. REST current body alone does not.

## Selection, withdrawal and republication

Retain the core's immutable delivery-record binding: ReviewInventory.SelectedID
comes from an authenticated exact-candidate delivery record, never the release
caller's selector, newest COMMENT, posting account or latest review per user.
On this route that delivery record is the pinned-reviewer-authenticated V bound
to its actual original review R. The trusted source discovers candidates from
the complete exact-PR inventory, verifies their signatures and actual identities,
and requires a unique original delivery for this exact tuple. It returns R only
when the actual containing record's ID equals signed R. Signature verification
alone is not selection. Preserve R in the phase qualification/summary and require
the same original delivery across the operation's phase/effect bindings.

At every BeforeBuild and BeforeSign read, independently fetch R by actual
platform identity and cross-check the
complete current inventory. Require its repository/PR/head, signed B and scope
to match the current exact tuple. Require original submitted C intact, current
active COMMENT state, no dismissal/withdrawal and no post-submission body edit.
Use authenticated platform state and retained revision/dismissal evidence, not
a release caller's asserted `intact`/`active` flag. Pre-submission initialization
is permitted only by the pending-to-submitted flow above; any later edit,
including edit-and-restore, refuses. A lastEditedAt timestamp alone does not
prove a complete edit history or distinguish tied timestamps. Missing revision
content, deleted revision content, permission-redacted history, ambiguous ordering,
unsupported history or inability to establish completeness is unavailable.
If a provider cannot supply the evidence, this route remains unqualified until
the trusted acquisition path can; no synthetic history or second journal fills it.

Dismissal or other withdrawal of R invalidates that signed delivery. Never
reactivate it based only on a later active-looking snapshot after a recorded
withdrawal; unavailable withdrawal history refuses. A deleted/missing R, failed
direct lookup, absent R in the complete inventory, or inconsistent identities
refuses. Do not use a cached body/signature to fill a missing original record.

If a producer copies C into new record R2, its signed selector still names R.
R2 cannot qualify, whether R is active, dismissed, edited, deleted or unavailable.
Changing the selector to R2 changes V and requires a new reviewer signature;
producer keys and posting-account permissions cannot authorize that change.
Dismissal followed by byte-identical republication therefore still refuses.
Do not fall back to R2 when R refuses. A new independent signature is a new
review authorization, never an automatic reinstatement of the old delivery.
This first-run contract refuses multiple authenticated original deliveries for
the same exact tuple, including a dismissed original alongside a new one; any
replacement procedure requires separate reviewed disposition.

Repeated identical pages for the same platform ID may be deduplicated only
after exact field equality; conflicting repeats are unavailable. Distinct review
IDs are distinct records even with identical bodies. Multiple copies of C or
multiple qualifying originals in current inventory refuse ambiguity; an unsigned
or invalid review never supplies a selector. Active CHANGES_REQUESTED anywhere
in the effective exact-PR inventory still blocks. No rule requires reconstructing
an unbounded global account history: inspect this PR's bounded inventory plus the
selected original's complete integrity/withdrawal history. Do not claim that
current inventory proves the absence of previously deleted records. Missing
history affecting that proof or selected-original integrity is unavailable.

## Constructor-bound route and producer gates

Route selection is trusted constructor configuration, outside Request, provider
payloads, policy-file inference and caller input. An unset/unknown route refuses
construction. The route and policy digest stay bound to the authority instance;
they cannot change between phases. Explicit route predicates replace both the
unconditional Matrix field validation in authority.go:validPolicy and the
unconditional Matrix-shaped producer predicate in Authority.qualify. Replacing
only lookupVerdict is insufficient. This is a required core change, not a claim
that the inspected base already accepts the new fields.

Common validation retains Product, Alias, canonical repository/name, DefaultBranch,
expected exact-byte Policy.SHA256, producer OwnerKeys and finite Profile limits.
Copy Scopes, ReviewerSenders, OwnerKeys and ReviewerKeys at construction. Clone
every PublicKey byte slice inside both key slices, as well as the outer slices;
caller mutation after New must not alter admitted keys or policy. On GitHub
require 1..4 ReviewerKeys; Matrix may retain an absent ReviewerKeys slice and
must validate any supplied pins with the same maximum of four. Validate each
pin's exact 51-byte Ed25519 encoding, recomputed fingerprint,
canonical repository, uniqueness and inequality with every producer public key.
Invalid role configuration refuses before source reads or effects.

For the explicitly selected GitHub-PR route require the accepted single scope,
canonical repository and DefaultBranch main, admitted producer and reviewer pins,
MatrixOrigin and ProducerSender empty, ReviewerSenders empty. These empty native
fields are intentional and cannot supply Matrix evidence. Reject contradictory
mixed-route configuration. Require trusted GitHub provenance instead of the
Matrix ProducerHandoff predicate, without fabricating Origin/Scope/Event/Sender:

- Authenticate actual repository identity and default branch/head from the
  configured provider; no alias, redirect or producer-supplied repository claim
  can substitute for the canonical repository.
- Authenticate the actual PR resource, positive N, base repository equal to the
  canonical repository, base ref main, exact head H and base commit B. Bind H to
  Request.Commit and the parsed Git object; B must match the current provider
  observation and signed verdict. Preserve the real head-repository provenance
  for fork PRs; do not relabel the head repository as the base repository or trust
  PR author/login as a producer key. Fork origin alone grants no trust.
- Verify the raw exact commit's Git SSHSIG under admitted repository-bound
  producer OwnerKeys, namespace git, and existing merged/nonrewriting landing
  ancestry to the actual default head. A producer signature alone is insufficient:
  actual PR repository/head/base/base-ref, merge state and landing must all pass.
- Obtain this evidence from the constructor-bound trusted source, with complete
  coverage, fresh observation and exact Query/phase/nonce/operation binding.
  A normalized caller claim or invented Matrix event is not a producer handoff.
  An open/draft PR never becomes a landed candidate by this mapping.

For the Matrix route retain all existing MatrixOrigin, ProducerSender,
ReviewerSenders, room Scopes, authenticated intact ProducerHandoff and
lookupVerdict window/frontier/uniqueness/independent-sender predicates. Unset
required Matrix fields still refuse at construction and phase verification.
GitHub empty-field rules, repository scope and reviewer signature lookup do not
relax or infer Matrix behavior. Any configured ReviewerKeys still receive the
common pin validation/copying; their presence cannot replace Matrix identity.

BeforeBuild and BeforeSign independently reread installed policy, repository,
actual PR tuple/provenance, original delivery R, complete effective review
inventory/history, required-check rules and check inventory. Preserve existing
clock/lease/effect freshness, producer signatures, nonce/operation binding and
nonrewriting landing gates. Changed route/policy/repository/PR/head/base/scope,
withdrawn review or unavailable provider state refuses before effects.
CheckFreshness remains the existing local clock/lease check, not a provider
reread or revocation check. Each effect must consume its own phase's current
qualification and pass that check; never substitute the build qualification for
the independent sign read. The trusted operation compares original R across
phases using the existing summary/bindings, without adding a caller selector,
new request format or persistent authority journal. A detected intervening
withdrawal refuses; this contract does not claim to observe changes after the
last provider frontier or eliminate the bounded observation lease.

## Finite bounds and implementation custody

Before allocation cap each COMMENT at 8192 decoded UTF-8 bytes, V at 2048,
armor at 2048, decoded SSHSIG at 512, public key at 51 and signature at 64.
Check each SSH length against remaining input. Parse no JSON inside V/armor and
never recurse. Scope is the fixed accepted ASCII string. The policy remains at
most 65536 bytes, CCJ-1 depth 16, commit bytes 1048576, ancestry 256, reviews 256
and check records 256. Review aggregate bytes stay at most 16 MiB.

Bound PR review inventory and selected-original history together: at most 256
normalized review/revision/withdrawal records in total, at most 16 MiB aggregate
raw body/history bytes, and at most 32 provider pages/requests including direct
identity and integrity reads per phase. Apply stricter existing adapter caps
where present; do not enlarge them. Overflow, absent pages/cursors, partial
coverage, redaction or unknown semantics is unavailable. A truncated response
is not an empty history. All reads, parsing and cryptography share the existing
30-second phase budget and maximum 300-second observation lease. A provider
cannot claim an atomic snapshot: cross-check selected identity/state within
each phase's read, and refuse detected races or expired observations before
effects. Local freshness does not establish a later provider frontier.

The existing sourceauthority Git framing primitives may be reused with explicit
role/domain selection; the inspected verifyOwner itself verifies only Git
commits. The core implementer owns constructor/producer gates, ReviewerKeys,
signed-original selection, history capability checks and paired implementation
tests. The sealed PR adapter and protected loader are separate components;
this revision changes neither and does not claim they supply new provenance or
history fields. If their interfaces omit required evidence, report the pairing
gap and refuse qualification until a separately reviewed compatible change.

The loader preserves the accepted nonrecursive digest mapping: omit SHA256 from
serialized bytes, hash the exact complete canonical file, compare with the
admission record's expected digest and populate native Policy.SHA256 from that
digest. Repeat at phase/effect reads. Preserve no-follow protected descriptor
reads, 0600 single-link ownership and directory custody. Mirror the reviewed
native ReviewerKeys/Scopes shape; no alternate JSON authority format.

The adjacent known-fields.ccj.json and public-bindings.ccj.json are unchanged
historical partial proposal artifacts. Their missing scope/ReviewerKeys or null
Scope reflect their original bytes, not a pending owner decision. Neither hash
is a complete or installable policy digest. Produce and admit complete exact
CCJ-1 bytes only against the freshly reviewed implemented native shape. No
installation precedes exact-byte acceptance and the new admission marker.

## Paired architectural controls required for fresh review

These are conditional acceptance criteria, not executed verifier tests or
manufactured signed positives. Each refusal needs its neighboring valid control
using an independently obtained reviewer signature and actual supported evidence.

| Valid control (all other gates satisfied) | Required refusal |
| --- | --- |
| Original preallocated R, reviewer-bound V, intact active submitted C | Dismiss R; same V/signature refuses |
| That original R before dismissal | Dismiss R, repost byte-identical C at R2; R2 refuses and R remains withdrawn |
| V naming actual R in R | Copy C to R2 while R is active; distinct-ID duplicate refuses; changing R to R2 invalidates signature |
| Complete selected-original integrity history | Edit, edit-and-restore, delete R, missing direct R, redacted/deleted revision, missing history or conflicting repeated ID refuses |
| One authenticated original for the exact tuple | Multiple authenticated originals or partial/overflow inventory/history refuses; no latest-active fallback |
| Pending allocation, independent read, signature, submit SAME R | Pending/placeholder body, producer-chosen unverified ID, changed tuple before submit, guessed replacement or circular future-ID signing refuses |
| Distinct admitted reviewer pin in swarma-source-review | Reviewer pin equal to any producer pin fails load; unsigned, producer-key, unpinned or git-namespace verdict refuses |
| Producer Git commit signed in git | Same commit signed in swarma-source-review refuses |
| Exact repository/main/PR/H/B and signed scope | Another repository/base branch/PR/head/base/scope or fabricated provenance refuses before effects |
| Explicit GitHub route with intentional empty Matrix fields | Unset/unknown route, caller route switch or mixed-route policy refuses |
| Existing valid Matrix policy/handoff/verdict path | Unset Matrix fields or substitution of GitHub signature evidence refuses |
| Constructor-owned immutable key copies | Mutate caller ReviewerKeys outer slice or nested PublicKey after New; admitted policy remains unchanged |
| Fresh policy/provenance/R/inventory/checks at both phases and local effect freshness | Detected withdrawal/change/unavailable state at a phase read, changed original R, or expiry at the effect boundary refuses |

This contract revision needs fresh independent exact-head review and a new
marker. It authorizes no actual platform review, reviewer signature generation, owner-key
use, new grant, installation, public publication, native execution or merge.
