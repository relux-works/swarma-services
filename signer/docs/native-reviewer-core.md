# Native reviewer core composition

This source delta adds repository-bound `Policy.ReviewerKeys []OwnerKey` as a
separate public role. It supplies local verification helpers and preserves the
existing Matrix authority. It does not construct a GitHub acquisition adapter,
select a route, load an installed file, or claim production qualification.

`ValidateGitHubPolicy` requires 1..4 distinct valid SSH Ed25519 pins and the exact
repository `https://github.com/relux-works/swarma-keyvault`, repository name
`relux-works/swarma-keyvault`, default branch `main` and single scope
`github.com/relux-works/swarma-keyvault@main`. All three Matrix identity fields
must be empty on this route. Matrix `New` still refuses absent Matrix identity
fields and never infers a route. Existing Matrix policies may omit reviewer
pins; if present, they receive the same key-shape, repository, duplicate and
producer-separation checks at construction. Every reviewer public key must
be distinct from **every** configured producer/owner key, including producer
keys associated with a different repository. Pins are admitted only by trusted
native policy, never by a GitHub posting login or comment body.

`ValidateGitHubReviewBinding` consumes `GitHubReviewBinding{Repository,
BaseBranch, Head, Base, PR}` from the trusted adapter's current exact PR read.
Repository is the canonical HTTPS repository; BaseBranch is the actual provider
branch name, not the base object ID. Head and Base are lowercase 40-hex object
IDs; PR is positive and at most 2^63-1. Any other repository or base branch
refuses. No Matrix room identifier represents this GitHub scope.

`VerifyGitHubReview(policy, binding, exactCommentBytes)` returns a local
`ReviewerVerdict{Fingerprint, BodySHA256}` only after checking the exact signed
contract. It slices the verdict bytes from the supplied COMMENT without
normalization. It checks SHA256 of those exact bytes, canonical 70-column
OpenSSH armor, SSHSIG v1, exact namespace `swarma-source-review`, empty reserved
bytes, SHA-512, a pinned Ed25519 key, and the exact repository/PR/head/base/scope
preimage. It accepts no generic signature fallback. Commit verification retains
namespace `git` and its existing SHA-256/SHA-512 support. Neither namespace
qualifies in the other role. COMMENT, verdict, armor and binary limits are
8192, 2048, 2048 and 512 bytes respectively; SSH strings are bounded by the
remaining input before slicing. Commit armor/binary receive the same explicit
upper bounds. No external SSH process is used by the product verifier.

The root composition must call these checks on the explicitly selected GitHub
route **inside** the existing 30-second phase budget, after current bounded
inventory acquisition and unique effective review selection. Keep blocking
reviews, complete coverage, check policy, signed commit, exact merged PR and
nonrewriting landing predicates. BeforeBuild and BeforeSign each need their own
fresh complete read. A helper success alone cannot establish those predicates
or the existing 300-second maximum lease.

For the independently owned policy codec, add `ReviewerKeys` to the closed
native shape with the same public triple and standard padded base64 as
`OwnerKeys`. Validate it at load, normalize an omitted legacy Matrix reviewer
array consistently if retaining legacy compatibility, and defensively copy each
public byte slice. Preserve the codec's SHA256 `json:"-"` field, no-follow,
ownership, directory, race, expected-launch-digest and phase-refresh guards.
Do not replace the loader's authority implementation with this branch's base
version: merge the small common validator and defensive-copy changes. Invoke
`ValidateGitHubPolicy` once the exact-byte digest has been derived and compared;
before that, mirror its payload rules without adding any digest to payload
bytes. The externally expected launch digest remains unchanged in meaning.

A whole composed candidate requires fresh independent review and the required
source-owner marker before installation or use. This core head's authorship
signature is not that review. No provider account identity, actual review
comment, owner/release key, new wire format or grant/envelope is introduced.
