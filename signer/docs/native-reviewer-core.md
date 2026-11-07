# Native reviewer pins and original-record binding

The native Policy has optional `ReviewerKeys []OwnerKey`. Each pin uses the
existing Repository/Fingerprint/PublicKey triple. GitHub requires 1..4 distinct
Ed25519 SSH public pins bound to the canonical repository. Every reviewer pin
must differ from every producer pin, including pins with another repository
label. Constructors copy the slices and each public-key byte array. Existing
Matrix policies omit ReviewerKeys when absent and retain their sender gates.

The explicit GitHub configuration has exactly the scope
`github.com/relux-works/swarma-keyvault@main`. MatrixOrigin and ProducerSender
are empty strings and ReviewerSenders is an empty array. These values do not
select a route. `NewForRoute` selects a trusted constructor route, unknown routes
refuse, and `New` continues to require complete Matrix configuration.

The signed V and COMMENT C are exactly the five-line original-delivery contract
in `first-run-policy-signature-contract.md`. SSHSIG uses
`swarma-source-review`, sha512 and the distinct reviewer pins. Git commits still
use namespace `git` and producer OwnerKeys. Original review ID is a positive
canonical decimal int63, inside the signed preimage and checked against the
actual containing PlatformReview record. Copying C to another review cannot
change its signed original ID. The old four-line tuple-only verdict refuses.

`VerifyGitHubReview` proves bounded syntax, signature and signed tuple/selector.
`VerifyGitHubReviewRecord` additionally binds actual record identity, tuple,
COMMENT state and submission presence. `BindGitHubReviewInventory` establishes
only a bounded current-inventory binding, ignoring a supplied SelectedID. It
refuses conflicting repeats, distinct copies, multiple signed originals,
withdrawn originals and active blocking reviews. These primitives never establish
history, platform acquisition, provider completeness or release authority.

The sealed REST adapter has no complete original edit/revision, withdrawal or
deleted-inventory history capability. Repeated current snapshots, current body,
state, login and `intact` flags cannot supply it. Both GitHub authority and source
constructors return `github_original_history_unqualified`; Source.Read also
refuses before any provider callback. No enabling flag, synthetic history,
provider interface, alternate journal or reviewer signature is supplied here.
Consequently there is no successful GitHub BeforeBuild/BeforeSign path in this
candidate. A future provider implementation needs a separate reviewed change.

The policy codec serializes actual native fields in CCJ-1. Runtime SHA256 is the
hash of the complete exact canonical file and is excluded from its payload.
The expected digest comes from trusted external admission. The protected loader
retains no-follow descriptor custody, exact 0600/single-link/UID checks and fresh
reads at phases/effects. Encoding a complete policy does not install or admit it.

Finite bounds: COMMENT 8192 bytes; V 2048; armor 2048; decoded SSHSIG 512;
reviewer pins 4; current inventory 256 records and 16 MiB aggregate bodies;
canonical configuration 65536 bytes and CCJ-1 depth 16. GitHub profile caps are
1 MiB commit and 256 ancestry/review/check records. Existing transport limits,
30-second phases, 300-second leases and audit entry checks remain unchanged.
