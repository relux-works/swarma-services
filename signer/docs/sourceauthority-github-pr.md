# GitHub PR composition status

Status: **UNQUALIFIED**. The native policy codec and original-review signature
binding are composed with the protected loader, finite transport and audited
signer. There is no production history provider and no usable GitHub authority.

The acquisition component can decode current PR/review REST fields under finite
transport bounds. It now retains the actual head repository and base ref rather
than relabeling fork provenance. These current reads cannot establish complete
post-submission edits (including edit-and-restore), retained revision content,
withdrawal/dismissal history, deleted-original inventory or history completeness.
Its verdict reader is an unresolved component seam, not an implemented provider.
The sealed source constructor and Read entry point therefore explicitly refuse
with `github_original_history_unqualified` before provider operations.

The original review ID is authenticated in V and bound to the actual containing
record. Repository, PR, head, base and accepted scope are exact. Posting accounts
supply no reviewer authority; ReviewerKeys is distinct from producer OwnerKeys.
Current inventory binding refuses copies, conflicting repeated IDs, multiple
originals and active blocking reviews. These controls cannot prove past history.

Owner disposition needed: provide a separately reviewed trusted acquisition path
that honestly supports the complete original record edit/withdrawal/inventory
history under the corrected contract, or explicitly disposition the first run
as blocked. Ordinary REST current-body/state reads do not satisfy the contract.
A future pending-review mutation and reviewer signing require their own admission.
No policy install, first run, public publication or activation occurs here.

Fresh independent review of the whole composed head and a new admission marker
are required; component reviews and markers do not transfer. Exact policy bytes
and their external SHA256 require separate owner acceptance before installation.
