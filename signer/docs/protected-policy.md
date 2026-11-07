# Protected local Policy snapshots

`internal/sourceauthority` provides `EncodePolicy`, `DecodePolicy` and a Linux
`ProtectedPolicySource`. This is the core's local configuration, with the
configuration fields of `Policy`, `OwnerKey` and `Profile`. It adds no wire record,
identity, grant, adoption object, provider authority or selected policy values.
An installation custodian must obtain acceptance of the exact bytes and their
full SHA-256 before installing anything. This source does not install a file.

The native field mapping is closed and case-sensitive:

| Native field | JSON representation |
| --- | --- |
| Product, Alias, CanonicalRepository, RepositoryName, DefaultBranch | Strings with those exact field names |
| MatrixOrigin, ProducerSender | Strings with those exact field names |
| ReviewerSenders, Scopes | Ordered arrays of strings |
| OwnerKeys | Ordered array of objects containing exactly Fingerprint, PublicKey, Repository |
| OwnerKeys[].PublicKey | Standard padded-base64 encoding of the existing binary SSH public-key bytes |
| Profile | Object containing exactly AncestryCommits, CheckRecords, CommitBytes, PlatformReviews, all integers |

`Policy.SHA256` is excluded from the payload. All eleven configuration fields
are present. There is no enclosing object or schema version. Unknown, omitted,
duplicated, incorrectly cased or wrongly typed fields at any depth refuse.
Noncanonical bytes refuse, including whitespace, alternate string escapes,
member order, BOM, invalid UTF-8, lone surrogates, floats, exponents and unsafe
integers. Strings are not normalized. Arrays preserve order. The exact canonical
file is nonempty, at most 65,536 bytes and has no trailing newline.

Serialization uses CCJ-1, reusing the registrar codec at public commit
`5f44ebf3f78829144aa7864ca2e4ad62bea43eb5` in `internal/policyccj`. Only its
package name and refusal plumbing are adapted. It sorts member names by Unicode
scalar value, uses minimal string escapes and shortest integer spelling. It
introduces no module dependency or dependency upgrade.

The installer computes SHA-256 over the exact complete installed bytes and
records it on the admission element. At launch the custodian supplies that
expected digest to `NewWithPolicySource(ctx, source, expectedSHA256, provider,
clock)` or the corresponding effect-runner constructor. A missing, malformed or
mismatched digest refuses before provider acquisition. The core never treats a
digest learned from the current file as admission. `DecodePolicy` derives the
in-memory `Policy.SHA256` from the complete bytes, so request, observation and
effect bindings use the same exact-byte digest as `PolicySnapshot.SHA256()`.
The payload never contains its own digest. Legacy `SHA256` fields, including
zero-valued or matching values, refuse as unknown fields. No self-hash,
placeholder, exclusion-at-hash-time or zeroing convention is used.

`EncodePolicy` and `DecodePolicy` select the existing Matrix configuration.
That route requires nonempty `MatrixOrigin`, `ProducerSender` and
`ReviewerSenders`; none is defaulted. `EncodePolicyForRoute` and
`DecodePolicyForRoute` require an explicit `PolicyRoute`. Only
`GitHubPRPolicyRoute` accepts the three fields set to `""`, `""`, and `[]`.
The fields remain mandatory in serialized bytes; omissions and null arrays
refuse. Mixed Matrix identities in a GitHub policy also refuse. Empty or unknown
route selectors refuse. Route selection is a trusted constructor choice outside
the payload and request, independent of reviewer-signature syntax.

`NewProtectedPolicySourceForRoute` fixes the explicit route with path and UID.
`NewProtectedPolicySource` selects the existing Matrix loader and cannot infer
GitHub from empty identities. The protected Authority/effect constructors in
this candidate implement the Matrix route only. A GitHub snapshot refuses with
`policy_route_unbound`, before any provider read. Its actual PR-source mapping,
reviewer public-pin field mapping, signature format/namespace and single lab
scope require the separately agreed contract and implementation; the codec does
not invent them or qualify GitHub evidence. No partial policy is installable.

The trusted custodian constructs `NewProtectedPolicySource(ctx, absolutePath,
expectedUID)` outside request handling. The file must be owned by exactly that
UID, single-link regular and exactly 0600. An ordinary installation UID is
supported; root ownership is not assumed. Every ancestor is opened with
directory descriptors and `O_NOFOLLOW`, must be a root- or custodian-owned
directory without group/other write access, and has its device/inode pinned.
The absolute path must already be clean. No path, URL, key, header or policy
override exists in the release request. A directory replacement requires
reconstruction, rather than silently following a new installation namespace.
These checks enforce UID-level custody; they do not isolate processes sharing
the same UID.

Each `Snapshot` independently opens the installed pathname, bounds size before
allocation, checks descriptor metadata before/after reading, then reopens and
compares a second complete read and metadata. It rechecks the pathname after
decoding. It refuses a racing replacement rather than retrying. The custodian
must install updates by writing a complete private file and atomically renaming
it inside the protected directory; in-place concurrent editing is unsupported.
Stable atomic updates are readable without restarting the loader. Snapshot
accessors return fresh owned copies of every byte and mutable native field.

Use `NewWithPolicySource` for the protected Authority route, or
`NewEffectRunnerWithPolicySource` for the existing effect composition. Construction
binds the admission-supplied exact-byte digest. BeforeBuild and BeforeSign
each reread installed policy before acquiring provider evidence and again before
issuing qualification, within the same phase context. A changed raw digest,
including a key removal, refuses the old
authority. Missing, malformed or unsafe current installation refuses as unknown.
An authorized reinstall therefore requires a newly constructed authority/runner.
No previous snapshot or successful build provides a fallback.

`CheckFreshnessContext` rereads installed policy and checks the lease before and
afterward; pass the original job context at effects. Its read cap is the minimum
of that context, remaining monotonic lease and the 30-second authority budget.
`CheckFreshness` provides the same installed check with no external job context;
it is unsuitable for replacing a caller's original job deadline. Neither method
refreshes provider evidence or replaces an independent BeforeSign. The legacy
`New` route remains an explicitly supplied in-memory Policy, for callers already
responsible for protected configuration custody and for synthetic controls.

Filesystem operations run synchronously, with cancellation checks around each
syscall, bounded read and decode. There is no background worker or retry loop.
Ordinary kernel filesystem calls cannot promise interruption while blocked in
uninterruptible I/O. Use a trusted local filesystem and an outer supervised
process for a hard wall-clock bound; a Go context alone does not provide that
containment. Verification is point-in-time, not a filesystem transaction locking
out future custodian decisions after the final check.

Controls use only declared public policy fixtures in private temporary trees:
regular/mode/ownership/size, symlink and hardlink refusals, directory substitution,
nonblocking FIFO refusal, cancellation, canonical field/byte neighbors, independent
phase reads, raced provider-read replacement, atomic replacement with no hybrid
snapshot and stale-lease refusal. Serialization controls pair an independently
computed exact-byte digest with missing/mismatched launch admission, embedded
legacy digest fields and changed in-memory identity values. Route controls pair
complete Matrix and explicit empty-field GitHub codec/snapshot cases with wrong,
unknown, partially unset, mixed, omitted and null neighbors and the unbound
GitHub authority refusal. They establish local source behavior only.
No actual installed policy, public owner pin, native provider, build, signing,
first-run execution or deployment is qualified by these tests. The final signed
candidate still requires independent exact-head review and its admission marker.
