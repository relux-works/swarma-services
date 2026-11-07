# Protected local Policy snapshots

`internal/sourceauthority` provides `EncodePolicy`, `DecodePolicy` and a Linux
`ProtectedPolicySource`. This is the core's local configuration, with its exact
existing `Policy`, `OwnerKey` and `Profile` fields. It adds no wire record,
identity, grant, adoption object, provider authority or selected policy values.
An installation custodian must obtain acceptance of the exact bytes and their
full SHA-256 before installing anything. This source does not install a file.

The native field mapping is closed and case-sensitive:

| Native field | JSON representation |
| --- | --- |
| Product, Alias, CanonicalRepository, RepositoryName, DefaultBranch | Strings with those exact field names |
| SHA256, MatrixOrigin, ProducerSender | Strings with those exact field names |
| ReviewerSenders, Scopes | Ordered arrays of strings |
| OwnerKeys | Ordered array of objects containing exactly Fingerprint, PublicKey, Repository |
| OwnerKeys[].PublicKey | Standard padded-base64 encoding of the existing binary SSH public-key bytes |
| Profile | Object containing exactly AncestryCommits, CheckRecords, CommitBytes, PlatformReviews, all integers |

Every existing field is present. There is no enclosing object or schema version.
The core struct and its validity predicate are unchanged. Unknown, omitted,
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

`Policy.SHA256` is an existing core identity field. It is preserved verbatim.
It cannot equal the hash of the full bytes that include itself without solving
a self-reference. `PolicySnapshot.SHA256()` separately hashes the complete
installed bytes. The admission element must retain that full-file digest;
request/observation bindings retain the existing core identity. A composition
must preserve this distinction and must not omit, zero or overwrite the native
field to manufacture an undocumented hash recipe. If an existing admission
contract requires these two values to be equal, it needs an explicit disposition
before use; this loader does not silently change that contract.

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
binds both native identity and installed-byte digest. BeforeBuild and BeforeSign
each reread installed policy before acquiring provider evidence and again before
issuing qualification, within the same phase context. A changed raw digest,
including a key removal with an unchanged native identity, refuses the old
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
snapshot and stale-lease refusal. They establish local source behavior only.
No actual installed policy, public owner pin, native provider, build, signing,
first-run execution or deployment is qualified by these tests. The final signed
candidate still requires independent exact-head review and its admission marker.
