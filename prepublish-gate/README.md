# prepublish-gate

A Go tool qualified here only on Linux for checking a bounded Git candidate before an explicitly
requested publication. It scans added lines, complete commit messages, non-signature commit headers and changed
paths, verifies candidate SSH signatures with native Git/OpenSSH, and pushes exact
object IDs with explicit leases. `check` and `publish` responses are single JSON objects of
integer counts. The separate read-only `tails` command has structured inventory
JSON; see [TAILS.md](TAILS.md) for scope, incomplete coverage and offline PR
metadata. Patterns, matches, paths, messages and subprocess diagnostics never
appear in its output. No fetch, signing, review, approval or deployment is performed.

This subproject is a local candidate requiring independent exact-head review and
source-owner publication gates. A clean check or successful lease is not permission
to publish. The repository's signer/source-authority services remain independent;
this tool does not replace their review or authority contracts.

## Build and check

Use the existing Go 1.26.8 toolchain. There are no third-party modules or downloads.
The executable requires trusted `/usr/bin/git`, `/usr/bin/ssh-keygen`, and Linux.
GitHub publication additionally uses the existing `/usr/bin/gh` authorized client.

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build -o /private/bin/prepublish-gate ./cmd/prepublish-gate
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=1 go test -race -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
```

Run development checks offline in a network namespace with read-only source/tools,
a fresh private 0700 absolute HOME, TMPDIR and cache, and no host home, keys,
agent sockets, credentials or borrowed caches. OpenSSH fixture generation needs a
synthetic passwd/group entry for the invoking UID. All test signing keys are fresh,
task-local and removed with their temporary directories. Use an outer hard timeout.
The command itself is not an OS sandbox. The environment assertions are opt-in:
run `PREPUBLISH_VERIFY_SANDBOX=1 go test -run TestSandboxExcludesCredentialsAndSocket ./internal/gate`
inside that sandbox. Ordinary product tests do not claim to qualify their host.
Native macOS operation/isolation is unqualified; a successful portable test is not
Mac qualification.

Acquire public source separately with the normal public client. Supply an immutable
base commit and candidate commit as full lowercase SHA-1 IDs; branch names,
abbreviations, revision expressions and SHA-256 Git repositories are unsupported.
`--objects` points to the acquired repository's absolute Git object directory.
The worktree, index, refs and source repository configuration are never consulted.

```sh
prepublish-gate check \
  --objects /private/source/.git/objects --base BASE_OID --candidate CANDIDATE_OID \
  --patterns /private/controls/patterns --allowed-signers /private/controls/signers \
  --principal release@example.test
```

All flags follow `check` or `publish`; positional arguments, unknown flags and help
requests refuse. The command requires private 0700 absolute HOME and TMPDIR.
On macOS as well, use dedicated directories instead of the ordinary login HOME
or system temporary directory; do not change those host directories' permissions.
For example, create a task-owned working directory and run the built tool with:

```sh
(
umask 077
mkdir -m 700 ./gate-home ./gate-tmp
HOME="$PWD/gate-home"
TMPDIR="$PWD/gate-tmp"
TMPDIR=${TMPDIR%/}
HOME=${HOME%/}
export HOME TMPDIR
prepublish-gate check \
  --objects /private/source/.git/objects --base BASE_OID --candidate CANDIDATE_OID \
  --patterns /private/controls/patterns --allowed-signers /private/controls/signers \
  --principal release@example.test
)
```

macOS commonly supplies a trailing `/` in TMPDIR, which the clean-path admission
check refuses even when the directory is owned by the effective UID and is 0700.
After selecting a dedicated directory as above, or an existing directory explicitly
admitted against the same ownership, non-symlink and 0700 requirements, use
`TMPDIR=${TMPDIR%/}` before invoking the tool. HOME must likewise have no trailing
slash; use `HOME=${HOME%/}` if the selected HOME value has one. Export the adjusted
values, as in the example. Removing a trailing slash only adjusts path spelling:
it does not fix wrong permissions, ownership or symlinks. Do not chmod the host
HOME or system temporary directory to make admission pass.

Use clean absolute, non-symlink paths owned by the invoking effective UID. The
tool refuses unsafe existing directories without repairing them. The caller owns
these dedicated directories and their cleanup after the invocation; internal
snapshots are removed on return. TMPDIR must have space for the private object
copy and Git state. These environment overrides do not provide OS isolation or
qualify native macOS operation.
Pattern and control paths must be clean absolute paths to regular non-symlink
files. Every control is checked against the effective UID and must deny group/other
write; patterns additionally deny every group/other permission. Public signers and
exceptions permit 0600 or 0644, but never 0666. HOME, TMPDIR and the selected
client directory also require effective-UID ownership and mode 0700. Native stat
owner mapping is implemented for Linux, Darwin and the named BSD build targets;
other mappings refuse. Only Linux was exercised here. POSIX mode admission does
not establish ACL or ancestor safety. Controls and object storage must remain
trusted and quiescent; source-storage ownership is a caller precondition, not a
recursive owner/ACL audit.
Source objects are copied into a fresh 0700 private bare repository before checking.
Native `git fsck --strict` verifies the complete stored object pool and the base and
candidate closures. Corruption in unrelated stored objects may therefore refuse.
Before fsck, native object metadata must declare at most 65,536 stored objects
and 64 MiB total expanded object data. Every stored blob must fit 4 MiB;
commits, trees and tags must each fit 1 MiB, including unrelated/base objects.
Source alternates, symlinked object files, unknown object-storage extensions and
incomplete closures refuse. Loose SHA-1 objects and ordinary pack/idx/rev files are
supported. Known regular derived metadata (`info/commit-graph`, `info/packs`,
`pack/multi-pack-index`, `pack/multi-pack-index-<sha1>.bitmap`, and
`pack/pack-<sha1>.bitmap`/`.keep`) is skipped without reading/copying it; the private
repository uses its own object view. Links at those paths still refuse. Incremental
commit-graph directories and unknown metadata still refuse. Skipped regular files
count toward the 4096-file visit bound. A private snapshot is deleted after either
success or refusal.

## Scope and refusal policy

The candidate must be a nonempty linear chain of at most 64 single-parent commits
ending at the specified trusted base. All candidate commits are checked, including
intermediate changes later removed. The base and its history are trusted external
input: their signatures and unchanged contents are excluded. Merges, unrelated
histories and root candidates refuse. There is no implicit default branch or base;
a publication plan requires an explicit `--default-ref refs/heads/NAME`.

Each commit's complete UTF-8 message is one record. Each non-signature logical
header (including author, committer, tree, parent and extra headers) is a `header`
record; continuation lines stay in that record with their LF and leading space.
Only the exact `gpgsig` SSH armor block, with valid base64 continuation syntax
and an exact end marker, is excluded. Orphan continuations and malformed armor
refuse. Native verification still verifies the complete exact signed commit.
Each changed leaf path is one complete record, including embedded LF. Rename detection is disabled, so a rename
is a deletion plus addition and both names are checked. Added content is matched
one LF-delimited line at a time, without the diff `+` prefix or LF delimiter.
CR is retained in source records. A final line without LF is checked normally.
Context, removed lines and hunk headings are excluded from pattern counts. Native
Myers diff uses zero context; the parser checks both hunk lengths and refuses
malformed/truncated/binary output. Mode-only changes check paths with zero additions.

Both complete old and new changed blobs must be valid UTF-8 without NUL, and every
line must fit the record limit, even for deletions. No decoding or binary heuristic
is attempted. Symlinks, submodules and special modes refuse. Only regular-file
modes 100644 and 100755 are supported. This deliberately refuses a changed legacy
binary or invalid-text file instead of reporting a misleading zero.

Signature verification requires an explicit allowed-signers file and exact
principal. Its grammar is one or more LF-separated lines of exactly:

```text
release@example.test ssh-ed25519 BASE64_PUBLIC_KEY
```

One ASCII space separates each field; a final LF is optional. Every entry must use
the requested exact principal. Multiple keys for that principal are allowed.
Wildcards, principal lists, comments, options, certificates and other key algorithms
refuse. The principal is 1–128 ASCII letters/digits or `_.@+-`, starting with a
letter/digit. Native Git/OpenSSH decode keys and verify every candidate commit at
its exact OID, with the Git signature namespace. Only SSH signature headers are
admitted. This module implements no signature cryptography, key storage or signer.

## Private patterns and reviewed examples

The required private pattern file must grant no group/other permission (normally
0600 or 0400). Its finite grammar is 1–256 nonempty LF-separated UTF-8 records;
a final LF is optional. CR, NUL, blank lines, comments and whitespace trimming are
unsupported. Each record is at most 1024 bytes including the two-byte prefix:

- `L:` followed by a nonempty case-sensitive literal substring.
- `R:` followed by a nonempty Go RE2 expression, as accepted by `regexp.Compile`.

Regex matching uses Unicode code points and Go's locale-independent RE2 dialect,
including inline flags, character classes, anchors, alternation and bounded repeats.
Lookaround and backreferences are unsupported. A regex that matches empty text
refuses. Parsed repeat expansion and cumulative compiled instructions are bounded
at 16,384; exceeding either budget refuses before matching. Syntax/compile failures
never echo the expression. Patterns match each path, whole message or logical header, and each
added content line independently. Escaped LF can match LF in paths/messages, but
content patterns cannot span added lines. Matching is Boolean per record across
all private patterns; counts do not identify unique values or individual patterns.

Generic public conservative hygiene checks personal home paths, per-user runtime and temporary paths,
multicast-DNS hostnames ending in the local suffix,
dotted IPv4-like text, valid IPv6 addresses, Matrix-shaped identifiers,
event-shaped identifiers, and GitHub credential shapes. Installation-specific
agent names, host names, workbench names and task identifier formats have no
built-in fallback: the operator must supply them through the required private
pattern file. Such hits increment `private_hits`, never `hygiene_hits`. The
private file is operational input and must stay outside public source, history,
diffs, archives and review artifacts. No default inventory is embedded or loaded. IPv4 uses a
conservative dotted shape; complete colon-containing tokens must pass the standard
IP parser as IPv6. Non-hex language tokens such as `std::vector`, `String::from`,
`a::before` and `f :: Int` are neutral. Hex-only scoped names can parse as IPv6
and trigger hygiene checks even when intended as language identifiers. The lexically ambiguous bare `::` is treated
as the unspecified address only as a whole trimmed record or inside brackets;
inside a larger expression it is treated as an operator. This is an explicit
hygiene limitation, not a semantic language parser. Other valid address tokens,
including loopback, full addresses and scoped addresses, remain recognized.
More than 1024 IPv6-shaped candidates in one record refuses. This is a finite set of
rules, not a promise to identify every operational identifier or credential. The
local-suffix rule is deliberately conservative: ordinary language identifiers
such as the `Local` selector on `time`, or the `local()` selector on
`threading`, can trigger it. Environment filenames ending in that suffix can also trigger it.
These false positives are an explicit limitation; the matcher does not parse
language context. Per-user temporary forms include a username followed by a
numeric identifier and the numeric user-directory form under the temporary root.
The word-followed-by-digits rule is conservative: ordinary temporary names such
as `build-2024` also trigger it, including beneath `var/tmp` and in URL-shaped
text containing the same temporary path. Review such product examples through
the exact-record hygiene exceptions described below; no exception is automatic.
The module inspected the existing packet scanner's product guard conventions;
it imports no private pattern inventory and shares no internal code.

An optional `--exceptions FILE` admits explicitly reviewed product examples for
**hygiene only**. Each nonempty LF-separated record is exactly
`KIND<TAB>LOWERCASE_SHA256`, where KIND is `line`, `path`, `message` or `header`, and the
64 hex digits hash that complete record's UTF-8 bytes. The hash excludes the
content LF delimiter; a complete message includes its actual final LF. A logical
header includes its internal LF continuations but excludes its terminal LF. Limits are
256 records, 1024 bytes per record and 64 KiB per file. Duplicates, wildcard entries,
invalid kinds and invalid hashes refuse. An exception matches only that exact
record and kind; it never suppresses private-pattern hits. It is an explicit
review input, not evidence that review happened. Changing a byte requires another
reviewed exception. Unused entries do not grant broader exclusions.

## Explicit publication and leases

`check` performs no network access and no publication. A validated publication
plan may be supplied to `check` without contacting its destination. To mutate,
use the separate `publish` command **and** `--execute-publication`; all candidate
checks must complete with zero blocking hits first. Every invocation checks from
scratch; there is no reusable unchecked receipt or automatic retry.

```sh
prepublish-gate publish --execute-publication \
  --objects /private/source/.git/objects --base BASE_OID --candidate CANDIDATE_OID \
  --patterns /private/controls/patterns --allowed-signers /private/controls/signers \
  --principal release@example.test \
  --repository example/project --remote https://github.com/example/project.git \
  --gh-config-dir /private/authorized-client --default-ref refs/heads/main \
  --update refs/heads/candidate=EXPECTED_OLD_OID
```

Use the caller's existing authorized GitHub CLI configuration; this tool does not
log in, request OAuth scopes, inspect credential contents or introduce another
client. The explicitly selected configuration directory must be absolute, private
0700 and non-symlink. It is supplied only to the native Git push credential helper
`/usr/bin/gh auth git-credential`. The scan and public ref preflight receive no
authorization environment. Every Git subprocess uses the fresh private state
directory as HOME, including transport/helper descendants, so an operator HOME
`.netrc` is not exposed through HOME. Git config remains explicitly isolated; the
selected GH_CONFIG_DIR helper route is unchanged. No credential-content or network
authentication tests were performed. No credentials are supplied as CLI values.
Development and integration tests never mount a real authorized configuration or exercise a
GitHub publication. A future operational invocation requires separate permission
and an appropriately confined authorized-client environment.

Only an exact canonical `https://github.com/OWNER/REPOSITORY.git` URL matching
`--repository OWNER/REPOSITORY` is supported. No remote aliases, SSH transport,
userinfo, redirects, query strings, URL rewrites or source repository config are
used. Identity here is the explicitly supplied canonical GitHub repository path;
the tool does not query ownership or infer authority from it.

Supply 1–8 distinct `--update refs/heads/NAME=EXPECTED` entries. EXPECTED must be
exactly the trusted base OID or the literal `absent`; omission refuses. Restricting
existing refs to the checked base prevents unscanned replacement histories.
Destinations are branch refs only; tags, deletions, wildcards, options, unsafe ref
syntax and duplicate refs refuse. Every ref points to the same exact checked
candidate OID. The source branch may move without changing publication bytes.

The tool reads the explicit default ref and requested destination refs in the
same projected `ls-remote --refs` call. The default ref must exist and equal
`--base`; moved/absent default refs refuse with `lease_errors` before receive-pack
can transfer unscanned base history into an absent destination. Every target must
also match its expected value (including explicit absence). Checking the default
ref never adds it to the update plan; only an explicit `--update` updates a ref.
The caller must designate the actual remote default branch: the tool does not
resolve or verify a symbolic HEAD.

A remaining read-to-push race is unavoidable here: native Git push cannot
atomically assert a default ref that it does not update. If that ref changes
after preflight, an otherwise valid target push can still succeed. This gate
detects drift observed by preflight; it does not eliminate that race. To require
a stronger invariant, use a separately qualified receiver-side policy. Do not
add a default-branch update merely to assert it.

After preflight the tool runs exactly one native push.
Every ref has its own exact `--force-with-lease=REF:OLD` (empty OLD for absent),
and every source refspec is the full candidate OID. `--atomic` is required even
for a single ref. Stale/missing/colliding refs, unsupported atomic capability or
receiver rejection fail closed. There is no non-atomic fallback, wildcard refspec,
implicit force, fallback transport, second push or automatic rerun. A lease guards
concurrency; it grants no permission. Network loss after submission may leave an
uncertain result: inspect destination state through the authorized client before
any separately authorized attempt. A publication-error count does not assert that
the remote was unchanged. Even exit 0 must supply exactly one matching per-ref
porcelain status (`*` for creation or a space for a fast-forward), followed by
`Done`. Forced `+`, up-to-date `=`, rejected, duplicate, missing or malformed
records refuse; `published_refs` stays zero and the remote outcome is uncertain.

`--local-test-destination` replaces the canonical endpoint rule with an absolute
non-symlink task-owned bare repository and requires `--repository local-test`.
It forbids an authorized-client directory. This explicit mode exists for offline
integration fixtures; trust the receiver, its directory ancestry and its hooks.
It is not a GitHub publication or a portable remote identity mechanism.

## Counts, exits and limits

Output has integer fields only. `completed=1` means all candidate scan/signature
checks finished, even when hits block publication. `private_hits` and
`hygiene_hits` count matching records, once per category; `hygiene_exceptions`
counts admitted hygiene records. `commits`, `signatures`, `messages`, `headers`, `paths` and
`added_lines` describe the completed or partially processed scope. `published_refs`
is positive only after a successful push. `commands` and `command_bytes` account
for native invocations and captured stdout/stderr bytes; no child output is exposed.

Exit 0 means a completed clean check or a successful explicitly requested push.
Exit 1 means blocking hits or any scan, signature, lease, publication or cleanup
error. Exit 2 means an argument grammar, plan or opt-in error.
Each error category has a numeric field. Zero hits with `completed=0` is a scan
failure, never a clean result. Partial counts are diagnostic only and cannot
permit publication. An output-write failure returns nonzero, without a fallback
output channel. Unexpected internal panics produce only a fixed numeric refusal.

`home_admission_errors=1` or `tmpdir_admission_errors=1` identifies refusal of
the corresponding environment directory, without exposing its value or the
underlying OS diagnostic. Both are additive integer counters: existing
`scan_errors=1`, `completed=0` and exit 1 remain unchanged. HOME is checked first;
if it refuses, TMPDIR is not checked. A counter covers any directory admission
failure (including mode, ownership, symlink, missing or non-clean absolute path),
not only permissions. Other scan and signature failures leave these counters at
zero. No error details are written to stderr.

| Resource | Fixed maximum |
| --- | ---: |
| Each control file | 64 KiB |
| Patterns / example exceptions | 256 each |
| Pattern/control record | 1024 bytes |
| Regex expansion / compiled instructions | 16,384 cumulative |
| Candidate commits | 64 |
| Changed path records across commits | 1024 |
| Each changed path | 4096 bytes |
| Each complete commit / message / logical header / content line | 1 MiB |
| Each complete changed blob | 4 MiB |
| Copied compressed/loose object storage | 64 MiB / 4096 files |
| Declared expanded stored object pool | 64 MiB / 65,536 objects |
| Native commands | 4096 |
| Each command stdout and stderr | 16 MiB each |
| Cumulative command output, both streams | 64 MiB |
| Each native command | 10 seconds |
| Candidate checking and publication | 120 seconds |
| Process pipe cleanup grace | 1 second |
| Publication refs | 8 |

All bounds are cumulative independent ceilings, not a promise that all maxima can
be reached in one run. A changed path costs roughly five native invocations;
4096 commands can refuse near 800 paths before the 1024-path ceiling. Histories,
output size and time also consume budgets. There is no unlimited setting or
truncation-to-success. Native
process groups are killed on cancellation, including transport/helper descendants.
The deadline is checked between private regex evaluations; an individual match,
file copy or filesystem operation is not preempted by Go context. An outer hard
process timeout remains required. A push may be attempted only while budgets
remain; timeout never triggers another mutation.

Controls, trusted tools and object storage must remain quiescent. This tool does
not defend against hostile same-UID rewriting of private snapshots, inherited
mount changes or a malicious native tool installation. It creates no source
checkout and executes no candidate code, source hooks, attributes, filters,
submodules or source-defined diff programs. Receiver hooks in the explicit local
fixture mode belong to the trusted task-owned receiver. Credential validity,
private-pattern completeness, review acceptance, repository custody and operational
publication permission remain caller responsibilities.

Follow-ups for broader use are merge-aware histories with explicit parent policy,
additional Git object/signature formats, calibrated hygiene rules, and separately
qualified deployment of the existing authorized-client publication seam. Those
cases are unsupported or unqualified in this candidate rather than silently allowed.
