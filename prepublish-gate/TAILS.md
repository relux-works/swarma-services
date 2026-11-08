# Read-only tails inventory

`prepublish-gate tails` inventories **explicitly selected** local checkouts and
bounded work roots. It makes no network calls, has no GitHub authentication seam,
and cannot publish, close, merge, schedule, fetch, prune, garbage-collect or delete.
The existing `check` and `publish` commands retain their own separate contracts.
The tails implementation uses Unix APIs available on Linux and macOS and trusted
`/usr/bin/git`. Cross-compilation is distinct from qualification by native Mac use.

```sh
prepublish-gate tails --repo /private/work/project
prepublish-gate tails --root /private/work --repo /private/work/project \
  --pr-metadata /private/inputs/open-prs.json
```

`--scope-kind unknown|unit-scratch|product` adds classification metadata for the
entire selected repository scope. Omission produces `scope_kind="unknown"` and
`scope_kind_basis="default_unknown"`; each explicit value, including `unknown`,
produces `scope_kind_basis="declared_by_operator"`. Invalid, empty or repeated
values refuse with exit 2 before any inventory children run. These are additive
fields in the version 1 output schema; all existing inventory fields retain their
meaning. Programmatic `Scan` callers use `Options.ScopeKind`, with an empty value
meaning the same unknown default; invalid values return incomplete before children.

For example, use `tails --repo /private/work/unit --scope-kind unit-scratch` for
an operator-declared unit checkout. A single invocation may select multiple repos
or roots only under one common declaration. If roots contain different kinds,
use separate invocations; per-root declarations and repeated `--scope-kind` flags
are unsupported and refuse. The tool cannot detect a false operator declaration.
The declaration covers selected scope only, not the identity of unselected linked
worktrees or a count of products. A dirty checkout, branch or retained review
fixture is not a separate product. No kind is inferred from paths, names, remotes
or dirty counts; unknown never silently becomes product.

Classification is not proof that unique commits are published, reviewed or
rejected, that a result packet is exported/verified, or that any path is safe to
delete. Those require separate evidence and custodian disposition. This flag adds
no deletion, cleanup command, scheduler or publication authority.

Repeat `--repo` or `--root` to select more paths; positional arguments, unknown
flags and an empty selection refuse. Paths must be clean absolute paths with no
symlink in their ancestry. Broad filesystem roots, the process HOME and sensitive
credential/cache paths refuse. Root discovery inspects the root and
at most two directory levels, skips hidden and sensitive directories before opening
them, stops at checkouts, and reports depth/budget exclusions. It is not a host or
organization census. Prefer a short explicit `--repo` list for stable scopes.
Bare repositories and SHA-256 repositories are unsupported in this version.
A linked worktree's Git directory and common database must remain inside that
checkout or an explicitly supplied work root. An escaped database refuses.

The JSON contains local branches, registered worktrees (including detached HEADs),
stash reflog counts, tracked/untracked dirty state, and commit OIDs reachable from local
branches or registered worktree HEADs but absent from the **observed cached**
remote-ref ancestry. A missing cached remote ref set means all observed local
history is a candidate; it does not prove any commit is absent online. No remote
URL, commit/stash message, filename, branch name, child diagnostic or credential is
printed. Paths and refnames are SHA-256 identifiers over their exact bytes, without
a terminating LF; OIDs are full lowercase SHA-1. `selections` maps selection
indices to path hashes; `root_sha256` records the exact supplied root scope.
`selected_inputs` connects each common database to those indices. Operators can
hash their own path/ref strings to map an observation back to the selected source.

Deduplication uses the canonical admitted common-database path, then ref identity
or commit OID within that database. Worktrees registered by a selected database
are listed even when their checkout was not selected, with `selected=false` and
unknown dirty state. Their files are not inspected. Counts describe these Git
observations, not products or ownership. Copies of a repository with different
common databases remain separate observations. Unreachable objects and general
reflog-only commits are outside the ancestry scope; stash entries are counted
separately. Branches with the same OID remain distinct branches; absent commits
are deduplicated across branches and detached worktree heads.

`tracked_dirty` is a nullable Boolean: null means not inspected or unavailable,
false means the selected checkout had no tracked change at observation. `dirty`
combines tracked and untracked state, remaining null when exclusions prevent a
clean assertion. A known tracked/untracked change makes it true even when another
part of the scope is incomplete. `untracked_count` is a lower bound with partial
coverage, or an exact count within `complete_safe_scope`.

The tool walks only finite source filesystem metadata to assemble candidate paths;
it reads no untracked file contents. Git receives that finite list on stdin to
classify ignore rules, rather than crawling untracked directories itself. The
normal `check-ignore` exit 1 means no supplied candidate was ignored and is retained
in the child audit. Sensitive directories, nested checkouts and submodules are
skipped before opening them and cause explicit incomplete coverage. `.git` metadata
is excluded from untracked enumeration by definition. A clean assertion is limited
to the declared source/ignore scope, not the online repository. Dirty scans first
inspect bounded index path metadata and refuse sensitive tracked paths before Git
status can read their contents. The sensitive-name denylist is conservative, not a
classifier for every possible private filename. Select only trusted source
checkouts; this tool does not read credential files to classify them.

Every repository records coverage reasons, child failures (fixed stage/kind,
actual exit and elapsed milliseconds), a per-child timing/exit/byte audit, cached remote-ref count, and
`remote_freshness="unknown_cached_only"`. No fetch timestamp is treated as proof
of online freshness. Missing/corrupt objects, unavailable refs, shallow history,
bounds, unsupported storage/configuration and child timeouts remain incomplete.
Refs, worktree records, selected HEADs and tracked status are observed twice;
changes and existing Git lock files flag a race. This is best-effort race detection,
not a transactional snapshot: concurrent changes that return to the same observed
state may be missed. Keep inputs quiescent; a changing checkout cannot prove a
negative. Re-run only by a separate operator decision after resolving uncertainty.

## Offline open-PR metadata

`--pr-metadata` accepts an explicitly supplied projected open-PR snapshot. It does
not contact GitHub, discover repositories, infer an author/owner, or read any client
configuration. The strict input object is:

```json
{
  "observed_at": "2026-01-02T12:00:00Z",
  "repositories": ["example/project"],
  "pagination_complete": true,
  "open_prs": [
    {"repository": "example/project", "number": 42,
     "created_at": "2026-01-01T12:00:00Z"}
  ]
}
```

The example date must be replaced with the actual observation time. Snapshots
older than 24 hours, future observations/creation dates, out-of-scope repositories,
duplicate PRs/scopes, malformed names, credential-shaped values, extra fields and
trailing JSON refuse. At most 64 repositories and 4096 PRs are admitted. Age is
whole elapsed seconds at `observed_at`, with that timestamp and exact PR scope in
the report. Every row has `ownership="unknown"`. A complete flag is the supplied
producer's assertion, reported as
`supplied_metadata_declares_complete_at_observation`; the tool cannot verify the
API or pagination from offline metadata. False or missing pagination completion
is explicitly incomplete. Omitted metadata yields `pr_coverage="not_requested"`,
never a claim of zero online PRs. API acquisition and local Git coverage remain
separate scopes; no relation between repository names and checkout paths is inferred.

An authorized operator producing this file must use the existing authorized client
and project fields **at the command boundary**, before capturing stdout. For
example, for each explicitly selected repository use a bounded pull-list endpoint
with a projection equivalent to:

```sh
gh api repos/example/project/pulls --method GET \
  -f state=open -f per_page=100 -f page=1 \
  --jq '[.[] | {number: .number, created_at: .created_at}]'
```

The separate producer must complete all pages through a short final page (or mark
incomplete), bind each row to the requested repository, and stop at its own finite
page/time/byte limits. Never acquire raw repository JSON, PR titles/bodies/authors,
remote URLs or client credential contents for this tool. There is no implicit
organization crawl or alternate authentication route. API acquisition is outside
this subcommand and outside its offline tests.

## Safety and finite limits

Run with distinct task-owned, private 0700 absolute HOME and TMPDIR and a trusted
system Git. No inherited Git/client environment is forwarded. Git is invoked with
fixed argv, no shell, explicit worktree/Git directory, `GIT_OPTIONAL_LOCKS=0`, no
system/global config, no replacement objects, no lazy fetch, disabled fsmonitor,
hooks, untracked cache, external attributes/ignore files and external diff. No
index/config/ref/source write is requested. The local configuration parser has a
small allowlist and rejects includes, filters, command-valued hooks/fsmonitor,
credential configuration, custom worktree paths and unsupported extensions before
starting Git. Trusted installed tool binaries and quiescent source metadata remain
operator responsibilities. Symlinks and special files in consulted Git metadata
refuse; hooks directories are skipped and hooks are disabled. Alternates and grafts
refuse. Ref, reflog and linked-worktree registry names are validated as Git metadata,
so source exclusion words in those names do not exclude an otherwise supported
repository. Non-name metadata retains permissive admission for ordinary Git storage and
in-progress operations, subject to the same credential exclusions, traversal
bounds, configuration grammar and redirect refusals. Physical source paths
retain their exclusions. No other identity's credentials, caches or session records are inputs.

| Limit | Maximum |
| --- | ---: |
| Selected/discovered checkouts | 64 |
| Work-root discovery entries per root / untracked entries per checkout | 4096 each |
| Git metadata entries per database admission | 65,536 |
| Metadata traversal depth | 32 |
| Each metadata file / total metadata file sizes | 64 MiB / 256 MiB |
| Config, pointer or PR metadata file | 2 MiB |
| Ref/worktree/commit/stash/index-path rows | 4096 per inventory kind |
| Git children / total observed child output | 1024 / 16 MiB |
| Each child stdout and stderr | 2 MiB each |
| Each child / pipe drain grace | 3 seconds / 250 milliseconds |
| Whole command context | 90 seconds |

Directory names are read in finite batches; exclusions apply before opening a
skipped directory. Every child runs in its own process group, killed on timeout.
Bounds never become silent truncation-to-success. Blocked filesystem calls are not
preempted by Go contexts, so an outer hard process timeout is still required.
Exit 2 means invalid CLI grammar; exit 1 means incomplete scope, an operational
failure or output failure; exit 0 requires complete coverage within the declared
local and supplied-metadata scopes. Consumers must retain the JSON and inspect coverage;
nonzero is not permission to erase observations or declare zero tails.

For development, run tests/helpers offline in a clear-environment, unshare-all
sandbox with read-only tools/source and fresh task-owned HOME/TMP/cache. Fixtures
create only their own repositories/worktrees and synthetic files. No shared
checkout or real client configuration is needed. There are no third-party modules;
the parent's Go toolchain and dependency versions are unchanged.

An operator can consume this inventory every three days on approved Mac and Linux
work roots, compare the same explicit scopes, and assign each tail a separate
owner/date and land/close/hold decision. Preserve incomplete and stale observations;
changes in scope or caching prevent a simple before/after comparison. This is an
operator suggestion only: this change installs no scheduler, makes no dispositions
and grants no publication authority. Independent source review and the applicable
marker/custody gates remain required before operational adoption.
