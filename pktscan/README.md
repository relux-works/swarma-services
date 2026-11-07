# pktscan

`pktscan` classifies bounded packets without disclosing contents or matches.
A successful invocation emits one JSON count report. Any secret, incomplete
classification, malformed input, integrity error or exceeded bound emits only a
fixed diagnostic and exits 1; it emits no counts or partial extracted output.
Argument errors exit 2. `DIR` precedes flags; `--help` is an argument error.

This Linux composition is a **local candidate**. Fresh independent whole-head
review and the source owner's marker/checks are required before publication or
installed use. No acceptance, deployment or landing is implied.

Build with the unchanged Go 1.26.8 toolchain from this independent subproject:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build ./cmd/pktscan
./pktscan /absolute/packet --patterns /absolute/patterns.txt \
  --known-base /absolute/known-paths.nul
```

`--known-base` is optional. Set `TMPDIR` to an existing absolute private 0700
directory outside the packet. Run the command offline with read-only trusted
source/tools, private 0700 HOME/TMP/cache, no host home, keys, sockets or foreign
cache, and an outer hard process timeout. The command is not an OS sandbox.
No third-party modules, dependency/toolchain upgrades, providers or network are
required. Only bundle inspection additionally requires trusted native Git.

## Secret blocking and refusal

Every complete text leaf and every input/member path is classified before ERE
matching, known-base bucketing or patch-line filtering. Recognizable JSON is
parsed strictly regardless of filename; `.json` files, including scalar JSON
and Git blobs with that source suffix, always use strict document parsing.
`.jsonl` and `.ndjson` are unsupported and refuse. NUL, invalid UTF-8, BOM,
unpaired JSON surrogate escapes, incomplete/trailing/malformed JSON and exceeded
classifier bounds refuse. Errors invalidate every earlier callback and count.

The blocking classes are decoded ASCII case-insensitive exact JSON field names
`temp_clone_token`, `token` and `secret`, at any object depth, when populated;
and conservative GitHub token shapes in decoded JSON keys/strings or ordinary
text. Null, empty string/array/object are empty. Whitespace strings, numbers,
booleans and nonempty containers are populated. Duplicate keys are independently
classified. Classic prefixes gh[pousr]_ require at least 36 ASCII alphanumerics;
the fine-grained prefix github_pat_ requires at least 82 ASCII alphanumerics or
underscores. Longer/embedded shapes block; unprefixed hashes are not shapes.
These rules do not establish credential validity or live status.

Positive blocking counts refuse the entire invocation, including known-base
paths, removed/context/metadata patch lines, empty-container/directory paths,
Git headers/commits/trees/path metadata and archive textual metadata. No matched
value, parser offset, tool stderr or sensitive path appears in diagnostics.
In-packet pattern/known-base controls and their hard-link aliases are audited,
then excluded from ERE counts by identity. NUL-delimited known-base controls are
validated and classified one complete path at a time. External controls are not
packet members and are not exported or claimed safe.

The classifier bounds are 16 MiB per complete leaf, 1 MiB per decoded JSON
key/string or text line, 128 JSON containers and 65,536 JSON values. There is no
base64/URL/HTML/UTF-16 decoding, recursive parsing of JSON inside strings,
arbitrary embedded-JSON extraction from logs or patch reconstruction. Ordinary
text receives the token-shape policy, not a claim that every possible embedded
serialization has been decoded. Supply complete JSON metadata as `.json`, or
refuse unsupported representations before export. This is a packet policy
check, not a general credential-discovery or sanitization service. Sanitize
separate copies and seal their actual new bytes; an old seal cannot survive edits.

## Count report

The existing `new` and `known_base` buckets retain `files`, `hitfiles`, `hitlines`
and `pathhits`. `files` counts ordinary complete text leaves, including empty
files. Content hits count at most once per line across all EREs, and `hitfiles`
counts leaves with any content hit. `pathhits` counts at most once per complete
logical path. Containers/directories are not ordinary files. Names containing
LF remain complete paths. Archive members use `outer.zip/inner.tgz/member`.

`--known-base` is a NUL-terminated list of exact canonical logical paths. It is
case-sensitive, not a prefix/pattern exclusion. Listed paths are still scanned;
unseen names add no counts. Duplicate/empty/unsafe paths or a missing final NUL
refuse. Original hard-linked data files count per path. Unknown files, hidden
files and caller-created in-packet caches are candidates.

`git_objects` uses the same four count fields for full classified blob contents,
including recursively expanded blob packets. `metadata` uses those count fields
for Git headers/commits/trees/full paths and supported archive textual metadata.
These are separate from source-file buckets; no filename-to-blob multiplicity is
claimed. Git blobs are scanned in full even when their source name ends in
`.patch`; ordinary `.patch`/`.diff` leaves retain the added-line ERE behavior.
`blocking` contains `github_tokens` and `secret_fields`, always zero on success.
A refusal emits neither positive nor partial counts. Counts do not identify
unique secrets. `baseline_content_excluded` explicitly states whether external
Git baseline content was excluded by scope; excluded never means checked safe.

`traversal` reports cumulative `Files`, `Entries`, `Containers`, `Commands`,
`CompressedBytes`, `ExpandedBytes`, `StreamBytes`, `CommandBytes`, `Leaves`,
`GitImportedObjects`, `GitBaseObjects` and `GitDeltaObjects`. These measure work,
not original source size or ERE hits. Layers are deliberately charged again.
A successful zero blocking count applies only to the documented classified scope.

## Bounded ERE dialect and text behavior

Patterns are LF-separated UTF-8 EREs, compiled with Go's standard-library
`regexp.CompilePOSIX` and parsed first with `regexp/syntax` POSIX mode to bound
expansion. A final LF is optional; empty patterns, NUL and invalid UTF-8 are
refused. There are no comments or whitespace trimming: `#`, spaces and CR are
literal pattern text. Supported syntax includes literals, `.`, bracket classes,
ASCII POSIX classes such as `[[:alpha:]]`, grouping, alternation, `*`, `+`, `?`,
and bounded repeats. Go's POSIX parser limits repeat counts to 1000. Its accepted
character escapes (for example `\n`, `\t`, octal and hex) are included in this
dialect. Perl groups/flags, lookaround, backreferences, `\d`/`\w`, Unicode
property escapes, collating symbols and equivalence classes are unsupported and
refused without printing the pattern. This is Go's bounded ERE dialect, not a
promise of every libc ERE extension.

Matching is case-sensitive and locale-independent, over Unicode code points.
POSIX named classes use ASCII; ranges use code-point order (`[A-Z]` is ASCII),
not the host locale.
Go's POSIX mode uses leftmost-longest matching, although only a Boolean match
affects counts. `^` and `$` anchor lines, including embedded LF in a path;
`.` and negated bracket classes do not cross LF in this mode. A positive class
or explicit escaped LF may match LF in a path. Content is tested one LF-delimited
line at a time, so no pattern can span content lines. CR is retained. A leaf with NUL or invalid UTF-8 refuses the entire invocation. Binary leaves
never produce successful zero content counts. No bytes are silently decoded or
locale-folded.

Files ending in **case-sensitive** `.patch` or `.diff` are interpreted as unified
diffs. Only added content inside a valid `@@ -old[,count] +new[,count] @@` hunk
is tested, with the leading `+` removed. Metadata, `+++` file headers, hunk
headings, context, removed lines, and additions outside hunks do not count.
Hunk lengths are checked; malformed/truncated hunks and combined diffs are
refused. An actual added line beginning with `++` has a `+++` patch prefix
inside its hunk and **does** count. This distinguishes content from headers.
Patch headers use LF; CR in a hunk header is not normalized. Binary patches are refused; non-hunk metadata alone adds no content hits.

## Nested archives and extraction

ZIP, tar, tar.gz/tgz and bundle suffixes and recognizable magic select
containers, including renamed/nested containers and archives inside Git blobs.
The existing [packet walker](packetwalk/README.md) performs bounded recursive
traversal. ZIP CRC/framing, exact compressed-member consumption and gzip/tar
EOF/integrity are required. Deflate read-ahead cannot mask a trailing extent. Unsafe paths,
links, special types, collisions and unsupported representations refuse.
ZIP64/comments/encryption, ZIP extra fields (central and local), gzip extra
fields, non-POSIX-USTAR tar headers, PAX/GNU/sparse tar extensions and nonzero
tar member padding refuse. USTAR regular/directory headers require empty
linkname, zero device fields/reserved padding, portable nonnegative octal
numbers and zero padding after textual NUL terminators.
Gzip names/comments and tar user/group names are classified as textual metadata.
Unsupported metadata is never silently labeled clean.

The walker supplies explicit content/path origins. Ordinary paths containing
`.bundle/objects/` or `.bundle/source/` keep ordinary patch, known-base and
extraction rules. Actual Git blobs and their recursively expanded members use
full-object matching; Git source-path inventory callbacks are not extracted.

All leaf checks finish before extracted output is published beneath the
exclusively created `DIR/.pktscan-unpacked/files/`. Only complete regular member
leaves and explicit member directories are staged in an external private tree.
No packet bytes are executed or checked out. Members cannot clobber source or
controls. The original containers remain unchanged. Existing reserved output of
any type refuses, even on a repeated invocation. On refusal, private staging and
any exclusively owned partial output are removed; cleanup failure is a fixed
output refusal. Preexisting output is never removed. Extracted files are 0600,
directories 0700; ownership/executable/archive metadata is not installed.

`os.Root`, input identity/mode/size/mtime checks and canonical paths constrain
resolution. The packet must be operator-owned and quiescent. This does not defend
against malicious same-UID rewrites, restored metadata, existing hard links or
mount changes. Keep controls/caches outside the packet where practical.

## Git bundle full and delta scope

Pin exactly one logical bundle path and an actual lowercase SHA-1 commit OID:

```sh
./pktscan /absolute/packet --patterns /absolute/patterns.txt \
  --bundle-path source.zip/change.bundle --current COMMIT_OID \
  --base BASE_COMMIT_OID --base-bundle /absolute/trusted-base.bundle \
  --git /usr/bin/git
```

Omit both `--base` and `--base-bundle` for full Current closure. The baseline must
be a standalone complete closure outside the packet, including no in-packet
hard-link alias. It is external trust evidence: retain its separate review/seal.
The selected bundle must actually be encountered exactly once. Missing policy,
unexpected bundle paths, wrong OIDs/types/prerequisites, extra packed objects and
unsupported formats refuse. Bundle v2 SHA-1 commit closures only are supported;
v3/SHA-256/annotated tags are unsupported. No ancestor relationship is assumed.

The content scope is exactly reachable(Current) minus reachable(Base), including
intermediate new commits, trees and blobs. Full paths at Current and each new
commit are classified, including baseline-shared paths. Source suffix hints from
all those trees preserve strict JSON/stream/archive handling for blob object
names. Conflicting hints for one object refuse conservatively. Objects are
visited in sorted OID order. Baseline-only content is excluded, never declared
secret-free; its bytes and inflation still consume invocation budgets.

Git uses fresh private bare repositories and its own object storage. Pack/delta
sizes are bounded before import. No checkout, shell, inherited configuration,
network protocol, hooks, replace refs, filters or submodules are used. Native
Git verifies identities/connectivity. Tool output/stderr and subprocess counts
consume shared bounds; tool errors are fixed diagnostics. Quarantines are
removed after success/refusal. See the walker contract for exact accounting.

## Finite limits

Every walker flag is positive with a finite hard ceiling; zero/negative/excessive
values refuse. Budgets are cumulative across siblings, nesting, Git objects and
baseline materialization. No container gets a fresh allowance.

| CLI flag | Default | Hard ceiling |
| --- | ---: | ---: |
| `--max-depth` | 8 | 32 |
| `--max-files` | 4096 | 65536 |
| `--max-entries` | 8192 | 131072 |
| `--max-containers` | 64 | 1024 |
| `--max-commands` | 256 | 65536 |
| `--max-file-bytes` | 16 MiB | 16 MiB (classifier ceiling) |
| `--max-compressed-bytes` | 64 MiB | 1 GiB |
| `--max-expanded-bytes` | 128 MiB | 1 GiB |
| `--max-stream-bytes` | 128 MiB | 1 GiB |
| `--max-command-bytes` | 64 MiB | 1 GiB |
| `--timeout` | 30s | 5m |

Existing independent CLI bounds remain: 4096 filesystem inventory entries,
32 suffix-selected top-level archives, 16 MiB per input, 64 MiB total ordinary
leaf bytes, 1 MiB per text line/control file, 4096-byte/128-component canonical
paths, 256 patterns of at most 4096 bytes, 65,536 estimated regexp nodes and
4096 known-base paths. Controls consume walker entry/materialization budgets
but are excluded from ordinary ERE leaf counts. Git metadata/object stdout and
reconstructed bytes consume the walker budgets described in its contract.
Nested buffers can coexist; finite does not mean constant or small memory.

The walker timeout covers its parser/read boundaries, Git and cooperative
callbacks. Preflight/control reads and final bounded filesystem publication
also require an outer hard process timeout. The library cannot cancel a stuck
filesystem syscall or an uncooperative caller. Use an OS memory/process limit
where required by the operator environment.

## Verification

All fixtures are inert synthetic data. Run checks offline with read-only
source/tools and fresh private HOME/TMP/cache, without host homes/keys/sockets:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
```

Composition controls cover nested archives with empty/populated/malformed JSON,
known-base/patch/control/path blocking, full/delta Git closures and suffix hints,
metadata/binary/unsupported-format refusals, deterministic cumulative caps,
transactional extraction and sandbox isolation. Delivery evidence binds the
exact candidate head/tree and preserves actual failures, times and exits.
Independent whole-composition review and source-owner marker/checks remain
required before publication; no landing or installed qualification is claimed.
