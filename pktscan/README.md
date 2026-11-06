# pktscan

`pktscan` extracts a bounded packet and reports **counts only**. It never executes
packet contents. Success writes one JSON object to stdout; failures write a fixed
diagnostic to stderr and no counts. Neither channel includes input names, pattern
text, matched values, regexp diagnostics, or archive diagnostics.

From this `pktscan/` subproject, build with Go **1.26.8** (Linux is the supported
and tested platform):

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build ./cmd/pktscan
./pktscan /absolute/packet --patterns /absolute/patterns.txt \
  --known-base /absolute/known-paths.nul
```

`DIR` must precede the flags. `--known-base` is optional. This module has no
third-party dependencies and requires no network, external scanner, shell, cache,
or provider at runtime. There is no automatic dependency or toolchain upgrade.
Exit status is 0 on success, 2 for argument errors, and 1 for refused input or
operation failures. `--help` is an argument error; usage is documented here.

Example output (illustrative counts):

```json
{"new":{"files":3,"hitfiles":1,"hitlines":2,"pathhits":1},"known_base":{"files":1,"hitfiles":1,"hitlines":1,"pathhits":0}}
```

## Count contract

Each accepted regular file has a logical relative path with `/` separators.
An ordinary file's logical path is its path relative to `DIR`. An extracted
member's logical path is `<archive-relative-path>/<member-path>`, for example
`pack.zip/notes.txt`. Output-directory prefixes are **not** part of logical paths.

* `files`: regular files in that bucket, including empty and binary files.
* `hitfiles`: files with at least one matching content line. A path-only hit does
  not make a content hit file.
* `hitlines`: matching content lines, at most once per line across all patterns
  and all occurrences. A final line without LF counts; a trailing LF does not
  create an extra line. Empty files have zero lines; blank lines in nonempty
  files can match a pattern such as `^$`.
* `pathhits`: files whose entire logical path is tested against the patterns,
  at most once per file. Directory paths and archive-container paths are not
  separate candidates. Embedded newlines remain part of a path.

`new` and `known_base` partition the files; add corresponding counts for totals.
The known-base file is a **NUL-terminated list** of exact logical paths, not
patterns, basenames, prefixes, or directory exclusions. Unlisted paths are new;
listed paths are still scanned and their hits are reported separately. An empty
list is valid. Unseen listed paths add no counts. Duplicate entries, empty
entries, noncanonical or unsupported paths, and a missing final NUL are refused.
NUL separation permits filenames containing LF. Matching is case-sensitive and
does not normalize Unicode.

The pattern file and known-base file, including hard-link aliases inside `DIR`,
are excluded by file identity. Archive containers are replaced by their regular
members in counts, not scanned again as raw bytes. Different member paths count
as different files even if their bytes are equal; duplicate output file paths
are refused. Original hard-linked data files count once per input path. All
other regular input files, including hidden files and any caller-created cache,
are candidates. The program creates no cache. Keep unrelated files outside
`DIR`. Inventory precedes extraction, so staging/output files are never rescanned.

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
line at a time, so no pattern can span content lines. CR is retained. A file with
any NUL or invalid UTF-8 is binary: it contributes `files` and possibly
`pathhits`, but no content hits. No bytes are silently decoded or locale-folded.

Files ending in **case-sensitive** `.patch` or `.diff` are interpreted as unified
diffs. Only added content inside a valid `@@ -old[,count] +new[,count] @@` hunk
is tested, with the leading `+` removed. Metadata, `+++` file headers, hunk
headings, context, removed lines, and additions outside hunks do not count.
Hunk lengths are checked; malformed/truncated hunks and combined diffs are
refused. An actual added line beginning with `++` has a `+++` patch prefix
inside its hunk and **does** count. This distinguishes content from headers.
Patch headers use LF; CR in a hunk header is not normalized. Binary patches use
the binary-file rule above; non-hunk metadata alone adds no content hits.

## Extraction and limits

Supported top-level archive suffixes are `.zip`, `.tar`, `.tar.gz`, and `.tgz`,
case-insensitively. Other suffixes are ordinary files. Extraction happens under
`DIR/.pktscan-unpacked`, created exclusively with mode 0700. Members are staged
in `stage`, then published as `files` after the complete scan succeeds:

```text
DIR/.pktscan-unpacked/files/pack.zip/notes.txt
```

The original archive and other source files are retained. No existing file is
overwritten. Existing `.pktscan-unpacked` of any type makes the whole operation
fail, including a subsequent invocation: explicitly move/remove that output
yourself before rescanning the original packet. Each archive has its own
namespace, so members named like input files or the pattern file cannot clobber
them. Members are never recursively expanded. Recognizable nested archive
suffixes and ZIP/gzip/ustar magic are refused; unrecognized nested bytes are
ordinary bounded content, never another extraction pass.

Only regular files and directories are accepted, both in the input inventory and
in archives. Archive symlinks, hard links, devices, FIFOs and other special types
are refused. Input symlinks are refused, including links to targets inside `DIR`.
Paths must be canonical relative UTF-8 paths: no absolute names, empty/`.`/`..`
components, backslashes, colons, NUL, or more than 128 components. A single final
slash is allowed only for archive directory records. Newlines are permitted.
Files get 0600 and directories 0700; executable, ownership, timestamp and special
permission metadata from an archive is not installed. Original modes, sizes and
mtimes are not changed (reading can update access times).

Fixed limits (MiB means 1,048,576 bytes):

| Resource | Limit |
| --- | ---: |
| Input inventory entries, including controls/directories | 4096 |
| Top-level archives | 32 |
| Archive member records, across all archives | 4096 |
| Each input file/archive or extracted regular file | 16 MiB |
| Scanned regular-file contents, across both buckets | 64 MiB |
| Extracted regular-file bytes, across all archives | 64 MiB |
| Inflated tar streams including metadata/padding, across tar archives | 64 MiB |
| Trailing tar padding | 1 MiB, zero bytes only |
| Text line, excluding LF | 1 MiB |
| Logical/input path | 4096 bytes |
| Each control file | 1 MiB |
| Patterns / each pattern | 256 / 4096 bytes |
| Estimated expanded regexp nodes, all patterns | 65,536 |
| Known-base list entries | 4096 |

ZIP claimed sizes are checked before decompression; actual bytes and CRC are
checked while reading. Tar parsing, metadata and gzip inflation are bounded
before parsing. Gzip CRC/truncation is checked through the end; nonzero trailing
payload is refused. Absolute limits bound compressed bombs without depending on
a compression ratio. Failures remove only the exclusively created output tree;
if cleanup itself fails a fixed output error is reported and the operator must
inspect that reserved tree. No partial counts are emitted.

All data traversal and output operations beneath `DIR` use `os.Root`. Inventory
rejects links/special files, and file identity, size, mode and mtime are checked
around reads. Exclusive file creation prevents archive collisions. This tool
expects an operator-owned, quiescent directory on a local filesystem. `os.Root`
confines path resolution; this is **not** a proof against a malicious process
with the same UID rewriting files, moving directories, changing mounts, or
restoring metadata during a scan. It does not sandbox the operator's environment
or defeat hard links already supplied as input. Run it offline with only the
intended packet/control files accessible when handling sensitive material.

## Verification and landing

All development fixtures are synthetic. Ordinary tests, race tests, vet and a
build should run with a fresh private HOME/TMP/cache, read-only source/tools and
no network. The task delivery includes the exact sandbox command and actual
checks. No real pattern file, credentials or provider are needed or exercised.

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
```

This initial implementation is a PR candidate. Product landing requires a fresh,
independent Codex review bound to the exact head/tree, source-owner marker/check
gates, and a signed landing by the authorized source owner. This subproject
transfers the sealed candidate from the superseded private `meta-tools` PR;
that repository's bootstrap main remains empty. No landing is claimed here.
