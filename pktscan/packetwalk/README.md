# Bounded packet traversal component

This package is part of a **local composition candidate**. The CLI composes
it with the separate secret classifier; no installed scanner is changed. Final composition requires independent review of the
exact composed head and explicit Meta GO before installed use. Nothing here
claims that packet verification has been replaced.

`Walk(ctx, root, Options, Visitor)` traverses an operator-owned, quiescent
`*os.Root`, recursively replacing ZIP, tar and tar.gz/tgz containers with their
regular members. Names and ZIP/gzip/ustar/bundle magic select containers, even
when renamed. Nothing is extracted to the input root, executed, or checked out.
Only the optional Git quarantine writes files. Controls and caches belong outside
the packet root. There are no third-party modules or dependency changes.

## Integration contract

1. Resolve the packet root and controls using the existing scanner's exclusion
   and custody rules. This component has **no implicit control-file exclusions**.
   Give it an immutable packet-only root or add reviewed file-identity exclusions
   when composing it. It does not open paths for patterns or credentials.
2. Construct explicit positive `Limits`; `DefaultLimits()` is a starting point.
   Invalid, zero, negative, excessive or overflow-prone settings are refused.
   CLI flags and policy defaults are intentionally left to composition.
3. Supply a nonnil visitor which classifies **every byte and logical path** of
   each callback. The visitor must honor its context, avoid side effects and
   accumulate results privately. Visitor errors become a fixed `ErrVisit`.
4. Publish counts/results only when `Walk` returns nil error. Every error returns
   a zero report and invalidates **all** preceding callbacks. The component does
   not roll back a caller's own output. Do not emit partial success.
5. Binary leaves (NUL or invalid UTF-8) return `ErrBinary`. They never contribute
   a successful zero-hit source count. A later binary classifier needs its own
   explicit reviewed contract. Empty text files still get a callback; a verified
   empty archive has no leaf callback.
6. A regular archive leaf's path is `outer.zip/inner.tgz/path/to/file`. These
   paths preserve case, Unicode and LF. Git leaves use the separate namespace
   described below. The report measures traversal work, not the CLI's matching
   counts or a certificate that an arbitrary visitor actually checked contents.
7. Keep the entire invocation offline with read-only trusted source/tools,
   private absolute 0700 HOME/TMP/cache, no host home, keys, sockets or foreign
   cache. The library does not establish an OS sandbox. Its deadline covers
   parser read boundaries, loops and Git commands; trusted visitors/resolvers
   must cooperate with context cancellation. An outer process timeout provides
   a hard wall-clock termination bound.

Archive entries and input paths must be canonical relative UTF-8, at most 4096
bytes and 128 components: no empty/dot/dotdot component, backslash, colon, NUL
or leading slash. A final slash is permitted only for directory records.
Symlinks, hard links in archives, devices, FIFOs, duplicate records and
file/directory collisions are refused. Input hard-linked regular files are read
per path. Identity/mode/size/mtime are checked around regular file reads.
`os.Root` confines resolution, but neither it nor these checks defeat concurrent
same-UID changes, restored metadata, hard links or malicious mount changes.

ZIP CRC and claimed/actual sizes are checked. Local records must exactly cover
the data region; hidden records, SFX prefixes, gaps and overlaps are refused.
ZIP64, split archives, archive/entry comments, unsupported compression and
encryption are refused. Tar physical headers are checked before parsing, including
entry counting; PAX/GNU extension records, sparse files and base-256 sizes are
refused. This narrower, fail-closed tar subset is intentional. Gzip CRC/truncation,
single-stream framing and bounded zero tar padding are checked through EOF.
These refusals must remain visible during composition rather than becoming
ordinary files or success with zero counts.

## Limits and accounting

| Resource | Default | Hard configurable ceiling |
| --- | ---: | ---: |
| Container depth | 8 | 32 |
| Regular payload nodes (`Files`) | 4096 | 65536 |
| Entry records | 8192 | 131072 |
| Containers | 64 | 1024 |
| Git subprocesses | 256 | 65536 |
| Each file, object or captured command stdout | 16 MiB | 256 MiB |
| Container input bytes (`CompressedBytes`) | 64 MiB | 1 GiB |
| Materialized/reconstructed bytes (`ExpandedBytes`) | 128 MiB | 1 GiB |
| Inflated tar/pack streams (`StreamBytes`) | 128 MiB | 1 GiB |
| All Git stdout plus stderr | 64 MiB | 1 GiB |
| Invocation duration | 30 seconds | 5 minutes |

All limits are cumulative within one invocation, including sibling and nested
packets and the baseline bundle. Bytes are deliberately charged again at each
materialization layer, so deeply nested containers do not obtain fresh budgets.
`CompressedBytes` includes tar/bundle container bytes even when they are not
compressed. Expanded bytes charge top-level files, archive members, baseline
bundle bytes, pack-declared reconstructed bytes and visited object bytes.
Stream bytes charge full inflated tar streams (headers/padding included) and
pack representations. A blob nested packet also consumes ordinary container
budgets. Entries count filesystem records, archive physical records, bundle
header/pack records, delta objects and Git tree/path entries. Metadata callbacks
are bounded by entries, command output and bytes rather than `Files`.

The separate counters intentionally overlap; none is an estimate of original
source size. The peak memory is finite but not a small constant: nested input
buffers and an inflated tar stream may coexist. Operators should choose lower
limits and an OS memory limit where appropriate.

## Git bundles and delta scope (Linux)

Bundle scanning requires `BundleOptions{GitPath, TempDir, Resolve}`. `GitPath`
is an explicit absolute trusted tool path, never a packet-supplied executable.
`TempDir` must be an absolute, private 0700 directory inside the sandbox. Each
bundle gets a new private quarantine and a bare SHA-1 repository with its own
objects. The quarantine is removed on both success and refusal; cleanup failure
becomes a fixed `ErrCleanup` and requires operator attention.

The resolver must pin an actual 40-character lowercase commit OID `Current`.
An optional `Base` commit OID requires a standalone `BaseBundle` holding its
complete closure. The current bundle may be thin against that baseline. Missing
prerequisites, wrong types/OIDs, malformed bundles and objects outside the union
of Current/Base closures are refused. Inputs are bundle v2 with SHA-1 only;
bundle v3, SHA-256 object format and annotated tags are explicitly unsupported.
Pack checksums, physical object streams and delta source/target sizes are bounded
**before** native Git imports anything. Native Git verifies object identities,
delta instructions and connectivity. A checksum/OID is not owner authorization.

The classified content set is exactly `reachable(Current) - reachable(Base)`,
including intermediate commits, trees and blobs. Empty Base means the full
Current closure. This is actual object reachability, independent of filenames,
bundle size, textual patches or advertised ref labels. No ancestor relationship
is assumed. Base-only content is **excluded by explicit caller scope**, never
reported as scanned or known safe. Its physical pack inflation is still bounded.
The caller must retain the baseline's own trust/review evidence.

`GitImportedObjects`, `GitBaseObjects` and `GitDeltaObjects` report the actual
union, baseline closure and classified difference cardinalities per quarantine;
they do not claim globally deduplicated file counts. Synthesized tree/path text
also consumes the expanded-byte budget.

Callbacks include:

- `.bundle/header`: the current bundle's actual textual header;
- `.bundle/objects/<oid>`: raw commit/blob text, or decoded tree entries;
- `.bundle/paths/<commit-oid>`: full tree paths for Current and every new commit.

Each is prefixed by the bundle's logical path. Tree/path data uses records with
mode/type/OID and length-prefixed names so LF remains unambiguous. Both tree entry
names and full paths are validated; Git symlinks and gitlinks are refused,
including baseline-shared paths at Current. Blobs are scanned once per delta
object, not once per checkout path. Archive magic inside a blob recurses under
the same budgets. This intentionally scans complete new object contents,
including commit metadata; it is not the CLI's added-patch-line behavior. A
composed count schema must distinguish object/metadata leaves from source files
and scan full path metadata instead of treating OIDs as original source names.

Git runs without inherited environment or user/system configuration, templates,
replace refs, hooks, attributes/filter processing, submodule traversal, checkout
or network protocols. No shell is used. All arguments which name revisions are
validated OIDs, and packet ref strings are never arguments. Bare repository
configuration is created locally rather than copied from packet data. Every
command consumes an invocation-wide count/output/time budget; overflow or
deadline kills the process group. Stderr is charged and discarded, and all
outward errors are fixed strings. Offline OS isolation remains mandatory.

## Verification

The tests use only synthetic text, archives, Git objects and inert fixture
executables; no credential values or live providers are exercised. Run tests,
race tests, vet and build with a fresh private HOME/TMP/cache, read-only source
and tools, cleared environment and no network. Exact commands and actual
exit/timing evidence belong in the delivery packet. Independent composition
review and Meta GO remain outstanding by design.

## Composition hooks

`Options.Path` validates every input/member path, including directories and
containers without leaves. Its fourth argument is the walker-assigned `Origin`.
`File.Origin` identifies `PacketContent`, `GitBlobContent`, `GitMetadata` or
`ArchiveMetadata`; `GitSourcePath` marks Git source inventory callbacks only.
Archive recursion propagates the content origin, including Git blob provenance.
Logical path strings never confer an origin or change publication rules.
`Exclude` contains pinned control file identities;
excluded controls still consume entry/read budgets and require the nonnil
`ValidateControl` callback before omission from ERE leaves. No arbitrary
path-prefix exclusions are introduced. Callback errors remain fixed `ErrVisit`
and invalidate the report. Callers must retain their own fixed error class.

Archive textual metadata uses `ObjectType=archive-metadata`. ZIP extra fields,
gzip extra fields and nonzero tar member padding are refused by this composition.
ZIP members require exact Store/Deflate extent consumption and decoded CRC/size
agreement. Deflate reads from an `io.ByteReader` to avoid hidden read-ahead.
Only POSIX USTAR regular/directory headers are supported. Inapplicable linkname
and device fields, nonzero reserved padding, text after a NUL terminator and
nonportable numeric encodings refuse rather than being silently discarded.
Git paths are validated before object callbacks, and source suffix hints are
collected from all new commits plus Current before visiting sorted object IDs.
`File.FormatHint` is `json` or `stream` for strict document/refusal routing.
Archive suffix hints retain recognition even under object names. Conflicting
nonempty hints for one blob refuse. Noncontainer Git blobs have `ObjectType=blob`
and their actual ObjectID; recursively expanded blob members retain
`GitBlobContent` explicitly. No checkout-path-to-blob counting multiplicity is implied.
