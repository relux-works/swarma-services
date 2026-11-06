# Supplied-module collision resources

The collision index in `internal/moduleinput` uses an operation-local segment
trie. Exact segment spellings and their NFD/simple-case-folded forms are interned
as integer IDs. Each edge stores its parent, folded segment, exact spelling and
file kind. It compares actual strings when interning; integer IDs are identities
within the call, not truncated hashes. Stored file paths are never normalized.

Slash is an NFD normalization boundary and is unchanged by simple case folding.
Folded segment chains therefore have the same equivalence as folding complete
ancestor paths. Different exact spellings under the same folded parent, duplicate
files and both file/directory conflict directions refuse. A refused checker is
permanently unusable; `Verify` aborts and discards it. The existing path, order,
mode, collision, layout and checksum check order remains unchanged. No partial
verified handle or caller mutation is permitted on refusal.

For summed path bytes B, component occurrences S, distinct edges E and unique
segments U, expected map work is O(B), including folding distinct segment bytes;
retained index space is O(E + U + B). E is at most S. Canonical paths have
nonempty components, so S is at most `8192 * ((1024+1)/2) = 4,194,304` under the
existing file/path bounds. The fixed pinned Unicode expansion factor is included
in these bounds. IDs fit in uint32. This replaces repeated normalization and
retention of full ancestor prefixes, whose total byte cost can grow with depth.
Go map/allocator overhead and randomized hash-map operation costs still apply.

These are algorithmic bounds, not a hard process memory or latency guarantee.
Snapshot payloads can reach 1 GiB before allocator overhead, source-sum parsing,
material checks and caller-requested accessor copies. This pure synchronous API
does not accept cancellation or enforce process CPU, RSS or wall-time limits.
Before native integration, the caller must qualify and enforce finite memory,
CPU, wall-time and concurrency budgets around admission, with genuine bounded
termination and cleanup. No success may be published from partial verification.
Whole-manifest accounting, native filesystem equivalence, graph completeness,
source authority, production builds, signing and audit qualification remain
separate gates. No native enforcement policy is installed by this package.

Tests compare bounded inputs with the frozen accepted collision algorithm and
verification loop, including exact refusal reasons and valid neighbors. Shared
deep and distinct deep full-module fixtures use independent standard-Go anchors.
Resource benchmarks generate and validate paths outside measurement, retain
fresh per-operation state, and report actual allocations and cardinalities.
The explicit 8192-path distinct benchmark represents 3,883,010 implied ancestors;
it deliberately ends in `Layout` because root go.mod is absent. It is not a
verified module receipt. Run it separately, one heavy fixture at a time, under
an external memory and time guard; benchmark timing is never an admission test.
