# Strict native journal profile and sitting check

`internal/nativedurability` implements the existing `signingaudit.Durability`
interface. `cmd/durability-check` is a real source runner for a controlled native
fixture, with synthetic trust/sign/release callbacks. Neither is a service
controller, native signer, production admission, or storage qualification.

## Selected operations and refusal contract

The explicit profile name is `darwin-apfs-fullfsync-strict-v1`. There is no
default profile or weaker fallback. `LocalFSync` retains its fixture-only name.

`New(openDirectory, expectedDevice)` requires an existing effective-UID-owned
0700 directory and a nonzero explicitly configured device number. The native
implementation reads `fstat` and `fstatfs` through the pinned descriptor. It
requires local, writable APFS and binds the actual device number and filesystem
ID. Each subsequent operation rechecks the descriptor's type and volume binding.
Remote/read-only/other filesystems, wrong devices, changed filesystem IDs,
inspection failures and invalid descriptors refuse before the flush call.
An APFS name match does **not** establish API support or admit that volume.

For both regular-file `File` and directory `Directory`, the Darwin+cgo bridge
calls the SDK's libc `fcntl(fd, F_FULLFSYNC, 0)`. It uses SDK header symbols,
not a hard-coded syscall number. This requests data/metadata synchronization and
a device-cache flush, including for new journal/seal directory entries. Every
error, including `EINVAL`, `ENOTSUP`, `ENOTTY`, `EIO` or `EINTR`, propagates. There
is no retry, fsync-only substitution, directory omission, global sync, or
`F_BARRIERFSYNC` downgrade. If the directory call is unsupported, this profile
cannot be used on that volume. Non-Darwin or non-cgo builds return
`native_durability_unavailable`; they never acquire a native implementation.

The journal still flushes creation file then directory, reestablishes both on
open/replay, and flushes every append before advancing trusted state. Intent
precedes signer entry; outcome precedes release eligibility. Failed appends
poison the writer. Flush/write and cleanup causes now remain reachable through
`errors.Is`/`errors.As` alongside `ErrAudit`; callers must not compare error
values directly. Torn tails remain sealed and held, and history is never pruned.

## Official contract and limits

Apple's [fsync manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
distinguishes host-to-drive synchronization from persistence in device media.
The [fcntl manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
describes the additional drive-flush request and warns about devices that ignore
it. Its historical filesystem list does not qualify modern APFS or directory
descriptors. Apple's published
[XNU dispatch](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L3860-L3893)
passes the request to the filesystem vnode operation and returns its error;
that is not proof of APFS's implementation or a particular device's behavior.

Consequently this source selects **strict attempted API completion** and hard
refusal. It does not assert that directory full-sync is supported on the intended
volume. Successful calls do not prove survival of arbitrary power loss, lying
storage/firmware, filesystem bugs, rollback, or a hostile writer. A silent no-op
that dishonestly returns success inside a trusted profile cannot be detected by
the `Durability` interface. The omission controls below return explicit errors;
they do not pretend to detect dishonest hardware or an opaque no-op shim.

An installed protected ancestor chain, same-UID/root exclusion, storage budgets,
independently retained checkpoint custody and real native effect adapters remain
external requirements. Device numbers are per-host observations, not durable
volume identities across reboot. The initial pin must come from protected
configuration in the sitting, not from an untrusted request. There is no new
per-release owner confirmation or automatic checkpoint/pruning policy.

## Source runner

Build entrypoint: `./cmd/durability-check` within the `signer` module. A future
native build requires an independently reviewed exact source tree, pinned Go,
Darwin/arm64, cgo enabled, and actual Apple SDK/Clang/linker/libSystem inputs.
The bridge requires `<fcntl.h>`, `<errno.h>` and `<sys/mount.h>` with
`F_FULLFSYNC`, `MNT_LOCAL`, `MNT_RDONLY`, plus the Go Darwin `Stat_t`/`Statfs_t`
fields used in source. Missing symbols fail the build. No SDK bytes, native
binary, exact deployment target, actual volume pin or absolute executable/root
paths are supplied by this source change.

After those inputs exist, the literal argument structure is:

```text
<reviewed-absolute-binary> -root <approved-existing-absolute-fixture-root> -device <actual-st_dev-decimal> -control suite
```

These placeholders are deliberately not runnable host paths. The execution
receipt must replace **all** of them, bind exact binary/source/SDK hashes, and
retain stdout, stderr, start/end times and exit status before any native claim.
The source runner is only for the already planned owner sitting. It performs
real writes and cache-flush requests there; it is not to be run speculatively on
other native volumes or against an installed journal.

`suite` performs a baseline and the following fixed controls, each in a newly
created private child directory. One named control can also be explicitly
selected. Fixtures and journals are retained after success and failure; cleanup
closes descriptors and writer locks only.

| Control | Required observation |
| --- | --- |
| `baseline` | Exact creation/replay/acceptance/intent/outcome flush order, one synthetic sign and one synthetic release. |
| `open-file-error`, `open-directory-error`, `unsupported` | Injected EIO or ENOTSUP refuses opening before any effect; actual profile errors are reported separately and cannot satisfy an injected control. |
| `directory-omit`, `accepted-omit`, `intent-omit`, `outcome-omit` | The named sync is explicitly skipped with an omission error and is never marked attempted/completed. |
| `accepted-error`, `intent-error` | EIO before durable acceptance/intent prevents signer entry. |
| `outcome-error` | Sign may have occurred; outcome is uncertain, the instance is poisoned, and release/re-sign both refuse. |
| `cleanup-refusal` | Synthetic signer uncertainty and unknown synthetic child cleanup keep reconciliation, release, re-sign and new work held. No actual native child cleanup is proved. |
| `ambiguous-release` | A synthetic partial-transfer error survives; historical success/receipt remain and signing cannot recur. No actual bytes are transferred. |
| `close-error` | A separately labeled injected close failure remains visible after real descriptor closure. Real close errors are also retained. |

The runner validates the complete expected boundary sequence, so a missing call
cannot yield a passing control. A suite exits 0 only if all expected observations
hold; expected refusals remain errors in its JSON rather than being rewritten as
successful operations. Unexpected refusal exits 1; invalid argv exits 2. A
120-second process watchdog exits 124 with cleanup explicitly unknown. It cannot
cancel or prove completion of kernel I/O. A system or scheduler failure may
defeat even that bound. A failed baseline stops the suite; it never silently
switches profiles. JSON contains profile, fixture basename, boundary events,
failure codes/errno, synthetic-effect counts, and actual per-case times; it
always declares native power-loss proof and production admission false.

Linux tests use an explicitly named `LocalFSync` fixture and substituted native
observations. They verify failure propagation, volume/type refusals and journal
ordering/cleanup controls. They do not compile or execute the Darwin bridge,
qualify APFS, prove native storage persistence, or authorize installation.

If strict directory full-sync refuses on the actual target, keep this profile
unavailable. The smallest subsequent custodian choice is either a supported
qualified target under this exact profile, or an explicitly different profile
such as file full-sync plus directory fsync with separately evidenced namespace
and power-loss limits. The latter is not implemented or selected here and cannot
reuse this profile name to replay existing history. No extra general owner
permission follows from a source review or passing fixture tests.
