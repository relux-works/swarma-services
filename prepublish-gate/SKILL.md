---
name: prepublish-gate
description: Check a bounded immutable Git candidate with private patterns, operational hygiene and SSH signatures, or perform an explicitly authorized leased publication using the existing client.
---

Read [README.md](README.md) for exact input grammars, counts, finite limits,
unsupported histories and publication requirements. This is an independent Go
1.26.8 module with no third-party dependencies. Build `./cmd/prepublish-gate`;
run `go test -count=1 ./...`, `go test -race -count=1 ./...` and `go vet ./...`
with downloads disabled in a private offline sandbox. Use synthetic fixtures only.

Acquire source separately. Pin full base/candidate OIDs and use only the
operator-designated private patterns, public allowed-signers file and exact
principal. Run `check` first. Never seek actual private marker inventories for
tests or log caller paths, patterns, messages, values or native tool diagnostics.
Installation-specific names and identifier formats must be supplied through that
private input; there is no embedded inventory or fallback. Keep that file out of
public source, diffs, history and artifacts. Private hits are counts only.
A zero hit count is meaningful only with completed checks and a successful exit.

Run with dedicated, effective-UID-owned 0700 HOME and TMPDIR at clean absolute
paths, including on macOS; each directory's final component must not be a
symlink. This does not establish ancestor or ACL safety. The ordinary login HOME can refuse.
macOS TMPDIR commonly ends in `/`, which clean-path admission refuses even for
an owned 0700 directory. After selecting dedicated directories,
use `TMPDIR=${TMPDIR%/}` and export TMPDIR before invocation. HOME must also have
no trailing slash; use `HOME=${HOME%/}` and export HOME if needed. This adjusts
path spelling only and does not fix wrong permissions, ownership or symlinks.
Use the [private directory example](README.md#build-and-check); never chmod the
host HOME or system temporary directory to make a check pass. The caller owns
the dedicated directories and cleanup; allow TMPDIR space for the object copy
and private Git state. These overrides are not OS isolation or Mac qualification.
Runtime and sandbox checks are qualified only on Linux. Native macOS isolation,
real publication and GitHub HTTPS operation remain unqualified. Portable tests
and the directory example do not establish those qualifications.
`home_admission_errors` and `tmpdir_admission_errors` distinguish directory
admission refusals while preserving `scan_errors=1`, `completed=0` and exit 1.
HOME is checked first. Counters disclose no paths, values or OS diagnostics.

Large stored histories can exceed the unchanged aggregate pool bounds even for a
small candidate diff. `pool_limit_errors=1` distinguishes that limit while retaining
`scan_errors=1`, `completed=0` and exit 1; it discloses no caller bytes. Follow the
[large-history acquisition route](README.md#large-histories-and-an-explicit-shallow-base)
to prepare a separate bounded shallow object pool. Use `--shallow-base` only with
the exact trusted base and candidate IDs, with every candidate commit and complete
baseline/candidate tree available. The flag ends ancestry only at the exact base;
strict fsck, candidate ancestry, signature and diff checks still apply. Source
shallow metadata is not imported. A too-shallow acquisition, missing/corrupt object
or candidate outside the base chain refuses. The flag does not prune an oversized
pool or raise any resource bound. This route grants no acquisition or publication
authority and does not qualify the real HTTPS publication seam.

The temporary word-followed-by-digits hygiene rule can flag ordinary names such
as `build-2024`, including beneath `var/tmp` and in URL-shaped text. It matches
any slash-delimited `tmp` path segment, including relative paths such as
`./tmp/…` or `src/tmp/…`. Use only the documented, reviewed exact-record hygiene
exception route for product examples;
do not weaken the matcher or add default exceptions.

Publication requires explicit user authorization, `publish --execute-publication`,
a canonical matching repository/URL, the existing authorized-client configuration,
an explicit default-branch ref that preflight observes equal to the base,
and an exact base OID or explicit `absent` lease for every destination branch.
Checking the default ref does not update it. Its read-to-push race remains unless
a separately qualified receiver policy closes it; do not add a default update to
assert it. Review/custody/marker gates are external requirements. A clean scan and lease do
not supply them. Stop on any refusal or uncertain push result; inspect remote
state through the authorized client before any separately authorized new attempt.
Do not retry, change authentication routes or fall back to a non-atomic push.

For an explicitly selected read-only tail inventory, use `tails --repo ABSOLUTE`
or bounded `tails --root ABSOLUTE`; read [TAILS.md](TAILS.md) first. The command
never contacts GitHub or modifies sources. Optional PR ages use validated, supplied
projected metadata. Preserve incomplete coverage, unknown ownership/freshness and
nonzero exits; cached-remote absence is not proof of absence online. The every
three day operator suggestion creates no schedule or disposition authority.
