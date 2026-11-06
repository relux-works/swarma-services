# Proposed execution and artifact-release contract

Status: proposed, 2026-11-01. These are source mechanisms for the Curator-first slice. No process, principal,
socket, directory or policy described here is asserted to exist or authorized for installation.

## Principals and data custody

The signer runs under its configured signing principal and binds its own sockets. A separately launched,
unprivileged builder process runs under the configured distinct keyless principal. A separate evidence-adapter
process runs under its own configured unprivileged principal, distinct from signer, builder and requesting client.
It owns provider-read credentials and returns authenticated authority projections and verified source inputs;
its [authority contract](authority-v1.md) preserves the signer's credential-free boundary. These processes belong
to the signer's one module and communicate through external role interfaces. A reviewed service launcher
can start each process as its own UID; the signer does not switch UID, execute builds or provide a root command
runner. Principal UIDs/GIDs and narrowly enumerated socket-group memberships are mandatory trusted deployment
inputs. Unknown host state is neither absence nor permission to create or repurpose an account.

Proposed paths are `/var/run/relux-signer/{requests,builder,evidence}.sock`, protected policy/admission records under
`/Library/Application Support/relux/swarma-signer`, signer-private journal/snapshots under `/var/db/relux-signer`,
and builder-private workspaces under `/var/tmp/relux-signer-build`. The runtime socket directory is signer-owned
0755; sockets are signer-owned 0660 with distinct configured client/build/evidence groups. Policy records are root-owned
0644; signer state and builder workspace directories are each 0700 under their separate principals.

Both endpoints verify kernel peer UIDs for the configured role. Group access, socket possession and JSON UID
claims do not authorize work. Same-UID executable identity is not attested by peer UID. Isolation must additionally
exclude signer secrets from build groups, environment, mounts and descendants. Exact Darwin peer semantics and
filesystem isolation require target qualification in safe fixtures.

## Source acquisition before the offline build

The evidence adapter uses only the configured repository and dependency authority routes. The request cannot
add a repository URL, helper, filter, hook, submodule or replacement outside that trusted policy. Acquisition
never runs source commands, build scripts or module tools with the adapter's credentials. Actual provider access
and repository/dependency closure must be qualified; a read-only code path is not proof of a read-only token.

The adapter supplies bounded content-addressed source and dependency data with an acquisition receipt binding
the canonical repository, exact commit and tree, bundle hashes/sizes, module sums and policy. It does not supply
a compiled artifact. The signer authenticates its configured peer, copies the bounded data into its own custody
and binds their digests to the operation before handing the same verified bytes to the builder. A bundle that
cannot establish the requested object/tree or dependency closure refuses; authentication alone is insufficient.
Extraction must reject traversal, escaping links and writes outside the private workspace. Source-data framing,
capacity and the exact dependency closure remain qualification inputs; none is an unbounded upload allowance.
The [finite protocol](protocol-v1.md) supplies a proposed inline module receipt and exact bounded DATA format.
Whole source can contain links or Gitlinks outside the accepted transport subset. The actual target's necessary
input closure must be qualified explicitly; unsupported required inputs cannot be silently omitted or transformed.

The builder verifies those inputs, creates two clean workspaces from them and has no network or credential
access. Dependencies are preverified read-only inputs to both builds; the compiler cannot fetch missing modules
or a toolchain. Failure to establish the isolated offline environment refuses before compilation. No secret
is copied into an environment merely to make a private source build work.

## Builder job and byte-stream result

The builder connects to the signer-created builder endpoint. Its bounded versioned registration binds the
configured recipe-policy digest. The signer dispatches one finite job only for the accepted active operation:
operation ID, service-generated nonce, configured repository alias, exact source commit, trusted recipe identity
and digest, verified source/dependency input digests, toolchain/target identities, and installed resource limits.
No client-selected URL, shell command,
environment, output path or binary is accepted. The builder independently selects that installed recipe and
refuses a policy/job mismatch. Registration and idle reconnection are bounded; they do not create a signing job.

The builder acknowledges the exact job, builds in two clean private workspaces, and returns a bounded result
receipt binding the job/nonce, source/policy/recipe/toolchain/target, two unsigned hashes and sizes, and bounded
build-log evidence. It then streams exactly those two artifact byte sequences on the authenticated connection.
Unsolicited output, a wrong operation/nonce, extra fields including arbitrary paths, over-limit or short streams,
and mismatched source/recipe identities refuse without signing.

The signer never traverses the builder's 0700 workspace or treats a builder path/descriptor as immutable input.
It creates exclusive private staging files and copies both bounded streams, computing its own hashes and sizes.
Both actual copied artifacts must match their receipts and each other byte for byte. Only the verified
signer-controlled snapshot may proceed to signing. The builder cannot reopen or mutate that snapshot. An
authenticated builder peer alone does not authorize arbitrary bytes independently of the accepted source job.

## Framing, deadlines and operation acceptance

The proposed frame header is one opcode byte and a four-byte network-order JSON length. Client opcodes are
sign, inspect and fetch; the builder endpoint has separate registration/job/acknowledgement/result messages.
Each opcode has its own exact member set and role. The sign request is the finite envelope in the main contract;
inspect identifies the authenticated caller's request, and fetch identifies its recorded operation. Result JSON
is length-prefixed. Only a successful authorized fetch carries a server-to-client artifact stream. There is no
client-to-service binary upload operation.
Client opcode values are 1/2/3 respectively; builder registration/job/acknowledgement/result use 16/17/18/19,
and an idle builder response uses 20. A builder idle response closes the channel; bounded reconnect is 1s–10s.

Proposed trusted limits for first-client agreement are:

| Boundary | Proposed bound |
| --- | ---: |
| Client / builder / evidence-adapter connections | 4 / 1 / 1 |
| Header / JSON body read | 2s / 2s |
| JSON request / result size | 4096 bytes / 16384 bytes |
| JSON response write | 5s |
| Authority refresh | 30s |
| Builder acknowledgement / complete build job | 5s / 600s |
| Builder idle registration wait before clean close/reconnect | 30s |
| Native signing / native signature verification | 60s / 30s |
| Managed child termination/reap after timeout | 10s |
| Each artifact stream read or write | 60s |
| Each unsigned or signed artifact | 256 MiB |

Deadlines are absolute budgets for the whole phase, not sliding per-byte resets. Trusted policy may select
different finite limits after client qualification; callers cannot extend them. An unresponsive native signer
cannot be treated as proof that no signing effect occurred. Termination targets only recorded child PIDs; if
termination/reap cannot be established within its budget, return uncertain and keep the gate closed to new work.

Authenticate, read the complete bounded frame, decode/validate it, check pairing/admission and deduplicate before
acquiring the active-operation gate. Persist acceptance before dispatching source qualification or builder work.
An unparsed connection never holds that gate. A matching retry returns the recorded state; a different request
receives busy without an implicit queue. The gate covers the operation through its terminal or uncertain state.

Close malformed, stalled or over-limit connections deterministically. Before acceptance there is no build/sign
effect or retained operation gate. A response timeout after acceptance preserves the operation's journal state;
a reconnect can inspect it instead of inventing a new request. Pre-sign job/stream failure cleans up private
partial output without key use. Any timeout after a possible signing effect retains uncertain/reconciliation
semantics and cannot release or blindly sign again. Client fetch interruption does not start another build/sign.

## Durable operation history

One protected-writer append-only journal is the authoritative operation history and replayed request index.
Bounded records bind schema, sequence, previous digest, caller/request/operation, exact source/policy/recipe,
snapshot and transition. A complete intent must pass the qualified durable-flush boundary before native signing;
the verified signature outcome, signed hash/size and certificate/DR evidence must pass it before release.
File creation, segment transitions and staging publication require the target-qualified directory-persistence
protocol too. Buffered writes and unqualified renames are insufficient. The implementation must refuse an
unavailable durability profile; no power-loss guarantee follows from source fixtures alone.

After intent without a durable outcome, retain the gate and reconcile signer-private staging against the
recorded operation, native signature and current authority/admission. Append a recovery outcome only when those
claims are established. Otherwise retain uncertainty with no release or new signing. Preserve torn-tail bytes
and seal the old segment; a linked recovery segment binds the full predecessor and its last complete record.
Never truncate or overwrite evidence to make replay succeed. Unreconcilable history refuses further effects.

This is application append-only custody, not OS-enforced immutability or protection from root/signer compromise.
Outcome sequence/digest receipts support an agreed external checkpoint custodian. The signer gets no messaging
credential. No automatic audit/idempotency pruning is proposed for the first slice. A trusted storage budget
must refuse new work before effects rather than delete evidence; retention and capacity must be agreed with
the client and host. No periodic checkpoint job is claimed to be armed.

## Fetch eligibility and historical success

Historical operation success and current artifact-release eligibility are separate. Inspect may truthfully
report recorded success after a later revocation or artifact expiry. Fetch additionally authenticates the caller,
verifies the stored bytes/receipt, and applies the current trusted admission/policy and evidence-freshness rule
before emitting any artifact byte. A past success receipt is not perpetual release authority.

The proposed freshness rule uses a versioned protected local admission/policy snapshot and an independently
verified qualification lease bound to the exact source/evidence/policy, with maximum age 300s. A still-current
lease needs no per-fetch network lookup. A stale lease is refreshed autonomously through the actual authority
adapter within its finite budget, without rebuilding/signing or owner presence; unavailable evidence refuses
release. Missing or revoked admission refuses release regardless of a valid historical lease.

The release decision binds the validated policy snapshot immediately before streaming starts. An already
authorized in-flight transfer is bounded by its artifact deadline; bytes already delivered cannot be recalled.
New fetch decisions under the applicable revoked policy emit zero bytes. The client must agree this freshness
and invalidation boundary before freeze. Retention/expiry is a separate decision and never silently triggers
another signature. Refusal preserves the historical outcome and records the current release reason separately.

## Paired acceptance controls

Run target-qualified controls with separate fixture principals and private directories, without live keys:
valid jobs deliver both unsigned outputs despite builder0700, while path-only/forged-job/wrong-peer/mutated-stream
results refuse without signing. A complete timely frame passes while zero/partial headers, short bodies and
stalled readers close at their intended boundary without pre-acceptance effects or leaked snapshots. An
accepted lost-response operation remains inspectable and never signs twice. Native timeout or missing outcome
remains uncertain. A current authorized fetch returns the recorded bytes without new signing; a fetch invalidated
by applicable revocation returns zero artifact bytes despite the same caller and historical receipt.
