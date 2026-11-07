# Landed signer source components

These packages belong to `github.com/relux-works/swarma-services/signer/internal`.
Contributor importers must be inside the signer module's import-path tree. Use
the [module status](../../../../signer/README.md#implementation-status) to separate
landed source from service, provider, policy and host qualification. No component
here supplies a service command, installation or permission to operate a signer.

## Unsigned artifact snapshots

Read the [caller contract](../../../../signer/docs/artifact-snapshot.md) and
[`artifactsnapshot.Verify`](../../../../signer/internal/artifactsnapshot/snapshot.go)
when consuming the two consecutive unsigned artifact streams. Supply the original
active job `context.Context`, trusted scratch parent, authenticated `net.Conn`
positioned after the validated success result, and the two decoded `Receipt`
values. The caller must first authenticate the complete result and its job,
nonce, source, policy, recipe, target and log bindings. Matching receipts cannot
establish those facts.

The scratch parent must be absolute, owned by the running principal, mode 0700
and not a symlink; ancestor and concurrent namespace custody remain host
preconditions. Accept no builder-supplied path or descriptor. The connection must
support real absolute read deadlines and concurrent close. `Verify` consumes and
closes it on success and refusal; do not reuse the exchange.

Each receipt requires 1..268,435,456 bytes and 64 lowercase hex SHA-256 characters.
The two streams must independently match their receipts and each other byte for
byte, followed by EOF. Keep the original job deadline: no missing, expired or
greater-than-600-second remaining budget is accepted. Each stream has an absolute
60-second deadline capped by that job deadline; EOF shares the second deadline.
Calling the verifier cannot renew the job's original 600-second ceiling.

Valid contributor use retains the returned opaque `*Snapshot`, uses its value
`Receipt()` and concurrent `ReadAt`, and checks `Close()` to release storage.
Its temporary names are already removed before return; there is no path or
writable descriptor to pass downstream. The handle is unsigned and process-local,
not durable native staging. As an adjacent refusal, an otherwise valid pair with
one trailing byte yields no snapshot (`ErrStream`); equal receipt fields alone
never waive stream checks. The existing [snapshot controls](../../../../signer/internal/artifactsnapshot/snapshot_test.go)
pair `TestVerifiedSnapshot` with `TestStreamRefusals`.

Refusal removes only the verifier's private child. Preserve `ErrCleanup` (including
joined context/cleanup errors) and retain the operation gate for recovery instead
of claiming clean completion. Cancellation/expiry suppresses any candidate
snapshot after connection and callback cleanup. Native custody, admission, durable
intent/outcome and signature verification remain separate gates.

## Fixed keyless executor

Read the [fixed executor contract](../../../../signer/docs/first-client-keyvault/executor-source.md)
and [`keylessexecutor.PlanInput`](../../../../signer/internal/keylessexecutor/plan.go)
when planning the selected mac-keyvault input. Obtain the opaque
`*keyvaultinput.Prepared` through the existing
[`keyvaultinput.New(manifests)` and `Verifier.Prepare(binding, raw, data)`](../../../../signer/internal/keyvaultinput/input.go)
with exact pinned installed artifacts and authenticated retained job/transfer
bindings. Keep supplied slices stable during verification and the prepared
handle stable during planning. A caller projection or matching hash is not peer
or source authority.

Valid contributor use passes that verified handle to `PlanInput` and inspects
the owned plan's copied `Entries()`, `Binding()`, `GraphCommand()` and
`BuildCommand()` descriptions. Planning performs no filesystem or process work;
it does not execute those command descriptions. Nil or zero-value `Prepared`
returns no plan and `ErrInput`; altered required DATA refuses in `Prepare` before
planning. Existing [executor controls](../../../../signer/internal/keylessexecutor/controller_test.go)
cover receipt-only planning and these adjacent refusals without adding a native
capability.

Preserve original source bytes, selected versions and both canonical Go h1
domains. Graph-only records remain anchored `.mod` only; full records reconstruct
verified source, `.mod`, locally derived ZIP and original h1 `.ziphash`. Do not
import foreign caches, synthesize `.info`/`.list` or replacement `go.mod`, upgrade
dependencies or broaden the recipe. `CheckGraph` accepts only the selected graph's
exact edges, permitting reordering, and refuses changed, missing, extra or
duplicate edges.

The private controller and runner are not public extension points. Their source
uses graph-before-compile, two independent 0700 clean states, one concurrent job,
bounded combined logs and cleanup on every outcome. Keep the fixed per-build and
whole-job bounds; the 10-second termination allowance is inside the 600-second
job budget and the log budget is shared across both builds. Synchronous
verification/planning belongs inside the admitted worker resource domain; a
goroutine timeout cannot contain it. Process groups and file modes alone do not
provide native containment or read-only mounts.

`RunNative(prepared)` and `RunNative(nil)` always return
`keyvaultinput.ErrNativeInputsMissing` (`native_runtime_inputs_missing`) before
filesystem or process effects. There is no caller qualification switch, supplied
executable/recipe or test-backend parameter. Synthetic controller success proves
no Mac build, Keychain access, resource admission or installed comparison. Actual
policy, fresh `BeforeBuild`, SDK/toolchain/runtime closure, separate native
principals, read-only mounts, CPU/RSS/process enforcement and immutable output
handoff remain missing inputs. `BeforeSign`, signing, provider, owner-key and
installation operations are outside this component.
