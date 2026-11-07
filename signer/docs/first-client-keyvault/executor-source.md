# Fixed keyless executor source

Status: source candidate. Native execution remains unavailable. Offline source
controls are synthetic execution and prove no Mac, Keychain, toolchain, native
resource enforcement, signature, release or installed-binary capability.

`internal/keylessexecutor.PlanInput` consumes the existing opaque
`keyvaultinput.Prepared`. The integrator authenticates the retained job and
transfer before the unchanged verifier; an internal projection is never peer or
source authority. The existing manifestbody/moduleinput/keyvaultinput code and
all recipe, original source anchors, selected versions and canonical h1 domains
remain unchanged. Invalid required content refuses before planning or compile.

The plan owns its bytes and records every reconstructed path, input origin,
actual byte count and SHA256. Only verified receipt content contributes module
files. Module identities use standard escaped Go cache paths. Graph-only records
produce only their original anchored `.mod`. Full records produce the verified
canonical source tree, anchored `.mod`, locally derived ZIP and original h1
`.ziphash`. ZIP serialization is a local derivation, not imported foreign cache;
its SHA256 is separately ledgered. No `.info`, `.list`, imported cache, generated
replacement go.mod or new dependency is accepted. The exact graph is the
previously observed selected offline graph; comparison rejects changed, missing,
extra or duplicate edges, allowing only edge reordering. Pruned graph edges do
not imply missing compiled module bodies.

The private controller implements graph-before-compile, two separately allocated
0700 states, identical namespace destinations, per-build and whole-job deadlines,
whole-job combined log bounds, regular bounded output, byte comparison, one concurrent job
per controller and cleanup on every outcome. Each build has empty home, temporary
directory, build cache and output. No state is reused between builds. Canonical
files and source directories are read only; Go auxiliary download lock/stat
state is separately writable and excluded from canonical content. A native
backend must mount canonical files read only even inside that auxiliary tree;
permissions alone cannot stop a same-owner process. The source controls exercise
reconstruction and lifecycle with an explicitly synthetic private runner.

The process supervisor starts with an explicitly nonnil closed environment,
absolute executable and working directory, no shell, a combined bounded output
pipe, process-group TERM then KILL, bounded reap/drain and cancellation. The
supervisor must contain the entire synchronous input verifier and planner in its
child; timing out a goroutine does not stop verification. The controls exercise
this using a self-contained worker process inside an offline PID/network
namespace. Process groups alone cannot contain a child that creates a session;
they are not native isolation. Any termination, drain or cleanup failure refuses
and is not converted to successful equality.

The exact recipe remains two builds, parallel compiles 2, each build 240 seconds,
whole job 600 seconds, termination 10 seconds, input 1 GiB, entries 8192, artifact
256 MiB, proposed combined logs 1 MiB, memory 4 GiB and processes 64. The controller
adds a conservative one-job concurrency bound. CPU, aggregate RSS, process-tree
limits and cleanup isolation require the actual native admitted process domain.
A virtual-address limit or an algorithmic input bound is not RSS enforcement.
These native enforcement values remain proposed, not qualified.

`RunNative` always returns `native_runtime_inputs_missing` before any filesystem
or process effect. There is no native backend, caller qualification boolean,
caller executable/recipe, alternate protocol or positive synthetic native fixture.
Actual protected policy, fresh sourceauthority BeforeBuild observation,
SDK/compiler/linker/framework/runtime closure, installed comparison, separate
native principals, read-only mounts, finite CPU/RSS/process enforcement and
immutable output handoff are still missing runtime inputs. Missing inputs do not
prevent this refusal and controller source from being specified or reviewed.
BeforeSign and all signing/provider/key/owner/installation actions remain outside
this component. Curator remains the second client.

The ten-second termination allowance is reserved inside the 600-second job
budget. TERM, KILL, reap and drain share one termination deadline; their bounds
are not added together. Graph and build logs across both clean states share one
combined byte budget, which is not renewed for the second build.
