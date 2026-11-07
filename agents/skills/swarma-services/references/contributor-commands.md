# Contributor commands, not a service CLI

The [signer Tools section](../../../../signer/README.md#tools) documents Go 1.24 or newer, pinned module dependencies and the selected development lanes below. Run from the repository root only when the user requests the corresponding contributor check and its execution is permitted. Reading this skill does not request these checks.

These are inert command examples. Each invocation is bounded to 120 seconds here; `GOTOOLCHAIN=local` selects the local Go toolchain rather than automatic toolchain acquisition. Go can still use its normal module/build caches and acquire missing dependencies; this is not an offline or isolated build recipe.

```sh
timeout 120s mkdir -p .temp/signer-tests
GOTOOLCHAIN=local timeout 120s go -C signer test -count=1 ./... > .temp/signer-tests/unit.log 2>&1
GOTOOLCHAIN=local timeout 120s go -C signer test -race -count=1 ./... > .temp/signer-tests/race.log 2>&1
GOTOOLCHAIN=local timeout 120s go -C signer vet ./... > .temp/signer-tests/vet.log 2>&1
```

Choose the requested lane and inspect its exit code; a timeout is not a pass. `-C signer` selects the signer module, `-count=1` disables cached test results, `-race` requests the race detector and `./...` selects packages beneath that module. `vet` is a Go analysis command, not a signer operation. Logs stay under the repository's ignored `.temp/`.

For patch whitespace only, the repository documents:

```sh
timeout 120s git diff --check
```

These checks do not run a signer service, qualify a production toolchain, prove native isolation or authorize signing or installation. There is no signer service command, plugin registration command, registry entry or install procedure. Constructor injection for the source-authority adapter is covered in [the adapter reference](source-adapter.md); the separate native durability fixture runner is not a signer service.
