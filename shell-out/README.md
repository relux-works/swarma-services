# shell-out

Manual private output capture for independently authorized commands, on Linux and macOS. The service is a standalone Go module under `src`, with no third-party dependencies. Requires Go 1.25 or later and Git when running in a Git project. It installs no runtime hooks, shell configuration, permission rules, or global commands.

Build from `src` with `go build -o <private-binary-location> ./cmd/shell-out`. Run `go test -race ./...` and `go vet ./...` there. The package exports the compiled command as `shell-out` through the existing Curator `go-v1` driver, not through a launcher-specific schema.

```sh
shell-out run --cwd . --session example -- bash -o pipefail -c 'printf "synthetic\n" | cat'
printf 'synthetic stdin\n' | shell-out run --cwd . -- /bin/cat
shell-out run --cwd . --clear-env --env PATH=/usr/bin:/bin --env EXAMPLE=synthetic -- /bin/sh -c 'printf "%s\n" "$EXAMPLE"'
shell-out run --cwd . --timeout 30s --progress 5s -- /bin/sh -c 'printf started; sleep 60'
shell-out lookup --cwd . -- 'example/ID-FROM-RESULT'
shell-out purge --cwd .
```

All options precede `--`; remaining elements are the original argv, passed without joining or quoting again. Select a shell explicitly when needed (`bash -c SCRIPT`, `zsh -c SCRIPT`, etc.). There is no implicit login shell, shell initialization, or persistent native session. Cwd is explicit; environment inherits by default, `--clear-env` starts empty, and repeatable `--env NAME=value` overrides individual values. Executable lookup uses that child's PATH and cwd. An empty PATH requires an executable path. Stdin is forwarded from the caller, including EOF. Avoid secrets in CLI arguments and session labels.

## Output and results

Every successfully initialized run creates separate stdout and stderr logs before spawning the child, including empty output and failed executable starts. Each stream's byte order is retained independently. No total ordering across streams is claimed. The final stdout preview goes to stdout, the final stderr preview goes to stderr, and the final result is one JSON object prefixed by `[shell-out result]` on stderr. Progress information shares the wrapper's stderr, not the child's stderr log.

Each result includes a stable `ref` (`session/id`), the two private paths, original command exit code, signal number when applicable, command status, capture status, observed bytes, saved bytes, logical line counts, timestamps and expiry. The filenames are `YYYYMMDD-HHMMSS_<executable-slug>_<random-id>.out.log` and `.err.log`. Only a small fixed allowlist of ordinary executable basenames is used for slugs (at most 32 characters); everything else becomes `command`. Arguments and executable paths never enter the slug. There is no runtime call id available in this manual CLI; ids are 128-bit cryptographic random values, with exclusive creation and no overwrite.

- Small printable UTF-8 output (at most 4,096 bytes and 40 logical lines per stream) is printed byte-for-byte, preserving a missing final newline. Terminal controls are escaped even in small output; only newlines remain line delimiters. Output with NUL or invalid UTF-8 is summarized as binary, never emitted as raw terminal bytes.
- Larger output uses a head and tail, each at most 2,048 **rendered** bytes and 20 lines, plus fixed markers. This limits giant lines and escape expansion. Each progress update has at most 1,024 rendered bytes and 10 lines per stream plus fixed status text. Progress repeats at the configured interval; total progress over an indefinitely running command is not a fixed-size result.
- Default saved output is capped at 64 MiB **per stream**, configurable with `--max-capture-bytes`. This is a disk-use ceiling, distinct from preview limits. Exceeding it reports `partial`, retaining the saved prefix and a bounded in-memory head/tail of observed data until the result is presented. Captures are never described as complete after this limit, read/write/close/sync failure, or pipe-drain deadline.
- A file-open failure prevents spawn. Mid-run write failure keeps draining the child, preserves the bounded observed preview and the command's actual outcome, and reports observed and saved sizes separately. Metadata failures are reported separately in `capture_error`. Storage failures do not magically make unsaved bytes recoverable from a log.

Wrapper exit status is the original nonzero exit code when available; an actual child signal is re-raised after the final result by replacing the finalized wrapper with a fixed, empty-environment POSIX shell self-signal helper (JSON also contains conventional `128+signal`). This avoids Go runtime fatal-signal traceback behavior and preserves signal termination, including QUIT and ABRT. No original command text is passed to this helper. A zero-exit command with a capture/presentation failure returns 125, as do initialization and spawn errors. **Read the JSON for command outcome versus capture outcome**; the wrapper's 125 alone does not distinguish a command that itself returned 125. Final-result presentation can itself fail if the caller closes the wrapper's streams; file metadata remains available if storage succeeded.

## Process and TTY contract

The command runs in a new process group. INT, TERM, HUP and QUIT received by the wrapper are forwarded to the group; timeout or context cancellation sends TERM. Cancellation escalates to KILL after 250 ms. The actual direct-child exit/signal is retained even if it handles the signal and exits with another code.

When the direct child exits, remaining group members receive TERM and then KILL after a 100 ms grace period. This deliberately bounds ordinary background jobs to one invocation. Pipes get a one-second drain deadline. Programs that call setsid or otherwise detach may survive the process group; their inherited pipes trigger an explicitly partial result at the deadline. This is not a process containment or policy enforcement service. A wrapper forcibly killed by SIGKILL cannot finalize metadata; its running record is conservatively retained and never purged automatically.

Within one explicit shell invocation, quoting, heredocs, pipelines/pipefail, cd and export work as that shell defines. They do not change the calling shell or persist into another call. File descriptors 1 and 2 are pipes, not a PTY. Programs may suppress colors, choose different buffering, disable prompts or refuse interactive use. Stdin can retain the caller's own TTY identity if forwarded directly. No terminal resize, job control, PTY emulation or persistent shell state is promised.

## Storage, refs and retention

In a Git project the destination is the project's `.temp/shell-out/<session>/`. The tool creates `.temp` if necessary, rejects tracked `.temp` contents, and checks the **exact** destinations with `git check-ignore`. When needed it appends `/.temp/` only to local `info/exclude`, resolved through Git (including linked worktrees). It never edits a tracked `.gitignore`. A still-not-ignored destination is refused, including higher-priority negation rules.

Outside Git, use the per-user cache's `shell-out` directory (Linux honors `XDG_CACHE_HOME`; macOS uses the user Library cache). Broken Git worktrees fail instead of silently falling back. The caller-selected cwd anchor is canonicalized once (including macOS system aliases). Storage traversal beneath the selected project or cache refuses symlink components, even when a symlink stays in the same tree. Descriptor-rooted operations stay anchored across renames; exclusive log creation uses no-follow flags. Capture directories are 0700 and new files 0600. Metadata is locked during a live run; purge refuses special files, symlinks and hardlinked metadata. Lookup accepts only the fixed ref grammar, never a path supplied by metadata. Same-UID adversarial processes and mount substitution are outside this MVP's containment guarantee; do not use a shared untrusted account as a security boundary.

Retention defaults to 24 hours from completion (`--retention-hours`, positive and at most 8,760). `purge` explicitly removes only expired, completed logs inside this service's own directories, skipping locked/running records. No recursive deletion, running-file deletion, or automatic global scan occurs. Metadata tombstones remain to prevent ref reuse. Lookup reports expired/unknown after expiry or removal and cannot redirect an old ref to a new capture. Purge must be invoked to reclaim expired disk usage; abandoned running records and metadata tombstones need operator inspection, so this is not an aggregate disk quota.

Logs can contain sensitive output. Investigate only needed ranges with head/tail, grep or sed. Never copy logs into reports, attachments, task resources or version control. Do not include private paths in public commit or PR text.

## Skill export and future seam

`SKILL.md` plus `agent-skill.json` implement the existing schema-8 compiled skill contract: `build_roots: ["src"]`, exported command `shell-out`, driver `go-v1`, source directory `src/cmd/shell-out`. The source build root is excluded from skill context/runtime by Curator. It uses no external dependency, build hook, compiler bootstrap or global install. The repository remains movable as one subproject.

The conventions were checked against Curator spec commit `8b34c870ab7deba99b243ba26646d68b07bb630b`, Protocol Core sections 4.2–4.3, manager section 2, and Skillfile sources section 4. A consumer selects the `shell-out` package directory from this repository at the reviewed, landed commit, records that exact source revision in its Skillfile, and resolves the exported command through its lock. The keeper handoff supplies a concrete pinned candidate Skillfile outside this repository; publication and landing remain separate steps.

Capabilities are an **audit surface**, not a sandbox for this compiled command. The manifest's fixed executable names cover Git and common shell dependencies; the purpose statement explicitly discloses arbitrary independently authorized child dispatch, inherited environment, cache storage and sensitive captures. This list must not be interpreted as granting blanket permission for child commands, denying the tool's documented effects, or establishing a runtime enforcement boundary.

Curator owns its optional generic extension rail and runtime integration. No extension profile, lock format or launcher schema is invented here. The installed Codex 0.166.0 protocol exposes hook events, but a rewrite preserving original-command authorization and shell state has not been established. Automatic capture is **unsupported/unverified** in this MVP. A future adapter must refuse if original permissions cannot be preserved. The paired known-denied/nearby-allowed permission test remains pending a real runtime seam; manual subprocess tests are not proof of that property. Claude native spill measurement is also outside this Codex-first manual MVP.
