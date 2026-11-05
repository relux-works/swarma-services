---
name: shell-out
description: Capture an explicitly authorized shell command's output privately with bounded previews and stable references; use manually for potentially large output.
---

Use the exported `shell-out` command manually. Authorization applies to the original command and all its effects. This wrapper grants no additional permissions. Never rely on a blanket allow rule for the wrapper, and do not install hooks or rewrite permission settings.

Pass explicit argv after `--`. For shell syntax, pass the intended shell and its script as separate argv elements, for example `shell-out run --cwd . -- bash -o pipefail -c 'printf "synthetic\n" | cat'`. Caller stdin is forwarded; use native redirection when needed. Environment inherits unless `--clear-env` is specified; repeat `--env NAME=value` for overrides. Avoid secrets in command-line options and session labels.

Small printable output stays unchanged; large output has bounded head and tail. Binary output is summarized and controls are escaped. The final result on stderr contains the ref, private stream paths, command status, capture status, and observed/saved byte counts. A preview is not the full output. Check `capture_status` before treating a log as complete. Investigate only needed ranges with grep, head, tail or sed; never copy captured output into reports, attachments, or task resources, or include private paths in commits or PRs.

Refs use `session/id`; `shell-out lookup --cwd . -- REF` returns their metadata. `shell-out purge --cwd .` explicitly removes expired completed captures and keeps tombstones. Default retention is 24 hours from completion. Run purge regularly; lookup expiry alone does not reclaim disk.

Each call creates a subprocess with pipes. Shell-local cd/export state persists only within that invocation; it does not update the caller. No PTY is allocated, so colors, prompts, pagers and interactive programs may behave differently. Background processes in the command's process group are terminated when the main process ends. Programs that detach themselves can outlive this lifecycle; a pipe-drain deadline reports partial capture. See [README.md](README.md) for status, signal, retention, and packaging details.

Automatic runtime capture is unsupported in this MVP. A future adapter must refuse if it cannot preserve the original permission decision. The known-denied/nearby-allowed runtime integration test is pending a real seam, not satisfied by the manual command.
