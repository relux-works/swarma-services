---
name: swarma-services
description: Explain and use the current Swarma Services signer moduleinput verifier in contributor code within its Go module, or select documented contributor checks. Use for this signer source, not generic signing or shell output capture.
---

# Swarma Services: current signer

This skill describes the signer at source commit `dec7c4f3a212b01f563c11571b0bdad431d5112a`. It provides source guidance, not an installed service or permission to operate one.

The implemented signer surface is the pure Go package `signer/internal/moduleinput`. It verifies supplied typed module material and returns an immutable snapshot. Success establishes integrity of the supplied subset; it does not establish source authority, dependency closure, build sufficiency or release approval.

For contributor input preparation, results and an inert valid/refused pair, read [moduleinput usage](references/moduleinput.md). The package is internal: its importers must be within the signer module's import-path tree. Do not offer it as an external library or live agent operation.

For an explicitly requested development check, read [contributor commands](references/contributor-commands.md). Those Go commands check the pure package; they are not signer service commands.

There is no signer service CLI, implemented plugin seam, registry or installation command in this source. If asked to sign, install, register or connect a signer plugin, report that missing implementation boundary and the requested capability. Do not invent a command, transport or procedure.

For future design work, follow the design documents in [the signer status and reading order](../../../signer/README.md). These proposed contracts do not expand the implemented package. Raw manifest parsing, whole-manifest accounting, cache synthesis, production builds, signing and native isolation remain integration or qualification work. The admitted manifest limit remains 1 MiB; the proposed 4 MiB limit is not active.

Shell output capture is a separate subproject with its own [shell-out skill](../../../shell-out/SKILL.md).
