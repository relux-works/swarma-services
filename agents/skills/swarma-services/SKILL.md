---
name: swarma-services
description: Use the Swarma Services signer source packages, wire and test its source-authority adapter seam in contributor code, or select documented contributor checks. Use for this signer source, not generic signing or shell output capture.
---

# Swarma Services: current signer

This skill provides contributor guidance for the signer source, not an installed service or permission to operate one. Read the [implementation status](../../../signer/README.md#implementation-status) for the available packages and their qualification boundaries.

The supplied-module verification surface is the pure Go package `signer/internal/moduleinput`. It verifies supplied typed module material and returns an immutable snapshot. Success establishes integrity of the supplied subset; it does not establish source authority, dependency closure, build sufficiency or release approval.

For contributor input preparation, results and an inert valid/refused pair, read [moduleinput usage](references/moduleinput.md). The package is internal: its importers must be within the signer module's import-path tree. Do not offer it as an external library or live agent operation.

For an explicitly requested development check, read [contributor commands](references/contributor-commands.md). Those Go commands check the pure package; they are not signer service commands.

For writing, wiring and testing a contributor source-authority adapter, read [the existing adapter seam](references/source-adapter.md). Its `Source` and `Clock` interfaces are constructor-injected trusted dependencies. There is no plugin discovery, registration command, registry or production provider adapter. Do not turn caller-supplied evidence into an adapter or infer permission for provider access.

There is no signer service CLI or installation command. The separate native durability fixture runner is described in the [native check contract](../../../signer/docs/native-durability-check.md); it is not a service or an inert example. Actual Mac SDK, provider, clock and native isolation qualification remain unavailable from contributor examples.

For future design work, follow the design documents in [the signer status and reading order](../../../signer/README.md). Separate implementation notes describe landed body-shape decoding and the fixed KeyVault source-input composition; neither establishes native readiness or a production service. The design contracts do not supply missing adapters, cache synthesis, production builds, signing or native isolation. The admitted manifest limit remains 1 MiB; the proposed 4 MiB limit is not active.

Shell output capture is a separate subproject with its own [shell-out skill](../../../shell-out/SKILL.md).

Packet scanning is a separate subproject with its own [pktscan skill](../../../pktscan/SKILL.md).
