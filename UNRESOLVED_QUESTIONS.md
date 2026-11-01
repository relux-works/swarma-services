# Open agreement points

2026-11-01. These facts are required before the proposed signer version 1 contract is frozen or built.

| Question | Required source | Effect while open |
| --- | --- | --- |
| Exact dated original signing decisions, current first-admission amendment, KEK broker addendum and sanitized retained handoff | Existing macOS signing custodian | Preserve current first-admission-only rule; no custody or runtime claims |
| Canonical repo/default branch, first identifier, target, entrypoint, toolchain/recipe digest, dependency policy and entitlements | Curator and proxy maintainers, separately | No invented product allowlist or build recipe |
| Actual exact signed/reviewed/checked/landed evidence forms, freshness and revocation | Both client delivery owners | No speculative authority adapter |
| Request/result JSON bounds and grammars, transport authorization, artifact transfer, timeout and retry horizon | Both client maintainers and service maintainer | Version 1 envelope remains proposed |
| First-admission confirmation record and identity binding; policy changes, revocation and re-admission semantics | Signing custodian and service maintainer under the owner decision | No release-specific approval requirement added |
| Builder account/isolation, source access, immutable IPC custody, signer snapshot ownership and reproducibility envelope | macOS host custodian and client build owners | No host writes or assertion that UID separation alone protects all host secrets |
| Durable audit primitive, checkpoint custodian, retention, recovery and concurrent/retried operation semantics | Signing custodian and service/client maintainers | No artifact release without durable outcome; uncertainty stays explicit |

No service, user, key, ACL, Keychain, sudo, daemon or private broker operation is authorized by this proposal.
