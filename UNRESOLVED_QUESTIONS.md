# Open agreement points

2026-11-01. These facts are required before the proposed signer version 1 contract is frozen or built.

| Question | Required source | Effect while open |
| --- | --- | --- |
| Curator repo/default branch, exact source release, identifier, target, entrypoint, toolchain/recipe digest, dependency policy and entitlements | Curator maintainer | No invented Curator allowlist or recipe |
| Later broker release candidate, native deterministic recipe, toolchain/SDK digests, dependency policy and entitlements | Broker source maintainer and service maintainer | Repo/identifier/entrypoint, required CGO/native frameworks and constant-version constraints are known; broker integration follows Curator rollout |
| Exact signed/reviewed/checked/landed receipt verification, freshness and revocation | Both client delivery owners and service maintainer | Legitimate COMMENT plus independent-verdict form is known; verifiable mapping remains to be agreed |
| Request/result JSON bounds and grammars, transport authorization, artifact transfer, timeout and retry horizon | Both client maintainers and service maintainer | Version 1 envelope remains proposed |
| First-admission confirmation record and identity binding; policy changes, revocation and re-admission semantics | Signing custodian and service maintainer under the owner decision | No release-specific approval requirement added |
| Builder account/isolation, source access, immutable IPC custody, signer snapshot ownership and reproducibility envelope | macOS host custodian and actual Curator/broker build owners | No host writes or assertion that UID separation alone protects all host secrets |
| Durable audit primitive, checkpoint custodian, retention, recovery and concurrent/retried operation semantics | Signing custodian and service/client maintainers | No artifact release without durable outcome; uncertainty stays explicit |

No service, user, key, ACL, Keychain, sudo, daemon or private broker operation is authorized by this proposal.

The original requirements, current first-admission-only amendment and broker compatibility addendum have been
received. Historical per-release-presence wording remains superseded. The known source boundary is documented
in [broker compatibility inputs](signer/docs/broker-compatibility-v1.md); it is not runtime acceptance.
