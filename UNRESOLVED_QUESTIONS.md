# Open agreement points

2026-11-01. These facts are required before the proposed signer version 1 contract is frozen or built.

| Question | Required source | Effect while open |
| --- | --- | --- |
| Curator exact qualified source release, signing identifier, complete toolchain/recipe and source/dependency manifests, entitlements and runtime compatibility | Curator maintainer and service maintainer | Repo/branch/entrypoint/target and secret-bearing classification are known; one commit-labelled recipe is proposed, not qualified |
| Later broker release candidate, native deterministic recipe, toolchain/SDK digests, dependency policy and entitlements | Broker source maintainer and service maintainer | Repo/identifier/entrypoint, required CGO/native frameworks and constant-version constraints are known; broker integration follows Curator rollout |
| Actual forward-form COMMENT/verdict grammar and passing witness; exact check policy, freshness and revocation qualification | First-client delivery owner and service maintainer | Explicit room/event citation and independent authenticated sender mapping are selected; historical uncited COMMENT cannot pass the new rule |
| Request/result JSON bounds and grammars, transport authorization, artifact transfer, timeout and retry horizon | First-client maintainer and service maintainer; broker compatibility retained for later integration | Version 1 envelope remains proposed; second-client qualification does not block the first slice |
| First-admission confirmation record and identity binding; policy changes, revocation and re-admission semantics | Signing custodian and service maintainer under the owner decision | No release-specific approval requirement added |
| Builder account/isolation, source access, immutable IPC custody, signer snapshot ownership and reproducibility envelope | macOS host custodian and actual Curator/broker build owners | No host writes or assertion that UID separation alone protects all host secrets |
| Separate evidence principal's actual provider access, own signed binary/DR, Keychain custody and bounded source/dependency transfer | Evidence and signing custodians with service maintainer | Selected credential placement is not an account, enforced token scope or bootstrap exemption |
| Durable audit primitive, checkpoint custodian, retention, recovery and concurrent/retried operation semantics | Signing custodian and service/client maintainers | No artifact release without durable outcome; uncertainty stays explicit |

No service, user, key, ACL, Keychain, sudo, daemon or private broker operation is authorized by this proposal.

The original requirements, current first-admission-only amendment and broker compatibility addendum have been
received. Historical per-release-presence wording remains superseded. The known source boundary is documented
in [broker compatibility inputs](signer/docs/broker-compatibility-v1.md); it is not runtime acceptance.
