# Release signing contract, version 1

Status: proposed, 2026-11-01. Client and host parameters listed below remain open. This is a source contract
proposal, not evidence of counterpart acceptance, deployment, key access or installation authority.

## Required behavior

The service accepts a configured repository alias and an exact commit for an allowlisted product identifier.
It never accepts a caller's binary. The exact commit must be signed by an admitted owner key, independently
reviewed, checked and landed. A separate keyless builder builds the source. The signing account never builds.
The existing signing identity uses ECDSA P-256. A prepared identity alone is not a running service.

Owner decision, 2026-11-01: owner presence is required only at the first allowlist admission of a tool that
holds or binds secrets. Subsequent qualified releases are autonomous. No release-specific presence approval,
build-hash approval or Touch ID prompt is added to that later-release path.

The owner's words on 2026-11-01 were «чтоб не мне каждый раз подписывать а ты сам» and, about presence once for
a new tool, «да ок, пока можно оставить я пер новый тул». The earlier 2026-10-30 boundary was
«тач айди только для тулов с секретом».

Admission and artifact integrity serve different purposes. The trusted admission record binds the configured
product/repository identity and admitted policy; build and signing receipts bind each release's exact bytes.
The admission confirmation mechanism and policy-change/revocation behavior require custody agreement before
implementation. The caller cannot declare a tool admitted or non-secret-bearing.

## Independent service boundary

The signer is a separately movable Go module with its own README and shipped skill when executable tooling
exists. It shares no internal packages with other services or clients. Curator signing/OAuth and the proxy KEK
broker integrate through a versioned external contract and configuration seams. Their standalone MVPs do not
depend on a new shared framework. This interface neither reads nor returns OAuth tokens, KEKs or private keys.

The network proxy application and its separately provisioned KEK broker are distinct products. An application
repository, identifier, build recipe or historical ad-hoc pilot signature cannot establish the broker's source,
allowlist admission or production signing policy. Broker facts come from the actual broker source and custodian.
The proxy consumer's existing private-store and failure-before-listener guarantees remain its own contract;
a signing receipt does not establish broker deployment, envelope migration or private-host qualification.
The [broker compatibility inputs](broker-compatibility-v1.md) record its known source boundary and remaining
recipe and installation limits.

## Proposed request and result envelope

Version 1 is a finite local request/result protocol. Its transport, peer authorization, framing and final
numeric limits must be confirmed with both clients and the host custodian before freezing a wire schema.
Transport authorization cannot be inferred from a correlation identifier.

| Request member | Proposed type and meaning |
| --- | --- |
| `version` | Integer `1`; other versions refuse |
| `product_id` | Configured exact identifier; no caller-selected signing identifier |
| `repository` | Configured alias paired with that identifier; no URL or path |
| `commit` | Full exact object ID under the repository's configured object format |
| `request_id` | Client-scoped correlation and retry key; grammar/length pending client evidence |

Objects reject duplicate or unknown members, missing/null/wrong-type values, trailing content and oversized
frames before any build or sign effect. Bounds apply before unbounded allocation. The request contains no binary,
artifact path, branch, command, recipe, toolchain, certificate, entitlement or secret-bearing override.
Examples from both real clients will fix accepted grammars and limits; an invented identifier is not admission.

Every accepted exchange has a version and correlation identifier. Success returns the configured product and
repository, exact source commit, policy/recipe/toolchain identities, target, unsigned SHA-256 and size, signed
SHA-256 and size, certificate pin, designated-requirement verification and durable audit receipt. The agreed
transport delivers the immutable signed artifact corresponding to that receipt; an arbitrary output path is not
authority. Clients verify the signed hash/size and signature evidence before consuming it.

Refusal returns a stable machine-readable code, sanitized explanation, retry classification and known operation
state. A malformed request with no valid correlation identifier must not echo arbitrary input. Logs and results
exclude private paths, credentials, raw provider responses and key material. The precise JSON result schema and
artifact transfer method remain unaccepted.

| Proposed code | Meaning and required effect |
| --- | --- |
| `invalid_request`, `unsupported_version` | Input rejection; no build/sign |
| `not_allowlisted`, `admission_required` | Unknown pairing or missing first admission; no build/sign |
| `authority_rejected`, `authority_unavailable` | Exact signature/review/check/landing not established; no sign |
| `build_failed`, `build_isolation_failed` | Trusted build or isolation failed; no sign/release |
| `artifact_rejected` | Receipt/snapshot/hash/size/rebuild mismatch; no sign/release |
| `audit_unavailable` | Required durable intent/outcome unavailable; withhold release |
| `signature_failed` | Native signing or verification failed; no release |
| `request_conflict` | Retry identifier reused for a different semantic request; no new effect |
| `outcome_uncertain` | Signature may exist in private staging; no release or automatic blind re-sign |

These codes are proposals for client agreement, not promises about an existing executable.

## Source authority and trusted policy

Installed trusted policy selects the repository URL/default branch, product pairing, admitted owner key,
independent review evidence adapter, required checks, build recipe, target, signing certificate pin and
entitlements. The caller selects none of these. Policy and evidence receipts have explicit identities.

Resolve the current canonical default branch from the configured authority and verify that the exact requested
commit is landed there. Verify the commit's cryptographic signature against the configured owner key and obtain
actual independent acceptance and required successful checks for that exact candidate. Missing, unknown, stale,
wrong-head or unavailable evidence refuses. Caller assertions, tags, commit trailers and a producer's own
review comment cannot establish independent acceptance. Provider records must match the actual delivery
mechanisms used by both clients; no approval-only adapter is assumed.

A legitimate delivery form can record an independently received exact-head verdict in a GitHub COMMENT review
when the publishing account cannot approve its own PR. The service must also verify the independent verdict's
provenance and exact candidate binding; the COMMENT alone is insufficient. A successfully read, empty inventory
of checks under an independently established no-required-check policy is distinct from green CI. Unknown rules,
unavailable inventory or missing required checks cannot be interpreted as that empty case. Review-receipt format
and verification remain to be agreed; this contract introduces no shared review framework dependency.

Recheck authority and admission immediately before build and before sign, with explicit freshness and revocation
rules. The accepted adapter must define how an exact reviewed signed head remains attributable after a permitted
nonrewriting landing. Freeze those evidence forms with clients before writing the admission implementation.

## Keyless build and immutable handoff

The builder is a distinct unprivileged account with no signing key or signer-home access. It uses a clean exact
commit, a trusted pinned recipe/toolchain, bounded resources, and a sanitized environment without inherited
authentication. Go recipes use `GOTOOLCHAIN=local`, `-mod=readonly`, `-trimpath` and verified dependency sums;
they do not run caller commands or `go generate`. Exact client architectures, dependency/network policy and
deterministic build inputs remain to be confirmed.

Account separation alone is not a general filesystem sandbox. The host contract must demonstrate that a build
cannot read the signer home/keychain or secrets exposed elsewhere on the host. Isolation controls run in safe
fixtures; source tests never authorize probing live keys or user data.

The builder emits a bounded regular artifact and receipt binding product, repository, commit, recipe/toolchain,
target, unsigned SHA-256 and exact byte size. The signer opens the input without following links, creates its
own private immutable snapshot, and independently verifies size/hash and receipt. It refuses links, replacement,
truncation, mutation or mismatch. The builder cannot alter the snapshot or trusted signing policy. The unsigned
artifact must reproduce byte for byte in an independent rebuild under the same recorded deterministic inputs;
a mismatch refuses signing. Recipes must bind version, date, VCS and other build inputs instead of inheriting
ambient values. The exact pinned recipe and independent rebuild procedure remain to be agreed before building.

## Signing, audit and recovery

The signer signs only its verified snapshot using the admitted P-256 identity. Native verification must establish
the actual selected certificate pin and designated requirement. Ad-hoc output, a different certificate or a
failed verification cannot succeed. Signing changes bytes: unsigned and signed hashes are separate fields.

The ordered release boundary is:

1. Establish request, allowlist admission, exact source authority and verified build snapshot.
2. Durably append an intent binding the operation and all release inputs before signing.
3. Sign the private snapshot and verify the resulting signature, identity and final hash/size.
4. Durably append the outcome and its artifact identity before releasing the artifact.
5. Release only the artifact bound to the successful outcome and return its receipt.

The log is append-only, inaccessible to the builder, integrity chained and externally checkpointed. Chaining
alone does not establish resistance to root or signing-account compromise. The checkpoint custodian, durability
primitive, concurrency ordering and retention policy require agreement. An audit failure before intent prevents
signing; failure after signing withholds the artifact in private staging and truthfully reports its known state.

A client scopes `request_id` within its authenticated identity. The semantic request includes version, product,
repository and commit. Reuse for different inputs refuses. A matching retry returns the existing operation's
state/result; policy and authority changes must never be hidden by retry. Stored policy identity and retry
freshness behavior remain to be specified before implementation.

Concurrent duplicates must not start independent signing operations. An interrupted operation with an intent
and no durable outcome remains uncertain until recovery reconciles private staging and verification evidence.
It must neither release nor blindly sign again. Recovery records append to the audit instead of rewriting it.
An uncertain result is not a claim that no signature was created. Audit retention must cover the retry horizon.

## Acceptance controls

Each forbidden case has a nearby valid control and asserts the intended refusal and post-state. Live destructive
plants and real private-key reads are excluded; runtime isolation evidence needs its separately authorized lane.
Every selected test lane runs and reports even if an earlier lane fails.

| Surface | Valid control | Forbidden case and observable invariant |
| --- | --- | --- |
| Envelope | Both clients' complete requests | Binary/path/command injection, duplicate/unknown/oversize fields; no build/sign |
| Admission | First confirmed secret-tool admission; later qualified release | Missing admission/unknown identifier; no build/sign. Later release has no presence prompt |
| Authority | Exact owner-signed independently reviewed checked landed commit | Wrong signer, unlanded, unreviewed, wrong-head review, missing/unknown checks; no sign |
| Builder | Real trusted exact-source build | Signer builds or builder reaches signing secrets; intended isolation refusal, no release |
| Snapshot | Matching immutable artifact/receipt and independent unsigned rebuild | Symlink, substitution, truncation, hash or reproducibility mismatch; no sign |
| Signature | Pinned P-256 identity and native verification | Ad-hoc/wrong identity/DR mismatch; no release |
| Audit | Durable intent then signature then durable outcome | Missing intent prevents sign; failed outcome withholds artifact without claiming no signature |
| Recovery | Same completed request returns its result | Changed-input retry conflicts; interrupted/parallel retry cannot duplicate signing or release uncertain output |

Instrument controls must demonstrate a known forbidden effect is detected for the intended reason. Source
fixtures prove only the paths they exercise; they do not establish host account isolation or deployment success.

## Open agreement points

The [open agreement register](../../UNRESOLVED_QUESTIONS.md) names the missing client and custody facts. Building
starts only after the request/result/data/error/refusal, authority, build/handoff, admission, audit/recovery and
acceptance contracts are agreed. A later installer must enumerate exact write targets, preflight, rollback and
one absolute maintenance entrypoint. Host execution remains a separate exact-operation decision.
