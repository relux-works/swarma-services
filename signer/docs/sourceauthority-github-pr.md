# Explicit GitHub PR source route

This source candidate implements a separate PR-derived handoff and the native
PR/review acquisition and normalization portion of `Source.Read`. It is ready
for independent source review. It is **not** an installed provider or a completed
first run. Transport qualification, protected policy installation, Git-object
acquisition and complete check visibility remain separate composition work.

`New` retains the legacy Matrix route and its exact configured origin, sender,
event, scope, window and frontier predicates. `NewGitHubPR` explicitly binds the
PR route at protected construction. Requests cannot change the route. The PR
handoff is the canonical repository, exact head, exact base and PR number read
from the native merged, non-draft PR. Its native producer account must match
protected installation. Matrix producer and lookup fields remain empty. No
message envelope, fabricated Matrix event or additional wire format is used.

A protected account-to-member mapping is required. It binds immutable numeric
GitHub account IDs and exact logins to the **existing** configured producer and
reviewer members. An account is not membership by itself. The selected reviewer
must be an allowed member, with both a different numeric account ID and a
case-insensitively different login from the producer. Missing admission fails
configuration. This candidate supplies no real account mapping.

The platform review must still be an active `COMMENT` normalized from native
`COMMENTED`, tied to the exact PR/head/base. `APPROVED` is not a substitute. The
existing finite platform header/digest and stored-verdict grammars are unchanged.
The current PR base is only correlation: the original COMMENT header and the
separately acquired stored-verdict body must independently bind the historical
base. Current unresolved `CHANGES_REQUESTED` reviews block qualification even
on other heads. A dismissed or absent selected review refuses.

## Unresolved stored-verdict contract

The existing COMMENT grammar names the SHA256 of a **different stored verdict
body**. Its original decoded UTF-8 bytes must match, and the original stored
verdict grammar must bind the canonical PR/head/base. The core counts all digest matches
before filtering by member, deduplicates identical references, and refuses
conflicting references or multiple distinct matches. Stored bodies remain
capped at 16 MiB and examined records at 16,384. A review header alone cannot
satisfy this requirement. The PR disposition does not identify a real
store, original verdict selection/provenance, unique-match proof, or current
integrity mechanism. This candidate deliberately leaves the production
`githubVerdictReader` unimplemented. It does not invent a PR comment convention,
copy configured IDs into claimed evidence, collapse the two existing body
grammars, or treat a digest as self-authentication.

The source custodian must resolve that exact storage/provenance/selection
mapping and admit the real account/member relation. Until then production
assembly refuses missing dependencies. The test-only stored verdict reader is
an explicit deterministic laboratory fixture. Its successful result does not
resolve this contract or create an installed policy.

## Acquisition and phase binding

The concrete adapter uses the existing bounded anonymous transport with fixed
canonical GitHub API paths for the installed repository and PR number. It adds
no transport changes, credentials, redirects, provider URLs from requests, or
fallback reads. Git objects are obtained through the separate source-owned Git
reader; no GitHub JSON reconstruction or synthetic raw-object endpoint is used
as original Git evidence.

The supported review inventory is conservatively a non-full default GitHub page
(fewer than 30 records), additionally bounded by installed profile capacity.
Full pages refuse rather than implying complete pagination. Pagination, response
header qualification and transport corrections remain pending composition. The
adapter is therefore unqualified for production visibility; a short successful
laboratory page does not prove live provider coverage.

Every phase independently acquires the current installed-policy state,
repository/default head, original Git object/path, PR, reviews, checks and stored
verdict. It re-reads mutable state before return and refuses byte changes in the
PR/review documents or changes in policy generation, Git snapshot, check state,
or verdict provenance. The current policy snapshot must also retain the exact
installed account/member admission; a constructor mapping alone is insufficient.
This is a bounded change-detection protocol, not an atomic provider transaction
or proof of an unseen transient change. Each phase
retains its service-generated query/nonce, the existing absolute 30-second
budget, cancellation, single active read, body/record limits and final core
signature, ancestry, check, lease and clock validation. Build success supplies
no cached signing authorization.

JSON is bounded by the existing transport before decoding. Invalid UTF-8,
unpaired UTF-16 surrogate escapes, decoded duplicate keys, case-folded member
aliases, excessive depth and excessive native review arrays refuse before typed
normalization. Exact decoded body bytes are preserved for the unchanged digest
and finite grammar checks. New helper and test code is Go.

## Validation and first-run limits

Offline synthetic TLS tests exercise the actual acquisition/normalization and
both core phases with original ephemeral fixture-signed Git bytes. They test
fresh phase reads, immutable membership copying, missing/self/dismissed reviews,
changed heads and bases, source snapshot changes, absent policy/provenance,
unsigned/unadopted commits, cancellation, limits and malformed JSON. Legacy
Matrix tests remain supported and run in the same suite.

A real first run needs a new real candidate PR and a fresh independent COMMENT
review in the pinned grammar from a platform account distinct from its producer.
No such PR tuple or distinct authenticated reviewer account is supplied here.
Old or self-authored reviews cannot be positive evidence. No installed policy,
real successful first run, independent review, marker, public push, PR creation,
landing, runtime activation or signing release is claimed.
