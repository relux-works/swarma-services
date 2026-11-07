This component remains PARTIAL and uninstalled. Its public
`ReadEffectiveGitHubChecks` method never returns qualifying evidence. A valid
candidate still returns `github_effective_checks_integration_gap` with a zero
result before acquisition. Synthetic TLS success is not public-provider qualification.

The private implementation acquires and repeats six canonical anonymous REST
reads: branch, branch protection, active branch rules, suites, runs and combined
statuses. It uses an already admitted acquisition phase and its exact context,
consumes the existing attempt pool, and reserves candidate parser/storage space
from that phase before each transfer. It never starts a new deadline or pool.
The reservation is conservative candidate accounting; it does not prove the
missing enclosing provider-wide work/TLS/transport accounting contract.

The supported candidate subset is deliberately narrow: a simple branch whose
current head equals the requested commit, public suites, fewer than 30 entries
per inventory, required checks pinned to numeric application IDs, successful
completed runs, and no legacy commit statuses. Full pages, missing totals,
inconsistent counts, unknown rules, unknown apps, duplicate runs, competing
attempts, empty policy and inaccessible policy refuse. Exact duplicate run IDs
also refuse; they are not silently deduplicated. Attempts are not ordered by
numeric ID or timestamps. The provider's documented default latest filter is
used only for candidate acquisition, with ambiguity refusing. Output ordering
is deterministic presentation, not proof of attempt recency.

Minimal shared integration changes, separately owned and NOT made here:

1. Pass a source-owned admitted phase and exact phase context into the checks
   port, including both rechecks. The current public checks interface and source
   composition do not pass this budget. Context values are deliberately stripped;
   they must not become a hidden accounting channel.
2. Extend the concrete transport with bounded pagination/visibility metadata and
   installed page profiles. It currently drops Link and disallows query strings.
   Unknown or missing page metadata must refuse. A short array is only a
   candidate here; it cannot assert Complete.
3. Qualify aggregate response, parser, transport and work preallocation across
   all readers, failed attempts and repeated reads. Retain the original deadline,
   joined cancellation lifetime and every stricter installed limit.
4. Admit protected source visibility and app policy. No anonymous first-run
   claim follows from the synthetic protection response. Represent policy source
   visibility in the shared result contract or retain refusal.

The existing strict never-edited GraphQL requirement, policy/member rechecks,
lease/admission/audit behavior, other missing provider ports, and installation
gates remain. This unit introduces no authentication issuer, token, scope,
resolver, connector capability, signing/grant/funds/runtime action or live probe.

Endpoint choices follow official primary documentation:

- [Branch protection](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection)
  documents the protection response and Administration read permission. It does
  not document the public unauthenticated exception shown for the checks/rules
  endpoints. Anonymous protection visibility remains a real first-run blocker;
  404 is never interpreted as no required checks.
- [Active branch rules](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch)
  includes active applicable rules across repository and organization levels,
  permits public unauthenticated reads, and defaults to 30 entries per page.
- [Check runs](https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference)
  documents latest filtering and the reference endpoint's 1000-suite limit.
  The candidate separately bounds the complete suite count below that limit.
- [Check suites](https://docs.github.com/en/rest/checks/suites#list-check-suites-for-a-git-reference)
  supplies app, repository and head identity for suite correlation.

These documents informed a conservative offline subset. They are not a live
visibility test, owner admission or guarantee that all provider cases work.
