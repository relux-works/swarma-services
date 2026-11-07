# Anonymous PR first-run contract gap

The anonymous PR first-run route cannot currently produce a truthful successful
`Source.Read` using the unchanged source-authority core. This is a source
contract compatibility finding, not a provider failure or a denial of the
authorized route. No production reader, installation or runtime is claimed by
this candidate. The bounded response transport and effect boundary are composed
as explicit unaccepted dependencies; their independent review is not inherited.

The route selects its handoff directly from repository, head, base and PR number,
and reads current PR reviews independently at both boundaries. It has no
message delivery, attestation or grant on this path. Anonymous transport requires
no provider credential or read-capability claim. A protected installed Policy
remains required; a request digest cannot admit that policy.

## Exact incompatibility

1. `New` requires nonempty `Policy.MatrixOrigin`, `ProducerSender`, reviewer
   senders and one or more scopes. Removing the delivery installation does not
   yield a valid Policy. Retaining those configuration fields does not prove
   that a PR was an authenticated delivery from that origin and sender.
2. After verifying the original signed commit and merged PR, `qualify` requires
   a `ProducerHandoff` with that exact configured origin and producer sender,
   nonempty scope and event, intact state, repository, head and PR number.
   The authorized PR tuple supplies repository/head/base/number. It supplies no
   Matrix origin, scope, event or authenticated Matrix sender. Copying configured
   identities into these fields would fabricate an acquired handoff. Leaving
   them absent refuses at `producer_handoff`.
3. `verifyReview` requires an active exact-head/base `COMMENT`, whose ORIGINAL
   body begins with the exact platform ACCEPT declaration and contains exactly
   one digest of a distinct stored verdict body. It then requires complete
   configured-origin/scope window frontiers and exactly one matching intact
   stored event from an allowed independent sender. Native `APPROVED` is not
   `COMMENT`; a generic comment is not the finite ACCEPT grammar. Even an exact
   existing platform comment cannot supply absent stored-event coverage.
   The stored verdict and platform comment have different required first lines;
   the same body cannot be reused as both. Provider user IDs or logins do not
   themselves prove configured Matrix-member identity.

The narrow missing contract is an explicitly authorized, core-compatible
PR-native producer/review provenance and selection mapping. It must say how real
immutable provider identities, original body bytes, independent reviewer
identity, original base binding and current complete visibility satisfy the
existing predicates, or explicitly authorize a reviewed change to the core's
mandatory delivery/verdict contract. The adapter cannot make that change by
manufacturing observations. A native approval alone does not authorize replacing
either existing grammar. No fallback to authenticated reads is proposed.

This finding does not claim anything about which reviews or Git objects exist
in the public selected repository. No live provider evidence was read. Exact
original signed-object acquisition and effective rule/attempt visibility still
need their own implementation and qualification; metadata JSON reconstruction,
a green check or a metadata 404 cannot establish them. The bounded transport
alone proves none of those facts.

## Executable causal evidence

`first_run_contract_test.go` reuses the current core, its positive synthetic
signed-object fixture, and the existing bounded HTTP acquisition implementation.
Its synthetic TLS server serves bounded native-shaped PR and review documents
and original signed Git object bytes. The raw-object endpoint is explicitly a
fixture oracle, not a claimed GitHub endpoint or Git pack implementation.

The full legacy synthetic evidence qualifies. Holding all unrelated evidence
positive, the acquired PR tuple alone fails `producer_handoff` at both phases.
Removing delivery configuration fails construction. With counterfactual legacy
delivery retained solely to isolate review gates, native approval fails review
kind/binding, an ordinary comment fails exact grammar, absent scopes fail
coverage, and empty scope events fail digest uniqueness. These are compatibility
controls, not a successful anonymous production path or accepted installation.

The package's existing missing/self/stale-head/ambiguous review, check-policy,
signature, cancellation and absolute-budget controls remain unchanged. No
second transport, core, parser grammar, success-returning observation factory or
refusal-only production placeholder is introduced.

Before any actual first run: obtain the missing mapping decision, accept the
exact protected local configuration, implement and qualify actual anonymous
acquisition, and obtain fresh independent whole-graph review plus the required
exact marker. Build and signing phases must each acquire current mutable state;
no successful build observation is signing authority. No release or native
activation is authorized by these synthetic checks.
