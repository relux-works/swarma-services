# Exact landed source authority component



The governing contract is [baseline r5](baseline-r5.md), [builder/DATA r2](builder-wire-data-r2.md), [capacity r3](manifest-capacity-r3.md), then [integrated r2](integrated-addendum-r2.md); the latter controls its explicit deltas. The [open register](../../UNRESOLVED_QUESTIONS.md) remains applicable. This component changes no existing package, wire schema, dependency, active manifest capacity or README.

`internal/sourceauthority.New` accepts protected policy and two explicitly trusted dependencies: `Source` and `Clock`. A release caller supplies only a configured product/alias, exact lowercase 40-hex SHA-1 commit and service correlation bindings. It cannot supply observations, keys, URLs, review scopes, check policy or verification booleans. The constructor copies mutable policy slices and public key bytes. A zero `Qualification` is absent. Results contain immutable scalar summaries; raw event bodies and Matrix room/event/sender provenance remain outside product summaries.

`BeforeBuild` and `BeforeSign` each perform a new complete source observation and check every request/response field, including phase, operation, nonce and policy. Build success is never cached as presign authority. The [effect-boundary source composition](sourceauthority-effects.md) generates service nonces, checks constructor-bound endpoint identities, retains exact job/manifest correlation and records neutral projections before invoking trusted effect adapters. Actual authenticated transports, native effects/admission and durable intent/outcome remain absent production dependencies; the composition does not qualify them.

## Verified predicates

The raw signed Git commit is hashed in Git's SHA-1 object domain; its requested object identity and tree are checked without substituting a tree-equivalent commit.

SSH Ed25519 signatures use real cryptographic verification of Git's unchanged unsigned commit bytes, the `git` namespace, empty reserved field and SHA-256 or SHA-512 SSHSIG digest domain; full public-key fingerprints and exact public key bytes must be admitted for this canonical repository.

The current authenticated canonical repository/default-branch record must match installed configuration; equal landing compares the exact object, and ancestor landing requires a hash-verified parent path from the observed default head to that same signed object, including a nonrewriting merge path.

The authenticated exact-head producer handoff, current merged PR, selected active COMMENT review, review inventory and explicit blocking/withdrawal state must bind the configured repository, PR, head and base.

The platform COMMENT must start with the finite head/base ACCEPT declaration and contain exactly one neutral digest line, plain or singly backticked; COMMENT, a hosting-account name, a quoted ACCEPT or a missing digest alone never qualifies.

The stored verdict body is hashed as its exact JSON-decoded UTF-8 string, preserving newlines and Unicode spelling, and must declare ACCEPT at byte zero with one canonical PR line and one exact-head/base line; explicit unquoted blocking or contradictory verdict markers refuse.

Lookup covers exactly all configured scopes at their authenticated read frontiers over platform time minus 24 hours through plus 300 seconds, within 30 seconds, four scopes, 256 aggregate pages, 16,384 read events and 16 MiB decoded bodies; partial, truncated, unknown, conflicting replay or over-budget coverage never proves uniqueness.

Pagination repeats of the identical scope/event are one event, conflicting versions refuse, different events with the same digest are ambiguous, and exactly one matching event must be intact and from an allowed authenticated reviewer distinct from the authenticated producer.

Required checks are matched by exact head and context/application identity against a separately established current required-check policy and complete inventory; missing, pending, failed, skipped, ambiguous or wrong-head required checks refuse.

`no_required_and_none_present` requires a positively known no-required policy and a complete successful empty inventory; unknown rules, API denial, partial inventory and green CI cannot establish that case.

Observations use zero positive future tolerance and a 1..300-second lease; the complete source read and local verification share one absolute 30-second budget, and remaining lifetime is capped by a same-process monotonic deadline without rounding fractional time upward. Sampled clock readings carry their full measured `SampleSpan`: receipt deadlines retain the leading monotonic anchor, while final qualification, budget and freshness checks include the trailing endpoint and conservative upper wall bound. Sampling delay cannot extend the receipt deadline or hide expiry inside the measured bracket.

`CheckFreshness` checks the local lease and trusted clock epoch. The optional [protected local Policy route](protected-policy.md) also rereads the current installed file digest, both at qualification boundaries and freshness checks. This cannot establish another phase or replace a new presign provider observation or final release-policy check. Effect callers pass their original job context to `CheckFreshnessContext`.

## Trust boundary and remaining dependencies

`Source.Read` is a privileged adapter seam, not a user-input decoder. The adapter must acquire and authenticate the actual configured provider records, current local policy, default branch, current effective review state, required-check rules/inventory, Matrix origin/member senders, producer handoff and complete per-scope pagination/frontiers. Enum values describe those reads; setting an enum in a client record or fixture does not authenticate anything. A callback that returns caller assertions is an invalid implementation of this interface. No production adapter is supplied, and no fixture result is described as actual GitHub/Matrix authority.

The normative source does not supply the producer-handoff body grammar, current-provider normalization/selection proof, complete ruleset access or an actual forward-form body packet in this workbench. Those are precise production dependencies. The finite text implementation recognizes these local fixture spellings:

```text
Independent source review: **ACCEPT** for exact head `<head>` (base `<base>`).
Verdict record digest: sha256:<digest>

ACCEPT: independent source review of <configured repository name> PR #<number>.
PR <configured canonical repository URL>/pull/<number>
Exact head <head>, base <base>.
```

The stored declaration also accepts the same line without its final period, and the digest value also accepts one enclosing pair of backticks. Qualification against the actual supplied forward-form COMMENT/verdict is still required before freezing or activating this parser. Unrecognized forms refuse; no permissive substring fallback is provided. This fixture spelling is not a claim that a missing real witness used these exact punctuation bytes.

The source must normalize current effective review state and select the eligible review from authenticated delivery records, including withdrawal/blocking coverage; this package does not infer that selection from arbitrary historical comments. Source must likewise normalize current required-check identities and attempt selection. Multiple unresolved records for one check identity return `authority_unavailable`; no invented latest-attempt policy is applied. A known no-required policy with a nonempty inventory has no corresponding success variant in the present projection contract and returns `authority_unavailable: no_required_nonempty_inventory` pending its precise source-owned treatment.

Only SSH Ed25519 owner signatures are implemented. Admission of actual full repository-scoped owner pins, actual key algorithm and its qualified verifier remain external; unsupported algorithms fail closed and no unrelated signers file is consulted. The synthetic fixture key is not an admitted owner. ECDSA P-256 native artifact signing is a distinct downstream boundary and is absent here.

Installed `Profile` bounds commit bytes, ancestry path length, platform-review count and check count before processing. The contract does not fix capacities for these raw adapter-internal records. Fixture values (1 MiB/256/256/256) are resource bounds for local qualification, not a selected production policy; exhaustion returns unavailable. An actual source/adapter profile must be agreed and qualified before production. Source must enforce bounded acquisition before allocation, honor its context deadline and transfer stable ownership of returned observations. The in-process core does not sandbox or forcibly terminate a malicious configured Source.

`Clock` must come from a qualified same-process clock/discontinuity detector, change epoch on restart/detected discontinuity, and return errors on unknown time. No host clock is declared qualified. Refresh failures, expired observations, changed/revoked/unknown policy and clock uncertainty refuse. There is no per-release owner-presence requirement, retry override or cache fallback.

The [process clock source implementation](sourceauthority-clock.md) implements this seam with sampled wall/monotonic continuity and permanent refusal on uncertainty. Its source controls do not establish target clock admission or native qualification.

There is no credential reader, provider transport, live request, private-key reader, source DATA acquisition, admission store, IPC parser, production adapter, builder, native signing, audit, fetch or service entrypoint in this package. Signing/audit composition belongs to separate units. Native account/Keychain/DR isolation, actual provider access/custody and whole-solution acceptance remain explicit gates.

## Executable control groups

Boundary controls pair valid independently refreshed build/sign observations with wrong source bindings, wrong repository-scoped keys, unsigned or altered signatures, unlanded/draft/wrong-head candidates, unavailable providers and changed presign review/check/policy state.

Signature/landing controls use synthetic in-memory keys and an independent Git/OpenSSH public-key verification oracle, test both SSHSIG hash algorithms, and pair equal/nonrewriting ancestor landings with tree-only or substituted ancestry failures.

Review/lookup controls pair valid plain/backticked digest forms, exact body bytes, complete multiple scopes and identical pagination replay with missing/changed/ambiguous verdicts, producer reviews, quoted or contradictory verdicts, partial frontiers and finite window/page/event/body-budget failures.

Check controls pair all required exact-head context/application successes and the complete no-required empty case with unknown/partial inventories, missing checks, wrong bot/head, non-success conclusions and unresolved duplicate check coverage.

Clock/control controls pair valid bounded leases and 30-second contexts with stale/future/overlong observations, expiry during verification, restart/backward clocks and monotonic-cap failures; malformed digest/SSHSIG controls reject at their intended predicates without manufacturing native effects.

Qualification receipts, initial failures, causal bypass plants, exact byte restoration and final ordinary/race/vet outcomes are exported in the workbench packet, not asserted by this source document. Synthetic observations establish local verifier behavior only; they establish no actual provider authority, installation or release acceptance.

## Conservative review-line visibility and pending syntax decision

The existing authority requirements are in [the r5 text grammar](baseline-r5.md#proposed-finite-release-signing-protocol), specifically its unquoted initial declaration, exactly one canonical PR/head binding, exclusion of quoted/fenced matches, and refusal of the four explicit unquoted contradiction prefixes. [The authority adapter contract](baseline-r5.md#proposed-exact-source-authority-adapter) separately requires the exact neutral digest and exact stored-body hashing. These requirements remain unchanged at both `BeforeBuild` and `BeforeSign`.

Those paragraphs do **not** define fence run length, tab/space indentation, info strings, closing suffixes, lazy quote continuation or arbitrary Markdown containers. The following is this component's conservative supported implementation subset, not an owner-adopted contract amendment or a claim to implement a complete Markdown renderer:

- Only LF separates lines; CR, vertical tab and form feed refuse the body. Required declaration/binding bytes and digest spelling remain exactly as above. Context scanning neither trims nor normalizes accepted authority lines or the hashed body.
- A fence opens only after zero through three ASCII spaces, with a complete run of at least three identical backticks or tildes. The complete delimiter character and run length are retained. Backtick opener suffixes may contain text/space/tab but no backtick; tilde opener suffixes may contain backticks. An unsupported backtick info string refuses.
- While fenced, all lines are non-authoritative, including quote-prefixed lines, shorter runs, other delimiter characters, more deeply indented apparent closers and apparent closers with text suffixes. A closer has zero through three ASCII leading spaces, the same delimiter, a full run **at least** the opening length, and only ASCII spaces/tabs afterward. These other apparent closers remain literal fenced content; they never toggle state. An eventual real closer can end the section.
- Four or more leading spaces, or a tab after zero through three spaces, are literal indentation and cannot open/close a fence. An indented block must start after a blank line, or continue existing literal indentation; ambiguous paragraph-adjacent indentation refuses. Dedenting exposes the next ordinary unquoted line, including a contradiction. Blank lines contain only ASCII spaces/tabs.
- Outside fences/literal indentation, a line with zero through three spaces followed by `>` is quoted and never authoritative. Nested or quoted fence delimiters do not open a global fence. An unprefixed continuation without a blank separator is unsupported quote ambiguity and refuses, unless it is an actual supported fence opener (which interrupts the quote). A blank line ends quote context.
- HTML introducers (`<`, including inline comments), bullet/ordered-list container introducers and inline backtick spans that do not close on the same line with an identical run are unsupported outside code/quotes and refuse. Matched inline spans in ordinary notes remain supported. Outside an inline span, a backtick run immediately preceded by a backslash refuses conservatively, regardless of backslash parity; the scanner neither unescapes those bytes nor guesses a rendering. Inside a matched same-line span, backslashes remain literal code content. Only exact raw, unindented platform COMMENT digest prefixes defer payloads to its strict digest-value parser, preserving `platform_digest` for malformed values (HTML ambiguity still uses `platform_format`); no malformed value can qualify. Stored verdicts have no digest field: notes with that label receive the same delimiter/escape checks as every other ordinary note.
- Every opened global fence must close. Any unsupported or unclosed context invalidates the whole body, even when bindings precede it; earlier valid fields cannot authorize an ambiguous suffix. Context refusals use the existing platform/verdict format predicates, except malformed platform digest payloads use the strict parser's `platform_digest` predicate as bounded above. Ordinary unquoted contradictions still use `review_blocking`. Quoted/indented/fenced bindings cannot count, and ambiguous context never becomes authority by a fallback interpretation.

**Proposed contract decision, not adoption:** the source/delivery owner must settle the versioned rendering/visibility subset (including the above indentation, delimiter and ambiguity rules) against the actual forward-form COMMENT/verdict witness before production freeze. Supporting additional container, multiline inline-code or renderer-specific forms requires an explicit grammar decision and qualification. This revision supplies conservative local behavior and regressions; it does not invent that missing agreement, expand trust or change the canonical body-field grammar.
