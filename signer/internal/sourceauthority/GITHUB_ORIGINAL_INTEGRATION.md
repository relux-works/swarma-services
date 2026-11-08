The original Git reader is a closed component. It does not make protected first
run ready and has no public constructor. Its zero value returns a finite
`github_git_shared_phase_connector_missing` refusal without I/O.

The composition owner needs a small, separately reviewed integration change:

* Pass the currently admitted `acquisitionPhase` to the objects leg (including
  its second refresh), instead of passing only context/query. Do not start a
  phase inside this reader. Preserve the original deadline, remaining attempt
  and aggregate counters, and installed policy rechecks.
* Supply an installation-qualified numeric connector for `github.com:443`.
  The existing API connector admits only `api.github.com:443` and cannot be
  reused as evidence of Git destination provenance/currentness. No issuer or
  DNS fallback is supplied here.
* Qualify the combined transport/parser/work reservations against the whole
  source phase. Component fixtures cannot establish this. In particular, the
  existing phase has no separate allocator/work ledger or production issuer
  for this new transport's conservative TLS reservation.

The supported wire subset is smart HTTPS Git protocol v2, SHA-1, filtered
commit-only pack v2 with full commits and in-pack REF_DELTA objects. Delta
instructions reproduce original bytes before normal commit parsing and content
OID checks. Bases may occur before or after their users. The existing inventory
count bounds resolution passes and chain length; both inflated instructions and
reconstructed commits must fit the existing commit-size ceiling. All storage,
copy/parser work and bounded resolution scans debit the same phase byte ledger,
without refunds, a new budget or a renewed deadline.

Missing/external bases, unresolved cycles, OFS_DELTA, other object kinds,
malformed instructions, invalid sizes/ranges, checksum failures, duplicates and
incomplete/trailing packs refuse. There is no thin-pack lookup or Git subprocess
fallback. The client does not request `ofs-delta` or `thin-pack`.

REF_DELTA qualification is a prerequisite before any real reader integration or
issuance. The offline default-window stock-Git control inspects object headers
to require an actual REF_DELTA, then verifies exact signed commits, trees, OIDs,
ancestry and shared accounting. The older `pack.window=0` control covers only
the explicitly limited non-delta subset. Neither control qualifies a live
provider. Fresh independent whole-candidate review, an exact-head marker and
pinned-dependency Linux CI must qualify this source revision before publication;
the separate transport/phase integration obligations above still apply.

This remains a bounded PARTIAL implementation with unreachable new readers.
The public effective-checks port still refuses, no issuer or provider is
installed, and the separate `q-gql-token` integration question remains open.

The reader checks canonical installed repository/name, default HEAD symref and
branch OID, exact requested object OID, raw pack and commit hashes, bounded real
parent reachability, and a second default-ref read. It returns the untouched
commit bytes. Signature trust remains with the existing owner verifier; this
reader does not invent trust or treat an embedded signature as verified.

No effective-checks, strict never-edited GraphQL, installation membership,
admission, audit, lease or effect gate is changed. Whole-candidate independent
review and source-owner custody remain required before any integration.
