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
commit-only pack v2 without deltas. Unsupported capabilities, pack encodings,
progress/fatal sidebands and extra refs refuse. Supporting common delta packs
is remaining reader work, so this is a bounded PARTIAL implementation.

The reader checks canonical installed repository/name, default HEAD symref and
branch OID, exact requested object OID, raw pack and commit hashes, bounded real
parent reachability, and a second default-ref read. It returns the untouched
commit bytes. Signature trust remains with the existing owner verifier; this
reader does not invent trust or treat an embedded signature as verified.

No effective-checks, strict never-edited GraphQL, installation membership,
admission, audit, lease or effect gate is changed. Whole-candidate independent
review and source-owner custody remain required before any integration.
