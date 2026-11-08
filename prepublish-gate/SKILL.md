---
name: prepublish-gate
description: Check a bounded immutable Git candidate with private patterns, operational hygiene and SSH signatures, or perform an explicitly authorized leased publication using the existing client.
---

Read [README.md](README.md) for exact input grammars, counts, finite limits,
unsupported histories and publication requirements. This is an independent Go
1.26.8 module with no third-party dependencies. Build `./cmd/prepublish-gate`;
run `go test -count=1 ./...`, `go test -race -count=1 ./...` and `go vet ./...`
with downloads disabled in a private offline sandbox. Use synthetic fixtures only.

Acquire source separately. Pin full base/candidate OIDs and use only the
operator-designated private patterns, public allowed-signers file and exact
principal. Run `check` first. Never seek actual private marker inventories for
tests or log caller paths, patterns, messages, values or native tool diagnostics.
Installation-specific names and identifier formats must be supplied through that
private input; there is no embedded inventory or fallback. Keep that file out of
public source, diffs, history and artifacts. Private hits are counts only.
A zero hit count is meaningful only with completed checks and a successful exit.

Publication requires explicit user authorization, `publish --execute-publication`,
a canonical matching repository/URL, the existing authorized-client configuration,
an explicit default-branch ref that preflight observes equal to the base,
and an exact base OID or explicit `absent` lease for every destination branch.
Checking the default ref does not update it. Its read-to-push race remains unless
a separately qualified receiver policy closes it; do not add a default update to
assert it. Review/custody/marker gates are external requirements. A clean scan and lease do
not supply them. Stop on any refusal or uncertain push result; inspect remote
state through the authorized client before any separately authorized new attempt.
Do not retry, change authentication routes or fall back to a non-atomic push.

For an explicitly selected read-only tail inventory, use `tails --repo ABSOLUTE`
or bounded `tails --root ABSOLUTE`; read [TAILS.md](TAILS.md) first. The command
never contacts GitHub or modifies sources. Optional PR ages use validated, supplied
projected metadata. Preserve incomplete coverage, unknown ownership/freshness and
nonzero exits; cached-remote absence is not proof of absence online. The every
three day operator suggestion creates no schedule or disposition authority.
