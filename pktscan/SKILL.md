---
name: pktscan
description: Build or use the standalone pktscan packet scanner with counts-only output and bounded extraction.
---

# pktscan

Read [the README](README.md) for the exact count contract, bounded ERE dialect,
archive limits, refusal behavior and operator-owned-directory assumptions.

This is an independent Go subproject. From `pktscan/`, use Go 1.26.8 with
`GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build ./cmd/pktscan`.
It has no third-party dependencies. Contributor checks are `go test -count=1
./...`, `go test -race -count=1 ./...` and `go vet ./...` in this module.
Run development checks offline with read-only source/tools and a fresh private
HOME/TMP/cache, as described in the README.

Invocation: `./pktscan DIR --patterns FILE [--known-base FILE]`; DIR precedes
flags. Use only the operator-designated packet and controls. Extraction creates
`DIR/.pktscan-unpacked` exclusively and refuses existing output. It never
executes extracted files. It is not a sandbox against hostile same-UID writers.

Keep patterns, input paths and matches out of diagnostics and logs. Successful
output contains only JSON counts in `new` and `known_base` buckets. Test with
synthetic fixtures only; never seek actual owner marker patterns for testing.
Independent exact-head review and source-owner gates remain required for landing.
