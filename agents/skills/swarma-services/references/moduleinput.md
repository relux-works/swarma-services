# Contributor use of moduleinput

Read the [implementation](../../../../signer/internal/moduleinput/input.go) for exact types and checks. Its Go module is `github.com/relux-works/swarma-services/signer`. An importer must be inside that module's import-path tree, beneath the parent of `internal`; an unrelated external module cannot import this package.

## Supplied input and result

Pass `Input` to `Verify`. Preserve the exact original `GoMod` and `GoSum` bytes and their receipt-provided lowercase `GoModSHA256` and `GoSumSHA256` values. Matching hashes bind bytes; they do not authenticate their source. Do not regenerate real trust anchors from replacement content.

- `Records` contain `Path`, `Version`, `Directory`, `GoModH1` and `ModuleH1`, ordered strictly by path then version using Go string order. `Directory` is `m/` plus the lowercase SHA-256 of path, one NUL byte and version.
- `GoModH1` is mandatory and must match the original `go.sum` key for path and version plus `/go.mod`. Nonempty `ModuleH1` must match its separate path/version key and the full supplied module contents. An empty `ModuleH1` means metadata-only: supply exactly its root `go.mod`, not compiled-module closure.
- `Files` contain `Path`, `Mode` and `Bytes`, ordered strictly by path. Paths are canonical modules-root-relative paths under the record's directory. Only mode `"100644"` is accepted; directories are implied. Symlinks, executable entries, duplicate paths and case/Unicode or file/directory collisions are refused.
- Keep caller buffers stable during `Verify`. All supplied records are checked, including records not used by a later build. The verifier checks finite subset bounds before copying; these are not whole-manifest limits.

On success, use the returned `*Verified`, whose `IsVerified()` is true. A zero value is not verified. `Source()`, `SourceHashes()`, `Records()`, `Files()` and `FileSHA256s()` expose the snapshot; returned slices and file bytes are independent copies. Per-file SHA-256 values describe content and cannot replace original Go `h1` anchors.

On refusal, the snapshot is nil. Classify with `errors.Is(err, ErrInputInvalid)` and `errors.As(err, &invalid)` for `*InvalidError`; its `Reason` is a predicate identifier without input bytes. Do not repair, reorder, drop an unused record or rebind source bytes to turn a refusal into approval.

## Inert valid example and adjacent refusal

This is documentation for contributor code **within the signer module**, for example a hypothetical `signer/examples/moduleinput/example.go`. It is not an external import recipe, executable entrypoint or agent live operation. Do not create or run it as part of reading this skill.

The synthetic metadata-only input follows the first fixed vector and fixture construction in [the package tests](../../../../signer/internal/moduleinput/input_test.go) and [standard Go vectors](../../../../signer/internal/moduleinput/testdata/standard-go.json). Its literal source hashes bind only the synthetic bytes shown here; they confer no authority for real source acquisition.

```go
package example

import (
	"errors"

	mi "github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

func contributorExample() error {
	const dir = "m/cc9b3d5cc55385bb26c5cae18e78f1e5d964f7929d5bed0a13487408b88009da"
	in := mi.Input{
		GoMod:       []byte("module example.com/source\n\ngo 1.24.0\n"),
		GoSum:       []byte("example.com/alpha v1.0.0/go.mod h1:IsP8vCNFdW6vmpL0E7nsHMTrIg0FpnD14y/rw0deHog=\n"),
		GoModSHA256: "043f8028c69aae66aae202fde1ac2d72732bfa0eb286def733f7a276e6b7e920",
		GoSumSHA256: "0735c8abbb19493910c79231c34a4e6391cd2576b4fd67ea2296e45f21b54e00",
		Records: []mi.Record{{
			Path: "example.com/alpha", Version: "v1.0.0", Directory: dir,
			GoModH1: "h1:IsP8vCNFdW6vmpL0E7nsHMTrIg0FpnD14y/rw0deHog=",
			ModuleH1: "",
		}},
		Files: []mi.File{{
			Path: dir + "/go.mod", Mode: "100644",
			Bytes: []byte("module example.com/alpha\n\ngo 1.24.0\n"),
		}},
	}
	verified, err := mi.Verify(in)
	if err != nil {
		return err
	}
	if !verified.IsVerified() {
		return errors.New("missing verified snapshot")
	}

	// Adjacent refusal: change only a copied file entry's mode.
	bad := in
	bad.Files = append([]mi.File(nil), in.Files...)
	bad.Files[0].Mode = "120000"
	refused, err := mi.Verify(bad)
	var invalid *mi.InvalidError
	if refused != nil || !errors.Is(err, mi.ErrInputInvalid) ||
		!errors.As(err, &invalid) || invalid.Reason != mi.Mode {
		return errors.New("expected input_invalid: mode")
	}
	return nil
}
```

Expected from the implementation: the first call verifies this supplied metadata-only subset. The second returns nil and `input_invalid: mode` before material/checksum checks. It does not create a symlink. Neither outcome proves graph completeness, compiled-content sufficiency, an admitted manifest, a production build or signing readiness. This example was checked statically, not compiled or executed.
