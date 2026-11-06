// Package moduleinput verifies supplied, decoded module material against exact
// original source checksums. It performs no filesystem, network, graph, build,
// acquisition, wire-decoding, or signing operation. Success establishes only the
// integrity of the supplied subset, never that omitted material is unnecessary.
package moduleinput

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/swarma-services/signer/internal/moduleformat"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/text/unicode/norm"
)

// These are independent upper bounds on this supplied subset. Whole-manifest
// accounting, raw framing/size/deadlines and qualified native filesystem
// semantics remain the responsibility of the integrating caller.
const (
	MaxRecords      = 512
	MaxFiles        = 8192
	MaxPathBytes    = 1024
	MaxVersionBytes = 128
	MaxFileBytes    = 64 << 20
	MaxDataBytes    = 1 << 30
	maxModuleBytes  = 500 << 20 // Standard expanded module zip limit.
	maxGoModBytes   = 16 << 20  // Standard module go.mod and root LICENSE limit.
)

// Record describes a supplied module. Empty ModuleH1 denotes metadata-only
// material. GoModH1 is always mandatory. There is no caller-supplied unused flag.
type Record struct {
	Path, Version, Directory string
	GoModH1, ModuleH1        string
}

// File is a decoded modules-root entry. Only mode "100644" is admitted.
// Other modes (including directory and symlink modes) remain representable so
// that the verifier can reject them. Directories are implied, never entries.
type File struct {
	Path, Mode string
	Bytes      []byte
}

// Input preserves both sequences exactly as supplied. Source hashes are the
// receipt's expected lowercase SHA256 values, not newly inferred trust anchors.
// The caller must keep all slices stable during Verify; unsynchronized concurrent
// mutation is outside this contract. No wire parsing or acquisition is implied.
type Input struct {
	GoMod, GoSum             []byte
	GoModSHA256, GoSumSHA256 string
	Records                  []Record
	Files                    []File
}

// ErrInputInvalid classifies any refused typed input.
var ErrInputInvalid = errors.New("input_invalid")

// Reason identifies the predicate that refused input, without echoing its bytes.
type Reason string

const (
	Bounds     Reason = "bounds"
	SourceHash Reason = "source_hash"
	SourceSum  Reason = "source_sum"
	Identity   Reason = "identity"
	Order      Reason = "order"
	Collision  Reason = "collision"
	Path       Reason = "path"
	Mode       Reason = "mode"
	Layout     Reason = "layout"
	Anchor     Reason = "anchor"
	Checksum   Reason = "checksum"
)

// InvalidError is an internal input_invalid refusal. It contains no input text.
type InvalidError struct{ Reason Reason }

func (e *InvalidError) Error() string { return "input_invalid: " + string(e.Reason) }
func (e *InvalidError) Unwrap() error { return ErrInputInvalid }
func invalid(r Reason) error          { return &InvalidError{Reason: r} }

type snapshot struct {
	input      Input
	fileHashes []string
}

// Verified is an immutable snapshot of verified SUPPLIED modules. It does not
// certify graph completeness, compiled-content sufficiency, or an admitted
// manifest. A zero value is not verified. Only Verify constructs a valid value.
// Accessors return independent copies, and can be called concurrently.
type Verified struct{ data *snapshot }

func (v *Verified) IsVerified() bool { return v != nil && v.data != nil }

// Source returns fresh copies of the exact original source bytes.
func (v *Verified) Source() (goMod, goSum []byte) {
	if !v.IsVerified() {
		return nil, nil
	}
	return bytes.Clone(v.data.input.GoMod), bytes.Clone(v.data.input.GoSum)
}

func (v *Verified) SourceHashes() (goMod, goSum string) {
	if !v.IsVerified() {
		return "", ""
	}
	return v.data.input.GoModSHA256, v.data.input.GoSumSHA256
}

func (v *Verified) Records() []Record {
	if !v.IsVerified() {
		return nil
	}
	return append([]Record(nil), v.data.input.Records...)
}

// Files returns copies in the original validated order, including fresh bytes.
func (v *Verified) Files() []File {
	if !v.IsVerified() {
		return nil
	}
	out := append([]File(nil), v.data.input.Files...)
	for i := range out {
		out[i].Bytes = bytes.Clone(out[i].Bytes)
	}
	return out
}

// FileSHA256s returns actual snapshot byte hashes in Files order. These hashes
// describe verified material; they are never substitutes for original h1 anchors.
func (v *Verified) FileSHA256s() []string {
	if !v.IsVerified() {
		return nil
	}
	return append([]string(nil), v.data.fileHashes...)
}

// Verify first checks finite bounds, then takes an operation-owned defensive
// copy. Every check and returned byte/hash refers to that same copy. Failure
// returns nil and never mutates caller state or exposes a partial snapshot.
func Verify(in Input) (*Verified, error) {
	s, err := copyBounded(in)
	if err != nil {
		return nil, err
	}
	if err = verify(s); err != nil {
		return nil, err
	}
	return &Verified{data: s}, nil
}

// budget uses subtraction before addition, independent of machine int width.
func budget(total *uint64, n, limit uint64) bool {
	if *total > limit || n > limit-*total {
		return false
	}
	*total += n
	return true
}

func copyBounded(in Input) (*snapshot, error) {
	if err := checkBounds(in); err != nil {
		return nil, err
	}
	// No input-sized allocation before all bounds have passed. Strings are
	// cloned as well, and checks below use only this operation's snapshot.
	out := in
	out.GoMod = bytes.Clone(in.GoMod)
	out.GoSum = bytes.Clone(in.GoSum)
	out.GoModSHA256 = strings.Clone(in.GoModSHA256)
	out.GoSumSHA256 = strings.Clone(in.GoSumSHA256)
	out.Records = make([]Record, len(in.Records))
	for i, r := range in.Records {
		out.Records[i] = Record{strings.Clone(r.Path), strings.Clone(r.Version), strings.Clone(r.Directory), strings.Clone(r.GoModH1), strings.Clone(r.ModuleH1)}
	}
	out.Files = make([]File, len(in.Files))
	for i, f := range in.Files {
		out.Files[i] = File{strings.Clone(f.Path), strings.Clone(f.Mode), bytes.Clone(f.Bytes)}
	}
	return &snapshot{input: out}, nil
}

func checkBounds(in Input) error {
	if len(in.Records) > MaxRecords || len(in.Files) > MaxFiles || len(in.GoModSHA256) != 64 || len(in.GoSumSHA256) != 64 {
		return invalid(Bounds)
	}
	var total uint64
	for _, b := range [][]byte{in.GoMod, in.GoSum} {
		if len(b) > MaxFileBytes || !budget(&total, uint64(len(b)), MaxDataBytes) {
			return invalid(Bounds)
		}
	}
	for _, r := range in.Records {
		if len(r.Path) > MaxPathBytes || len(r.Version) > MaxVersionBytes || len(r.Directory) > 66 || len(r.GoModH1) > 47 || len(r.ModuleH1) > 47 {
			return invalid(Bounds)
		}
	}
	for _, f := range in.Files {
		if len(f.Path) > MaxPathBytes || len(f.Mode) > 6 || len(f.Bytes) > MaxFileBytes || !budget(&total, uint64(len(f.Bytes)), MaxDataBytes) {
			return invalid(Bounds)
		}
	}
	return nil
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func h1(s string) bool             { return moduleformat.ValidH1(s) }
func identity(p, v string) bool    { return moduleformat.ValidIdentity(p, v) }
func directory(p, v string) string { return moduleformat.Directory(p, v) }

type sumKey struct{ path, version string }

func sourceSums(b []byte) (map[sumKey]string, error) {
	if !utf8.Valid(b) {
		return nil, invalid(SourceSum)
	}
	sums := make(map[sumKey]string)
	for line := range bytes.SplitSeq(b, []byte{'\n'}) {
		var fields [3]string
		n := 0
		for s := range strings.FieldsSeq(string(line)) {
			if n == 3 {
				return nil, invalid(SourceSum)
			}
			fields[n] = s
			n++
		}
		if n == 0 {
			continue
		}
		v := strings.TrimSuffix(fields[1], "/go.mod")
		if n != 3 || !identity(fields[0], v) || !h1(fields[2]) {
			return nil, invalid(SourceSum)
		}
		k := sumKey{fields[0], fields[1]}
		if old, ok := sums[k]; ok && old != fields[2] {
			return nil, invalid(SourceSum)
		}
		sums[k] = fields[2]
	}
	return sums, nil
}

func verify(s *snapshot) error {
	in := s.input
	if !lowerHex(in.GoModSHA256, 64) || !lowerHex(in.GoSumSHA256, 64) || sha(in.GoMod) != in.GoModSHA256 || sha(in.GoSum) != in.GoSumSHA256 {
		return invalid(SourceHash)
	}
	sums, err := sourceSums(in.GoSum)
	if err != nil {
		return err
	}
	claimed := make(map[string]int, len(in.Records))
	for i, r := range in.Records {
		if !identity(r.Path, r.Version) || r.Directory != directory(r.Path, r.Version) {
			return invalid(Identity)
		}
		if i > 0 {
			prev := in.Records[i-1]
			if r.Path == prev.Path && r.Version == prev.Version {
				return invalid(Collision)
			}
			if r.Path < prev.Path || r.Path == prev.Path && r.Version < prev.Version {
				return invalid(Order)
			}
		}
		if _, ok := claimed[r.Directory]; ok {
			return invalid(Collision)
		}
		if !h1(r.GoModH1) || r.ModuleH1 != "" && !h1(r.ModuleH1) {
			return invalid(Anchor)
		}
		if sums[sumKey{r.Path, r.Version + "/go.mod"}] != r.GoModH1 || r.ModuleH1 != "" && sums[sumKey{r.Path, r.Version}] != r.ModuleH1 {
			return invalid(Anchor)
		}
		claimed[r.Directory] = i
	}
	groups := make([][]File, len(in.Records))
	var collisions collisionSet
	s.fileHashes = make([]string, len(in.Files))
	for i, f := range in.Files {
		if !validPath(f.Path) {
			return invalid(Path)
		}
		if i > 0 {
			if f.Path == in.Files[i-1].Path {
				return invalid(Collision)
			}
			if f.Path < in.Files[i-1].Path {
				return invalid(Order)
			}
		}
		if f.Mode != "100644" {
			return invalid(Mode)
		}
		if !collisions.check(f.Path) {
			return invalid(Collision)
		}
		parts := strings.SplitN(f.Path, "/", 3)
		if len(parts) != 3 || parts[0] != "m" || !lowerHex(parts[1], 64) {
			return invalid(Layout)
		}
		idx, ok := claimed[parts[0]+"/"+parts[1]]
		if !ok {
			return invalid(Layout)
		}
		groups[idx] = append(groups[idx], File{parts[2], f.Mode, f.Bytes})
		s.fileHashes[i] = sha(f.Bytes)
	}
	for i, r := range in.Records {
		if err := material(r, groups[i]); err != nil {
			return err
		}
	}
	return nil
}

func validPath(p string) bool {
	return p != "" && len(p) <= MaxPathBytes && utf8.ValidString(p) && !strings.ContainsAny(p, "\x00\\") && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "." && p != ".." && !strings.HasPrefix(p, "../") && module.CheckFilePath(p) == nil
}

// This portable collision predicate rejects Unicode case and canonical
// decomposition aliases without changing stored names. Actual Darwin volume
// behavior and materialization still require native integration qualification.
func fold(p string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for t := unicode.SimpleFold(r); t != r; t = unicode.SimpleFold(t) {
			if t < min {
				min = t
			}
		}
		return min
	}, norm.NFD.String(p))
}

// collisionSet is a segment trie belonging to one Verify call. Slash is an
// NFD normalization boundary and is unchanged by simple folding, so folded
// segment chains have exactly the same equivalence as folded full ancestors.
// Interned segment IDs avoid retaining or re-folding complete ancestor keys.
// After a refusal the set is poisoned: partially inserted state is abort-only.
type collisionSet struct {
	segments map[string]segmentIDs
	folds    map[string]uint32
	edges    map[collisionEdge]collisionNode
	rejected bool
}

type segmentIDs struct{ exact, folded uint32 }
type collisionEdge struct{ parent, folded uint32 }
type collisionNode struct {
	id, exact uint32
	file      bool
}

func (seen *collisionSet) check(p string) bool {
	if seen.rejected {
		return false
	}
	if seen.edges == nil {
		seen.segments = make(map[string]segmentIDs)
		seen.folds = make(map[string]uint32)
		seen.edges = make(map[collisionEdge]collisionNode)
	}
	var parent uint32
	for rest := p; rest != ""; {
		segment, tail, more := strings.Cut(rest, "/")
		isFile := !more
		ids, ok := seen.segments[segment]
		if !ok {
			key := fold(segment)
			folded, found := seen.folds[key]
			if !found {
				folded = uint32(len(seen.folds) + 1)
				seen.folds[key] = folded
			}
			ids = segmentIDs{uint32(len(seen.segments) + 1), folded}
			seen.segments[segment] = ids
		}
		key := collisionEdge{parent, ids.folded}
		n, found := seen.edges[key]
		if found {
			if n.exact != ids.exact || n.file || isFile {
				seen.rejected = true
				return false
			}
		} else {
			// Verify's canonical paths imply at most MaxFiles *
			// ((MaxPathBytes+1)/2) nodes, well below the uint32 ID limit.
			n = collisionNode{uint32(len(seen.edges) + 1), ids.exact, isFile}
			seen.edges[key] = n
		}
		parent, rest = n.id, tail
	}
	return true
}

func material(r Record, files []File) error {
	if len(files) == 0 {
		return invalid(Layout)
	}
	contents := make(map[string][]byte, len(files))
	var total uint64
	for _, f := range files {
		base := path.Base(f.Path)
		if strings.EqualFold(base, "go.mod") && f.Path != "go.mod" {
			return invalid(Layout)
		}
		if !budget(&total, uint64(len(f.Bytes)), maxModuleBytes) {
			return invalid(Bounds)
		}
		if (f.Path == "go.mod" || f.Path == "LICENSE") && len(f.Bytes) > maxGoModBytes {
			return invalid(Layout)
		}
		contents[f.Path] = f.Bytes
	}
	mod, ok := contents["go.mod"]
	if !ok {
		return invalid(Layout)
	}
	if r.ModuleH1 == "" && len(files) != 1 {
		return invalid(Layout)
	}
	got, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(mod)), nil })
	if err != nil || got != r.GoModH1 {
		return invalid(Checksum)
	}
	if r.ModuleH1 != "" {
		prefix := r.Path + "@" + r.Version + "/"
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = prefix + f.Path
		}
		got, err = dirhash.Hash1(names, func(n string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(contents[strings.TrimPrefix(n, prefix)])), nil
		})
		if err != nil || got != r.ModuleH1 {
			return invalid(Checksum)
		}
	}
	return nil
}
