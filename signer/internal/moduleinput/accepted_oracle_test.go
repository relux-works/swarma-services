package moduleinput

import (
	"golang.org/x/text/unicode/norm"
	"path"
	"strings"
	"unicode"
)

// Frozen accepted-r5 oracle. The accepted source SHA256 is
// 6204884140b909e8b562a1711582f493bdfc4e14f754c99bcf09595a9f6d0cbf.
// Only private symbol names are changed. Used only with bounded test inputs;
// no reuse after a refusal and no heavy fixture in ordinary/race suites.
type acceptedNode struct {
	path string
	file bool
}

// This portable collision predicate rejects Unicode case and canonical
// decomposition aliases without changing stored names. Actual Darwin volume
// behavior and materialization still require native integration qualification.
func acceptedFold(p string) string {
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

// acceptedCollisionSet belongs to one Verify call. An exact directory already admitted
// has admitted ancestors too, so a later visit can stop without folding again.
// Both indexes retain at most the acceptedNodes implied by the bounded input paths.
type acceptedCollisionSet struct {
	folded map[string]acceptedNode
	exact  map[string]bool // true for a file, false for an implied directory
}

func (seen acceptedCollisionSet) check(p string) bool {
	for q := p; q != "."; q = path.Dir(q) {
		isFile := q == p
		if file, ok := seen.exact[q]; ok {
			return !file && !isFile
		}
		key := acceptedFold(q)
		if old, ok := seen.folded[key]; ok {
			if old.path != q || old.file || isFile {
				return false
			}
		} else {
			seen.folded[key] = acceptedNode{q, isFile}
		}
		seen.exact[q] = isFile
	}
	return true
}

func acceptedVerify(s *snapshot) error {
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
	collisions := acceptedCollisionSet{folded: make(map[string]acceptedNode), exact: make(map[string]bool)}
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
