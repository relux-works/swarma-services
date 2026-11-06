package manifestbody

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/swarma-services/signer/internal/moduleformat"
)

// decodeBody's capacity parameter is an inactive WHITE-BOX test seam. Production
// has exactly one caller, binding the fixed public constant in body.go.
func decodeBody(raw []byte, limit int) (*UnqualifiedOpcode34Body, error) {
	if len(raw) > limit {
		return nil, &BodyShapeRefusal{ReasonBodyTooLarge}
	}
	owned := bytes.Clone(raw)
	if !utf8.Valid(owned) {
		return nil, &BodyShapeRefusal{ReasonJSONEncoding}
	}
	p := parser{raw: owned}
	p.ws()
	if bytes.HasPrefix(owned[p.pos:], []byte{0xef, 0xbb, 0xbf}) {
		return nil, &BodyShapeRefusal{ReasonJSONEncoding}
	}
	m := p.manifest()
	if p.err == nil && p.peek() != 0 {
		p.fail(ReasonJSONSyntax)
	}
	// A literal NUL suffix is not EOF.
	if p.err == nil && p.pos != len(owned) {
		p.fail(ReasonJSONSyntax)
	}
	if p.err == nil && p.sum != m.DataBytes {
		p.fail(ReasonDeclaredBytesInconsistent)
	}
	if p.err != nil {
		return nil, p.err
	}
	return &UnqualifiedOpcode34Body{&bodyState{owned, sha256.Sum256(owned), m}}, nil
}
func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (p *parser) identifier(n int) string {
	s := p.str(n, ReasonIdentifierSyntax)
	if p.err == nil && !lowerHex(s, n) {
		p.fail(ReasonIdentifierSyntax)
	}
	return s
}
func entryPath(s string) bool {
	if s == "" || s[0] == '/' || strings.ContainsAny(s, "\x00\\") {
		return false
	}
	if len(s) >= 2 && (s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') && s[1] == ':' {
		return false
	}
	for part := range strings.SplitSeq(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func targetPath(s string) bool { return s != "" && s[0] != '/' && !strings.ContainsAny(s, "\x00\\") }
func (p *parser) manifest() UnqualifiedManifestFields {
	var m UnqualifiedManifestFields
	p.object([]string{"version", "operation_id", "transfer_id", "commit", "tree", "policy_sha256", "recipe_sha256", "toolchain_sha256", "entries", "module_receipt", "data_bytes"}, func(i int) {
		switch i {
		case 0:
			m.Version = p.number()
			if p.err == nil && m.Version != 1 {
				p.fail(ReasonScalarBound)
			}
		case 1:
			m.OperationID = p.identifier(32)
		case 2:
			m.TransferID = p.identifier(32)
		case 3:
			m.Commit = p.identifier(40)
		case 4:
			m.Tree = p.identifier(40)
		case 5:
			m.PolicySHA256 = p.identifier(64)
		case 6:
			m.RecipeSHA256 = p.identifier(64)
		case 7:
			m.ToolchainSHA256 = p.identifier(64)
		case 8:
			p.array(8192, func() {
				e := p.entry()
				if p.err != nil {
					return
				}
				if n := len(m.Entries); n > 0 {
					prev := m.Entries[n-1]
					if e.Root < prev.Root || e.Root == prev.Root && e.Path <= prev.Path {
						p.fail(ReasonEntryOrderOrDuplicate)
						return
					}
				}
				if e.Kind == "file" {
					// Bound running sum before addition and before retention. Declared
					// data_bytes is independently bounded at its own encounter position.
					if e.Size > uint64(1073741824)-p.sum {
						p.fail(ReasonScalarBound)
						return
					}
					p.sum += e.Size
				}
				m.Entries = append(m.Entries, e)
			})
			if p.err == nil && len(m.Entries) == 0 {
				p.fail(ReasonScalarBound)
			}
		case 9:
			m.ModuleReceipt = p.receipt()
		case 10:
			m.DataBytes = p.number()
			if p.err == nil && m.DataBytes > 1073741824 {
				p.fail(ReasonScalarBound)
			}
		}
	})
	return m
}
func (p *parser) entry() UnqualifiedEntryFields {
	var e UnqualifiedEntryFields
	p.object([]string{"root", "path", "kind", "mode", "size", "sha256", "link_target"}, func(i int) {
		switch i {
		case 0:
			e.Root = p.str(7, ReasonEntryShape)
			if p.err == nil && e.Root != "source" && e.Root != "modules" {
				p.fail(ReasonEntryShape)
			}
		case 1:
			e.Path = p.str(1024, ReasonScalarBound)
			if p.err == nil && !entryPath(e.Path) {
				p.fail(ReasonPathShape)
			}
		case 2:
			e.Kind = p.str(7, ReasonEntryShape)
			if p.err == nil && e.Kind != "file" && e.Kind != "symlink" {
				p.fail(ReasonEntryShape)
			}
		case 3:
			e.Mode = p.str(6, ReasonEntryShape)
			if p.err == nil && e.Mode != "100644" && e.Mode != "100755" && e.Mode != "120000" {
				p.fail(ReasonEntryShape)
			}
		case 4:
			e.Size = p.number()
		case 5:
			e.SHA256 = p.identifier(64)
		case 6:
			e.LinkTarget = p.str(1024, ReasonScalarBound)
		}
	})
	if p.err != nil {
		return e
	}
	if e.Root == "modules" && (e.Kind != "file" || e.Mode != "100644") {
		p.fail(ReasonEntryShape)
		return e
	}
	if e.Kind == "file" {
		if (e.Mode != "100644" && e.Mode != "100755") || e.LinkTarget != "" {
			p.fail(ReasonEntryShape)
		} else if e.Size > 67108864 {
			p.fail(ReasonScalarBound)
		}
	} else {
		if e.Mode != "120000" {
			p.fail(ReasonEntryShape)
			return e
		}
		if !targetPath(e.LinkTarget) {
			p.fail(ReasonPathShape)
			return e
		}
		if e.Size != uint64(len(e.LinkTarget)) {
			p.fail(ReasonEntryShape)
			return e
		}
		h := sha256.Sum256([]byte(e.LinkTarget))
		if e.SHA256 != hex.EncodeToString(h[:]) {
			p.fail(ReasonEntryShape)
		}
	}
	return e
}
func (p *parser) receipt() UnqualifiedReceiptFields {
	var r UnqualifiedReceiptFields
	p.object([]string{"source_go_mod_sha256", "source_go_sum_sha256", "modules"}, func(i int) {
		switch i {
		case 0:
			r.SourceGoModSHA256 = p.identifier(64)
		case 1:
			r.SourceGoSumSHA256 = p.identifier(64)
		case 2:
			directories := make(map[string]bool)
			p.array(512, func() {
				m := p.moduleRecord()
				if p.err != nil {
					return
				}
				if n := len(r.Modules); n > 0 {
					prev := r.Modules[n-1]
					if m.Path < prev.Path || m.Path == prev.Path && m.Version <= prev.Version {
						p.fail(ReasonModuleOrderOrDuplicate)
						return
					}
				}
				if directories[m.Directory] {
					p.fail(ReasonModuleOrderOrDuplicate)
					return
				}
				directories[m.Directory] = true
				r.Modules = append(r.Modules, m)
			})
		}
	})
	return r
}
func (p *parser) moduleRecord() UnqualifiedModuleFields {
	var m UnqualifiedModuleFields
	p.object([]string{"path", "version", "directory", "go_mod_h1", "module_h1"}, func(i int) {
		switch i {
		case 0:
			m.Path = p.str(1024, ReasonScalarBound)
		case 1:
			m.Version = p.str(128, ReasonScalarBound)
		case 2:
			m.Directory = p.str(66, ReasonReceiptShape)
		case 3:
			m.GoModH1 = p.str(47, ReasonReceiptShape)
			if p.err == nil && !moduleformat.ValidH1(m.GoModH1) {
				p.fail(ReasonReceiptShape)
			}
		case 4:
			m.ModuleH1 = p.str(47, ReasonReceiptShape)
			if p.err == nil && m.ModuleH1 != "" && !moduleformat.ValidH1(m.ModuleH1) {
				p.fail(ReasonReceiptShape)
			}
		}
	})
	if p.err == nil && (!moduleformat.ValidIdentity(m.Path, m.Version) || m.Directory != moduleformat.Directory(m.Path, m.Version)) {
		p.fail(ReasonReceiptShape)
	}
	return m
}
