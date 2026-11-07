// Package keyvaultinput composes the fixed mac-keyvault source-input slice of
// G1. It does not qualify source authority, run a graph/compiler, materialize a
// filesystem, or authorize a native build or signature.
package keyvaultinput

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/relux-works/swarma-services/signer/internal/manifestbody"
	"github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

const (
	Product             = "mac-keyvault"
	Repository          = "swarma-keyvault" // Configured alias, never a caller URL.
	CanonicalRepository = "https://github.com/relux-works/swarma-keyvault"
	Commit              = "cc1aa20c551f5d2e4ed9785d844dd036ae8716ed"
	Tree                = "31c46e09909ba3c53b1b806d3eb74c2a7c5ffbbd"
	Target              = "darwin/arm64"
	RecipeSHA256        = "74c1e365d9edac891671ff036bb55bf4aa917f2561da4c6289c25b221cf23344"
	sourceSHA256        = "a0e052fe9273153954dc2fcd48d3d7c670cbb298d07f3f114cfa14a29f1e1aa1"
	dependenciesSHA256  = "33eaf445f6652196ab1f3ce08374d9a7e73bf73542cd2ae5a229493d8208152b"
	goToolchainSHA256   = "a09797ad0b3fdaefbf12bfe288ccd5c98dcd1f20dd2a80de361b02c53a92eaef"
	verifierSHA256      = "914109430c4d00414af2691fd273d0c57e8cf3d13bfbaef32be229d18fa7324e"
	goModSHA256         = "db787541f1be6f57243eb4a828d98062a0459f41bb347ceba1b3da2505b5f2d4"
	goSumSHA256         = "bc7cfbe712cb6a7aa247708a0322d2a6d7d8b0ec70621bccf2abf882cc3024d2"
)

var (
	ErrPairing             = errors.New("input_invalid: pairing")
	ErrInstalled           = errors.New("input_invalid: installed_manifests")
	ErrBinding             = errors.New("input_invalid: retained_binding")
	ErrClosure             = errors.New("input_invalid: required_closure")
	ErrData                = errors.New("input_invalid: data")
	ErrNativeInputsMissing = errors.New("native_runtime_inputs_missing")
)

// Manifests are the exact installed source artifacts, not transport fields.
// Keep input slices stable during New. Actual native SDK and enforcement bytes
// are deliberately absent; the Go inventories are not an effective Mac closure.
type Manifests struct{ Recipe, SourceClosure, Dependencies, GoToolchain, Verifier []byte }

type entry struct {
	Path, Mode, SHA256 string
	Bytes              uint64
}
type dependency struct {
	Module, Version, Directory string
	GoModH1                    string  `json:"go_mod_h1"`
	ModuleH1                   string  `json:"module_h1"`
	Files                      []entry `json:"files_manifest"`
}
type recipe struct {
	Executable, Cwd  string
	BuildArgv        []string `json:"build_argv"`
	GraphArgv        []string `json:"graph_argv"`
	VerifyArgv       []string `json:"verify_argv"`
	Env              map[string]string
	GraphEnvOverride map[string]string `json:"graph_env_override"`
}

// Verifier owns its installed configuration. Only New constructs one.
type Verifier struct {
	recipe  recipe
	entries []manifestbody.UnqualifiedEntryFields
	records []moduleinput.Record
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hexString(s string, n int) bool {
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

// New pins every supplied artifact to the selected source tuple before parsing.
// A version, caller hash, or a new serialization cannot replace these bytes.
func New(m Manifests) (*Verifier, error) {
	for _, p := range []struct {
		b    []byte
		hash string
	}{
		{m.Recipe, RecipeSHA256}, {m.SourceClosure, sourceSHA256},
		{m.Dependencies, dependenciesSHA256}, {m.GoToolchain, goToolchainSHA256}, {m.Verifier, verifierSHA256},
	} {
		if len(p.b) > 8<<20 || digest(p.b) != p.hash {
			return nil, ErrInstalled
		}
	}
	v := &Verifier{}
	var src struct{ Entries []entry }
	var deps []dependency
	if json.Unmarshal(m.Recipe, &v.recipe) != nil || json.Unmarshal(m.SourceClosure, &src) != nil || json.Unmarshal(m.Dependencies, &deps) != nil {
		return nil, ErrInstalled
	}
	for _, e := range src.Entries {
		v.entries = append(v.entries, manifestbody.UnqualifiedEntryFields{Root: "source", Path: e.Path, Kind: "file", Mode: e.Mode, Size: e.Bytes, SHA256: e.SHA256})
	}
	for _, d := range deps {
		v.records = append(v.records, moduleinput.Record{Path: d.Module, Version: d.Version, Directory: d.Directory, GoModH1: d.GoModH1, ModuleH1: d.ModuleH1})
		prefix := d.Module + "@" + d.Version + "/"
		for _, e := range d.Files {
			if !strings.HasPrefix(e.Path, prefix) {
				return nil, ErrInstalled
			}
			v.entries = append(v.entries, manifestbody.UnqualifiedEntryFields{Root: "modules", Path: d.Directory + "/" + strings.TrimPrefix(e.Path, prefix), Kind: "file", Mode: "100644", Size: e.Bytes, SHA256: e.SHA256})
		}
	}
	sort.Slice(v.entries, func(i, j int) bool {
		a, b := v.entries[i], v.entries[j]
		return a.Root < b.Root || a.Root == b.Root && a.Path < b.Path
	})
	sort.Slice(v.records, func(i, j int) bool {
		a, b := v.records[i], v.records[j]
		return a.Path < b.Path || a.Path == b.Path && a.Version < b.Version
	})
	return v, nil
}

// Binding is the internal projection of the retained, independently admitted
// job17/transfer, NEVER a client request or self-authenticating authority. The
// integrator retains exact job bytes, authenticates peers, and supplies these
// values from that job. Policy/toolchain hashes here establish correlation only.
type Binding struct {
	Product, Repository, Commit, Tree, Target                string
	OperationID, TransferID                                  string
	PolicySHA256, RecipeSHA256, ToolchainSHA256, InputSHA256 string
}

// File is a verified ordinary file. Accessors below return independent copies.
type File struct {
	Root, Path, Mode string
	Bytes            []byte
}

// Prepared owns immutable source/module and raw BODY copies. It is source-input
// evidence only, not a native build capability or a new protocol receipt.
type Prepared struct {
	binding Binding
	raw     []byte
	source  []File
	modules *moduleinput.Verified
	recipe  recipe
}

// Prepare verifies exact required closure before calling the unchanged standard
// h1 verifier. DATA is the concatenation in actual manifest order. No filesystem
// writes or effects occur on either path. Keep caller slices stable until return.
func (v *Verifier) Prepare(b Binding, raw, data []byte) (*Prepared, error) {
	if v == nil || len(v.entries) == 0 {
		return nil, ErrInstalled
	}
	if b.Product != Product || b.Repository != Repository || b.Commit != Commit || b.Tree != Tree || b.Target != Target {
		return nil, ErrPairing
	}
	if !hexString(b.OperationID, 32) || !hexString(b.TransferID, 32) || !hexString(b.PolicySHA256, 64) || !hexString(b.ToolchainSHA256, 64) || !hexString(b.InputSHA256, 64) || b.RecipeSHA256 != RecipeSHA256 {
		return nil, ErrBinding
	}
	body, err := manifestbody.DecodeOpcode34BodyShape(raw)
	if err != nil {
		return nil, err
	}
	if digest(body.RawBodyCopy()) != b.InputSHA256 {
		return nil, ErrBinding
	}
	m := body.ManifestCopy()
	if m.OperationID != b.OperationID || m.TransferID != b.TransferID || m.Commit != b.Commit || m.Tree != b.Tree || m.PolicySHA256 != b.PolicySHA256 || m.RecipeSHA256 != b.RecipeSHA256 || m.ToolchainSHA256 != b.ToolchainSHA256 {
		return nil, ErrBinding
	}
	if len(m.Entries) != len(v.entries) || len(m.ModuleReceipt.Modules) != len(v.records) {
		return nil, ErrClosure
	}
	for i, e := range m.Entries {
		if e != v.entries[i] {
			return nil, ErrClosure
		}
	}
	in := moduleinput.Input{GoModSHA256: goModSHA256, GoSumSHA256: goSumSHA256}
	if m.ModuleReceipt.SourceGoModSHA256 != goModSHA256 || m.ModuleReceipt.SourceGoSumSHA256 != goSumSHA256 {
		return nil, ErrClosure
	}
	for i, r := range m.ModuleReceipt.Modules {
		want := v.records[i]
		got := moduleinput.Record{Path: r.Path, Version: r.Version, Directory: r.Directory, GoModH1: r.GoModH1, ModuleH1: r.ModuleH1}
		if got != want {
			return nil, ErrClosure
		}
		in.Records = append(in.Records, got)
	}
	if uint64(len(data)) != m.DataBytes || m.DataBytes > moduleinput.MaxDataBytes {
		return nil, ErrData
	}
	p := &Prepared{binding: b, raw: body.RawBodyCopy(), recipe: v.recipe}
	var offset uint64
	for _, e := range m.Entries {
		if e.Size > uint64(len(data))-offset {
			return nil, ErrData
		}
		owned := bytes.Clone(data[offset : offset+e.Size])
		offset += e.Size
		if digest(owned) != e.SHA256 {
			return nil, ErrData
		}
		if e.Root == "modules" {
			in.Files = append(in.Files, moduleinput.File{Path: e.Path, Mode: e.Mode, Bytes: owned})
		} else {
			p.source = append(p.source, File{Root: e.Root, Path: e.Path, Mode: e.Mode, Bytes: owned})
			if e.Path == "go.mod" {
				in.GoMod = owned
			}
			if e.Path == "go.sum" {
				in.GoSum = owned
			}
		}
	}
	if offset != uint64(len(data)) {
		return nil, ErrData
	}
	p.modules, err = moduleinput.Verify(in)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Prepared) RawBody() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.raw)
}
func (p *Prepared) Binding() Binding {
	if p == nil {
		return Binding{}
	}
	return p.binding
}
func (p *Prepared) Source() []File {
	if p == nil {
		return nil
	}
	out := append([]File(nil), p.source...)
	for i := range out {
		out[i].Bytes = bytes.Clone(out[i].Bytes)
	}
	return out
}

// Modules is the immutable existing supplied-module snapshot. It includes only
// canonical content and anchored go.mod metadata, never imported cache files.
func (p *Prepared) Modules() *moduleinput.Verified {
	if p == nil || p.modules == nil {
		return nil
	}
	// Copy the handle as well as protecting its private snapshot: callers can
	// overwrite an exported struct through a pointer even without field access.
	copy := *p.modules
	return &copy
}

// Command is a declarative fixed recipe invocation, with a closed environment.
// An eventual executor must assign Env directly, never append os.Environ().
type Command struct {
	Executable, Cwd string
	Argv, Env       []string
}

func (p *Prepared) command(args []string, graph bool) Command {
	if p == nil || p.modules == nil {
		return Command{}
	}
	r := p.recipe
	env := make(map[string]string, len(r.Env))
	for k, v := range r.Env {
		env[k] = v
	}
	if graph {
		for k, v := range r.GraphEnvOverride {
			env[k] = v
		}
	}
	c := Command{Executable: r.Executable, Cwd: r.Cwd, Argv: append([]string(nil), args...)}
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}
	sort.Strings(c.Env)
	return c
}
func (p *Prepared) GraphCommand() Command {
	if p == nil || p.modules == nil {
		return Command{}
	}
	return p.command(p.recipe.GraphArgv, true)
}
func (p *Prepared) BuildCommand() Command {
	if p == nil || p.modules == nil {
		return Command{}
	}
	return p.command(p.recipe.BuildArgv, false)
}

// NativeReadiness always refuses in this source-only implementation. No boolean,
// invented digest, or source-validation success can admit the absent bytes.
func (p *Prepared) NativeReadiness() error { return ErrNativeInputsMissing }

func MissingRuntimeInputs() []string {
	return []string{
		"actual Apple Xcode 16.4/macOS SDK 15.5 compiler/linker/framework/runtime bytes and complete effective toolchain manifest",
		"actual protected policy bytes, authority adapter/profile/owner pins and fresh BeforeBuild qualification",
		"admitted native read-only input/private-state isolation and enforced finite resource/cleanup profile",
		"qualified receipt-only cache derivation ledger and actual offline graph, followed by two clean native builds and immutable handoff",
	}
}
