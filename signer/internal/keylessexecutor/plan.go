// Package keylessexecutor implements the fixed mac-keyvault controller source
// slice. Planning is not authority or native qualification. No native backend
// is installed: RunNative fails closed before allocation or execution.
package keylessexecutor

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/keyvaultinput"
	"golang.org/x/mod/module"
)

var (
	ErrInput   = errors.New("keyless_input_refused")
	ErrGraph   = errors.New("keyless_graph_refused")
	ErrState   = errors.New("keyless_state_refused")
	ErrLimit   = errors.New("keyless_limit_refused")
	ErrCleanup = errors.New("keyless_cleanup_failed")
	ErrUnequal = errors.New("keyless_builds_unequal")
	ErrWorker  = errors.New("keyless_worker_failed")
)

// The existing independently observed selected graph, including pruned edges
// whose module bodies are deliberately not required. This adds no dependency.
//
//go:embed selected.graph
var selectedGraph string

// Limits retain the exact recipe's bounds. Memory/process/CPU admission on Mac
// remains absent; these proposed values cannot qualify a backend.
type Limits struct {
	InputBytes, ArtifactBytes, LogBytes, MemoryBytes           uint64
	SourceEntries, Processes, ParallelCompiles, ConcurrentJobs int
	EachBuild, WholeJob, Termination                           time.Duration
}

func ProposedLimits() Limits {
	return Limits{InputBytes: 1 << 30, ArtifactBytes: 256 << 20, LogBytes: 1 << 20,
		MemoryBytes: 4 << 30, SourceEntries: 8192, Processes: 64, ParallelCompiles: 2,
		ConcurrentJobs: 1, EachBuild: 240 * time.Second, WholeJob: 600 * time.Second, Termination: 10 * time.Second}
}

// Entry describes a deterministic receipt-only reconstruction. Origin is the
// validated source/module path, or a named derivation from original receipt
// anchors. SHA256 is of the actual reconstructed bytes, not a caller digest.
type Entry struct {
	Path, Origin, SHA256 string
	Bytes                uint64
	Executable           bool
}
type file struct {
	Entry
	data []byte
}

// Plan owns all bytes. There is no public constructor for a native capability.
// Only the existing opaque verified snapshot can produce a plan. Keep the
// Prepared handle stable during PlanInput; returned plan methods make copies.
type Plan struct {
	binding      keyvaultinput.Binding
	files        []file
	graph, build keyvaultinput.Command
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validPath(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\\\x00") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../")
}
func (p *Plan) add(name, origin string, b []byte, executable bool) error {
	if !validPath(name) {
		return ErrInput
	}
	p.files = append(p.files, file{Entry: Entry{Path: name, Origin: origin, SHA256: sum(b), Bytes: uint64(len(b)), Executable: executable}, data: bytes.Clone(b)})
	return nil
}

// PlanInput does no filesystem or process work. It consumes the immutable
// keyvaultinput result without reimplementing manifest or module validation.
// Its synchronous bounded copying/ZIP derivation must itself be run inside the
// admitted worker resource domain; a goroutine timeout would not contain it.
func PlanInput(prepared *keyvaultinput.Prepared) (*Plan, error) {
	if prepared == nil || !prepared.Modules().IsVerified() {
		return nil, ErrInput
	}
	b := prepared.Binding()
	if b.Product != keyvaultinput.Product || b.Commit != keyvaultinput.Commit || b.Tree != keyvaultinput.Tree || b.RecipeSHA256 != keyvaultinput.RecipeSHA256 {
		return nil, ErrInput
	}
	p := &Plan{binding: b, graph: prepared.GraphCommand(), build: prepared.BuildCommand()}
	source := prepared.Source()
	if len(source) != 35 {
		return nil, ErrInput
	}
	for _, f := range source {
		if err := p.add("source/"+f.Path, "source/"+f.Path, f.Bytes, f.Mode == "100755"); err != nil {
			return nil, err
		}
	}
	modules := prepared.Modules()
	fs := modules.Files()
	for _, r := range modules.Records() {
		ep, err := module.EscapePath(r.Path)
		if err != nil {
			return nil, ErrInput
		}
		ev, err := module.EscapeVersion(r.Version)
		if err != nil {
			return nil, ErrInput
		}
		cache := "modules/cache/download/" + ep + "/@v/" + ev
		prefix := r.Directory + "/"
		var mod []byte
		var entries []file
		for _, f := range fs {
			if !strings.HasPrefix(f.Path, prefix) {
				continue
			}
			rel := strings.TrimPrefix(f.Path, prefix)
			if rel == "go.mod" {
				mod = f.Bytes
			}
			entries = append(entries, file{Entry: Entry{Path: rel, Origin: "modules/" + f.Path}, data: f.Bytes})
			if r.ModuleH1 != "" {
				if err = p.add("modules/"+ep+"@"+ev+"/"+rel, "modules/"+f.Path, f.Bytes, false); err != nil {
					return nil, err
				}
			}
		}
		if len(mod) == 0 {
			return nil, ErrInput
		}
		if err = p.add(cache+".mod", prefix+"go.mod", mod, false); err != nil {
			return nil, err
		}
		if r.ModuleH1 == "" {
			continue
		} // Metadata-only stays metadata-only.
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, f := range entries {
			h := &zip.FileHeader{Name: r.Path + "@" + r.Version + "/" + f.Path, Method: zip.Deflate}
			h.SetMode(0644)
			w, e := zw.CreateHeader(h)
			if e != nil {
				return nil, ErrInput
			}
			if _, e = w.Write(f.data); e != nil {
				return nil, ErrInput
			}
		}
		if err = zw.Close(); err != nil {
			return nil, ErrInput
		}
		// ZIP serialization is derived locally. The canonical h1 remains the
		// verified original receipt domain; no downloaded cache file is imported.
		if err = p.add(cache+".zip", "derived:canonical-module-zip:"+r.Directory, buf.Bytes(), false); err != nil {
			return nil, err
		}
		if err = p.add(cache+".ziphash", "derived:original-module-h1:"+r.Directory, []byte(r.ModuleH1), false); err != nil {
			return nil, err
		}
	}
	sort.Slice(p.files, func(i, j int) bool { return p.files[i].Path < p.files[j].Path })
	var total uint64
	for i, f := range p.files {
		if i > 0 && p.files[i-1].Path == f.Path {
			return nil, ErrInput
		}
		if f.Bytes > ProposedLimits().InputBytes-total {
			return nil, ErrLimit
		}
		total += f.Bytes
	}
	return p, nil
}
func (p *Plan) Entries() []Entry {
	if p == nil {
		return nil
	}
	out := make([]Entry, len(p.files))
	for i, f := range p.files {
		out[i] = f.Entry
	}
	return out
}
func cloneCommand(c keyvaultinput.Command) keyvaultinput.Command {
	c.Argv = append([]string(nil), c.Argv...)
	c.Env = append([]string(nil), c.Env...)
	return c
}
func (p *Plan) GraphCommand() keyvaultinput.Command {
	if p == nil {
		return keyvaultinput.Command{}
	}
	return cloneCommand(p.graph)
}
func (p *Plan) BuildCommand() keyvaultinput.Command {
	if p == nil {
		return keyvaultinput.Command{}
	}
	return cloneCommand(p.build)
}
func (p *Plan) Binding() keyvaultinput.Binding {
	if p == nil {
		return keyvaultinput.Binding{}
	}
	return p.binding
}

// CheckGraph rejects missing, additional, duplicate and changed edges. Edge
// order is not semantic; all bytes in each edge are. Output is bounded before
// parsing, independently of the worker's combined log bound.
func CheckGraph(raw []byte) error {
	if len(raw) == 0 || len(raw) > 1<<20 || raw[len(raw)-1] != '\n' {
		return ErrGraph
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	want := strings.Split(strings.TrimSuffix(selectedGraph, "\n"), "\n")
	if len(lines) != len(want) {
		return ErrGraph
	}
	sort.Strings(lines)
	sort.Strings(want)
	for i, s := range lines {
		if s != want[i] || i > 0 && s == lines[i-1] {
			return ErrGraph
		}
	}
	return nil
}

// Native execution is unavailable on every platform until actual protected
// inputs and an independently admitted native process domain are installed.
// There is deliberately no caller 'qualified' switch, executable path, shell,
// recipe replacement, or test backend parameter on this entrypoint.
func RunNative(_ *keyvaultinput.Prepared) error { return keyvaultinput.ErrNativeInputsMissing }
