package keyvaultinput

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-services/signer/internal/moduleinput"
)

func installed(t *testing.T) Manifests {
	t.Helper()
	read := func(n string) []byte {
		b, e := os.ReadFile("../../docs/first-client-keyvault/" + n)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	return Manifests{Recipe: read("recipe.json"), SourceClosure: read("source-closure.json"), Dependencies: read("dependencies.json"), GoToolchain: read("go-toolchain.json"), Verifier: read("go-verifier-linux.json")}
}

func TestInstalledArtifactChanges(t *testing.T) {
	m := installed(t)
	if _, e := New(m); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"Recipe", "SourceClosure", "Dependencies", "GoToolchain", "Verifier"} {
		t.Run(name, func(t *testing.T) {
			changed := m
			field := reflect.ValueOf(&changed).Elem().FieldByName(name)
			b := bytes.Clone(field.Bytes())
			b[len(b)/2] ^= 1
			field.SetBytes(b)
			if v, e := New(changed); v != nil || !errors.Is(e, ErrInstalled) {
				t.Fatalf("changed installed bytes: %v", e)
			}
		})
	}
	if v, e := New(Manifests{}); v != nil || !errors.Is(e, ErrInstalled) {
		t.Fatal("missing installed bytes accepted")
	}
}

// This is a real source/DATA integration fixture, not a fake Darwin execution.
// The private review packet supplies the original immutable public source tar
// and canonical module ZIP/.mod artifacts. No network/cache host lookup occurs.
// Set KEYVAULT_FIXTURES to that packet's input directory to run these controls.
func fixture(t *testing.T) (*Verifier, Binding, []byte, []byte, map[string]any) {
	t.Helper()
	dir := os.Getenv("KEYVAULT_FIXTURES")
	if dir == "" {
		t.Skip("real immutable public source/module artifacts required: KEYVAULT_FIXTURES")
	}
	m := installed(t)
	v, e := New(m)
	if e != nil {
		t.Fatal(e)
	}
	content := map[string][]byte{}
	f, e := os.Open(filepath.Join(dir, "keyvault-source.tar.gz"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	g, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	tr := tar.NewReader(g)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if h.Typeflag == tar.TypeReg {
			b, e := io.ReadAll(tr)
			if e != nil {
				t.Fatal(e)
			}
			content["source/"+h.Name] = b
		}
	}
	var deps []dependency
	if e = json.Unmarshal(m.Dependencies, &deps); e != nil {
		t.Fatal(e)
	}
	for _, d := range deps {
		base := filepath.Join(dir, "canonical-modules", d.Module, "@v", d.Version)
		if d.ModuleH1 == "" {
			b, e := os.ReadFile(base + ".mod")
			if e != nil {
				t.Fatal(e)
			}
			content["modules/"+d.Directory+"/go.mod"] = b
			continue
		}
		z, e := zip.OpenReader(base + ".zip")
		if e != nil {
			t.Fatal(e)
		}
		for _, f := range z.File {
			if f.FileInfo().IsDir() {
				continue
			}
			r, e := f.Open()
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
			content["modules/"+d.Directory+"/"+strings.TrimPrefix(f.Name, d.Module+"@"+d.Version+"/")] = b
		}
		z.Close()
	}
	// The original exported entry set is an independent oracle. Do not build a
	// positive BODY from the verifier's own expected-entry implementation.
	entryBytes, e := os.ReadFile(filepath.Join(dir, "data-entry-set.json"))
	if e != nil {
		t.Fatal(e)
	}
	var original struct {
		Entries []map[string]any
	}
	if e = json.Unmarshal(entryBytes, &original); e != nil {
		t.Fatal(e)
	}
	es := []any{}
	var data []byte
	for _, e := range original.Entries {
		root, path := e["root"].(string), e["path"].(string)
		b, ok := content[root+"/"+path]
		if !ok {
			t.Fatalf("missing fixture %s/%s", root, path)
		}
		es = append(es, e)
		data = append(data, b...)
	}
	rs := []any{}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Module < deps[j].Module })
	for _, d := range deps {
		rs = append(rs, map[string]any{"path": d.Module, "version": d.Version, "directory": d.Directory, "go_mod_h1": d.GoModH1, "module_h1": d.ModuleH1})
	}
	// Synthetic correlation values exercise BODY/job equality only. They are
	// explicitly not protected production policy/native-toolchain qualifications.
	b := Binding{Product: Product, Repository: Repository, Commit: Commit, Tree: Tree, Target: Target, OperationID: strings.Repeat("a", 32), TransferID: strings.Repeat("b", 32), PolicySHA256: strings.Repeat("c", 64), RecipeSHA256: RecipeSHA256, ToolchainSHA256: strings.Repeat("d", 64)}
	body := map[string]any{"version": 1, "operation_id": b.OperationID, "transfer_id": b.TransferID, "commit": Commit, "tree": Tree, "policy_sha256": b.PolicySHA256, "recipe_sha256": RecipeSHA256, "toolchain_sha256": b.ToolchainSHA256, "entries": es, "module_receipt": map[string]any{"source_go_mod_sha256": goModSHA256, "source_go_sum_sha256": goSumSHA256, "modules": rs}, "data_bytes": len(data)}
	raw, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	b.InputSHA256 = digest(raw)
	t.Logf("actual closure: %d entries, %d records, %d BODY bytes, %d DATA bytes", len(es), len(rs), len(raw), len(data))
	return v, b, raw, data, body
}

func TestRealSourcePositiveAndOwnership(t *testing.T) {
	v, b, raw, data, _ := fixture(t)
	p, e := v.Prepare(b, raw, data)
	if e != nil {
		t.Fatal(e)
	}
	if !p.Modules().IsVerified() || len(p.Source()) != 35 || len(p.Modules().Records()) != 4 || len(p.Modules().Files()) != 925 {
		t.Fatal("incomplete source/module result")
	}
	if !bytes.Equal(raw, p.RawBody()) || p.Binding() != b {
		t.Fatal("retained raw/binding changed")
	}
	if !errors.Is(p.NativeReadiness(), ErrNativeInputsMissing) || len(MissingRuntimeInputs()) != 4 {
		t.Fatal("source success admitted native runtime")
	}
	first := p.Source()
	first[0].Bytes[0] ^= 1
	if bytes.Equal(first[0].Bytes, p.Source()[0].Bytes) {
		t.Fatal("source accessor aliases state")
	}
	mod := p.Modules().Files()
	mod[0].Bytes[0] ^= 1
	if bytes.Equal(mod[0].Bytes, p.Modules().Files()[0].Bytes) {
		t.Fatal("module accessor aliases state")
	}
	graph, build := p.GraphCommand(), p.BuildCommand()
	if !reflect.DeepEqual(graph.Argv, []string{"mod", "graph"}) || !strings.Contains(strings.Join(graph.Env, "\n"), "GOFLAGS=-mod=readonly\n") {
		t.Fatal("graph environment")
	}
	if !strings.Contains(strings.Join(build.Env, "\n"), "GOFLAGS=\n") || build.Argv[len(build.Argv)-1] != "./cmd/mac-keyvault" {
		t.Fatal("build environment/entrypoint")
	}
	handle := p.Modules()
	*handle = moduleinput.Verified{}
	*v = Verifier{}
	if !p.Modules().IsVerified() || !reflect.DeepEqual(build, p.BuildCommand()) {
		t.Fatal("overwriting caller-owned handles changed prepared state")
	}
	for _, c := range []Command{graph, build} {
		for _, kv := range c.Env {
			if strings.HasPrefix(kv, "SSH_") || strings.HasPrefix(kv, "GITHUB_") {
				t.Fatal("inherited environment")
			}
		}
	}
	build.Env[0] = "MUTATED=true"
	build.Argv[0] = "sign"
	if reflect.DeepEqual(build, p.BuildCommand()) {
		t.Fatal("recipe accessor aliases state")
	}
	before := p.RawBody()
	raw[0] ^= 1
	data[0] ^= 1
	if !bytes.Equal(before, p.RawBody()) {
		t.Fatal("caller BODY mutation changed retained bytes")
	}
	if digest(p.Modules().Files()[0].Bytes) == digest(data[:len(p.Modules().Files()[0].Bytes)]) {
		t.Fatal("caller DATA mutation not isolated")
	}
}

func TestRealSourceRefusals(t *testing.T) {
	v, b, raw, data, body := fixture(t)
	if _, e := v.Prepare(b, raw, data); e != nil {
		t.Fatalf("positive causal neighbor: %v", e)
	}
	for _, name := range []string{"Product", "Repository", "Commit", "Tree", "Target", "OperationID", "TransferID", "PolicySHA256", "RecipeSHA256", "ToolchainSHA256", "InputSHA256"} {
		t.Run("binding_"+name, func(t *testing.T) {
			changed := b
			f := reflect.ValueOf(&changed).Elem().FieldByName(name)
			f.SetString("e" + f.String()[1:]) // Remain well-formed for digest/ID neighbors.
			want := ErrBinding
			switch name {
			case "Product", "Repository", "Commit", "Tree", "Target":
				want = ErrPairing
			}
			p, e := v.Prepare(changed, raw, data)
			if p != nil || !errors.Is(e, want) {
				t.Fatalf("changed binding did not reach intended guard: %v", e)
			}
		})
	}
	for _, name := range []string{"short", "extra", "changed", "changed_source"} {
		t.Run("DATA_"+name, func(t *testing.T) {
			d := data
			if name == "short" {
				d = d[:len(d)-1]
			}
			if name == "extra" {
				d = append(bytes.Clone(d), 0)
			}
			if name == "changed" {
				d = bytes.Clone(d)
				d[0] ^= 1
			}
			if name == "changed_source" {
				d = bytes.Clone(d)
				d[len(d)-1] ^= 1
			}
			p, e := v.Prepare(b, raw, d)
			if p != nil || !errors.Is(e, ErrData) {
				t.Fatalf("wrong DATA refusal: %v", e)
			}
		})
	}
	for _, name := range []string{"missing_source", "missing_compiled_module", "metadata_downgrade", "source_anchor", "self_consistent_substitution", "extra_cache"} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if e := json.Unmarshal(raw, &m); e != nil {
				t.Fatal(e)
			}
			es := m["entries"].([]any)
			r := m["module_receipt"].(map[string]any)
			d := data
			switch name {
			case "missing_source", "missing_compiled_module":
				idx := 0
				if name == "missing_source" {
					idx = len(es) - 1
				}
				size := es[idx].(map[string]any)["size"].(float64)
				m["data_bytes"] = m["data_bytes"].(float64) - size
				m["entries"] = append(es[:idx], es[idx+1:]...)
				if idx == 0 {
					d = data[int(size):]
				} else {
					d = data[:len(data)-int(size)]
				}
			case "metadata_downgrade":
				r["modules"].([]any)[2].(map[string]any)["module_h1"] = ""
			case "source_anchor":
				r["source_go_mod_sha256"] = strings.Repeat("e", 64)
			case "self_consistent_substitution":
				d = bytes.Clone(data)
				d[0] ^= 1
				e := es[0].(map[string]any)
				e["sha256"] = digest(d[:int(e["size"].(float64))])
			case "extra_cache":
				e := es[len(es)-1].(map[string]any)
				copy := map[string]any{}
				for k, v := range e {
					copy[k] = v
				}
				copy["path"] = "z.info"
				m["entries"] = append(es, copy)
				m["data_bytes"] = m["data_bytes"].(float64) + e["size"].(float64)
				d = append(bytes.Clone(data), data[len(data)-int(e["size"].(float64)):]...)
			}
			changed, e := json.Marshal(m)
			if e != nil {
				t.Fatal(e)
			}
			bb := b
			bb.InputSHA256 = digest(changed)
			p, e := v.Prepare(bb, changed, d)
			if p != nil || !errors.Is(e, ErrClosure) {
				t.Fatalf("required closure guard: %v", e)
			}
		})
	}
	// Permitted raw encodings remain distinct immutable identities, not a
	// canonical-JSON requirement or a reserialized digest acceptance.
	pretty, e := json.MarshalIndent(body, "", " ")
	if e != nil {
		t.Fatal(e)
	}
	if p, e := v.Prepare(b, pretty, data); p != nil || !errors.Is(e, ErrBinding) {
		t.Fatal("reserialized raw digest accepted")
	}
	b.InputSHA256 = digest(pretty)
	if p, e := v.Prepare(b, pretty, data); e != nil || !bytes.Equal(p.RawBody(), pretty) {
		t.Fatalf("legitimate raw encoding refused: %v", e)
	}
}
