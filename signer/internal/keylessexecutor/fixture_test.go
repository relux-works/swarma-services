package keylessexecutor

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-services/signer/internal/keyvaultinput"
)

type Manifests = keyvaultinput.Manifests
type Verifier = keyvaultinput.Verifier
type Binding = keyvaultinput.Binding

const (
	Product      = keyvaultinput.Product
	Repository   = keyvaultinput.Repository
	Commit       = keyvaultinput.Commit
	Tree         = keyvaultinput.Tree
	Target       = keyvaultinput.Target
	RecipeSHA256 = keyvaultinput.RecipeSHA256
	// Original anchors are test oracles, not newly supplied runtime authority.
	goModSHA256 = "db787541f1be6f57243eb4a828d98062a0459f41bb347ceba1b3da2505b5f2d4"
	goSumSHA256 = "bc7cfbe712cb6a7aa247708a0322d2a6d7d8b0ec70621bccf2abf882cc3024d2"
)

var New = keyvaultinput.New
var digest = sum

// Fixture reconstruction is copied from the selected keyvaultinput controls;
// the independent original DATA entry-set remains the positive oracle.
type dependency struct {
	Module, Version, Directory string
	GoModH1                    string `json:"go_mod_h1"`
	ModuleH1                   string `json:"module_h1"`
}

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
