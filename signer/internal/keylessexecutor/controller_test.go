package keylessexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/keyvaultinput"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
)

type syntheticRunner struct {
	roots  []string
	phases []string
	action func(context.Context, string, int, *state) ([]byte, error)
	t      *testing.T
	p      *Plan
}

func (r *syntheticRunner) run(ctx context.Context, phase string, n int, s *state, c keyvaultinput.Command) ([]byte, error) {
	r.t.Helper()
	want := r.p.GraphCommand()
	if phase == "build" {
		want = r.p.BuildCommand()
	}
	if !reflect.DeepEqual(c, want) {
		r.t.Fatal("fixed command changed")
	}
	r.phases = append(r.phases, phase)
	if phase == "graph" {
		r.roots = append(r.roots, s.root)
		for _, name := range []string{"home", "tmp", "cache", "out"} {
			p := filepath.Join(s.root, name)
			i, e := os.Stat(p)
			es, re := os.ReadDir(p)
			if e != nil || i.Mode().Perm() != 0700 || re != nil || len(es) != 0 {
				r.t.Fatal("nonempty or nonprivate initial state")
			}
		}
	}
	if r.action != nil {
		return r.action(ctx, phase, n, s)
	}
	if phase == "graph" {
		return []byte(selectedGraph), nil
	}
	// Label actual artifact bytes, not just the test name.
	return nil, os.WriteFile(filepath.Join(s.root, "out", "mac-keyvault"), []byte("OFFLINE SYNTHETIC EXECUTION; NOT NATIVE\n"), 0600)
}
func emptyParent(t *testing.T, parent string) {
	t.Helper()
	es, e := os.ReadDir(parent)
	if e != nil || len(es) != 0 {
		t.Fatalf("cleanup incomplete: entries=%d err=%v", len(es), e)
	}
}
func preparedFixture(t *testing.T) (*keyvaultinput.Prepared, *Plan) {
	t.Helper()
	v, b, raw, data, _ := fixture(t)
	p, e := v.Prepare(b, raw, data)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := PlanInput(p)
	if e != nil {
		t.Fatal(e)
	}
	return p, plan
}

func TestReceiptPlanAndLifecycle(t *testing.T) {
	prepared, p := preparedFixture(t)
	t.Run("exact-recipe-and-budget", func(t *testing.T) {
		if !reflect.DeepEqual(p.GraphCommand(), prepared.GraphCommand()) || !reflect.DeepEqual(p.BuildCommand(), prepared.BuildCommand()) {
			t.Fatal("recipe rewritten")
		}
		m := installed(t)
		var recipe struct {
			Limits      map[string]uint64
			CleanBuilds int `json:"clean_builds"`
		}
		if e := json.Unmarshal(m.Recipe, &recipe); e != nil {
			t.Fatal(e)
		}
		l := ProposedLimits()
		if recipe.CleanBuilds != 2 || l.EachBuild != time.Duration(recipe.Limits["each_build_seconds"])*time.Second || l.WholeJob != time.Duration(recipe.Limits["whole_job_seconds"])*time.Second || l.Termination != time.Duration(recipe.Limits["children_termination_seconds"])*time.Second || l.MemoryBytes != recipe.Limits["proposed_memory_bytes"] || uint64(l.Processes) != recipe.Limits["proposed_processes"] || l.LogBytes != recipe.Limits["proposed_combined_log_bytes"] || l.InputBytes != recipe.Limits["input_bytes"] || l.ArtifactBytes != recipe.Limits["artifact_bytes"] || uint64(l.SourceEntries) != recipe.Limits["source_entries"] || uint64(l.ParallelCompiles) != recipe.Limits["parallel_compiles"] {
			t.Fatal("recipe budget changed")
		}
		c := p.BuildCommand()
		c.Argv[0] = "not-a-build"
		c.Env[0] = "not-an-env"
		es := p.Entries()
		es[0].SHA256 = "changed"
		if reflect.DeepEqual(c, p.BuildCommand()) || p.Entries()[0].SHA256 == "changed" {
			t.Fatal("plan accessor aliases")
		}
	})
	t.Run("receipt-only-materialization-and-canonical-h1", func(t *testing.T) {
		parent := t.TempDir()
		s, e := materialize(context.Background(), parent, p)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if e := s.cleanup(); e != nil {
				t.Fatal(e)
			}
		}()
		if len(s.ledger) != len(p.Entries()) {
			t.Fatal("partial ledger")
		}
		for _, entry := range s.ledger {
			if strings.HasSuffix(entry.Path, ".info") || strings.HasSuffix(entry.Path, ".list") {
				t.Fatal("foreign cache metadata")
			}
			b, e := os.ReadFile(filepath.Join(s.root, entry.Path))
			if e != nil || sum(b) != entry.SHA256 || uint64(len(b)) != entry.Bytes {
				t.Fatal("ledger mismatch")
			}
			i, e := os.Stat(filepath.Join(s.root, entry.Path))
			if e != nil || i.Mode().Perm()&0222 != 0 {
				t.Fatal("canonical writable file")
			}
		}
		for _, f := range prepared.Source() {
			b, e := os.ReadFile(filepath.Join(s.root, "source", f.Path))
			if e != nil || !bytes.Equal(b, f.Bytes) {
				t.Fatal("original source bytes changed")
			}
		}
		for _, r := range prepared.Modules().Records() {
			ep, _ := module.EscapePath(r.Path)
			ev, _ := module.EscapeVersion(r.Version)
			root := filepath.Join(s.root, "modules")
			archive := filepath.Join(root, "cache/download", ep, "@v", ev+".zip")
			if r.ModuleH1 == "" {
				if _, e := os.Stat(filepath.Join(root, ep+"@"+ev)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("metadata-only record became a source tree")
				}
				if _, e := os.Stat(archive); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("metadata-only record gained zip")
				}
				continue
			}
			h, e := dirhash.HashZip(archive, dirhash.Hash1)
			if e != nil || h != r.ModuleH1 {
				t.Fatalf("derived ZIP canonical h1 mismatch: %v", e)
			}
		}
	})
	t.Run("two-independent-states-cleanup-equality", func(t *testing.T) {
		parent := t.TempDir()
		r := &syntheticRunner{t: t, p: p}
		o, e := newController().exercise(context.Background(), parent, p, r)
		if e != nil || !o.Synthetic || o.CleanBuilds != 2 || o.Bytes == 0 || o.SHA256 == "" {
			t.Fatalf("synthetic lifecycle: %+v %v", o, e)
		}
		if len(r.roots) != 2 || r.roots[0] == r.roots[1] || !reflect.DeepEqual(r.phases, []string{"graph", "build", "graph", "build"}) {
			t.Fatal("state reused or compile preceded graph")
		}
		emptyParent(t, parent)
	})
	for _, kind := range []string{"bad-graph", "duplicate-graph", "missing-output", "unequal", "symlink-output", "artifact-limit", "log-limit", "combined-log-limit", "cancel", "deadline", "worker-exit", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			c := newController()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "deadline" {
				c.limits.EachBuild = 20 * time.Millisecond
			}
			if kind == "artifact-limit" {
				c.limits.ArtifactBytes = 2
			}
			if kind == "log-limit" {
				c.limits.LogBytes = 2
			}
			if kind == "combined-log-limit" {
				c.limits.LogBytes = uint64(2*len(selectedGraph) - 1)
			}
			r := &syntheticRunner{t: t, p: p}
			r.action = func(ctx context.Context, phase string, n int, s *state) ([]byte, error) {
				if phase == "graph" {
					switch kind {
					case "bad-graph":
						return []byte("different graph\n"), nil
					case "duplicate-graph":
						return []byte(selectedGraph + strings.Split(selectedGraph, "\n")[0] + "\n"), nil
					case "cancel":
						cancel()
						return nil, ctx.Err()
					}
					return []byte(selectedGraph), nil
				}
				switch kind {
				case "worker-exit":
					return nil, ErrWorker
				case "deadline":
					<-ctx.Done()
					return nil, ctx.Err()
				case "missing-output":
					return nil, nil
				case "symlink-output":
					return nil, os.Symlink("/dev/null", filepath.Join(s.root, "out", "mac-keyvault"))
				case "cleanup":
					if e := os.Chmod(parent, 0500); e != nil {
						return nil, e
					}
				}
				b := []byte("OFFLINE SYNTHETIC EXECUTION\n")
				if kind == "unequal" && n == 1 {
					b[0] = 'X'
				}
				return nil, os.WriteFile(filepath.Join(s.root, "out", "mac-keyvault"), b, 0600)
			}
			o, e := c.exercise(ctx, parent, p, r)
			if e == nil || o.CleanBuilds != 0 || o.SHA256 != "" {
				t.Fatalf("partial/failing result accepted %+v %v", o, e)
			}
			if kind == "cleanup" {
				if !errors.Is(e, ErrCleanup) {
					t.Fatalf("cleanup failure lost: %v", e)
				}
				if e = os.Chmod(parent, 0700); e != nil {
					t.Fatal(e)
				}
				// Preserve the failure result, then clean only the test-owned residual.
				es, _ := os.ReadDir(parent)
				for _, de := range es {
					s := &state{root: filepath.Join(parent, de.Name())}
					if e = s.cleanup(); e != nil {
						t.Fatal(e)
					}
				}
			}
			if kind == "bad-graph" || kind == "duplicate-graph" || kind == "log-limit" {
				for _, ph := range r.phases {
					if ph == "build" {
						t.Fatal("invalid graph compiled")
					}
				}
			}
			if kind == "combined-log-limit" && !reflect.DeepEqual(r.phases, []string{"graph", "build", "graph"}) {
				t.Fatal("whole-job log budget renewed between builds")
			}
			emptyParent(t, parent)
		})
	}
	t.Run("concurrent-job-refusal", func(t *testing.T) {
		parent := t.TempDir()
		c := newController()
		started := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		r := &syntheticRunner{t: t, p: p, action: func(ctx context.Context, phase string, n int, s *state) ([]byte, error) {
			once.Do(func() { close(started) })
			select {
			case <-release:
				return nil, ErrWorker
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}}
		done := make(chan error, 1)
		go func() { _, e := c.exercise(context.Background(), parent, p, r); done <- e }()
		<-started
		if _, e := c.exercise(context.Background(), parent, p, r); !errors.Is(e, ErrLimit) {
			t.Fatal("concurrency exceeded")
		}
		close(release)
		if e := <-done; e == nil {
			t.Fatal("worker failure hidden")
		}
		emptyParent(t, parent)
	})
	t.Run("native-always-unavailable", func(t *testing.T) {
		parent := t.TempDir()
		if !errors.Is(RunNative(prepared), keyvaultinput.ErrNativeInputsMissing) || !errors.Is(RunNative(nil), keyvaultinput.ErrNativeInputsMissing) {
			t.Fatal("synthetic/source evidence admitted native")
		}
		emptyParent(t, parent)
	})
	t.Run("readonly-source-and-tools-boundary", func(t *testing.T) {
		// These checks intentionally require the offline read-only test namespace.
		if os.Getenv("KEYVAULT_FIXTURES") == "" {
			t.Skip("offline harness required")
		}
		for _, name := range []string{"../../docs/first-client-keyvault/recipe.json", "/usr/bin/go"} {
			f, e := os.OpenFile(name, os.O_WRONLY, 0)
			if e == nil {
				f.Close()
				t.Fatal("source/tool mount writable")
			}
		}
		if _, e := os.Stat("/home"); !errors.Is(e, fs.ErrNotExist) {
			t.Fatal("host home exposed")
		}
	})
}

func TestPrecompileInvalidContent(t *testing.T) {
	v, b, raw, data, _ := fixture(t)
	data[len(data)/2] ^= 1
	if p, e := v.Prepare(b, raw, data); p != nil || e == nil {
		t.Fatal("invalid DATA prepared")
	}
	if p, e := PlanInput(nil); p != nil || !errors.Is(e, ErrInput) {
		t.Fatal("nil prepared planned")
	}
	if p, e := PlanInput(&keyvaultinput.Prepared{}); p != nil || !errors.Is(e, ErrInput) {
		t.Fatal("zero prepared planned")
	}
	// No filesystem/state or worker is reachable on this path.
}
func TestGraphRefusals(t *testing.T) {
	if e := CheckGraph([]byte(selectedGraph)); e != nil {
		t.Fatal(e)
	}
	for _, b := range [][]byte{nil, []byte(selectedGraph[:len(selectedGraph)-1]), []byte(strings.Replace(selectedGraph, "v0.55.0", "v0.55.1", 1)), bytes.Repeat([]byte("x"), 1<<20+1)} {
		if !errors.Is(CheckGraph(b), ErrGraph) {
			t.Fatal("changed graph accepted")
		}
	}
}
