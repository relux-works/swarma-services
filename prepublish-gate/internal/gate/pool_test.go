package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func removeFixtureObject(t *testing.T, objects, oid string) {
	t.Helper()
	if err := os.Remove(filepath.Join(objects, oid[:2], oid[2:])); err != nil {
		t.Fatal("fixture object removal failed")
	}
}

// Old versions are individually admissible; only their aggregate expanded size
// exceeds the pool ceiling. A depth-two acquisition retains the actual baseline
// and candidate trees, not a hand-built substitute for the checked history.
func TestLargeHistoryPoolAndSupportedShallowAcquisition(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 17; i++ {
		line := []byte(fmt.Sprintf("historical version %02d\n", i))
		blob := bytes.Repeat(line, MaxBlob/len(line))
		write(t, filepath.Join(f.repo, "data.txt"), blob)
		f.commit("historical content", false)
	}
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\n"))
	write(t, filepath.Join(f.repo, "unchanged.txt"), []byte("baseline unchanged\n"))
	f.base = f.commit("trusted current baseline", false)
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\nclean addition\n"))
	f.candidate = f.commit("clean candidate", true)
	// Ordinary packing remains well below the stored-byte ceiling. The confirmed
	// failure is expanded inventory, exactly after init and cat-file (commands=2).
	f.git("repack", "-a", "--window=0")
	c := f.config()
	r, code := run(c)
	require(t, code == 1 && r.ScanErrors == 1 && r.PoolLimitErrors == 1 && r.Completed == 0 && r.Commands == 2 && r.Signatures == 0, r, code)
	t.Logf("full_pool exit=%d scan_errors=%d pool_limit_errors=%d completed=%d commands=%d", code, r.ScanErrors, r.PoolLimitErrors, r.Completed, r.Commands)
	// The opt-in does not evade stored/expanded pool limits on an unpruned input.
	c.ShallowBase = true
	r, code = run(c)
	require(t, code == 1 && r.PoolLimitErrors == 1 && r.Commands == 2, r, code)
	shallow := filepath.Join(f.dir, "shallow.git")
	command(t, f.dir, "/usr/bin/git", "-c", "protocol.file.allow=always", "clone", "--bare", "--no-local", "--depth=2", "file://"+f.repo, shallow)
	boundary, err := os.ReadFile(filepath.Join(shallow, "shallow"))
	if err != nil || string(boundary) != f.base+"\n" {
		t.Fatal("acquisition did not end at exact base")
	}
	c.Objects = filepath.Join(shallow, "objects")
	c.ShallowBase = false
	r, code = run(c)
	require(t, code == 1 && r.ScanErrors == 1 && r.PoolLimitErrors == 0 && r.Completed == 0 && r.Commands == 3, r, code)
	t.Logf("depth_two_default exit=%d scan_errors=%d pool_limit_errors=%d completed=%d commands=%d", code, r.ScanErrors, r.PoolLimitErrors, r.Completed, r.Commands)
	c.ShallowBase = true
	r, code = run(c)
	require(t, code == 0 && r.Completed == 1 && r.Commits == 1 && r.Signatures == 1 && r.Paths == 1 && r.AddedLines == 1 && r.PoolLimitErrors == 0 && r.PrivateHits == 0 && r.HygieneHits == 0, r, code)
	t.Logf("depth_two_opt_in exit=%d scan_errors=%d pool_limit_errors=%d completed=%d commits=%d signatures=%d paths=%d added_lines=%d", code, r.ScanErrors, r.PoolLimitErrors, r.Completed, r.Commits, r.Signatures, r.Paths, r.AddedLines)
	// The caller's shallow metadata is not imported, changed or trusted.
	after, err := os.ReadFile(filepath.Join(shallow, "shallow"))
	if err != nil || !bytes.Equal(after, boundary) {
		t.Fatal("source boundary changed")
	}
	// Too little acquisition cannot turn a missing intended base into acceptance.
	shallowOne := filepath.Join(f.dir, "shallow-one.git")
	command(t, f.dir, "/usr/bin/git", "-c", "protocol.file.allow=always", "clone", "--bare", "--no-local", "--depth=1", "file://"+f.repo, shallowOne)
	c.Objects = filepath.Join(shallowOne, "objects")
	r, code = run(c)
	require(t, code == 1 && r.ScanErrors == 1 && r.PoolLimitErrors == 0 && r.Completed == 0, r, code)
	// Exercise the public CLI and only-count output on the valid acquired input.
	var out bytes.Buffer
	code = Run([]string{"check", "--shallow-base", "--objects", filepath.Join(shallow, "objects"), "--base", c.Base, "--candidate", c.Candidate, "--patterns", c.Patterns, "--allowed-signers", c.Signers, "--principal", c.Principal}, &out)
	var values map[string]int
	if code != 0 || json.Unmarshal(out.Bytes(), &values) != nil || values["completed"] != 1 {
		t.Fatal("shallow CLI failed")
	}
	if v, ok := values["pool_limit_errors"]; !ok || v != 0 {
		t.Fatal("pool counter absent or nonzero")
	}
	for _, private := range []string{c.Base, c.Candidate, c.Objects, "SYNTHETIC_PRIVATE_MARKER"} {
		if strings.Contains(out.String(), private) {
			t.Fatal("CLI disclosed input")
		}
	}
}

// This fixture omits only ancestors before the trusted base. All objects needed
// for the baseline tree, candidate tree, signature and per-commit diff exist.
func shallowFixture(t *testing.T) (*fixture, Config) {
	t.Helper()
	f := newFixture(t)
	parent := f.candidate
	write(t, filepath.Join(f.repo, "unchanged.txt"), []byte("baseline unchanged\n"))
	f.base = f.commit("trusted shallow baseline", false)
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\nclean changed\n"))
	f.candidate = f.commit("clean shallow candidate", true)
	c := f.config()
	c.ShallowBase = true
	removeFixtureObject(t, c.Objects, parent)
	return f, c
}

// The exact shallow base permits a valid closure while missing/corrupt objects,
// unsigned history, private additions and binary content retain their controls.
func TestShallowBaseIntegrityAndScanControls(t *testing.T) {
	for _, kind := range []string{"valid", "missing-base-tree", "missing-unchanged-blob", "missing-candidate-tree", "missing-candidate-blob", "corrupt-unchanged-blob", "unsigned", "private-hit", "binary"} {
		t.Run(kind, func(t *testing.T) {
			f, c := shallowFixture(t)
			switch kind {
			case "missing-base-tree":
				removeFixtureObject(t, c.Objects, f.git("rev-parse", f.base+"^{tree}"))
			case "missing-unchanged-blob":
				removeFixtureObject(t, c.Objects, f.git("rev-parse", f.base+":unchanged.txt"))
			case "missing-candidate-tree":
				removeFixtureObject(t, c.Objects, f.git("rev-parse", f.candidate+"^{tree}"))
			case "missing-candidate-blob":
				removeFixtureObject(t, c.Objects, f.git("rev-parse", f.candidate+":data.txt"))
			case "corrupt-unchanged-blob":
				oid := f.git("rev-parse", f.base+":unchanged.txt")
				name := filepath.Join(c.Objects, oid[:2], oid[2:])
				if os.Chmod(name, 0600) != nil {
					t.Fatal("fixture object mode")
				}
				write(t, name, []byte("corrupt fixture"))
			case "unsigned":
				c.Candidate = f.commit("unsigned candidate", false)
			case "private-hit":
				write(t, filepath.Join(f.repo, "data.txt"), []byte("SYNTHETIC_PRIVATE_MARKER\n"))
				c.Candidate = f.commit("private fixture", true)
			case "binary":
				write(t, filepath.Join(f.repo, "data.txt"), []byte{0, 1, 2})
				c.Candidate = f.commit("binary fixture", true)
			}
			r, code := run(c)
			switch kind {
			case "valid":
				require(t, code == 0 && r.Completed == 1 && r.Signatures == 1 && r.Commits == 1, r, code)
			case "unsigned":
				require(t, code == 1 && r.SignatureErrors == 1 && r.Completed == 0, r, code)
			case "private-hit":
				require(t, code == 1 && r.Completed == 1 && r.PrivateHits == 1 && r.Signatures == 2 && r.Commits == 2, r, code)
			default:
				require(t, code == 1 && r.ScanErrors == 1 && r.Completed == 0, r, code)
			}
			require(t, r.PoolLimitErrors == 0 && r.PublishedRefs == 0, r, code)
		})
	}
}

// On the same fixture, shallow-base accepts its linear signed candidate and
// refuses unrelated, sibling, incomplete and merged ancestry without publishing.
func TestShallowBaseDoesNotAdmitOtherAncestry(t *testing.T) {
	for _, kind := range []string{"valid", "unrelated-root", "sibling", "missing-intermediate", "merge"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			c := f.config()
			c.ShallowBase = true
			switch kind {
			case "unrelated-root":
				f.git("checkout", "--orphan", "other")
				c.Candidate = f.commit("other root", true)
			case "sibling":
				c.Base = f.candidate
				f.git("checkout", "--detach", f.base)
				c.Candidate = f.commit("sibling candidate", true)
			case "missing-intermediate":
				c.Candidate = f.commit("later candidate", true)
				removeFixtureObject(t, c.Objects, f.candidate)
			case "merge":
				f.git("checkout", "--detach", f.base)
				sibling := f.commit("sibling", true)
				f.git("checkout", "--detach", f.candidate)
				f.git("-c", "gpg.format=ssh", "-c", "user.signingkey="+f.key, "-c", "commit.gpgsign=true", "merge", "--no-ff", "-m", "merge candidate", sibling)
				c.Candidate = f.git("rev-parse", "HEAD")
			}
			r, code := run(c)
			if kind == "valid" {
				require(t, code == 0 && r.ScanErrors == 0 && r.PoolLimitErrors == 0 && r.Completed == 1 && r.Signatures == 1 && r.Commits == 1 && r.PublishedRefs == 0, r, code)
			} else {
				require(t, code == 1 && r.ScanErrors == 1 && r.PoolLimitErrors == 0 && r.Completed == 0 && r.PublishedRefs == 0, r, code)
			}
		})
	}
}

// The exact expanded-byte ceiling is admitted; one additional byte is a
// classified pool overflow, independently of per-object size and history.
func TestPoolExpandedByteAdjacentBoundary(t *testing.T) {
	f := newFixture(t)
	// An object-only repository makes the exact byte boundary independent of
	// commit timestamps, signatures and tree-record lengths.
	repo := filepath.Join(f.dir, "pool.git")
	command(t, f.dir, "/usr/bin/git", "init", "--bare", repo)
	file := filepath.Join(f.dir, "object")
	for i := 0; i < 16; i++ {
		blob := bytes.Repeat([]byte{byte('a' + i)}, MaxBlob)
		write(t, file, blob)
		command(t, f.dir, "/usr/bin/git", "--git-dir="+repo, "hash-object", "-w", file)
	}
	g := &runner{ctx: context.Background(), dir: repo, tmp: f.dir}
	if err := g.inventory(); err != nil {
		t.Fatal("exact expanded pool ceiling refused")
	}
	write(t, file, []byte("z"))
	command(t, f.dir, "/usr/bin/git", "--git-dir="+repo, "hash-object", "-w", file)
	if err := g.inventory(); err != poolLimitFailure {
		t.Fatal("one-byte expanded overflow not classified")
	}
}

// Stored bytes and visited-file counts admit their exact ceilings and classify
// adjacent overflows before inventory or integrity checking can begin.
func TestPoolStoredBytesAndFileVisitBoundary(t *testing.T) {
	f := newFixture(t)
	for _, kind := range []string{"bytes-at", "bytes-over", "files-at", "files-over"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			objects := filepath.Join(dir, "objects")
			if os.MkdirAll(filepath.Join(objects, "pack"), 0700) != nil {
				t.Fatal("fixture mkdir")
			}
			if strings.HasPrefix(kind, "bytes") {
				// snapshot tests storage admission only; inventory/fsck are tested above.
				file, err := os.Create(filepath.Join(objects, "pack", "pack-"+strings.Repeat("a", 40)+".pack"))
				if err != nil {
					t.Fatal("fixture file")
				}
				size := int64(MaxObjects)
				if kind == "bytes-over" {
					size++
				}
				if file.Truncate(size) != nil || file.Close() != nil {
					t.Fatal("fixture sparse size")
				}
			} else {
				count := MaxObjectFiles
				if kind == "files-over" {
					count++
				}
				if os.Mkdir(filepath.Join(objects, "aa"), 0700) != nil {
					t.Fatal("fixture mkdir")
				}
				for i := 0; i < count; i++ {
					write(t, filepath.Join(objects, "aa", fmt.Sprintf("%038x", i)), nil)
				}
			}
			g := &runner{ctx: context.Background(), dir: filepath.Join(dir, "private.git"), tmp: f.dir}
			err := g.snapshot(objects)
			if strings.HasSuffix(kind, "-at") && err != nil {
				t.Fatal("exact storage ceiling refused")
			}
			if strings.HasSuffix(kind, "-over") && err != poolLimitFailure {
				t.Fatal("storage overflow not classified")
			}
			if strings.HasSuffix(kind, "-over") {
				c := f.config()
				c.Objects = objects
				r, code := run(c)
				require(t, code == 1 && r.PoolLimitErrors == 1 && r.ScanErrors == 1 && r.Completed == 0 && r.Commands == 1, r, code)
			}
		})
	}
}
