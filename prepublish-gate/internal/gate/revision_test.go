package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Destinations are always task-owned, local bare repositories. The update hook
// records whether receive-pack was reached; default-ref refusals must precede it.
func TestDefaultRefPreflight(t *testing.T) {
	for _, kind := range []string{"equal", "moved", "absent", "empty-destination"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			dest := f.destination()
			switch kind {
			case "moved":
				f.seed(dest, "refs/heads/main", f.candidate)
			case "absent":
				f.seed(dest, "refs/heads/other", f.base)
				command(t, f.dir, "/usr/bin/git", "--git-dir="+dest, "update-ref", "-d", "refs/heads/main")
			case "empty-destination":
				command(t, f.dir, "/usr/bin/git", "--git-dir="+dest, "update-ref", "-d", "refs/heads/main")
			}
			witness := filepath.Join(f.dir, "receive-reached")
			hook := filepath.Join(dest, "hooks", "pre-receive")
			write(t, hook, []byte("#!/bin/sh\n: > '"+witness+"'\ncat >/dev/null\n"))
			if os.Chmod(hook, 0700) != nil {
				t.Fatal("hook")
			}
			before := command(t, f.dir, "/usr/bin/git", "--git-dir="+dest, "count-objects", "-v")
			r, code := run(f.pub(dest, "refs/heads/task=absent"))
			if kind == "equal" {
				require(t, code == 0 && r.PublishedRefs == 1 && r.LeaseErrors == 0, r, code)
				if f.remoteOID(dest, "refs/heads/main") != f.base || f.remoteOID(dest, "refs/heads/task") != f.candidate {
					t.Fatal("incorrect refs")
				}
			} else {
				if code != 1 || r.LeaseErrors != 1 || r.PublicationErrors != 0 || r.PublishedRefs != 0 {
					t.Errorf("default-ref guard failed: exit=%d lease_errors=%d publication_errors=%d published_refs=%d", code, r.LeaseErrors, r.PublicationErrors, r.PublishedRefs)
				}
				if _, e := os.Stat(witness); !os.IsNotExist(e) {
					t.Error("receive-pack reached")
				}
				after := command(t, f.dir, "/usr/bin/git", "--git-dir="+dest, "count-objects", "-v")
				if before != after {
					t.Error("unchecked history transferred")
				}
				if command(t, f.dir, "/usr/bin/git", "--git-dir="+dest, "for-each-ref", "--format=%(refname)", "refs/heads/task") != "" {
					t.Error("target created")
				}
			}
		})
	}
}

// upload-pack and receive-pack advertise different state. Removing only the
// per-ref --force-with-lease makes this test overwrite target (a fast-forward).
func TestPerRefLeaseAdvertisementWitness(t *testing.T) {
	f := newFixture(t)
	dest := f.destination()
	f.seed(dest, "refs/heads/target", f.base)
	command(t, f.dir, "/usr/bin/git", "--git-dir="+dest, "config", "uploadpack.hideRefs", "refs/heads/target")
	r, code := run(f.pub(dest, "refs/heads/target=absent"))
	if current := f.remoteOID(dest, "refs/heads/target"); current != f.base {
		t.Errorf("lease target changed; candidate_overwrite=%t", current == f.candidate)
	}
	require(t, code == 1 && r.LeaseErrors == 0 && r.PublicationErrors == 1 && r.PublishedRefs == 0, r, code)
}

func TestCommitIdentityHeadersAreScanned(t *testing.T) {
	for _, kind := range []string{"neutral", "author-private", "committer-ip"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			name, email := "Neighbor", "neighbor@example.test"
			if kind == "author-private" {
				name = "SYNTHETIC_PRIVATE_MARKER"
			}
			if kind == "committer-ip" {
				email = "neighbor@192" + ".0.2.1"
			}
			f.git("-c", "author.name="+name, "-c", "committer.email="+email, "-c", "gpg.format=ssh", "-c", "user.signingkey="+f.key, "commit", "--allow-empty", "-S", "-m", "header candidate")
			f.candidate = f.git("rev-parse", "HEAD")
			raw := f.git("cat-file", "commit", f.candidate)
			if !strings.Contains(raw, "author "+name+" <fixture@example.test>") || !strings.Contains(raw, "committer Fixture <"+email+">") {
				t.Fatal("identity fixture not installed")
			}
			r, code := run(f.config())
			if kind == "neutral" {
				require(t, code == 0 && r.Signatures == 2, r, code)
			} else {
				require(t, code == 1 && r.Completed == 1 && r.Signatures == 2 && (r.PrivateHits > 0 || r.HygieneHits > 0), r, code)
			}
		})
	}
}

func TestControlWriteModeNeighbors(t *testing.T) {
	f := newFixture(t)
	for _, private := range []bool{false, true} {
		for _, mode := range []os.FileMode{0600, 0644, 0666} {
			if os.Chmod(f.patterns, mode) != nil {
				t.Fatal("chmod")
			}
			_, e := readControl(f.patterns, private)
			want := mode == 0600 || (!private && mode == 0644)
			if (e == nil) != want {
				t.Fatalf("control mode/private neighbor: %o %t", mode, private)
			}
		}
	}
	if os.Chmod(f.patterns, 0600) != nil {
		t.Fatal("chmod")
	}
	if os.Chmod(f.signers, 0666) != nil {
		t.Fatal("chmod")
	}
	r, code := run(f.config())
	require(t, code == 1 && r.SignatureErrors == 1, r, code)
}

func TestDoubleColonLanguageNeighbors(t *testing.T) {
	p := policy{ctx: context.Background(), exceptions: map[string]bool{}}
	for _, s := range []string{"std::vector", "String::from", "a::before", "f :: Int"} {
		r := Report{}
		if p.match("line", []byte(s), &r) != nil || r.HygieneHits != 0 {
			t.Fatal("language neighbor refused")
		}
	}
	for _, s := range []string{":" + ":1", "fe80:" + ":1", "[:" + ":]", ":" + ":", "2001:" + "db8:" + ":1", "fe80:" + ":1%eth0", "2001:" + "db8:0:1:2:3:4:5", ":" + ":ffff:192" + ".0.2.1"} {
		r := Report{}
		if p.match("line", []byte(s), &r) != nil || r.HygieneHits != 1 {
			t.Fatal("IPv6 missed")
		}
	}
}

// Re-sign a synthetic commit with an extra logical header. All key material is
// generated by newFixture inside the offline test directory.
func signedExtraHeader(t *testing.T, f *fixture, header string) string {
	raw := f.git("cat-file", "commit", f.candidate)
	prefix := strings.SplitN(raw, "\ngpgsig ", 2)[0]
	unsigned := prefix + "\n" + header + "\n\nextra header candidate\n"
	input := filepath.Join(f.dir, "unsigned-commit")
	write(t, input, []byte(unsigned))
	command(t, f.dir, "/usr/bin/ssh-keygen", "-Y", "sign", "-n", "git", "-f", f.key, input)
	armor, e := os.ReadFile(input + ".sig")
	if e != nil {
		t.Fatal("synthetic signature")
	}
	sig := strings.ReplaceAll(strings.TrimSuffix(string(armor), "\n"), "\n", "\n ")
	signed := prefix + "\n" + header + "\ngpgsig " + sig + "\n\nextra header candidate\n"
	object := filepath.Join(f.dir, "signed-commit")
	write(t, object, []byte(signed))
	return f.git("hash-object", "-t", "commit", "-w", object)
}

func TestExtraHeadersAndExactHeaderExceptions(t *testing.T) {
	for _, kind := range []string{"neutral", "private", "ip", "continuation"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			header := "x-note neutral neighbor"
			switch kind {
			case "private":
				header = "x-note SYNTHETIC_PRIVATE_MARKER"
			case "ip":
				header = "x-note 192" + ".0.2.1"
			case "continuation":
				header = "x-note neutral\n SYNTHETIC_PRIVATE_MARKER"
			}
			f.candidate = signedExtraHeader(t, f, header)
			c := f.config()
			var out bytes.Buffer
			code := Run([]string{"check", "--objects", c.Objects, "--base", c.Base, "--candidate", c.Candidate, "--patterns", c.Patterns, "--allowed-signers", c.Signers, "--principal", c.Principal}, &out)
			var r Report
			if json.Unmarshal(out.Bytes(), &r) != nil {
				t.Fatal("report")
			}
			require(t, r.Completed == 1 && r.Signatures == 1 && r.Headers == 5, r, code)
			if strings.Contains(out.String(), header) || strings.Contains(out.String(), "SYNTHETIC_PRIVATE_MARKER") {
				t.Fatal("header escaped counts")
			}
			if kind == "neutral" {
				require(t, code == 0, r, code)
			} else if kind == "ip" {
				require(t, code == 1 && r.HygieneHits == 1 && r.PrivateHits == 0, r, code)
				h := sha256.Sum256([]byte(header))
				exceptions := filepath.Join(f.dir, "exceptions")
				write(t, exceptions, []byte("header\t"+hex.EncodeToString(h[:])+"\n"))
				c.Exceptions = exceptions
				r, code = run(c)
				require(t, code == 0 && r.HygieneExceptions == 1, r, code)
				write(t, f.patterns, []byte("L:"+header+"\n"))
				r, code = run(c)
				require(t, code == 1 && r.PrivateHits == 1 && r.HygieneExceptions == 1, r, code)
			} else {
				require(t, code == 1 && r.PrivateHits == 1, r, code)
			}
		})
	}
}

func TestSignatureArmorIsExcludedOnlyWithinItsRecord(t *testing.T) {
	f := newFixture(t)
	raw := f.git("cat-file", "commit", f.candidate)
	payload := strings.Split(strings.SplitN(raw, "gpgsig ", 2)[1], "\n")[1]
	write(t, f.patterns, []byte("L:"+strings.TrimPrefix(payload, " ")+"\n"))
	r, code := run(f.config())
	require(t, code == 0 && r.Signatures == 1 && r.Headers == 4, r, code)
	f.candidate = signedExtraHeader(t, f, "x-note neutral\n "+strings.TrimPrefix(payload, " "))
	r, code = run(f.config())
	require(t, code == 1 && r.Completed == 1 && r.PrivateHits == 1, r, code)
}

func TestDerivedGCMetadataAndUnsafeNeighbors(t *testing.T) {
	f := newFixture(t)
	f.git("gc", "--prune=now")
	r, code := run(f.config())
	require(t, code == 0 && r.Signatures == 1, r, code)
	objects := filepath.Join(f.repo, ".git", "objects")
	for _, name := range []string{"info/commit-graph", "info/packs", "pack/multi-pack-index", "pack/pack-" + strings.Repeat("1", 40) + ".bitmap", "pack/pack-" + strings.Repeat("1", 40) + ".keep"} {
		path := filepath.Join(objects, name)
		if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
			t.Fatal("remove derived fixture")
		}
		write(t, path, []byte("ignored derived metadata\n"))
	}
	r, code = run(f.config())
	require(t, code == 0, r, code)
	path := filepath.Join(objects, "info", "unknown")
	write(t, path, []byte("unknown\n"))
	r, code = run(f.config())
	require(t, code == 1 && r.ScanErrors == 1, r, code)
	if os.Remove(path) != nil {
		t.Fatal("remove")
	}
	path = filepath.Join(objects, "info", "packs")
	if os.Remove(path) != nil || os.Symlink(f.patterns, path) != nil {
		t.Fatal("symlink fixture")
	}
	r, code = run(f.config())
	require(t, code == 1 && r.ScanErrors == 1, r, code)
}

func TestPushPorcelainPreciseSuccessAndRefusals(t *testing.T) {
	c := Config{Remote: "/synthetic/destination", Candidate: strings.Repeat("a", 40)}
	plan := []update{{"refs/heads/existing", strings.Repeat("b", 40)}, {"refs/heads/new", "absent"}}
	good := "To " + c.Remote + "\n \t" + c.Candidate + ":refs/heads/existing\tbbbbbbb..aaaaaaa\n*\t" + c.Candidate + ":refs/heads/new\t[new branch]\nDone\n"
	if pushResult([]byte(good), c, plan) != nil {
		t.Fatal("good porcelain refused")
	}
	for _, bad := range []string{
		strings.TrimSuffix(good, "Done\n"), strings.Replace(good, " \t", "+\t", 1), strings.Replace(good, " \t", "=\t", 1), strings.Replace(good, "..", "...", 1),
		strings.Replace(good, "refs/heads/new", "refs/heads/unrequested", 1), strings.Replace(good, "*\t", "!\t", 1), good + "extra\n", strings.Replace(good, "bbbbbbb..aaaaaaa", "wrong..ids", 1), strings.Replace(good, "[new branch]", "[up to date]", 1),
	} {
		if pushResult([]byte(bad), c, plan) == nil {
			t.Fatal("malformed/forced/partial porcelain admitted")
		}
	}
}

func nativeScanRunner(f *fixture) *runner {
	return &runner{ctx: context.Background(), dir: filepath.Join(f.repo, ".git"), home: os.Getenv("HOME"), tmp: f.dir}
}

func TestScanPathCountAdjacentBoundary(t *testing.T) {
	f := newFixture(t)
	p := policy{exceptions: map[string]bool{}}
	for _, count := range []int{MaxPaths - 1, MaxPaths} {
		g := nativeScanRunner(f)
		r := Report{Paths: count}
		e := scanChange(g, p, f.base, f.candidate, &r)
		if count == MaxPaths-1 {
			if e != nil || r.Paths != MaxPaths || r.AddedLines != 1 {
				t.Fatal("path-count boundary refused")
			}
		} else if e == nil || r.Paths != MaxPaths || r.AddedLines != 0 || g.commands != 1 {
			t.Fatal("path-count neighbor did not refuse before blobs")
		}
	}
}

func TestScanBlobLimitAdjacentBoundary(t *testing.T) {
	for _, size := range []int{MaxBlob, MaxBlob + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := newFixture(t)
			block := append(bytes.Repeat([]byte("x"), 1023), '\n')
			content := bytes.Repeat(block, MaxBlob/len(block))
			if size > MaxBlob {
				content = append(content, 'x')
			}
			write(t, filepath.Join(f.repo, "data.txt"), content)
			old := f.commit("blob baseline", false)
			if os.Chmod(filepath.Join(f.repo, "data.txt"), 0700) != nil {
				t.Fatal("chmod")
			}
			now := f.commit("mode only", false)
			g := nativeScanRunner(f)
			r := Report{}
			e := scanChange(g, policy{exceptions: map[string]bool{}}, old, now, &r)
			if size == MaxBlob {
				if e != nil || r.Paths != 1 || r.AddedLines != 0 {
					t.Fatal("scan-time blob bound refused")
				}
			} else if e == nil || r.Paths != 1 || r.AddedLines != 0 || g.commands != 3 {
				t.Fatal("scan-time blob neighbor not refused by first blob")
			}
		})
	}
}

func TestScanPathLengthAdjacentBoundary(t *testing.T) {
	f := newFixture(t)
	blob := f.git("rev-parse", f.candidate+":data.txt")
	for _, size := range []int{4096, 4097} {
		// Build nested raw trees: every component is short, while the complete
		// path crosses 4096 bytes. No host worktree pathname is created.
		var components []string
		remaining := size
		for remaining > 201 {
			components = append(components, strings.Repeat("a", 200))
			remaining -= 201
		}
		components = append(components, strings.Repeat("a", remaining))
		tree := blob
		mode := "100644"
		path := filepath.Join(f.dir, "tree-input")
		for i := len(components) - 1; i >= 0; i-- {
			raw := append([]byte(mode+" "+components[i]+"\x00"), mustDecodeOID(t, tree)...)
			write(t, path, raw)
			tree = f.git("hash-object", "-t", "tree", "-w", path)
			mode = "40000"
		}
		commitFile := filepath.Join(f.dir, "commit-input")
		write(t, commitFile, []byte("tree "+tree+"\nparent "+f.base+"\nauthor Fixture <fixture@example.test> 0 +0000\ncommitter Fixture <fixture@example.test> 0 +0000\n\npath boundary\n"))
		now := f.git("hash-object", "-t", "commit", "-w", commitFile)
		g := nativeScanRunner(f)
		r := Report{}
		e := scanChange(g, policy{exceptions: map[string]bool{}}, f.base, now, &r)
		if size == 4096 {
			if e != nil || r.Paths != 2 {
				t.Fatal("path byte bound refused")
			}
		} else if e == nil || r.Paths != 0 || g.commands != 1 {
			t.Fatal("path byte neighbor not refused before blobs")
		}
	}
}
func mustDecodeOID(t *testing.T, oid string) []byte {
	t.Helper()
	b, e := hex.DecodeString(oid)
	if e != nil {
		t.Fatal("oid")
	}
	return b
}

func TestUpdateCountAndDefaultRefArgumentNeighbors(t *testing.T) {
	good := Config{Base: strings.Repeat("a", 40), DefaultRef: "refs/heads/main", Remote: "https://github.com/example/project.git", Repository: "example/project"}
	for _, n := range []int{8, 9} {
		c := good
		for i := 0; i < n; i++ {
			c.Updates = append(c.Updates, fmt.Sprintf("refs/heads/task%d=absent", i))
		}
		_, e := validatePlan(c)
		if (e == nil) != (n == 8) {
			t.Fatal("update count neighbor")
		}
	}
	good.Updates = []string{"refs/heads/task=absent"}
	for _, ref := range []string{"", "HEAD", "refs/heads/a..b", "refs/heads/.hidden", "refs/tags/main"} {
		c := good
		c.DefaultRef = ref
		if _, e := validatePlan(c); e == nil {
			t.Fatal("invalid default ref admitted")
		}
	}
}

func TestGHConfigDirectoryAdmissionNeighbors(t *testing.T) {
	f := newFixture(t)
	private := filepath.Join(f.dir, "client")
	if os.Mkdir(private, 0700) != nil {
		t.Fatal("mkdir")
	}
	c := f.config()
	c.Publish = true
	c.Repository = "example/project"
	c.Remote = "https://github.com/example/project.git"
	c.DefaultRef = "refs/heads/main"
	c.Updates = []string{"refs/heads/task=absent"}
	c.GHConfig = private
	// Check the admission function directly: no native network or credentials.
	if !privateDir(c.GHConfig) {
		t.Fatal("private config neighbor refused")
	}
	for _, mode := range []os.FileMode{0750, 0755, 0777} {
		if os.Chmod(private, mode) != nil {
			t.Fatal("chmod")
		}
		r, code := run(c)
		require(t, code == 2 && r.ArgumentErrors == 1 && r.Commands == 0, r, code)
	}
	if os.Chmod(private, 0700) != nil {
		t.Fatal("chmod")
	}
	for _, name := range []string{"relative", private + "/../client", filepath.Join(f.dir, "missing")} {
		c.GHConfig = name
		r, code := run(c)
		require(t, code == 2 && r.ArgumentErrors == 1 && r.Commands == 0, r, code)
	}
	link := filepath.Join(f.dir, "client-link")
	if os.Symlink(private, link) != nil {
		t.Fatal("link")
	}
	c.GHConfig = link
	r, code := run(c)
	require(t, code == 2 && r.ArgumentErrors == 1 && r.Commands == 0, r, code)
}

func TestRegexCompiledBudgetAdjacentBoundary(t *testing.T) {
	f := newFixture(t)
	for _, extra := range []int{0, 1} {
		// 15*(1022+2) + (1019+extra+2) + (1+2) instructions.
		patterns := strings.Repeat("L:"+strings.Repeat("z", 1022)+"\n", 15) + "L:" + strings.Repeat("z", 1019+extra) + "\nL:x\n"
		write(t, f.patterns, []byte(patterns))
		p, e := loadPolicy(f.patterns, "")
		if extra == 0 {
			if e != nil || len(p.privateRegex) != 17 {
				t.Fatal("16384-instruction boundary refused")
			}
		} else if e == nil {
			t.Fatal("16385-instruction neighbor admitted")
		}
	}
}

func TestAllOperatorControlsUseModeAdmission(t *testing.T) {
	f := newFixture(t)
	exceptions := filepath.Join(f.dir, "exceptions")
	write(t, exceptions, []byte("line\t"+strings.Repeat("0", 64)+"\n"))
	for _, mode := range []os.FileMode{0600, 0644, 0666} {
		if os.Chmod(f.signers, mode) != nil {
			t.Fatal("chmod")
		}
		r, code := run(f.config())
		if mode == 0666 {
			require(t, code == 1 && r.SignatureErrors == 1 && r.Commands == 0, r, code)
		} else {
			require(t, code == 0 && r.Signatures == 1, r, code)
		}
		if os.Chmod(f.signers, 0600) != nil || os.Chmod(exceptions, mode) != nil {
			t.Fatal("chmod")
		}
		c := f.config()
		c.Exceptions = exceptions
		r, code = run(c)
		if mode == 0666 {
			require(t, code == 1 && r.ScanErrors == 1 && r.Commands == 0, r, code)
		} else {
			require(t, code == 0 && r.Signatures == 1, r, code)
		}
	}
	for _, kind := range []string{"signers", "exceptions"} {
		link := filepath.Join(f.dir, kind+"-link")
		target := f.signers
		if kind == "exceptions" {
			target = exceptions
		}
		if os.Symlink(target, link) != nil {
			t.Fatal("link")
		}
		c := f.config()
		if kind == "signers" {
			c.Signers = link
		} else {
			c.Exceptions = link
		}
		r, code := run(c)
		require(t, code == 1 && r.Commands == 0 && ((kind == "signers" && r.SignatureErrors == 1) || (kind == "exceptions" && r.ScanErrors == 1)), r, code)
	}
}

func TestNativeEnvironmentUsesPrivateStateHOME(t *testing.T) {
	t.Setenv("HOME", "/operator/ambient-home")
	t.Setenv("GH_CONFIG_DIR", "/operator/ambient-client")
	t.Setenv("SSH_AUTH_SOCK", "/operator/ambient-socket")
	g := &runner{home: os.Getenv("HOME"), tmp: "/private/state"}
	for _, auth := range []bool{false, true} {
		g.authDir = ""
		if auth {
			g.authDir = "/selected/client"
		}
		env := map[string]string{}
		for _, entry := range g.environment() {
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) != 2 {
				t.Fatal("environment entry")
			}
			env[parts[0]] = parts[1]
		}
		if env["HOME"] != g.tmp || env["SSH_AUTH_SOCK"] != "" || env["GIT_CONFIG_GLOBAL"] != "/dev/null" || env["GIT_CONFIG_NOSYSTEM"] != "1" {
			t.Fatal("ambient environment admitted")
		}
		if auth {
			if env["GH_CONFIG_DIR"] != g.authDir {
				t.Fatal("selected client route lost")
			}
		} else if _, ok := env["GH_CONFIG_DIR"]; ok {
			t.Fatal("preflight received client environment")
		}
	}
}
