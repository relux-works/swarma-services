package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	t                                                  *testing.T
	dir, repo, key, signers, patterns, base, candidate string
}

func command(t *testing.T, dir string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Dir = dir
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.Getenv("TMPDIR"), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
	out, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("synthetic fixture command failed (output redacted): %v", c.ProcessState.ExitCode())
	}
	return strings.TrimSpace(string(out))
}
func write(t *testing.T, name string, b []byte) {
	t.Helper()
	if e := os.WriteFile(name, b, 0600); e != nil {
		t.Fatal("fixture write failed")
	}
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := t.TempDir()
	f := &fixture{t: t, dir: d, repo: filepath.Join(d, "work"), key: filepath.Join(d, "key"), signers: filepath.Join(d, "allowed"), patterns: filepath.Join(d, "patterns")}
	if os.Mkdir(f.repo, 0700) != nil {
		t.Fatal("mkdir")
	}
	command(t, d, "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f.key)
	pub, e := os.ReadFile(f.key + ".pub")
	if e != nil {
		t.Fatal("public key")
	}
	parts := strings.Fields(string(pub))
	write(t, f.signers, []byte("fixture@example.test "+parts[0]+" "+parts[1]+"\n"))
	write(t, f.patterns, []byte("L:SYNTHETIC_PRIVATE_MARKER\n"))
	f.git("init", "--initial-branch=main")
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\n"))
	f.base = f.commit("trusted baseline", false)
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\nclean addition\n"))
	f.candidate = f.commit("clean candidate", true)
	return f
}
func (f *fixture) git(args ...string) string {
	f.t.Helper()
	a := []string{"/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test"}
	return command(f.t, f.repo, append(a, args...)...)
}
func (f *fixture) commit(message string, sign bool) string {
	f.t.Helper()
	f.git("add", "--all")
	a := []string{"-c", "commit.gpgsign=false"}
	if sign {
		a = []string{"-c", "gpg.format=ssh", "-c", "user.signingkey=" + f.key, "-c", "commit.gpgsign=true"}
	}
	a = append(a, "commit", "--allow-empty", "-m", message)
	f.git(a...)
	return f.git("rev-parse", "HEAD")
}
func (f *fixture) config() Config {
	return Config{Objects: filepath.Join(f.repo, ".git", "objects"), Base: f.base, Candidate: f.candidate, Patterns: f.patterns, Signers: f.signers, Principal: "fixture@example.test"}
}
func (f *fixture) destination() string {
	f.t.Helper()
	p := filepath.Join(f.dir, "remote.git")
	command(f.t, f.dir, "/usr/bin/git", "init", "--bare", p)
	f.seed(p, "refs/heads/main", f.base)
	return p
}
func (f *fixture) seed(remote, ref, oid string) { f.t.Helper(); f.git("push", remote, oid+":"+ref) }
func (f *fixture) remoteOID(remote, ref string) string {
	f.t.Helper()
	return command(f.t, f.dir, "/usr/bin/git", "--git-dir="+remote, "rev-parse", "--verify", ref)
}
func (f *fixture) pub(remote string, updates ...string) Config {
	c := f.config()
	c.Publish = true
	c.LocalDestination = true
	c.Remote = remote
	c.Repository = "local-test"
	c.DefaultRef = "refs/heads/main"
	c.Updates = updates
	return c
}
func run(c Config) (Report, int) { return Execute(context.Background(), c) }
func require(t *testing.T, ok bool, r Report, code int) {
	t.Helper()
	if !ok {
		t.Fatalf("unexpected numeric result: %+v exit=%d", r, code)
	}
}

func TestKnownGoodAndCountsOnlyCLI(t *testing.T) {
	f := newFixture(t)
	r, code := run(f.config())
	require(t, code == 0 && r.Completed == 1 && r.Commits == 1 && r.Signatures == 1 && r.AddedLines == 1 && r.Paths == 1 && r.Messages == 1 && r.PrivateHits == 0, r, code)
	var out bytes.Buffer
	c := f.config()
	code = Run([]string{"check", "--objects", c.Objects, "--base", c.Base, "--candidate", c.Candidate, "--patterns", c.Patterns, "--allowed-signers", c.Signers, "--principal", c.Principal}, &out)
	var values map[string]any
	if json.Unmarshal(out.Bytes(), &values) != nil {
		t.Fatal("not JSON")
	}
	for _, v := range values {
		if _, ok := v.(float64); !ok {
			t.Fatal("non-count output")
		}
	}
	if code != 0 {
		t.Fatal("CLI failure")
	}
}
func TestPrivateHitsInEveryRequiredSurface(t *testing.T) {
	for _, kind := range []string{"line", "path", "message"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			const marker = "SYNTHETIC_PRIVATE_MARKER"
			message := "second candidate"
			name := "another.txt"
			content := "safe\n"
			switch kind {
			case "line":
				content = marker + "\n"
			case "path":
				name = marker + ".txt"
			case "message":
				message = marker
			}
			write(t, filepath.Join(f.repo, name), []byte(content))
			f.candidate = f.commit(message, true)
			var out bytes.Buffer
			c := f.config()
			args := []string{"check", "--objects", c.Objects, "--base", c.Base, "--candidate", c.Candidate, "--patterns", c.Patterns, "--allowed-signers", c.Signers, "--principal", c.Principal}
			code := Run(args, &out)
			var r Report
			if json.Unmarshal(out.Bytes(), &r) != nil {
				t.Fatal("report")
			}
			require(t, code == 1 && r.Completed == 1 && r.PrivateHits == 1 && !strings.Contains(out.String(), marker) && !strings.Contains(out.String(), name), r, code)
		})
	}
}
func TestIntermediateCommitCannotHideSecret(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.repo, "data.txt"), []byte("SYNTHETIC_PRIVATE_MARKER\n"))
	f.commit("intermediate", true)
	write(t, filepath.Join(f.repo, "data.txt"), []byte("clean again\n"))
	f.candidate = f.commit("final", true)
	r, code := run(f.config())
	require(t, code == 1 && r.PrivateHits == 1 && r.Commits == 3 && r.Completed == 1, r, code)
}
func TestBaselineRemovedAndContextExcluded(t *testing.T) {
	f := newFixture(t)
	write(t, f.patterns, []byte("L:base\n"))
	r, code := run(f.config())
	require(t, code == 0 && r.PrivateHits == 0, r, code)
	write(t, filepath.Join(f.repo, "data.txt"), []byte("replacement\n"))
	f.candidate = f.commit("delete old lines", true)
	r, code = run(f.config())
	require(t, code == 0 && r.PrivateHits == 0, r, code)
}
func TestUnsignedAndRejectedSigner(t *testing.T) {
	for _, kind := range []string{"unsigned", "wrong-key", "wrong-principal", "wildcard-principal"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "unsigned":
				f.candidate = f.commit("unsigned", false)
			case "wrong-key":
				f.key = filepath.Join(f.dir, "second-key")
				command(t, f.dir, "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f.key)
				f.candidate = f.commit("different key", true)
			case "wrong-principal":
				b, _ := os.ReadFile(f.signers)
				write(t, f.signers, bytes.ReplaceAll(b, []byte("fixture@example.test"), []byte("other@example.test")))
			case "wildcard-principal":
				b, _ := os.ReadFile(f.signers)
				write(t, f.signers, bytes.ReplaceAll(b, []byte("fixture@example.test"), []byte("*")))
			}
			r, code := run(f.config())
			require(t, code == 1 && r.SignatureErrors == 1 && r.Completed == 0, r, code)
		})
	}
}
func TestPatternRefusalsAndRedaction(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("R:[SYNTHETIC_PRIVATE_MARKER\n"), []byte("R:.*\n"), []byte("L:\n"), []byte("L:ok\n\n"), []byte("L:ok\r\n"), {0xff}, []byte("L:bad\x00"), []byte(strings.Repeat("L:x\n", MaxPatterns+1)), []byte("L:" + strings.Repeat("x", 1023)), []byte("R:(a{1000}){1000}\n")} {
		t.Run(fmt.Sprint(len(b)), func(t *testing.T) {
			f := newFixture(t)
			write(t, f.patterns, b)
			r, code := run(f.config())
			require(t, code == 1 && r.ScanErrors == 1 && r.Completed == 0, r, code)
		})
	}
	f := newFixture(t)
	c := f.config()
	c.Patterns = filepath.Join(f.dir, "SYNTHETIC_PRIVATE_MARKER-missing")
	r, code := run(c)
	require(t, code == 1 && r.ScanErrors == 1, r, code)
	if os.Chmod(f.patterns, 0644) != nil {
		t.Fatal("chmod")
	}
	r, code = run(f.config())
	require(t, code == 1 && r.ScanErrors == 1, r, code)
}
func TestRegexLiteralAndUnicode(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\na.b\nαβ\n"))
	f.candidate = f.commit("unicode", true)
	for _, tc := range []struct {
		pattern string
		hits    int
	}{{"L:a.b\n", 1}, {"L:a*b\n", 0}, {"R:^a.b$\n", 1}, {"R:^α[β]$\n", 1}} {
		write(t, f.patterns, []byte(tc.pattern))
		r, code := run(f.config())
		require(t, r.Completed == 1 && r.PrivateHits == tc.hits && (code == 0) == (tc.hits == 0), r, code)
	}
}
func TestHygieneExactExceptionsNeverSuppressPrivate(t *testing.T) {
	f := newFixture(t)
	line := "/" + "home/example/private"
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\n"+line+"\n"))
	f.candidate = f.commit("example", true)
	r, code := run(f.config())
	require(t, code == 1 && r.HygieneHits == 1, r, code)
	h := sha256.Sum256([]byte(line))
	exception := filepath.Join(f.dir, "exceptions")
	write(t, exception, []byte("line\t"+hex.EncodeToString(h[:])+"\n"))
	c := f.config()
	c.Exceptions = exception
	r, code = run(c)
	require(t, code == 0 && r.HygieneExceptions == 1 && r.HygieneHits == 0, r, code)
	write(t, f.patterns, []byte("L:"+line+"\n"))
	r, code = run(c)
	require(t, code == 1 && r.PrivateHits == 1 && r.HygieneExceptions == 1, r, code)
	write(t, exception, []byte("line\t*\n"))
	r, code = run(c)
	require(t, code == 1 && r.ScanErrors == 1, r, code)
}
func TestMalformedBinaryUnsupportedAndMissingObjects(t *testing.T) {
	for _, kind := range []string{"nul", "utf8", "symlink", "missing", "merge", "record-limit", "blob-limit", "corrupt", "alternates"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "nul":
				write(t, filepath.Join(f.repo, "data.txt"), []byte("binary\x00"))
				f.candidate = f.commit("binary", true)
			case "utf8":
				write(t, filepath.Join(f.repo, "data.txt"), []byte{0xff})
				f.candidate = f.commit("invalid text", true)
			case "symlink":
				if os.Symlink("data.txt", filepath.Join(f.repo, "link")) != nil {
					t.Fatal("link")
				}
				f.candidate = f.commit("link", true)
			case "missing":
				f.candidate = strings.Repeat("1", 40)
			case "merge":
				f.git("checkout", "-b", "side", f.base)
				write(t, filepath.Join(f.repo, "side.txt"), []byte("side\n"))
				f.commit("side", true)
				f.git("checkout", "main")
				f.git("-c", "gpg.format=ssh", "-c", "user.signingkey="+f.key, "-c", "commit.gpgsign=true", "merge", "--no-ff", "side", "-m", "merge")
				f.candidate = f.git("rev-parse", "HEAD")
			case "record-limit":
				write(t, filepath.Join(f.repo, "data.txt"), bytes.Repeat([]byte("x"), MaxRecord+1))
				f.candidate = f.commit("too long", true)
			case "blob-limit":
				write(t, filepath.Join(f.repo, "data.txt"), bytes.Repeat([]byte("x\n"), MaxBlob/2+1))
				f.candidate = f.commit("too big", true)
			case "corrupt":
				file := filepath.Join(f.repo, ".git", "objects", f.candidate[:2], f.candidate[2:])
				if os.Chmod(file, 0600) != nil {
					t.Fatal("object")
				}
				write(t, file, []byte("SYNTHETIC_PRIVATE_MARKER invalid zlib"))
			case "alternates":
				write(t, filepath.Join(f.repo, ".git", "objects", "info", "alternates"), []byte("/SYNTHETIC_PRIVATE_MARKER\n"))
			}
			r, code := run(f.config())
			require(t, code == 1 && r.ScanErrors == 1 && r.Completed == 0, r, code)
		})
	}
}
func TestPublishNewExistingAndPinnedRefRace(t *testing.T) {
	f := newFixture(t)
	dest := f.destination()
	f.seed(dest, "refs/heads/existing", f.base)
	checked := f.candidate
	write(t, filepath.Join(f.repo, "data.txt"), []byte("SYNTHETIC_PRIVATE_MARKER\n"))
	mutableHead := f.commit("unrelated future", true)
	c := f.pub(dest, "refs/heads/existing="+f.base, "refs/heads/new=absent")
	// The source branch has moved; the explicitly selected candidate has not.
	if mutableHead == checked {
		t.Fatal("fixture did not move")
	}
	r, code := run(c)
	require(t, code == 0 && r.PublishedRefs == 2 && r.PrivateHits == 0, r, code)
	for _, ref := range []string{"refs/heads/existing", "refs/heads/new"} {
		if f.remoteOID(dest, ref) != checked {
			t.Fatal("mutable ref was published")
		}
	}
}
func TestLeaseStaleMissingAndAbsentCollision(t *testing.T) {
	for _, kind := range []string{"stale", "missing", "absent-collision"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			dest := f.destination()
			expected := f.base
			switch kind {
			case "stale":
				f.seed(dest, "refs/heads/target", f.candidate)
			case "absent-collision":
				f.seed(dest, "refs/heads/target", f.base)
				expected = "absent"
			}
			r, code := run(f.pub(dest, "refs/heads/target="+expected))
			require(t, code == 1 && r.Completed == 1 && r.LeaseErrors == 1 && r.PublishedRefs == 0, r, code)
			if kind == "stale" && f.remoteOID(dest, "refs/heads/target") != f.candidate {
				t.Fatal("stale overwritten")
			}
		})
	}
}
func TestAtomicRejectAndUnsupportedAtomicNeverRetry(t *testing.T) {
	for _, kind := range []string{"hook-reject", "atomic-unsupported"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			dest := f.destination()
			f.seed(dest, "refs/heads/one", f.base)
			f.seed(dest, "refs/heads/two", f.base)
			if kind == "hook-reject" {
				hook := filepath.Join(dest, "hooks", "update")
				write(t, hook, []byte("#!/bin/sh\ncase \"$1\" in refs/heads/two) echo SYNTHETIC_PRIVATE_MARKER >&2; exit 1;; esac\nexit 0\n"))
				if os.Chmod(hook, 0700) != nil {
					t.Fatal("hook")
				}
			} else {
				command(t, f.dir, "/usr/bin/git", "--git-dir="+dest, "config", "receive.advertiseAtomic", "false")
			}
			r, code := run(f.pub(dest, "refs/heads/one="+f.base, "refs/heads/two="+f.base))
			require(t, code == 1 && r.PublicationErrors == 1 && r.PublishedRefs == 0, r, code)
			for _, ref := range []string{"refs/heads/one", "refs/heads/two"} {
				if f.remoteOID(dest, ref) != f.base {
					t.Fatal("atomicity lost")
				}
			}
		})
	}
}
func TestLeaseRaceBetweenPreflightAndPush(t *testing.T) {
	f := newFixture(t)
	dest := f.destination()
	f.seed(dest, "refs/heads/one", f.base)
	f.seed(dest, "refs/heads/two", f.base)
	f.seed(dest, "refs/heads/race-object", f.candidate)
	// The receiver changes a ref after advertisement/preflight. The atomic push
	// must fail for both refs. This witnesses receive-pack old-value atomicity;
	// TestPerRefLeaseAdvertisementWitness separately discriminates the lease.
	hook := filepath.Join(dest, "hooks", "pre-receive")
	script := "#!/bin/sh\n/usr/bin/env -u GIT_QUARANTINE_PATH -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES /usr/bin/git --git-dir='" + dest + "' update-ref refs/heads/two " + f.candidate + " " + f.base + " || exit 1\ncat >/dev/null\n"
	write(t, hook, []byte(script))
	if os.Chmod(hook, 0700) != nil {
		t.Fatal("hook")
	}
	r, code := run(f.pub(dest, "refs/heads/one="+f.base, "refs/heads/two="+f.base))
	require(t, code == 1 && r.PublicationErrors == 1, r, code)
	if f.remoteOID(dest, "refs/heads/one") != f.base {
		t.Fatal("unrelated ref mutated")
	}
	if f.remoteOID(dest, "refs/heads/two") != f.candidate {
		t.Fatal("race was not exercised")
	}
}
func TestNoMutationWithoutExplicitCommandAndChecks(t *testing.T) {
	f := newFixture(t)
	dest := f.destination()
	f.seed(dest, "refs/heads/target", f.base)
	c := f.pub(dest, "refs/heads/target="+f.base)
	c.Publish = false
	r, code := run(c)
	require(t, code == 0 && r.PublishedRefs == 0, r, code)
	if f.remoteOID(dest, "refs/heads/target") != f.base {
		t.Fatal("check mutated")
	}
	write(t, f.patterns, []byte("L:clean\n"))
	c.Publish = true
	r, code = run(c)
	require(t, code == 1 && r.PrivateHits > 0 && r.PublishedRefs == 0, r, code)
	if f.remoteOID(dest, "refs/heads/target") != f.base {
		t.Fatal("blocked candidate mutated")
	}
	var out bytes.Buffer
	code = Run([]string{"publish", "--remote", dest}, &out)
	if code != 2 {
		t.Fatal("missing opt-in accepted")
	}
}
func TestPlanValidationBoundedNeighbors(t *testing.T) {
	f := newFixture(t)
	good := Config{Base: f.base, DefaultRef: "refs/heads/main", Remote: "https://github.com/example/project.git", Repository: "example/project", Updates: []string{"refs/heads/candidate=" + f.base}}
	if _, e := validatePlan(good); e != nil {
		t.Fatal("valid canonical endpoint rejected")
	}
	for _, bad := range []string{"refs/heads/*", "refs/heads/a..b", "refs/heads/.hidden", "refs/heads/a.lock", "refs/tags/v1", "refs/heads/a/", "refs/heads/a//b", "refs/heads/a@{x}", "refs/heads/a:other", "--all", "refs/heads/a\nSYNTHETIC_PRIVATE_MARKER"} {
		c := good
		c.Updates = []string{bad + "=" + f.base}
		if _, e := validatePlan(c); e == nil {
			t.Fatal("unsafe ref accepted")
		}
	}
	for _, remote := range []string{"origin", "-oProxyCommand=bad", "ssh://example/project", "https://github.com/other/project.git", "https://github.com/example/project.git?x=1", "https://user@github.com/example/project.git"} {
		c := good
		c.Remote = remote
		if _, e := validatePlan(c); e == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	c := good
	c.Updates = []string{"refs/heads/a=" + strings.Repeat("1", 40)}
	if _, e := validatePlan(c); e == nil {
		t.Fatal("unchecked old head accepted")
	}
	c = good
	c.Updates = []string{"refs/heads/a=absent", "refs/heads/a=absent"}
	if _, e := validatePlan(c); e == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestDiffParserBoundaries(t *testing.T) {
	p := policy{privateRegex: []*regexp.Regexp{regexp.MustCompile(`secret`)}, exceptions: map[string]bool{}}
	for _, tc := range []struct {
		patch string
		ok    bool
		hits  int
	}{
		{"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1,1 @@\n+secret\n", true, 1},
		{"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1,1 @@\n+++secret\n", true, 1},
		{"diff --git a/x b/x\n@@ -1 +1 @@\n-secret\n+clean\n", true, 0},
		{"diff --git a/x b/x\n@@ -0,0 +1,2 @@\n+secret\n", false, 0},
		{"diff --git a/x b/x\nBinary files differ\n", false, 0},
		{"+++ secret\n+secret\n", false, 0},
		{"@@ -0,0 +1 @@\n+secret", false, 0},
	} {
		r := Report{}
		e := added(p, []byte(tc.patch), &r)
		if (e == nil) != tc.ok || (tc.ok && r.PrivateHits != tc.hits) {
			t.Fatal("diff parser boundary")
		}
	}
}

func TestSourceConfigurationAndReplaceRefsCannotChangeChecks(t *testing.T) {
	f := newFixture(t)
	f.git("config", "gpg.ssh.program", "/bin/false")
	f.git("config", "diff.external", "/bin/false")
	f.git("config", "core.hooksPath", "/unavailable")
	f.git("replace", f.candidate, f.base)
	r, code := run(f.config())
	require(t, code == 0 && r.Signatures == 1 && r.AddedLines == 1, r, code)
}
func TestPatternAndRecordBoundedNeighbors(t *testing.T) {
	f := newFixture(t)
	write(t, f.patterns, []byte(strings.Repeat("L:absent\n", MaxPatterns)))
	r, code := run(f.config())
	require(t, code == 0, r, code)
	write(t, f.patterns, []byte("L:"+strings.Repeat("z", 1022)+"\n"))
	r, code = run(f.config())
	require(t, code == 0, r, code)
	write(t, f.patterns, []byte("L:absent\n"))
	write(t, filepath.Join(f.repo, "data.txt"), append(bytes.Repeat([]byte("a"), MaxRecord), '\n'))
	f.candidate = f.commit("record boundary", true)
	r, code = run(f.config())
	require(t, code == 0 && r.Completed == 1, r, code)
	write(t, filepath.Join(f.repo, "data.txt"), append(bytes.Repeat([]byte("a"), MaxRecord+1), '\n'))
	f.candidate = f.commit("record neighbor", true)
	r, code = run(f.config())
	require(t, code == 1 && r.ScanErrors == 1, r, code)
}
func TestNewDeletionModeChangeAndNewlinePaths(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.repo, "new.txt"), []byte("new without newline"))
	f.candidate = f.commit("new file", true)
	r, code := run(f.config())
	require(t, code == 0 && r.AddedLines == 2 && r.Paths == 2, r, code)
	if os.Remove(filepath.Join(f.repo, "new.txt")) != nil {
		t.Fatal("remove")
	}
	f.candidate = f.commit("deletion", true)
	r, code = run(f.config())
	require(t, code == 0 && r.Paths == 3, r, code)
	if os.Chmod(filepath.Join(f.repo, "data.txt"), 0700) != nil {
		t.Fatal("mode")
	}
	f.candidate = f.commit("mode", true)
	r, code = run(f.config())
	require(t, code == 0 && r.Paths == 4, r, code)
	write(t, filepath.Join(f.repo, "line\nSYNTHETIC_PRIVATE_MARKER"), []byte("safe\n"))
	f.candidate = f.commit("newline path", true)
	r, code = run(f.config())
	require(t, code == 1 && r.Completed == 1 && r.PrivateHits == 1, r, code)
}
func TestMissingLeaseInMultiRefPlanNeverMutatesOtherRef(t *testing.T) {
	f := newFixture(t)
	dest := f.destination()
	f.seed(dest, "refs/heads/existing", f.base)
	r, code := run(f.pub(dest, "refs/heads/existing="+f.base, "refs/heads/missing="+f.base))
	require(t, code == 1 && r.LeaseErrors == 1, r, code)
	if f.remoteOID(dest, "refs/heads/existing") != f.base {
		t.Fatal("partial mutation")
	}
}
func TestControlSymlinksAndCancelRefuse(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.dir, "pattern-link")
	if os.Symlink(f.patterns, link) != nil {
		t.Fatal("link")
	}
	c := f.config()
	c.Patterns = link
	r, code := run(c)
	require(t, code == 1 && r.ScanErrors == 1, r, code)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, code = Execute(ctx, f.config())
	require(t, code == 1 && r.ScanErrors == 1, r, code)
}
func TestCLIArgumentBytesNeverEscape(t *testing.T) {
	for _, args := range [][]string{{"SYNTHETIC_PRIVATE_MARKER"}, {"check", "--SYNTHETIC_PRIVATE_MARKER"}, {"check", "--candidate", "SYNTHETIC_PRIVATE_MARKER"}, {"publish", "--execute-publication", "--remote", "SYNTHETIC_PRIVATE_MARKER"}, {"check", "--execute-publication"}} {
		var out bytes.Buffer
		code := Run(args, &out)
		var r Report
		if json.Unmarshal(out.Bytes(), &r) != nil || strings.Contains(out.String(), "SYNTHETIC_PRIVATE_MARKER") || code != 2 || r.ArgumentErrors != 1 {
			t.Fatal("argument boundary")
		}
	}
}
func TestSandboxExcludesCredentialsAndSocket(t *testing.T) {
	if os.Getenv("PREPUBLISH_VERIFY_SANDBOX") != "1" {
		t.Skip("requires an explicit Linux isolation fixture")
	}
	if os.Getenv("SSH_AUTH_SOCK") != "" || os.Getenv("GH_CONFIG_DIR") != "" || os.Getenv("GITHUB_TOKEN") != "" {
		t.Fatal("sandbox inherited authorization")
	}
	if _, e := os.Stat("/home"); !os.IsNotExist(e) {
		t.Fatal("host home visible")
	}
}

func TestHygieneCategoriesAndBenignNeighbors(t *testing.T) {
	p := policy{exceptions: map[string]bool{}}
	samples := []string{
		"/" + "home/example/file", "/" + "run/user/1234/socket",
		"192" + ".0.2.1", ":" + ":1", "fe80:" + ":1",
		"@fixture" + ":example.test", "!fixture" + ":example.test",
		"$" + strings.Repeat("a", 24),
		"ghp_" + strings.Repeat("a", 36),
	}
	for i, s := range samples {
		r := Report{}
		if p.match("line", []byte(s), &r) != nil || r.HygieneHits != 1 {
			t.Fatalf("hygiene category %d refused or missed", i)
		}
	}
	for _, s := range []string{"release@example.test", "/usr/bin/git", "12345", "normal text", "2026-01-01T00:00:00Z"} {
		r := Report{}
		if p.match("line", []byte(s), &r) != nil || r.HygieneHits != 0 {
			t.Fatal("benign neighbor refused")
		}
	}
}
func TestCommitCountBoundary(t *testing.T) {
	f := newFixture(t)
	for i := 1; i < MaxCommits; i++ {
		f.candidate = f.commit("bounded commit", true)
	}
	r, code := run(f.config())
	require(t, code == 0 && r.Commits == MaxCommits && r.Signatures == MaxCommits, r, code)
	f.candidate = f.commit("over count", true)
	r, code = run(f.config())
	require(t, code == 1 && r.ScanErrors == 1 && r.Completed == 0, r, code)
}
func TestOversizedUnreachableObjectRefusesBeforeScan(t *testing.T) {
	f := newFixture(t)
	untracked := filepath.Join(f.dir, "oversized")
	write(t, untracked, bytes.Repeat([]byte("x"), MaxBlob+1))
	f.git("hash-object", "-w", untracked)
	r, code := run(f.config())
	require(t, code == 1 && r.ScanErrors == 1 && r.Signatures == 0, r, code)
}
