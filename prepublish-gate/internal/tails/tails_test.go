package tails

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	git(t, root, "init", "-b", "main", repo)
	git(t, repo, "config", "user.name", "Fixture")
	git(t, repo, "config", "user.email", "fixture@example.test")
	write(t, filepath.Join(repo, "file"), "base\n")
	git(t, repo, "add", "file")
	git(t, repo, "commit", "-m", "base")
	return root, repo
}
func write(t *testing.T, p, s string) {
	t.Helper()
	if e := os.WriteFile(p, []byte(s), 0600); e != nil {
		t.Fatal(e)
	}
}
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
	defer c()
	a := append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", "-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/git", a...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.Getenv("TMPDIR"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0"}
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("fixture git failed: %s (%v)", args[0], e)
	}
	return strings.TrimSpace(string(b))
}
func reason(r Repository, s string) bool {
	for _, v := range r.Reasons {
		if v == s {
			return true
		}
	}
	return false
}
func TestSelectedDirtyStashDetachedAndCachedAncestry(t *testing.T) {
	root, repo := fixture(t)
	base := git(t, repo, "rev-parse", "HEAD")
	git(t, repo, "config", "remote.origin.url", "https://example.invalid/fixture.git")
	git(t, repo, "update-ref", "refs/remotes/origin/main", base)
	write(t, filepath.Join(repo, "file"), "stash\n")
	git(t, repo, "stash", "push", "-m", "fixture-message-never-emitted")
	write(t, filepath.Join(repo, "file"), "local\n")
	git(t, repo, "add", "file")
	git(t, repo, "commit", "-m", "secret-looking-message-never-emitted")
	local := git(t, repo, "rev-parse", "HEAD")
	wt := filepath.Join(root, "detached")
	git(t, repo, "worktree", "add", "--detach", wt, base)
	write(t, filepath.Join(wt, "other"), "detached\n")
	git(t, wt, "add", "other")
	git(t, wt, "commit", "-m", "detached")
	detached := git(t, wt, "rev-parse", "HEAD")
	write(t, filepath.Join(repo, "file"), "dirty\n")
	beforeIndex, _ := os.ReadFile(filepath.Join(repo, ".git/index"))
	beforeConfig, _ := os.ReadFile(filepath.Join(repo, ".git/config"))
	r := Scan(Options{Repos: []string{repo, wt, repo}, Roots: []string{root}})
	if len(r.Repositories) != 1 {
		t.Fatalf("dedup failed: %d failures=%v", len(r.Repositories), r.Failures)
	}
	rr := r.Repositories[0]
	if len(rr.Branches) != 1 || len(rr.Worktrees) != 2 || rr.Stash == nil || *rr.Stash != 1 || rr.RemoteRefs != 1 {
		t.Fatalf("wrong scoped inventory: %+v", rr)
	}
	seen := map[string]bool{}
	for _, o := range rr.Absent {
		seen[o] = true
	}
	if len(seen) != 2 || !seen[local] || !seen[detached] || seen[base] {
		t.Fatalf("wrong ancestry: %v", rr.Absent)
	}
	dirty, detach := false, false
	for _, w := range rr.Worktrees {
		if w.PathHash == hash(repo) {
			dirty = w.Dirty != nil && *w.Dirty
		}
		detach = detach || w.Detached
	}
	if !dirty || !detach || rr.Race {
		t.Fatalf("status/detached/race: %+v", rr)
	}
	afterIndex, _ := os.ReadFile(filepath.Join(repo, ".git/index"))
	afterConfig, _ := os.ReadFile(filepath.Join(repo, ".git/config"))
	if !bytes.Equal(beforeIndex, afterIndex) || !bytes.Equal(beforeConfig, afterConfig) {
		t.Fatal("source mutation")
	}
	b, _ := json.Marshal(r)
	for _, s := range []string{"secret-looking-message", "fixture-message", repo, "origin/main", "https://example.invalid/fixture.git"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatal("raw sensitive metadata emitted")
		}
	}
	if !r.Complete || rr.RemoteFreshness != "unknown_cached_only" {
		t.Fatal("false completeness")
	}
}
func TestMissingRemoteAndUnavailableObject(t *testing.T) {
	_, repo := fixture(t)
	r := Scan(Options{Repos: []string{repo}})
	if len(r.Repositories) != 1 || !reason(r.Repositories[0], "no_cached_remote_refs") || len(r.Repositories[0].Absent) != 1 {
		t.Fatal("missing remote hidden")
	}
	if r.Repositories[0].Stash == nil || *r.Repositories[0].Stash != 0 {
		t.Fatal("absent stash not zero")
	}
	// A valid ref syntax pointing to an unavailable object must never produce zero success.
	write(t, filepath.Join(repo, ".git/refs/remotes-bad"), "unused\n")
	if e := os.MkdirAll(filepath.Join(repo, ".git/refs/remotes/origin"), 0700); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(repo, ".git/refs/remotes/origin/main"), strings.Repeat("1", 40)+"\n")
	r = Scan(Options{Repos: []string{repo}})
	if len(r.Repositories) != 1 || len(r.Repositories[0].Failures) == 0 {
		t.Fatal("unavailable ancestry hidden")
	}
}
func TestHostileConfigAndStorageFailBeforeChildren(t *testing.T) {
	cases := []string{"[include]\npath = /unmounted-private-file\n", "[filter \"x\"]\nclean = /must-not-run\n", "[core]\nfsmonitor = /must-not-run\n", "[core]\nworktree = /unmounted-private-root\n", "[extensions]\nobjectFormat = sha256\n", "[]\nx = y\n"}
	for _, tail := range cases {
		t.Run(hash(tail)[:8], func(t *testing.T) {
			_, repo := fixture(t)
			p := filepath.Join(repo, ".git/config")
			b, _ := os.ReadFile(p)
			write(t, p, string(b)+tail)
			r := Scan(Options{Repos: []string{repo}})
			if len(r.Repositories) != 0 || r.Commands != 0 || len(r.Failures) == 0 {
				t.Fatal("hostile config reached git")
			}
		})
	}
	_, repo := fixture(t)
	if e := os.Symlink("/unmounted-private-file", filepath.Join(repo, ".git/objects/redirect")); e != nil {
		t.Fatal(e)
	}
	r := Scan(Options{Repos: []string{repo}})
	if r.Commands != 0 {
		t.Fatal("symlink reached git")
	}
}
func TestSensitiveTrackedPathsExcluded(t *testing.T) {
	_, repo := fixture(t)
	if e := os.Mkdir(filepath.Join(repo, ".ssh"), 0700); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(repo, ".ssh/fixture"), "inert\n")
	git(t, repo, "add", ".ssh/fixture")
	r := Scan(Options{Repos: []string{repo}})
	if !reason(r.Repositories[0], "excluded_tracked_path") {
		t.Fatal("sensitive tracked path not refused before status")
	}
}
func TestTimeoutOutputBoundAndDiagnosticSuppression(t *testing.T) {
	root := t.TempDir()
	fake := filepath.Join(root, "fake-git")
	write(t, fake, "#!/bin/sh\nexec /usr/bin/sleep 2\n")
	os.Chmod(fake, 0700)
	r := Report{}
	run := runner{ctx: context.Background(), timeout: 20 * time.Millisecond, report: &r, executable: fake}
	start := time.Now()
	_, f := run.git(root, "fixture-timeout", "status")
	if f == nil || f.Kind != "timeout" || time.Since(start) > time.Second {
		t.Fatal("timeout not bounded")
	}
	write(t, fake, "#!/bin/sh\n/usr/bin/head -c 2200000 /dev/zero\n")
	run.timeout = time.Second
	_, f = run.git(root, "fixture-bound", "status")
	if f == nil || f.Kind != "output_bound" {
		t.Fatal("output truncation not explicit")
	}
	write(t, fake, "#!/bin/sh\necho DO_NOT_EMIT >&2\nexit 7\n")
	_, f = run.git(root, "fixture-failure", "status")
	if f == nil || f.Exit != 7 || f.Kind != "command_failed" {
		t.Fatal("exit not preserved")
	}
}
func TestExplicitScopeAndDiscoveryBound(t *testing.T) {
	var b bytes.Buffer
	if Run(nil, &b) != 2 {
		t.Fatal("implicit scope accepted")
	}
	r := Scan(Options{Repos: []string{"/"}})
	if r.Commands != 0 || len(r.Failures) == 0 {
		t.Fatal("root accepted")
	}
	root, _ := fixture(t)
	if e := os.MkdirAll(filepath.Join(root, "deeper/than/bound"), 0700); e != nil {
		t.Fatal(e)
	}
	r = Scan(Options{Roots: []string{root}})
	if len(r.Failures) == 0 {
		t.Fatal("discovery depth silently complete")
	}
}
func TestProjectedPRMetadata(t *testing.T) {
	root, _ := fixture(t)
	p := filepath.Join(root, "prs.json")
	now := time.Now().UTC().Truncate(time.Second)
	created := now.Add(-8 * 24 * time.Hour)
	value := map[string]any{"observed_at": now, "repositories": []string{"example/project"}, "pagination_complete": true, "open_prs": []map[string]any{{"repository": "example/project", "number": 12, "created_at": created}}}
	b, _ := json.Marshal(value)
	write(t, p, string(b))
	r := Report{Started: now.Add(time.Second)}
	if metadata(p, &r) != nil || len(r.Pulls) != 1 || r.Pulls[0].AgeSeconds != 8*86400 || r.Pulls[0].Ownership != "unknown" || len(r.PRScope) != 1 {
		t.Fatal("PR metadata/age invalid")
	}
	value["pagination_complete"] = false
	b, _ = json.Marshal(value)
	write(t, p, string(b))
	if metadata(p, &r) != nil || r.PRCoverage != "supplied_metadata_incomplete" {
		t.Fatal("pagination incomplete hidden")
	}
	value["unexpected_field"] = "inert"
	b, _ = json.Marshal(value)
	write(t, p, string(b))
	if metadata(p, &r) == nil {
		t.Fatal("raw metadata accepted")
	}
}

func TestObservedLockAndUnselectedWorktree(t *testing.T) {
	root, repo := fixture(t)
	wt := filepath.Join(root, "other")
	git(t, repo, "worktree", "add", "--detach", wt, "HEAD")
	write(t, filepath.Join(repo, ".git/index.lock"), "")
	r := Scan(Options{Repos: []string{repo}})
	if len(r.Repositories) != 1 || !r.Repositories[0].Race || !reason(r.Repositories[0], "git_lock_observed") || !reason(r.Repositories[0], "unselected_worktree") {
		t.Fatal("lock or unselected scope hidden")
	}
	for _, w := range r.Repositories[0].Worktrees {
		if w.PathHash == hash(wt) && w.Dirty != nil {
			t.Fatal("unselected worktree inspected")
		}
	}
}
func TestStaleAndFuturePRMetadata(t *testing.T) {
	root, _ := fixture(t)
	p := filepath.Join(root, "prs.json")
	now := time.Now().UTC()
	r := Report{Started: now}
	for _, at := range []time.Time{now.Add(-25 * time.Hour), now.Add(time.Hour)} {
		b, _ := json.Marshal(map[string]any{"observed_at": at, "repositories": []string{"example/project"}, "pagination_complete": true, "open_prs": []any{}})
		write(t, p, string(b))
		if metadata(p, &r) == nil {
			t.Fatal("stale/future observation accepted")
		}
	}
}
func TestPrivateEnvironmentAdmissionAndOutputFailure(t *testing.T) {
	_, repo := fixture(t)
	old := os.Getenv("HOME")
	nonprivate := filepath.Join(t.TempDir(), "nonprivate")
	if e := os.Mkdir(nonprivate, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(nonprivate, 0755); e != nil {
		t.Fatal(e)
	}
	t.Setenv("HOME", nonprivate)
	r := Scan(Options{Repos: []string{repo}})
	if r.Commands != 0 || len(r.Failures) == 0 || r.Failures[0].Kind != "private_home_tmp_required" {
		t.Fatal("nonprivate home accepted")
	}
	t.Setenv("HOME", old)
	if Run([]string{"--repo", repo}, failWriter{}) != 1 {
		t.Fatal("output failure accepted")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestUntrackedIgnoreAndExcludedDirectory(t *testing.T) {
	_, repo := fixture(t)
	base := git(t, repo, "rev-parse", "HEAD")
	git(t, repo, "update-ref", "refs/remotes/origin/main", base)
	write(t, filepath.Join(repo, ".gitignore"), "ignored\n")
	git(t, repo, "add", ".gitignore")
	git(t, repo, "commit", "-m", "ignore fixture")
	git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
	write(t, filepath.Join(repo, "ignored"), "ignored\n")
	r := Scan(Options{Repos: []string{repo}})
	w := r.Repositories[0].Worktrees[0]
	if !r.Complete || w.UntrackedCount == nil || *w.UntrackedCount != 0 || w.AnyDirty == nil || *w.AnyDirty {
		t.Fatal("ignored file incorrectly dirty or incomplete")
	}
	write(t, filepath.Join(repo, "new"), "untracked\n")
	r = Scan(Options{Repos: []string{repo}})
	w = r.Repositories[0].Worktrees[0]
	if !r.Complete || w.UntrackedCount == nil || *w.UntrackedCount != 1 || w.AnyDirty == nil || !*w.AnyDirty {
		t.Fatal("untracked file not dirty")
	}
	if e := os.Mkdir(filepath.Join(repo, ".ssh"), 0000); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(filepath.Join(repo, ".ssh"), 0700)
	r = Scan(Options{Repos: []string{repo}})
	w = r.Repositories[0].Worktrees[0]
	if r.Complete || !reason(r.Repositories[0], "untracked_or_submodule_exclusions") || w.Untracked != "partial_exclusions" {
		t.Fatal("excluded directory not marked; must skip before opening")
	}
}

func TestUnbornAndMissingStashReflog(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "unborn")
	git(t, root, "init", "-b", "main", repo)
	r := Scan(Options{Repos: []string{repo}})
	if len(r.Repositories) != 1 || r.Complete || !reason(r.Repositories[0], "unborn_or_invalid_head") {
		t.Fatal("empty successful native output mistaken for scan failure or completeness")
	}
	_, repo = fixture(t)
	write(t, filepath.Join(repo, "file"), "stash\n")
	git(t, repo, "stash", "push", "-m", "fixture")
	if e := os.Remove(filepath.Join(repo, ".git/logs/refs/stash")); e != nil {
		t.Fatal(e)
	}
	r = Scan(Options{Repos: []string{repo}})
	if r.Repositories[0].Stash != nil || !reason(r.Repositories[0], "stash_reflog_unavailable") {
		t.Fatal("missing stash reflog silently became zero")
	}
}
func TestSubmoduleNotTraversed(t *testing.T) {
	_, repo := fixture(t)
	base := git(t, repo, "rev-parse", "HEAD")
	git(t, repo, "update-ref", "refs/remotes/origin/main", base)
	git(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+base+",module")
	if e := os.Mkdir(filepath.Join(repo, "module"), 0000); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(filepath.Join(repo, "module"), 0700)
	r := Scan(Options{Repos: []string{repo}})
	if len(r.Repositories) != 1 || !reason(r.Repositories[0], "untracked_or_submodule_exclusions") {
		t.Fatal("submodule exclusion hidden")
	}
	for _, f := range r.Repositories[0].Failures {
		if f.Stage == "untracked_walk" {
			t.Fatal("submodule opened instead of skipped")
		}
	}
}

func TestDiscoveryExcludedRootIsIncomplete(t *testing.T) {
	root, _ := fixture(t)
	if e := os.Mkdir(filepath.Join(root, ".ssh"), 0000); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(filepath.Join(root, ".ssh"), 0700)
	r := Scan(Options{Roots: []string{root}})
	found := false
	for _, f := range r.Failures {
		found = found || f.Stage == "discovery" && f.Kind == "excluded_subtree"
	}
	if !found || r.Complete {
		t.Fatal("excluded work-root subtree hidden")
	}
}
