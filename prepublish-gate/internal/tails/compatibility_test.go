package tails

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func expectGitConflict(t *testing.T, repo string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C", repo}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.Getenv("TMPDIR"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
	if e := cmd.Run(); e == nil || ctx.Err() != nil || cmd.ProcessState.ExitCode() != 1 {
		t.Fatal("fixture did not enter expected conflict")
	}
}

func requireFileShape(t *testing.T, repo, pattern string) {
	t.Helper()
	paths, e := filepath.Glob(filepath.Join(repo, ".git", pattern))
	if e != nil || len(paths) == 0 {
		t.Fatal("stock Git did not emit required storage shape")
	}
	for _, p := range paths {
		if _, e := os.Stat(p); e != nil {
			t.Fatal(e)
		}
	}
}

func TestStockGitMetadataCompatibility(t *testing.T) {
	for _, state := range []string{"control", "gc", "repack", "cruft", "split-graph", "multi-pack-index", "cherry-pick", "revert", "rebase", "rebase-apply", "sequencer", "branches", "stash-notes", "fetch", "merge", "ref-lock"} {
		t.Run(state, func(t *testing.T) {
			root, repo := fixture(t)
			base := git(t, repo, "rev-parse", "HEAD")
			git(t, repo, "update-ref", "refs/remotes/origin/main", base)
			switch state {
			case "ref-lock":
				write(t, filepath.Join(repo, ".git/refs/heads/main.lock"), base+"\n")
			case "gc":
				git(t, repo, "gc")
			case "repack":
				git(t, repo, "repack", "-adb")
			case "cruft":
				cmd := exec.Command("/usr/bin/git", "-C", repo, "hash-object", "-w", "--stdin")
				cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
				cmd.Stdin = strings.NewReader("unreachable synthetic blob\n")
				if _, e := cmd.Output(); e != nil {
					t.Fatal(e)
				}
				git(t, repo, "gc", "--cruft")
				requireFileShape(t, repo, "objects/pack/*.mtimes")
			case "split-graph":
				git(t, repo, "commit-graph", "write", "--reachable", "--split")
				requireFileShape(t, repo, "objects/info/commit-graphs/commit-graph-chain")
			case "multi-pack-index":
				git(t, repo, "repack", "-ad")
				git(t, repo, "multi-pack-index", "write")
				requireFileShape(t, repo, "objects/pack/multi-pack-index")
			case "branches":
				if e := os.Mkdir(filepath.Join(repo, ".git/branches"), 0700); e != nil && !os.IsExist(e) {
					t.Fatal(e)
				}
			case "stash-notes":
				write(t, filepath.Join(repo, "file"), "stash\n")
				git(t, repo, "stash", "push", "-m", "synthetic")
				git(t, repo, "notes", "add", "-m", "synthetic")
				git(t, repo, "pack-refs", "--all")
				git(t, repo, "update-server-info")
			case "fetch":
				remote := filepath.Join(root, "remote")
				git(t, root, "clone", "--bare", repo, remote)
				git(t, repo, "fetch", remote, "main:refs/remotes/fixture/main")
			case "cherry-pick", "revert", "rebase", "rebase-apply", "sequencer", "merge":
				git(t, repo, "checkout", "-b", "topic")
				write(t, filepath.Join(repo, "file"), "topic\n")
				git(t, repo, "commit", "-am", "topic")
				topic := git(t, repo, "rev-parse", "HEAD")
				write(t, filepath.Join(repo, "other"), "second\n")
				git(t, repo, "add", "other")
				git(t, repo, "commit", "-m", "second")
				second := git(t, repo, "rev-parse", "HEAD")
				git(t, repo, "checkout", "main")
				write(t, filepath.Join(repo, "file"), "main\n")
				git(t, repo, "commit", "-am", "main")
				switch state {
				case "cherry-pick":
					expectGitConflict(t, repo, "cherry-pick", topic)
					requireFileShape(t, repo, "CHERRY_PICK_HEAD")
				case "revert":
					expectGitConflict(t, repo, "revert", "--no-edit", topic)
					requireFileShape(t, repo, "REVERT_HEAD")
				case "rebase":
					expectGitConflict(t, repo, "rebase", "topic")
					requireFileShape(t, repo, "rebase-merge")
				case "rebase-apply":
					expectGitConflict(t, repo, "rebase", "--apply", "topic")
					requireFileShape(t, repo, "rebase-apply")
				case "sequencer":
					expectGitConflict(t, repo, "cherry-pick", topic, second)
					requireFileShape(t, repo, "sequencer/todo")
				case "merge":
					expectGitConflict(t, repo, "merge", "--no-edit", "topic")
					requireFileShape(t, repo, "MERGE_HEAD")
				}
			}
			r := Scan(Options{Repos: []string{repo}})
			if !r.Complete || len(r.Repositories) != 1 || r.Commands == 0 || r.Counts.Repositories != 1 || len(r.Repositories[0].Worktrees) != 1 || len(r.Repositories[0].Branches) == 0 || r.Repositories[0].Coverage != "complete" {
				t.Fatalf("stock Git inventory incomplete: failures=%v", r.Failures)
			}
		})
	}
}

func TestConfigNamedRefs(t *testing.T) {
	for _, name := range []string{"config", "feature/config", "config/x", "tag", "remote", "packed"} {
		t.Run(name, func(t *testing.T) {
			_, repo := fixture(t)
			base := git(t, repo, "rev-parse", "HEAD")
			git(t, repo, "update-ref", "refs/remotes/origin/main", base)
			switch name {
			case "tag":
				git(t, repo, "tag", "config")
			case "remote":
				git(t, repo, "update-ref", "refs/remotes/origin/config", base)
			case "packed":
				git(t, repo, "branch", "config")
				git(t, repo, "pack-refs", "--all")
				requireFileShape(t, repo, "logs/refs/heads/config")
			default:
				git(t, repo, "branch", name)
			}
			r := Scan(Options{Repos: []string{repo}})
			if !r.Complete || r.Commands == 0 || len(r.Repositories) != 1 || len(r.Repositories[0].Worktrees) != 1 {
				t.Fatal("config name lost repository")
			}
			expected := 1
			if name != "tag" && name != "remote" {
				expected = 2
			}
			if len(r.Repositories[0].Branches) != expected {
				t.Fatal("branch inventory incomplete")
			}
		})
	}
}

func TestConfigGrammarLocations(t *testing.T) {
	for _, name := range []string{"config", "config.worktree", "worktrees/feature/config.worktree", "worktrees/config/config.worktree"} {
		t.Run(name, func(t *testing.T) {
			_, repo := fixture(t)
			p := filepath.Join(repo, ".git", name)
			if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
				t.Fatal(e)
			}
			write(t, p, "[include]\npath = /unmounted-private-file\n")
			r := Scan(Options{Repos: []string{repo}})
			if r.Complete || r.Commands != 0 || len(r.Repositories) != 0 || len(r.Failures) == 0 {
				t.Fatal("hostile real config admitted")
			}
		})
	}
}

func TestPhysicalMetadataPaths(t *testing.T) {
	for _, dir := range []string{"ordinary", "secrets", ".cache", ".ssh"} {
		t.Run("pr-"+dir, func(t *testing.T) {
			root, repo := fixture(t)
			git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
			p := filepath.Join(root, dir)
			if e := os.Mkdir(p, 0700); e != nil {
				t.Fatal(e)
			}
			p = filepath.Join(p, "metadata.json")
			write(t, p, `{"observed_at":"`+time.Now().UTC().Format(time.RFC3339)+`","repositories":["example/fixture"],"pagination_complete":true,"open_prs":[]}`)
			r := Scan(Options{Repos: []string{repo}, Metadata: p})
			if len(r.Repositories) != 1 || r.Commands == 0 {
				t.Fatal("repository neighbor not inventoried")
			}
			if dir == "ordinary" {
				if !r.Complete || r.PRCoverage != "supplied_metadata_declares_complete_at_observation" {
					t.Fatalf("neutral metadata refused: %s", r.PRCoverage)
				}
			} else if r.Complete || r.PRCoverage != "incomplete_invalid_metadata" {
				t.Fatal("sensitive metadata admitted")
			}
		})
	}
	for _, dir := range []string{"ordinary", "vendor", "secrets"} {
		t.Run("database-"+dir, func(t *testing.T) {
			root, repo := fixture(t)
			target := filepath.Join(root, dir)
			if e := os.Mkdir(target, 0700); e != nil {
				t.Fatal(e)
			}
			moved := filepath.Join(target, "main")
			if e := os.Rename(repo, moved); e != nil {
				t.Fatal(e)
			}
			linked := filepath.Join(root, "linked")
			git(t, moved, "worktree", "add", "--detach", linked, "HEAD")
			_, e := locate(context.Background(), linked, []string{root})
			if dir == "ordinary" {
				if e != nil {
					t.Fatal("neutral linked database refused")
				}
			} else if e == nil || e.Error() != "outside_scope" {
				t.Fatal("physical database exclusion lost")
			}
		})
	}
}

func TestPhysicalGitdirTarget(t *testing.T) {
	for _, dir := range []string{"ordinary", "secrets", ".cache"} {
		t.Run(dir, func(t *testing.T) {
			root, repo := fixture(t)
			linked := filepath.Join(root, "linked")
			git(t, repo, "worktree", "add", "--detach", linked, "HEAD")
			parent := filepath.Join(root, dir)
			if e := os.Mkdir(parent, 0700); e != nil {
				t.Fatal(e)
			}
			target := filepath.Join(parent, "registry")
			if e := os.Rename(filepath.Join(repo, ".git/worktrees/linked"), target); e != nil {
				t.Fatal(e)
			}
			write(t, filepath.Join(target, "commondir"), filepath.Join(repo, ".git")+"\n")
			write(t, filepath.Join(linked, ".git"), "gitdir: "+target+"\n")
			_, e := locate(context.Background(), linked, []string{root})
			if dir == "ordinary" {
				if e != nil {
					t.Fatal("neutral physical gitdir refused")
				}
			} else if e == nil || e.Error() != "outside_scope" {
				t.Fatal("sensitive physical gitdir admitted")
			}
		})
	}
}
