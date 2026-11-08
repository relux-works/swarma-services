package tails

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// More than 64 KiB of admitted names must preserve complete tracked and
// untracked inventory. One excluded path must retain the bounded refusal.
func TestLargeTrackedScopeNeighbors(t *testing.T) {
	for _, kind := range []string{"clean", "dirty", "excluded"} {
		t.Run(kind, func(t *testing.T) {
			_, repo := fixture(t)
			pathBytes := len("file") + 1
			for i := 0; i < 1800; i++ {
				name := fmt.Sprintf("entry-%04d-%s.txt", i, strings.Repeat("n", 40))
				pathBytes += len(name) + 1
				write(t, filepath.Join(repo, name), "neutral fixture\n")
			}
			if pathBytes <= 64<<10 {
				t.Fatal("fixture does not exceed pathspec byte bound")
			}
			if kind == "excluded" {
				write(t, filepath.Join(repo, ".env.fixture"), "excluded marker\n")
			}
			git(t, repo, "add", ".")
			git(t, repo, "commit", "-m", "large neutral tree")
			git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
			if kind == "dirty" {
				write(t, filepath.Join(repo, "file"), "changed safe content\n")
				write(t, filepath.Join(repo, "untracked.txt"), "safe untracked\n")
			}
			var out bytes.Buffer
			code := Run([]string{"--repo", repo, "--scope-kind", "unit-scratch"}, &out)
			var r Report
			if json.Unmarshal(out.Bytes(), &r) != nil || len(r.Repositories) != 1 || len(r.Repositories[0].Worktrees) != 1 {
				t.Fatal("missing bounded inventory")
			}
			w := r.Repositories[0].Worktrees[0]
			if kind == "excluded" {
				if code != 1 || r.Complete || !reason(r.Repositories[0], "tracked_pathspec_bound") || w.Dirty != nil || w.SafeDirty != nil || w.AnyDirty != nil || w.UntrackedCount != nil {
					t.Fatal("excluded scope broadened or claimed clean")
				}
				for _, child := range r.Children {
					if child.Stage == "tracked_status" || child.Stage == "status_after" {
						t.Fatal("oversized excluded scope reached status")
					}
				}
				return
			}
			wantDirty, wantUntracked := kind == "dirty", 0
			if wantDirty {
				wantUntracked = 1
			}
			if code != 0 || !r.Complete || w.TrackedCoverage != "complete_safe_scope" || w.ExcludedTracked != 0 || w.Dirty == nil || *w.Dirty != wantDirty || w.SafeDirty == nil || *w.SafeDirty != wantDirty || w.AnyDirty == nil || *w.AnyDirty != wantDirty || w.UntrackedCount == nil || *w.UntrackedCount != wantUntracked || w.Untracked != "complete_safe_scope" {
				t.Fatalf("large admitted scope lost evidence: exit=%d %+v", code, w)
			}
			t.Logf("paths=1801 path_bytes=%d exit=%d complete=%t dirty=%t untracked=%d", pathBytes, code, r.Complete, *w.Dirty, *w.UntrackedCount)
		})
	}
}

// Excluded tracked bytes cannot prevent useful safe-scope evidence, or turn
// that partial evidence into a claim that the whole worktree is clean.
func TestExcludedTrackedDirtyNeighbors(t *testing.T) {
	for _, kind := range []string{"clean", "dirty", "staged-deletion", "secret-only-change", "secret-fifo", "all-excluded", "literal-pathspec"} {
		t.Run(kind, func(t *testing.T) {
			_, repo := fixture(t)
			secret := filepath.Join(repo, ".env.fixture")
			write(t, secret, "inert-excluded-marker\n")
			git(t, repo, "add", ".env.fixture")
			git(t, repo, "commit", "-m", "excluded fixture")
			git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
			wantDirty := false
			switch kind {
			case "dirty":
				write(t, filepath.Join(repo, "file"), "changed-safe\n")
				wantDirty = true
			case "staged-deletion":
				git(t, repo, "rm", "file")
				wantDirty = true
			case "secret-only-change":
				write(t, secret, "different-excluded-marker\n")
			case "secret-fifo":
				if os.Remove(secret) != nil || syscall.Mkfifo(secret, 0600) != nil {
					t.Fatal("fifo fixture")
				}
			case "all-excluded":
				git(t, repo, "rm", "file")
				git(t, repo, "commit", "-m", "excluded-only tree")
			case "literal-pathspec":
				write(t, filepath.Join(repo, ":(glob)*"), "literal\n")
				git(t, repo, "--literal-pathspecs", "add", ":(glob)*")
				git(t, repo, "commit", "-m", "clean literal fixture")
				git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
				// Only the excluded file changes. Interpreting the clean literal
				// name as glob magic would incorrectly observe that change.
				write(t, secret, "different-excluded-marker\n")
			}
			before, e := os.ReadFile(filepath.Join(repo, ".git/index"))
			if e != nil {
				t.Fatal(e)
			}
			r := Scan(Options{Repos: []string{repo}, ScopeKind: "unit-scratch", ChildTimeout: time.Second, TotalTimeout: 5 * time.Second})
			if r.Complete || len(r.Repositories) != 1 || !reason(r.Repositories[0], "excluded_tracked_path") {
				t.Fatal("exclusions lost")
			}
			w := r.Repositories[0].Worktrees[0]
			if len(r.Repositories[0].Failures) != 0 || w.TrackedCoverage != "partial_exclusions" || w.ExcludedTracked != 1 || w.SafeDirty == nil || *w.SafeDirty != wantDirty || w.UntrackedCount == nil || *w.UntrackedCount != 0 {
				t.Fatalf("wrong partial evidence: %+v", w)
			}
			if wantDirty {
				if w.Dirty == nil || !*w.Dirty || w.AnyDirty == nil || !*w.AnyDirty || r.Counts.DirtyTrackedWorktrees != 1 {
					t.Fatal("known dirtiness suppressed")
				}
			} else if w.Dirty != nil || w.AnyDirty != nil || r.Counts.UnknownDirtyWorktrees != 1 {
				t.Fatal("partial clean evidence presented as whole-scope clean")
			}
			if kind == "all-excluded" {
				for _, child := range r.Children {
					if child.Stage == "tracked_status" || child.Stage == "status_after" {
						t.Fatal("empty pathspec broadened to all files")
					}
				}
			}
			after, e := os.ReadFile(filepath.Join(repo, ".git/index"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("index mutated")
			}
			out, e := json.Marshal(r)
			if e != nil || bytes.Contains(out, []byte("inert-excluded-marker")) || bytes.Contains(out, []byte(".env.fixture")) || bytes.Contains(out, []byte(repo)) {
				t.Fatal("excluded bytes or path disclosed")
			}
		})
	}
}

// Ancestor redirects and file/directory overlaps must not broaden a literal
// pathspec into excluded descendants. A neutral sibling remains usable.
func TestTrackedSelectionUnsafeNeighbors(t *testing.T) {
	for _, kind := range []string{"valid", "symlink-ancestor", "overlap", "unmerged", "duplicate-stage", "malformed", "argument-bound"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			oid := strings.Repeat("1", 40)
			index := []byte("100644 " + oid + " 0\tfile\x00")
			head := []byte("100644 blob " + oid + "\tfile\x00")
			switch kind {
			case "symlink-ancestor":
				if os.Symlink("/unmounted-private-root", filepath.Join(root, "dir")) != nil {
					t.Fatal("fixture symlink")
				}
				index = append(index, []byte("100644 "+oid+" 0\tdir/child\x00")...)
			case "overlap":
				index = []byte("100644 " + oid + " 0\tfile/.env.fixture\x00")
			case "unmerged":
				index = []byte("100644 " + oid + " 2\tfile\x00")
			case "duplicate-stage":
				index = append(index, index...)
			case "malformed":
				index = []byte("100644 " + oid + " 0\t../outside\x00")
			case "argument-bound":
				for i := 0; i < 20; i++ {
					index = append(index, []byte("100644 "+oid+" 0\t"+strings.Repeat(string(rune('a'+i)), 4000)+"\x00")...)
				}
			}
			_, _, safe, excluded, e := trackedSelection(root, index, head)
			if kind == "valid" || kind == "symlink-ancestor" || kind == "unmerged" {
				wantExcluded := 0
				if kind == "symlink-ancestor" {
					wantExcluded = 1
				}
				if e != nil || len(safe) != 1 || safe[0] != "file" || excluded != wantExcluded {
					t.Fatal("valid neighbor or ancestor exclusion lost")
				}
			} else if e == nil {
				t.Fatal("ambiguous or unbounded evidence admitted")
			}
		})
	}
}

// An unchanged neighbor permits clean evidence; a failed or changed follow-up
// must erase it. The wrapper delegates real Git and alters only the named seam.
func TestTrackedFollowupUnknownNeighbors(t *testing.T) {
	for _, kind := range []string{"stable", "status-failure", "status-race", "index-race"} {
		t.Run(kind, func(t *testing.T) {
			root, repo := fixture(t)
			git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
			command, action := "status", ":"
			switch kind {
			case "status-failure":
				action = "exit 7"
			case "status-race":
				action = "printf 'changed\\n' > '" + filepath.Join(repo, "file") + "'"
			case "index-race":
				command = "ls-files"
				action = "/usr/bin/git -C '" + repo + "' update-index --chmod=+x -- file"
			}
			marker, fake := filepath.Join(root, "seen"), filepath.Join(root, "fake-git")
			write(t, fake, "#!/bin/sh\ncase \" $* \" in *' "+command+" '*)\nif [ -f '"+marker+"' ]; then "+action+"; else : > '"+marker+"'; fi;; esac\nexec /usr/bin/git \"$@\"\n")
			if os.Chmod(fake, 0700) != nil {
				t.Fatal("fixture executable")
			}
			report := Report{}
			l := location{path: repo, db: filepath.Join(repo, ".git"), gitdir: filepath.Join(repo, ".git")}
			run := runner{ctx: context.Background(), timeout: time.Second, report: &report, executable: fake, locations: map[string]location{repo: l}}
			r := scanRepo(&run, []location{l}, map[string]bool{repo: true})
			if len(r.Worktrees) != 1 {
				t.Fatal("missing observation")
			}
			w := r.Worktrees[0]
			if kind == "stable" {
				if r.Coverage != "complete" || w.Dirty == nil || *w.Dirty || w.AnyDirty == nil || *w.AnyDirty || w.SafeDirty == nil || *w.SafeDirty {
					t.Fatal("stable clean neighbor refused")
				}
			} else if r.Coverage != "incomplete" || w.TrackedCoverage != "unstable_or_unavailable" || w.Dirty != nil || w.AnyDirty != nil || w.SafeDirty != nil {
				t.Fatal("failed or racing follow-up claimed clean")
			}
		})
	}
}
