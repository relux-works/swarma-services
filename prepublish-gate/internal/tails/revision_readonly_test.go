package tails

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatDirtyContentCleanIndexReadOnly(t *testing.T) {
	for _, changed := range []bool{false, true} {
		name := "unchanged-stat"
		if changed {
			name = "changed-mtime"
		}
		t.Run(name, func(t *testing.T) {
			_, repo := fixture(t)
			git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
			file := filepath.Join(repo, "file")
			content, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			// Explicit old ticks avoid both filesystem clock granularity and
			// Git's racy-clean same-second index rule, without sleeping.
			tick := time.Unix(1700000000, 0)
			if e := os.Chtimes(file, tick, tick); e != nil {
				t.Fatal(e)
			}
			git(t, repo, "update-index", "--refresh")
			beforeStat, e := os.Stat(file)
			if e != nil {
				t.Fatal(e)
			}
			index := filepath.Join(repo, ".git", "index")
			beforeIndex, e := os.ReadFile(index)
			if e != nil {
				t.Fatal(e)
			}
			if changed {
				next := tick.Add(2 * time.Second)
				if e := os.Chtimes(file, next, next); e != nil {
					t.Fatal(e)
				}
				afterStat, e := os.Stat(file)
				if e != nil || beforeStat.ModTime().Equal(afterStat.ModTime()) {
					t.Fatal("fixture did not change actual mtime")
				}
			}
			r := Scan(Options{Repos: []string{repo}})
			if !r.Complete || len(r.Repositories) != 1 || len(r.Repositories[0].Worktrees) != 1 || r.Commands == 0 {
				t.Fatal("read-only witness did not complete inventory")
			}
			wt := r.Repositories[0].Worktrees[0]
			if wt.Dirty == nil || *wt.Dirty {
				t.Fatal("content-clean witness reported dirty")
			}
			afterIndex, e := os.ReadFile(index)
			if e != nil || !bytes.Equal(beforeIndex, afterIndex) {
				t.Fatal("content-clean status rewrote index bytes")
			}
			afterContent, e := os.ReadFile(file)
			if e != nil || !bytes.Equal(content, afterContent) {
				t.Fatal("tracked content changed")
			}
		})
	}
}

func TestGenericSourceExclusionsAndNeighbors(t *testing.T) {
	for _, name := range []string{".ssh", "credentials", "secrets", "id_ed25519", "fixture.key", ".env.sample"} {
		if !sensitive(name) {
			t.Fatal("generic credential exclusion lost")
		}
	}
	_, repo := fixture(t)
	git(t, repo, "update-ref", "refs/remotes/origin/main", git(t, repo, "rev-parse", "HEAD"))
	for _, name := range []string{".widget-state", ".reader", "transcripts", "records.jsonl"} {
		if sensitive(name) {
			t.Fatal("synthetic neighboring name excluded")
		}
		write(t, filepath.Join(repo, name), "synthetic\n")
	}
	r := Scan(Options{Repos: []string{repo}})
	if !r.Complete || len(r.Repositories) != 1 || r.Repositories[0].Worktrees[0].UntrackedCount == nil || *r.Repositories[0].Worktrees[0].UntrackedCount != 4 {
		t.Fatal("neutral untracked names not inventoried")
	}
}

func TestRefAndWorktreeNamesAreMetadata(t *testing.T) {
	for _, name := range []string{"feature", "vendor", "cache", "keys", "sessions", "secrets", "config"} {
		t.Run(name, func(t *testing.T) {
			root, repo := fixture(t)
			base := git(t, repo, "rev-parse", "HEAD")
			git(t, repo, "update-ref", "refs/remotes/origin/main", base)
			git(t, repo, "branch", name)
			// The registry identifier remains name after moving the checkout
			// to a neutral source path. Source path exclusions still apply.
			wt := filepath.Join(root, name)
			git(t, repo, "worktree", "add", "--detach", wt, base)
			neutral := filepath.Join(root, "linked")
			git(t, repo, "worktree", "move", wt, neutral)
			r := Scan(Options{Repos: []string{repo, neutral}, Roots: []string{root}})
			if !r.Complete || len(r.Repositories) != 1 || len(r.Repositories[0].Branches) != 2 || len(r.Repositories[0].Worktrees) != 2 {
				t.Fatal("valid ref/reflog/worktree metadata refused")
			}
		})
	}
}

func TestUnsafeMetadataStillRefuses(t *testing.T) {
	for _, name := range []string{"credentials", "secrets", "worktrees/cache/credentials", "logs/credentials"} {
		t.Run(name, func(t *testing.T) {
			_, repo := fixture(t)
			p := filepath.Join(repo, ".git", name)
			if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
				t.Fatal(e)
			}
			write(t, p, "synthetic-not-a-git-control\n")
			r := Scan(Options{Repos: []string{repo}})
			if r.Complete || r.Commands != 0 || len(r.Repositories) != 0 || len(r.Failures) == 0 {
				t.Fatal("unexpected metadata admitted to Git")
			}
		})
	}
}
