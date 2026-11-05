package capture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestResidualFIFOIsFinite(t *testing.T) {
	for _, operation := range []string{"run", "purge"} {
		t.Run(operation, func(t *testing.T) {
			p := project(t)
			s, e := OpenStore(p)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			var r Record
			if operation == "purge" {
				r, _, _ = runScript(t, s, p, "true")
			}
			exclude := filepath.Join(p, ".git", "info", "exclude")
			if e = os.Remove(exclude); e != nil {
				t.Fatal(e)
			}
			if e = syscall.Mkfifo(exclude, 0600); e != nil {
				t.Fatal(e)
			}
			start := time.Now()
			if operation == "run" {
				_, e = s.Run(context.Background(), options(p, "touch spawned"))
				if _, se := os.Stat(filepath.Join(p, "spawned")); !errors.Is(se, os.ErrNotExist) {
					t.Error("refused run spawned")
				}
				if _, se := os.Stat(filepath.Join(p, ".temp")); !errors.Is(se, os.ErrNotExist) {
					t.Error("refused run created custody")
				}
			} else {
				if _, le := s.Lookup(r.Ref); le != nil {
					t.Fatal("FIFO affected read-only lookup", le)
				}
				_, e = s.Purge(time.Now().Add(2 * time.Hour))
			}
			if e == nil || time.Since(start) > gitTimeout+time.Second {
				t.Fatal("FIFO was not refused within Git deadline", e)
			}
			if e = os.Remove(exclude); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(exclude, []byte("/.temp/\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if operation == "purge" {
				if n, pe := s.Purge(time.Now().Add(2 * time.Hour)); pe != nil || n != 1 {
					t.Fatal("purge did not recover after FIFO removal", n, pe)
				}
			}
		})
	}
}

func TestResidualFinalizeAfterRename(t *testing.T) {
	for _, component := range []string{"project", "session-swap"} {
		t.Run(component, func(t *testing.T) {
			s, p := store(t)
			c, e := s.create("test", []string{"/bin/sh"}, 1)
			if e != nil {
				t.Fatal(e)
			}
			defer c.close()
			original := p
			if component == "session-swap" {
				original = filepath.Dir(c.record.Stdout)
			}
			moved := original + "-moved"
			if e = os.Rename(original, moved); e != nil {
				t.Fatal(e)
			}
			outside := t.TempDir()
			if e = os.Symlink(outside, original); e != nil {
				t.Fatal(e)
			}
			defer func() {
				os.Remove(original)
				os.Rename(moved, original)
			}()
			c.record.CommandStatus = "exited"
			c.record.CaptureStatus = "complete"
			c.record.ExitCode = 7
			c.record.Finished = time.Now().UTC()
			if e = c.save(); e != nil {
				t.Fatal("held directory could not finalize", e)
			}
			b, e := c.dir.ReadFile(c.name + ".json")
			var retained Record
			if e != nil || json.Unmarshal(b, &retained) != nil || retained.CommandStatus != "exited" || retained.ExitCode != 7 || retained.Finished.IsZero() {
				t.Fatal("completion accounting not retained")
			}
			files, e := os.ReadDir(outside)
			if e != nil || len(files) != 0 {
				t.Fatal("save escaped held directory")
			}
			// Reusing a preflighted slot still requires exclusive/no-follow open.
			target := filepath.Join(outside, "keep")
			if e = os.WriteFile(target, []byte("KEEP"), 0600); e != nil {
				t.Fatal(e)
			}
			liveDir := moved
			if component == "project" {
				liveDir = strings.Replace(filepath.Dir(c.record.Stdout), p, moved, 1)
			}
			if e = os.Symlink(target, filepath.Join(liveDir, c.tempName)); e != nil {
				t.Fatal(e)
			}
			if e = c.save(); e == nil {
				t.Fatal("occupied temporary slot accepted")
			}
			after, _ := c.dir.ReadFile(c.name + ".json")
			keep, _ := os.ReadFile(target)
			if string(after) != string(b) || string(keep) != "KEEP" {
				t.Fatal("failed save changed published metadata or outside target")
			}
		})
	}
}
