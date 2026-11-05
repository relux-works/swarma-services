package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	st, e := os.Lstat(path)
	if e != nil {
		t.Fatal(e)
	}
	if st.Mode().Perm() != want || st.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("%s: mode %v, want %04o without symlink", path, st.Mode(), want)
	}
}

func TestProjectTempAdmission(t *testing.T) {
	for _, mode := range []fs.FileMode{0, 0700, 0750, 0755} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			p := project(t)
			temp := filepath.Join(p, ".temp")
			if mode != 0 {
				if e := os.Mkdir(temp, mode); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(temp, mode); e != nil {
					t.Fatal(e)
				}
			}
			exclude := filepath.Join(p, ".git", "info", "exclude")
			before, e := os.ReadFile(exclude)
			if e != nil {
				t.Fatal(e)
			}
			s, e := OpenStore(p)
			if e != nil {
				t.Fatalf("owned project .temp refused: %v", e)
			}
			defer s.Close()
			if _, e = s.Lookup("test/20000101-000000_sh_00000000000000000000000000000000"); e == nil {
				t.Fatal("unknown ref accepted")
			}
			if n, e := s.Purge(time.Now()); e != nil || n != 0 {
				t.Fatal("empty purge", n, e)
			}
			after, e := os.ReadFile(exclude)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("read-only discovery/lookup/purge changed exclusions", e)
			}
			if _, e = os.Lstat(s.Path); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("read-only operation bootstrapped custody", e)
			}
			if mode == 0 {
				if _, e = os.Lstat(temp); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("read-only operation created .temp", e)
				}
			} else {
				requireMode(t, temp, mode)
			}
			r, out, errout := runScript(t, s, p, "touch ran; printf synthetic-out; printf synthetic-err >&2")
			if string(out) != "synthetic-out" || string(errout) != "synthetic-err" || r.CommandStatus != "exited" || r.ExitCode != 0 || r.CaptureStatus != "complete" {
				t.Fatal("authorized child/capture failed")
			}
			if _, e = os.Stat(filepath.Join(p, "ran")); e != nil {
				t.Fatal("child did not execute", e)
			}
			a, b := logs(t, r)
			if !bytes.Equal(a, out) || !bytes.Equal(b, errout) {
				t.Fatal("capture content differs from preview")
			}
			want := mode
			if want == 0 {
				want = 0700
			}
			requireMode(t, temp, want)
			if e = filepath.WalkDir(s.Path, func(path string, entry fs.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if entry.IsDir() {
					requireMode(t, path, 0700)
				} else {
					requireMode(t, path, 0600)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			// Reopen exercises discovery with existing private custody beneath
			// the less restrictive project parent, then lookup the real capture.
			reopened, e := OpenStore(p)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			retained, e := reopened.Lookup(r.Ref)
			if e != nil || retained.Ref != r.Ref || retained.CaptureStatus != "complete" {
				t.Fatal("lookup after reopen failed", e)
			}
			requireMode(t, temp, want)
		})
	}
}

// Unlike an escaping symlink, this relative target is reachable through os.Root.
// TestProjectTempAdmission/0755 is the nearby real-directory positive control.
// Check discovery and initialization directly: Git refuses paths beneath a
// symlink before Run reaches initialization, which would mask a missing guard.
func TestProjectTempRelativeSymlinkRefusal(t *testing.T) {
	for _, phase := range []string{"discovery", "initialize"} {
		t.Run(phase, func(t *testing.T) {
			p := project(t)
			// Directory admission must not change even pre-ignored exclusions.
			if e := os.WriteFile(filepath.Join(p, ".gitignore"), []byte("/.temp/\n"), 0600); e != nil {
				t.Fatal(e)
			}
			exclude := filepath.Join(p, ".git", "info", "exclude")
			before, e := os.ReadFile(exclude)
			if e != nil {
				t.Fatal(e)
			}
			var s *Store
			if phase == "initialize" {
				s, e = OpenStore(p)
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
			}
			target := filepath.Join(p, "temp-target")
			if e = os.Mkdir(target, 0755); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(target, 0755); e != nil {
				t.Fatal(e)
			}
			requireMode(t, target, 0755)
			st, e := os.Stat(target)
			if e != nil {
				t.Fatal(e)
			}
			if e = checkProjectTemp(st); e != nil {
				t.Fatal("relative target must otherwise qualify for admission", e)
			}
			temp := filepath.Join(p, ".temp")
			if e = os.Symlink("temp-target", temp); e != nil {
				t.Fatal(e)
			}
			anchor, e := os.OpenRoot(p)
			if e != nil {
				t.Fatal(e)
			}
			resolved, e := anchor.Stat(".temp")
			anchor.Close()
			if e != nil || !os.SameFile(st, resolved) {
				t.Fatal("relative symlink must resolve to its target within the anchor", e)
			}
			if phase == "discovery" {
				s, e = OpenStore(p)
				if e == nil {
					defer s.Close()
				}
			} else {
				e = s.initialize()
			}
			if e == nil || !strings.Contains(e.Error(), `unsafe directory component ".temp"`) {
				t.Errorf("expected explicit relative-symlink refusal, got error=%v", e)
			}
			items, e := os.ReadDir(target)
			if e != nil || len(items) != 0 {
				t.Error("refusal created custody in relative target", e)
			}
			after, e := os.ReadFile(exclude)
			if e != nil || !bytes.Equal(before, after) {
				t.Error("refusal changed exclusions", e)
			}
			if link, e := os.Readlink(temp); e != nil || link != "temp-target" {
				t.Error("relative symlink changed", link, e)
			}
			requireMode(t, target, 0755)
		})
	}
}

func TestProjectTempWritableRefusal(t *testing.T) {
	for _, mode := range []fs.FileMode{0770, 0777, 0702} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			p := project(t)
			temp := filepath.Join(p, ".temp")
			if e := os.Mkdir(temp, mode); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(temp, mode); e != nil {
				t.Fatal(e)
			}
			exclude := filepath.Join(p, ".git", "info", "exclude")
			before, e := os.ReadFile(exclude)
			if e != nil {
				t.Fatal(e)
			}
			s, e := OpenStore(p)
			if e == nil {
				defer s.Close()
				_, e = s.Run(context.Background(), options(p, "touch ran"))
			}
			if e == nil || !strings.Contains(e.Error(), "group- or world-writable") {
				t.Fatal("expected project writable-mode refusal", e)
			}
			if _, e = os.Stat(filepath.Join(p, "ran")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("child ran", e)
			}
			items, e := os.ReadDir(temp)
			if e != nil || len(items) != 0 {
				t.Fatal("refusal created captures", e)
			}
			after, e := os.ReadFile(exclude)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal changed exclusions", e)
			}
			requireMode(t, temp, mode)
		})
	}
}

func TestProjectTempInitializeRechecks(t *testing.T) {
	for _, kind := range []string{"0770", "0777", "0702", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			p := project(t)
			// Pre-ignore so this test isolates initialization after discovery.
			if e := os.WriteFile(filepath.Join(p, ".gitignore"), []byte("/.temp/\n"), 0600); e != nil {
				t.Fatal(e)
			}
			s, e := OpenStore(p)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			temp := filepath.Join(p, ".temp")
			outside := t.TempDir()
			if kind == "symlink" {
				e = os.Symlink(outside, temp)
			} else {
				mode := map[string]fs.FileMode{"0770": 0770, "0777": 0777, "0702": 0702}[kind]
				e = os.Mkdir(temp, mode)
				if e == nil {
					e = os.Chmod(temp, mode)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if r, e := s.Run(context.Background(), options(p, "touch ran")); e == nil || r.Ref != "" {
				t.Fatal("unsafe parent admitted during initialization", e)
			}
			if _, e = os.Stat(filepath.Join(p, "ran")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("child ran", e)
			}
			items, e := os.ReadDir(temp)
			if e != nil || len(items) != 0 {
				t.Fatal("initialization created custody under unsafe parent", e)
			}
			if kind == "symlink" {
				if st, e := os.Lstat(temp); e != nil || st.Mode()&os.ModeSymlink == 0 {
					t.Fatal("symlink changed", e)
				}
			} else {
				requireMode(t, temp, map[string]fs.FileMode{"0770": 0770, "0777": 0777, "0702": 0702}[kind])
			}
		})
	}
}

func TestProjectTempPrivateDescendantsRefuse(t *testing.T) {
	for _, component := range []string{"shell-out", "shell-out/test"} {
		for _, mode := range []fs.FileMode{0755, 0770} {
			t.Run(fmt.Sprintf("%s/%04o", component, mode), func(t *testing.T) {
				p := project(t)
				temp := filepath.Join(p, ".temp")
				path := filepath.Join(temp, component)
				if e := os.MkdirAll(path, 0700); e != nil {
					t.Fatal(e)
				}
				for path, mode := range map[string]fs.FileMode{temp: 0755, path: mode} {
					if e := os.Chmod(path, mode); e != nil {
						t.Fatal(e)
					}
				}
				s, e := OpenStore(p)
				if e == nil {
					defer s.Close()
					_, e = s.Run(context.Background(), options(p, "touch ran"))
				}
				if e == nil || !strings.Contains(e.Error(), "private directory must have mode 0700") {
					t.Fatal("unsafe private descendant admitted", e)
				}
				if _, e = os.Stat(filepath.Join(p, "ran")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("child ran", e)
				}
				items, e := os.ReadDir(path)
				if e != nil || len(items) != 0 {
					t.Fatal("refusal created captures", e)
				}
				requireMode(t, path, mode)
				requireMode(t, temp, 0755)
			})
		}
	}
}

// Unprivileged tests cannot create a foreign-owned project directory. Exercise
// the actual admission predicate with a synthetic effective-UID mismatch only;
// this is not an end-to-end foreign-owner filesystem/spawn qualification.
type projectTempInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i projectTempInfo) Sys() any { return &i.stat }

func TestProjectTempForeignOwnerPredicate(t *testing.T) {
	p := t.TempDir()
	if e := os.Chmod(p, 0755); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	info := projectTempInfo{FileInfo: st, stat: *st.Sys().(*syscall.Stat_t)}
	if e = checkProjectTemp(info); e != nil {
		t.Fatal("nearby owned 0755 control rejected", e)
	}
	info.stat.Uid++
	if e = checkProjectTemp(info); e == nil || !strings.Contains(e.Error(), "effective user") {
		t.Fatal("foreign effective-UID predicate accepted", e)
	}
}

func TestProjectTempAccessFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary unprivileged filesystem access checks")
	}
	p := project(t)
	temp := filepath.Join(p, ".temp")
	if e := os.Mkdir(temp, 0500); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(temp, 0700) // fixture cleanup only; the tool must not repair it.
	s, e := OpenStore(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if r, e := s.Run(context.Background(), options(p, "touch ran")); !errors.Is(e, os.ErrPermission) || r.Ref != "" {
		t.Fatal("OS access failure not preserved", e)
	}
	requireMode(t, temp, 0500)
	if _, e = os.Stat(filepath.Join(p, "ran")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("child ran", e)
	}
	items, e := os.ReadDir(temp)
	if e != nil || len(items) != 0 {
		t.Fatal("capture created on OS access failure", e)
	}
}
