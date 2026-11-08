package gate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func admissionCLI(t *testing.T, c Config) (Report, int) {
	t.Helper()
	var out bytes.Buffer
	code := Run([]string{"check", "--objects", c.Objects, "--base", c.Base,
		"--candidate", c.Candidate, "--patterns", c.Patterns,
		"--allowed-signers", c.Signers, "--principal", c.Principal}, &out)
	var r Report
	if json.Unmarshal(out.Bytes(), &r) != nil {
		t.Fatal("invalid report")
	}
	var counts map[string]any
	if json.Unmarshal(out.Bytes(), &counts) != nil {
		t.Fatal("invalid counts")
	}
	for _, name := range []string{"home_admission_errors", "tmpdir_admission_errors"} {
		if _, ok := counts[name].(float64); !ok {
			t.Fatal("missing admission counter")
		}
	}
	for _, v := range counts {
		n, ok := v.(float64)
		if !ok || n < 0 || n != float64(int(n)) {
			t.Fatal("report contains non-count data")
		}
	}
	for _, value := range []string{os.Getenv("HOME"), os.Getenv("TMPDIR"), c.Objects,
		c.Patterns, c.Signers, c.Principal, "SYNTHETIC_PRIVATE_MARKER"} {
		if value != "" && strings.Contains(out.String(), value) {
			t.Fatal("report disclosed caller data")
		}
	}
	return r, code
}

func TestPrivateDirectoryAdmissionReport(t *testing.T) {
	f := newFixture(t)
	for _, variable := range []string{"HOME", "TMPDIR"} {
		t.Run(variable, func(t *testing.T) {
			// Both controls are task-owned fixtures inside the outer sandbox.
			root := t.TempDir()
			home, tmp := filepath.Join(root, "home"), filepath.Join(root, "temporary")
			for _, p := range []string{home, tmp} {
				if os.Mkdir(p, 0700) != nil {
					t.Fatal("fixture directory")
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("TMPDIR", tmp)
			p := os.Getenv(variable)
			for _, kind := range []string{"permissions", "mode-0500", "symlink", "missing", "relative", "unclean", "trailing-slash", "regular-file"} {
				t.Run(kind, func(t *testing.T) {
					// Establish a working neighbor before changing exactly one input.
					r, code := admissionCLI(t, f.config())
					require(t, code == 0 && r.Completed == 1 && r.HomeAdmissionErrors == 0 &&
						r.TmpdirAdmissionErrors == 0, r, code)
					bad := p
					switch kind {
					case "permissions", "mode-0500":
						mode := os.FileMode(0755)
						if kind == "mode-0500" {
							mode = 0500
						}
						if os.Chmod(p, mode) != nil {
							t.Fatal("fixture permissions")
						}
						t.Cleanup(func() {
							if os.Chmod(p, 0700) != nil {
								t.Error("fixture restoration")
							}
						})
					case "symlink":
						bad = filepath.Join(root, "link")
						if os.Symlink(p, bad) != nil {
							t.Fatal("fixture link")
						}
					case "missing":
						bad = filepath.Join(root, "missing")
					case "relative":
						t.Chdir(root)
						bad = "relative-fixture"
						if os.Mkdir(bad, 0700) != nil || !privateDir(filepath.Join(root, bad)) {
							t.Fatal("existing private relative fixture")
						}
					case "unclean":
						bad = p + "/."
					case "trailing-slash":
						bad = p + "/"
					case "regular-file":
						bad = filepath.Join(root, "regular-file")
						write(t, bad, []byte("neutral\n"))
						if os.Chmod(bad, 0700) != nil {
							t.Fatal("fixture file permissions")
						}
					}
					t.Setenv(variable, bad)
					r, code = admissionCLI(t, f.config())
					h, tmpErrors := 0, 0
					if variable == "HOME" {
						h = 1
					} else {
						tmpErrors = 1
					}
					require(t, code == 1 && r == (Report{ScanErrors: 1,
						HomeAdmissionErrors: h, TmpdirAdmissionErrors: tmpErrors}), r, code)
				})
			}
			// The same inputs succeed with both existing directories at 0700.
			r, code := admissionCLI(t, f.config())
			require(t, code == 0 && r.Completed == 1 && r.Signatures == 1 && r.Commits == 1 &&
				r.ScanErrors == 0 && r.HomeAdmissionErrors == 0 && r.TmpdirAdmissionErrors == 0, r, code)
		})
	}
}

// When both directories fail admission, only HOME's counter is reported.
func TestPrivateDirectoryAdmissionHomeFirst(t *testing.T) {
	f := newFixture(t)
	for _, kind := range []string{"permissions", "trailing-slash"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			home, tmp := filepath.Join(root, "home"), filepath.Join(root, "temporary")
			for _, p := range []string{home, tmp} {
				if os.Mkdir(p, 0700) != nil {
					t.Fatal("fixture directory")
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("TMPDIR", tmp)
			r, code := admissionCLI(t, f.config())
			require(t, code == 0 && r.Completed == 1, r, code)
			if kind == "permissions" {
				for _, p := range []string{home, tmp} {
					if os.Chmod(p, 0755) != nil {
						t.Fatal("fixture permissions")
					}
				}
			} else {
				t.Setenv("HOME", home+"/")
				t.Setenv("TMPDIR", tmp+"/")
			}
			r, code = admissionCLI(t, f.config())
			require(t, code == 1 && r == (Report{ScanErrors: 1, HomeAdmissionErrors: 1}), r, code)
		})
	}
}

// The optional read-only mount is supplied by the outer offline sandbox. No
// production fault seam or privilege is needed to reach MkdirTemp's failure.
func TestMkdirTempFailureDoesNotRelabelAdmission(t *testing.T) {
	readonly := os.Getenv("PREPUBLISH_READONLY_TMPDIR")
	if os.Getenv("PREPUBLISH_VERIFY_SANDBOX") != "1" || readonly == "" {
		t.Skip("requires an explicit read-only directory fixture")
	}
	f := newFixture(t)
	if !privateDir(readonly) {
		t.Fatal("read-only fixture must pass directory admission")
	}
	// Verify the failure precondition before exercising the report boundary.
	if p, e := os.MkdirTemp(readonly, "probe-"); e == nil {
		os.Remove(p)
		t.Fatal("fixture is writable")
	}
	r, code := admissionCLI(t, f.config())
	require(t, code == 0 && r.Completed == 1, r, code)
	t.Setenv("TMPDIR", readonly)
	r, code = admissionCLI(t, f.config())
	require(t, code == 1 && r == (Report{ScanErrors: 1}), r, code)
}

func TestAdmissionCountersDoNotRelabelOtherFailures(t *testing.T) {
	f := newFixture(t)
	for _, kind := range []string{"arguments", "patterns", "signers", "objects"} {
		t.Run(kind, func(t *testing.T) {
			c := f.config()
			want, wantCode := Report{}, 1
			switch kind {
			case "arguments":
				c.Base = "invalid"
				want.ArgumentErrors, wantCode = 1, 2
			case "patterns":
				c.Patterns = filepath.Join(f.dir, "missing-patterns")
				want.ScanErrors = 1
			case "signers":
				c.Signers = filepath.Join(f.dir, "missing-signers")
				want.SignatureErrors = 1
			case "objects":
				c.Objects = filepath.Join(f.dir, "missing-objects")
				want.ScanErrors = 1
			}
			r, code := admissionCLI(t, c)
			require(t, code == wantCode && r == want, r, code)
		})
	}
}
