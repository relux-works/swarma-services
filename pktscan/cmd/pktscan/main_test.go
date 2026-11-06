package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func put(t *testing.T, name string, data []byte) {
	t.Helper()
	if os.MkdirAll(filepath.Dir(name), 0700) != nil {
		t.Fatal("fixture directory failed")
	}
	if os.WriteFile(name, data, 0600) != nil {
		t.Fatal("fixture write failed")
	}
}

func setup(t *testing.T) (string, string) {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "patterns")
	put(t, p, []byte("SYNTHETIC\nTOKEN\n"))
	return d, p
}

func check(t *testing.T, got, want result) {
	t.Helper()
	if got != want {
		t.Fatalf("count mismatch: got %+v; want %+v", got, want)
	}
}

type member struct {
	name, data string
	mode       os.FileMode
	link       string
	typ        byte
	size       int64
}

func makeArchive(t *testing.T, kind string, members []member) []byte {
	t.Helper()
	var b bytes.Buffer
	if kind == "zip" {
		w := zip.NewWriter(&b)
		for _, m := range members {
			h := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
			h.SetMode(m.mode)
			f, e := w.CreateHeader(h)
			if e != nil {
				t.Fatal("zip fixture failed")
			}
			if _, e = io.WriteString(f, m.data); e != nil {
				t.Fatal("zip fixture failed")
			}
		}
		if w.Close() != nil {
			t.Fatal("zip fixture failed")
		}
	} else {
		var target io.Writer = &b
		var gz *gzip.Writer
		if kind == "tgz" {
			gz = gzip.NewWriter(&b)
			target = gz
		}
		w := tar.NewWriter(target)
		for _, m := range members {
			typ := m.typ
			if typ == 0 {
				typ = tar.TypeReg
			}
			size := int64(len(m.data))
			if m.size != 0 {
				size = m.size
			}
			h := &tar.Header{Name: m.name, Mode: 0600, Size: size, Typeflag: typ, Linkname: m.link}
			if w.WriteHeader(h) != nil {
				t.Fatal("tar fixture failed")
			}
			if _, e := io.WriteString(w, m.data); e != nil {
				t.Fatal("tar fixture failed")
			}
		}
		_ = w.Close() // Some refusal fixtures intentionally truncate their declared body.
		if gz != nil {
			if gz.Close() != nil {
				t.Fatal("gzip fixture failed")
			}
		}
	}
	return b.Bytes()
}

func TestCountsKnownPathsAndControls(t *testing.T) {
	d, p := setup(t)
	put(t, filepath.Join(d, "SYNTHETIC-TOKEN-new"), []byte("SYNTHETIC TOKEN TOKEN\nclean\nTOKEN"))
	put(t, filepath.Join(d, "base\nTOKEN"), []byte("SYNTHETIC\n"))
	put(t, filepath.Join(d, "binary"), []byte("SYNTHETIC\x00TOKEN"))
	put(t, filepath.Join(d, "invalid-utf8"), []byte{0xff, 'T', 'O', 'K', 'E', 'N'})
	put(t, filepath.Join(d, "empty"), nil)
	base := filepath.Join(d, "base-list")
	put(t, base, []byte("base\nTOKEN\x00"))
	if os.Link(p, filepath.Join(d, "pattern-alias")) != nil {
		t.Fatal("fixture link failed")
	}
	r, e := scan(d, p, base)
	if e != nil {
		t.Fatal(e)
	}
	check(t, r, result{New: counts{Files: 4, HitFiles: 1, HitLines: 2, PathHits: 1}, Known: counts{Files: 1, HitFiles: 1, HitLines: 1, PathHits: 1}})
}

func TestUnifiedPatchAddedOnly(t *testing.T) {
	d, p := setup(t)
	patch := "diff --git a/TOKEN b/TOKEN\n--- a/TOKEN\n+++ b/TOKEN\n@@ -1,3 +1,5 @@ TOKEN\n TOKEN\n-TOKEN\n+clean\n+TOKEN TOKEN\n+++TOKEN\n clean\n\\ No newline at end of file\n+TOKEN outside hunk\n"
	put(t, filepath.Join(d, "change.patch"), []byte(patch))
	r, e := scan(d, p, "")
	if e != nil {
		t.Fatal(e)
	}
	// The +++ inside the hunk adds content beginning with ++; it is not a file header.
	check(t, r, result{New: counts{Files: 1, HitFiles: 1, HitLines: 2}})
}

func TestPatchHeadersNeverCount(t *testing.T) {
	d, p := setup(t)
	put(t, filepath.Join(d, "change.diff"), []byte("--- TOKEN\n+++ TOKEN\n@@ -1 +1 @@ TOKEN\n-TOKEN\n+clean\n"))
	r, e := scan(d, p, "")
	if e != nil {
		t.Fatal(e)
	}
	check(t, r, result{New: counts{Files: 1}})
}

func TestMalformedPatchRefused(t *testing.T) {
	for _, patch := range []string{"@@ bad TOKEN\n+TOKEN\n", "@@ -1 +1 @@\n+TOKEN\n", "@@ -1 +1 @@\n?TOKEN\n"} {
		d, p := setup(t)
		put(t, filepath.Join(d, "change.patch"), []byte(patch))
		if _, e := scan(d, p, ""); e != errPatch {
			t.Fatal("malformed patch accepted")
		}
	}
}

func TestEREAndNoEcho(t *testing.T) {
	for _, pattern := range []string{"[SYNTHETIC", "(?i)SYNTHETIC", `\dSYNTHETIC`, `(SYNTHETIC)\1`, `SYNTHETIC(?=x)`, `\p{Latin}SYNTHETIC`, `[[.SYNTHETIC.]]`, `[a[=SYNTHETIC=]]`, "SYNTHETIC\n\n", "\xff", "SYNTHETIC\x00"} {
		d, p := setup(t)
		put(t, p, []byte(pattern))
		var out, diagnostic bytes.Buffer
		if run([]string{d, "--patterns", p}, &out, &diagnostic) == 0 {
			t.Fatal("unsupported pattern accepted")
		}
		if out.Len() != 0 || diagnostic.String() != "pktscan: patterns refused\n" {
			t.Fatal("unsafe pattern diagnostic")
		}
	}
	compiled, e := patterns([]byte("^[[:upper:]]{2,4}$\n(a|b)+\n"))
	if e != nil || !compiled[0].MatchString("ABC") || compiled[0].MatchString("abc") {
		t.Fatal("POSIX ERE control failed")
	}
	if _, e := patterns([]byte(strings.Repeat("a", 100) + "{1000}")); e != nil {
		t.Fatal("small expansion unexpectedly refused")
	}
	if _, e := patterns([]byte("(" + strings.Repeat("a", 100) + "){1000}")); e != errPattern {
		t.Fatal("large expansion accepted")
	}
	if _, e := patterns([]byte(`[.]` + "\n" + `[^^]` + "\n" + `[[]` + "\n" + `[[:alpha:]x]` + "\n" + `\[\.literal`)); e != nil {
		t.Fatal("ordinary bracket syntax refused")
	}
}

func TestEmptyLinesAndPathAnchors(t *testing.T) {
	d, p := setup(t)
	put(t, p, []byte("^$\n^TOKEN$\n"))
	put(t, filepath.Join(d, "prefix\nTOKEN\nsuffix"), []byte("\n\nTOKEN\n"))
	put(t, filepath.Join(d, "empty"), nil)
	r, e := scan(d, p, "")
	if e != nil {
		t.Fatal(e)
	}
	check(t, r, result{New: counts{Files: 2, HitFiles: 1, HitLines: 3, PathHits: 1}})
}

func TestInventoryLimit(t *testing.T) {
	d, p := setup(t)
	for i := 0; i < maxEntries; i++ {
		put(t, filepath.Join(d, strconv.Itoa(i)), nil)
	}
	if _, e := scan(d, p, ""); e != errLimit {
		t.Fatal("oversized inventory accepted")
	}
}

func TestLocaleAndLineSemantics(t *testing.T) {
	d, p := setup(t)
	put(t, p, []byte("^TOKEN$\n^[[:alpha:]]+$\n"))
	put(t, filepath.Join(d, "text"), []byte("TOKEN\nTOKEN\r\n\né\nABC"))
	r, e := scan(d, p, "")
	if e != nil {
		t.Fatal(e)
	}
	check(t, r, result{New: counts{Files: 1, HitFiles: 1, HitLines: 2, PathHits: 1}})
}

func TestValidArchivesAndInPlaceContract(t *testing.T) {
	for _, kind := range []string{"zip", "tar", "tgz"} {
		t.Run(kind, func(t *testing.T) {
			d, p := setup(t)
			name := "packet." + kind
			archive := filepath.Join(d, name)
			body := makeArchive(t, kind, []member{{name: "folder/", mode: os.ModeDir | 0755, typ: tar.TypeDir}, {name: "folder/TOKEN\nitem", data: "SYNTHETIC TOKEN\nclean", mode: 0755}})
			put(t, archive, body)
			base := filepath.Join(d, "base-list")
			put(t, base, []byte(name+"/folder/TOKEN\nitem\x00"))
			before, e := os.Stat(archive)
			if e != nil {
				t.Fatal("fixture stat failed")
			}
			r, e := scan(d, p, base)
			if e != nil {
				t.Fatal(e)
			}
			check(t, r, result{Known: counts{Files: 1, HitFiles: 1, HitLines: 1, PathHits: 1}})
			data, e := os.ReadFile(archive)
			if e != nil || !bytes.Equal(data, body) {
				t.Fatal("original archive changed")
			}
			after, _ := os.Stat(archive)
			if !unchanged(before, after) {
				t.Fatal("original metadata changed")
			}
			out := filepath.Join(d, outputDir, "files", name, "folder/TOKEN\nitem")
			i, e := os.Stat(out)
			if e != nil || i.Mode().Perm() != 0600 {
				t.Fatal("extracted file permissions unsafe")
			}
			if _, e := scan(d, p, base); e != errOutput {
				t.Fatal("existing output was accepted")
			}
			if _, e := os.Stat(out); e != nil {
				t.Fatal("existing output was removed")
			}
		})
	}
}

func TestArchiveLogicalPathDepth(t *testing.T) {
	for _, kind := range []string{"zip", "tar", "tgz"} {
		for _, prefix := range []string{"", "nested/"} {
			for _, directory := range []bool{false, true} {
				for _, depth := range []int{128, 129} {
					label := kind + "/" + prefix + strconv.FormatBool(directory) + "/" + strconv.Itoa(depth)
					t.Run(label, func(t *testing.T) {
						d, p := setup(t)
						archive := prefix + "packet." + kind
						archiveDepth := len(strings.Split(archive, "/"))
						name := strings.Repeat("d/", depth-archiveDepth-1) + "leaf"
						logical := archive + "/" + name
						subject := member{name: name, data: "TOKEN\n"}
						want := result{Known: counts{Files: 2, HitFiles: 2, HitLines: 2}}
						basePaths := archive + "/seed\x00"
						if directory {
							subject = member{name: name + "/", mode: os.ModeDir | 0700, typ: tar.TypeDir}
							want.Known = counts{Files: 1, HitFiles: 1, HitLines: 1}
						} else if depth == 128 {
							basePaths += logical + "\x00"
						}
						// Stage a valid member first, so refusal must remove earlier output too.
						body := makeArchive(t, kind, []member{{name: "seed", data: "TOKEN\n"}, subject})
						put(t, filepath.Join(d, archive), body)
						base := filepath.Join(d, "base-list")
						put(t, base, []byte(basePaths))
						var out, diagnostic bytes.Buffer
						code := run([]string{d, "--patterns", p, "--known-base", base}, &out, &diagnostic)
						if depth == 129 {
							if code != 1 || out.Len() != 0 || diagnostic.String() != "pktscan: archive refused\n" {
								t.Error("over-depth archive must refuse without counts or path disclosure")
							}
							if _, e := os.Lstat(filepath.Join(d, outputDir)); !os.IsNotExist(e) {
								t.Error("over-depth extraction not rolled back")
							}
						} else {
							if code != 0 || diagnostic.Len() != 0 {
								t.Fatal("valid depth neighbor refused")
							}
							var got result
							if json.Unmarshal(out.Bytes(), &got) != nil {
								t.Fatal("invalid count output")
							}
							check(t, got, want)
							extracted := filepath.Join(d, outputDir, "files", logical)
							info, e := os.Stat(extracted)
							if e != nil || info.IsDir() != directory {
								t.Fatal("valid depth output missing")
							}
						}
						if got, e := os.ReadFile(filepath.Join(d, archive)); e != nil || !bytes.Equal(got, body) {
							t.Fatal("original archive changed")
						}
					})
				}
			}
		}
	}
}

func TestArchiveRefusalsAndRollback(t *testing.T) {
	cases := []struct {
		name, kind string
		members    []member
	}{
		{"zip-slip", "zip", []member{{name: "../escape", data: "TOKEN"}}},
		{"zip-absolute", "zip", []member{{name: "/escape", data: "TOKEN"}}},
		{"zip-backslash", "zip", []member{{name: `..\escape`, data: "TOKEN"}}},
		{"zip-drive", "zip", []member{{name: "C:/escape", data: "TOKEN"}}},
		{"zip-symlink", "zip", []member{{name: "link", data: "../escape", mode: os.ModeSymlink | 0777}}},
		{"zip-device", "zip", []member{{name: "device", mode: os.ModeDevice}}},
		{"zip-duplicate", "zip", []member{{name: "same", data: "first"}, {name: "same", data: "second"}}},
		{"zip-parent-file", "zip", []member{{name: "parent", data: "first"}, {name: "parent/child", data: "second"}}},
		{"tar-slip", "tar", []member{{name: "../escape", data: "TOKEN"}}},
		{"tar-symlink", "tar", []member{{name: "link", typ: tar.TypeSymlink, link: "../escape"}}},
		{"tar-hardlink", "tar", []member{{name: "link", typ: tar.TypeLink, link: "../escape"}}},
		{"tar-fifo", "tar", []member{{name: "fifo", typ: tar.TypeFifo}}},
		{"tar-device", "tar", []member{{name: "device", typ: tar.TypeChar}}},
		{"tar-oversize", "tar", []member{{name: "large", size: maxFile + 1}}},
		{"nested-extension", "zip", []member{{name: "nested.zip", data: "not executed"}}},
		{"nested-magic", "zip", []member{{name: "hidden", data: "PK\x03\x04TOKEN"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, p := setup(t)
			put(t, filepath.Join(d, "archive."+c.kind), makeArchive(t, c.kind, c.members))
			put(t, filepath.Join(d, "preserved"), []byte("original"))
			if _, e := scan(d, p, ""); e == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, e := os.Lstat(filepath.Join(d, outputDir)); !os.IsNotExist(e) {
				t.Fatal("failed extraction not rolled back")
			}
			data, e := os.ReadFile(filepath.Join(d, "preserved"))
			if e != nil || string(data) != "original" {
				t.Fatal("source clobbered")
			}
		})
	}
}

func TestZipBombAndEntryLimit(t *testing.T) {
	d, p := setup(t)
	body := makeArchive(t, "zip", []member{{name: "large", data: strings.Repeat("A", maxFile+1)}})
	if len(body) > 1<<20 {
		t.Fatal("compression control failed")
	}
	put(t, filepath.Join(d, "bomb.zip"), body)
	if _, e := scan(d, p, ""); e != errLimit {
		t.Fatal("zip bomb accepted")
	}
	d, p = setup(t)
	members := make([]member, maxEntries+1)
	for i := range members {
		members[i].name = "item"
	} // Limit must precede duplicate-name detection.
	put(t, filepath.Join(d, "entries.zip"), makeArchive(t, "zip", members))
	if _, e := scan(d, p, ""); e != errLimit {
		t.Fatal("entry limit not enforced")
	}
}

func TestMembersCannotClobberInputsOrControls(t *testing.T) {
	d, p := setup(t)
	put(t, filepath.Join(d, "notes"), []byte("original"))
	put(t, filepath.Join(d, "packet.zip"), makeArchive(t, "zip", []member{{name: "patterns", data: "TOKEN"}, {name: "notes", data: "TOKEN"}}))
	r, e := scan(d, p, "")
	if e != nil {
		t.Fatal(e)
	}
	check(t, r, result{New: counts{Files: 3, HitFiles: 2, HitLines: 2}})
	for _, original := range []struct{ name, value string }{{p, "SYNTHETIC\nTOKEN\n"}, {filepath.Join(d, "notes"), "original"}} {
		b, e := os.ReadFile(original.name)
		if e != nil || string(b) != original.value {
			t.Fatal("input clobbered")
		}
	}
}

func TestZipCRCRefused(t *testing.T) {
	d, p := setup(t)
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, e := w.CreateHeader(&zip.FileHeader{Name: "file", Method: zip.Store})
	if e != nil {
		t.Fatal("fixture failed")
	}
	_, _ = io.WriteString(f, "SYNTHETIC payload")
	if w.Close() != nil {
		t.Fatal("fixture failed")
	}
	body := b.Bytes()
	i := bytes.Index(body, []byte("SYNTHETIC payload"))
	if i < 0 {
		t.Fatal("fixture failed")
	}
	body[i] ^= 1
	put(t, filepath.Join(d, "packet.zip"), body)
	if _, e := scan(d, p, ""); e != errArchive {
		t.Fatal("corrupt ZIP accepted")
	}
}

func TestInvalidArchiveDiagnostics(t *testing.T) {
	for _, name := range []string{"SYNTHETIC-secret.zip", "SYNTHETIC-secret.tar", "SYNTHETIC-secret.tar.gz"} {
		d, p := setup(t)
		put(t, filepath.Join(d, name), []byte("SYNTHETIC invalid content"))
		var out, diagnostic bytes.Buffer
		if run([]string{d, "--patterns", p}, &out, &diagnostic) == 0 {
			t.Fatal("invalid archive accepted")
		}
		if out.Len() != 0 || diagnostic.String() != "pktscan: archive refused\n" {
			t.Fatal("unsafe archive diagnostic")
		}
	}
}

func TestGzipIntegrityAndTrailingData(t *testing.T) {
	for _, mutation := range []string{"truncate", "crc", "trailing"} {
		d, p := setup(t)
		body := makeArchive(t, "tgz", []member{{name: "file", data: "TOKEN"}})
		switch mutation {
		case "truncate":
			body = body[:len(body)-4]
		case "crc":
			body[len(body)-8] ^= 0xff
		case "trailing":
			var b bytes.Buffer
			w := gzip.NewWriter(&b)
			_, _ = w.Write([]byte("SYNTHETIC trailing payload"))
			_ = w.Close()
			body = append(body, b.Bytes()...)
		}
		put(t, filepath.Join(d, "packet.tar.gz"), body)
		if _, e := scan(d, p, ""); e != errArchive {
			t.Fatal("invalid gzip accepted")
		}
	}
}

func TestInputSymlinkAndReservedOutput(t *testing.T) {
	d, p := setup(t)
	outside := filepath.Join(t.TempDir(), "outside")
	put(t, outside, []byte("TOKEN"))
	if os.Symlink(outside, filepath.Join(d, "link")) != nil {
		t.Fatal("fixture symlink failed")
	}
	if _, e := scan(d, p, ""); e != errInput {
		t.Fatal("input symlink accepted")
	}
	d, p = setup(t)
	put(t, filepath.Join(d, outputDir, "preserved"), []byte("original"))
	if _, e := scan(d, p, ""); e != errOutput {
		t.Fatal("reserved output accepted")
	}
	if b, e := os.ReadFile(filepath.Join(d, outputDir, "preserved")); e != nil || string(b) != "original" {
		t.Fatal("preexisting output clobbered")
	}
}

func TestKnownBaseValidation(t *testing.T) {
	for _, list := range []string{"path\n", "../escape\x00", "/absolute\x00", "a//b\x00", "same\x00same\x00", "\x00"} {
		if _, e := knownPaths([]byte(list)); e != errBase {
			t.Fatal("ambiguous known-base list accepted")
		}
	}
	d, p := setup(t)
	put(t, filepath.Join(d, "file"), []byte("TOKEN"))
	base := filepath.Join(d, "base-list")
	put(t, base, []byte("fi\x00"))
	r, e := scan(d, p, base)
	if e != nil {
		t.Fatal(e)
	}
	check(t, r, result{New: counts{Files: 1, HitFiles: 1, HitLines: 1}}) // No prefix matching.
}

func TestFileAndLineLimits(t *testing.T) {
	d, p := setup(t)
	put(t, filepath.Join(d, "large"), bytes.Repeat([]byte{'a'}, maxLine+1))
	if _, e := scan(d, p, ""); e != errLimit {
		t.Fatal("long text line accepted")
	}
	d, p = setup(t)
	f, e := os.Create(filepath.Join(d, "large"))
	if e != nil {
		t.Fatal("fixture failed")
	}
	e = f.Truncate(maxFile + 1)
	_ = f.Close()
	if e != nil {
		t.Fatal("fixture failed")
	}
	if _, e := scan(d, p, ""); e != errLimit {
		t.Fatal("oversized file accepted")
	}
}

func TestCLIOutputAndArguments(t *testing.T) {
	d, p := setup(t)
	put(t, filepath.Join(d, "TOKEN\nname"), []byte("TOKEN TOKEN\n"))
	var out, diagnostic bytes.Buffer
	if run([]string{d, "--patterns", p}, &out, &diagnostic) != 0 || diagnostic.Len() != 0 {
		t.Fatal("CLI failed")
	}
	var r result
	if json.Unmarshal(out.Bytes(), &r) != nil {
		t.Fatal("invalid count output")
	}
	check(t, r, result{New: counts{Files: 1, HitFiles: 1, HitLines: 1, PathHits: 1}})
	if bytes.Contains(out.Bytes(), []byte("TOKEN")) {
		t.Fatal("match leaked")
	}
	for _, args := range [][]string{nil, {d}, {d, "--SYNTHETIC-secret"}, {d, "--patterns", p, "SYNTHETIC-secret"}} {
		out.Reset()
		diagnostic.Reset()
		if run(args, &out, &diagnostic) != 2 || out.Len() != 0 || diagnostic.String() != "pktscan: invalid arguments\n" {
			t.Fatal("unsafe argument diagnostic")
		}
	}
}
