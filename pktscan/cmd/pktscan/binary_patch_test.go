package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTextualBinaryPatchRefusalAndNeighbors(t *testing.T) {
	for _, representation := range []struct{ name, data string }{
		{"git-binary", "diff --git a/file b/file\nGIT binary patch\nliteral 4\nLc$@<O0RR9S\n\nliteral 0\nHc$@<O00001\n"},
		{"binary-summary", "diff --git a/file b/file\nBinary files a/file and b/file differ\n"},
		{"text", "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+TOKEN\n"},
		{"marker-content", "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+GIT binary patch TOKEN\n"},
	} {
		for _, suffix := range []string{".patch", ".diff"} {
			for _, nested := range []bool{false, true} {
				name := representation.name + suffix
				if nested {
					name += "/zip"
				}
				t.Run(name, func(t *testing.T) {
					d, p := setup(t)
					inputName, data := "change"+suffix, []byte(representation.data)
					if nested {
						inputName, data = "packet.zip", makeArchive(t, "zip", []member{{name: inputName, data: string(data)}})
					}
					input := filepath.Join(d, inputName)
					put(t, input, data)
					if representation.name == "git-binary" || representation.name == "binary-summary" {
						assertRefused(t, d, p, "", errPatch)
					} else {
						r, e := scan(d, p, "")
						if e != nil || r.New != (counts{Files: 1, HitFiles: 1, HitLines: 1}) {
							t.Fatal("text neighbor failed")
						}
					}
					if after, e := os.ReadFile(input); e != nil || !bytes.Equal(after, data) {
						t.Fatal("original changed")
					}
				})
			}
		}
	}
}

func TestBinaryPatchKnownBaseAndRollback(t *testing.T) {
	text := "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+TOKEN\n"
	for _, binary := range []string{"GIT binary patch\n", "Binary files a/file and b/file differ\r\n"} {
		for _, mode := range []string{"known-direct", "known-nested", "mixed-files", "mixed-sections"} {
			t.Run(mode+"/"+binary[:3], func(t *testing.T) {
				d, p := setup(t)
				base, logical := "", "change.patch"
				data := []byte(binary)
				switch mode {
				case "known-direct", "known-nested":
					if mode == "known-nested" {
						logical = "packet.zip/change.patch"
					}
					base = filepath.Join(d, "known")
					put(t, base, []byte(logical+"\x00"))
				case "mixed-files":
					// A valid extracted member is staged before the later refusal.
					put(t, filepath.Join(d, "a-valid.zip"), makeArchive(t, "zip", []member{{name: "valid.patch", data: text}}))
					logical = "z-binary.patch"
				case "mixed-sections":
					data = []byte(text + "diff --git a/other b/other\n" + binary)
				}
				input := logical
				if mode == "known-nested" {
					input, data = "packet.zip", makeArchive(t, "zip", []member{{name: "change.patch", data: string(data)}})
				}
				put(t, filepath.Join(d, input), data)
				assertRefused(t, d, p, base, errPatch)
				if after, e := os.ReadFile(filepath.Join(d, input)); e != nil || !bytes.Equal(after, data) {
					t.Fatal("original changed")
				}
			})
		}
	}
}

func TestBinaryMarkerTextHunkSemantics(t *testing.T) {
	compiled, e := patterns([]byte("GIT binary patch\nBinary files\n"))
	if e != nil {
		t.Fatal(e)
	}
	s := &scanner{patterns: compiled}
	// Exact markers in added, removed and context lines remain hunk content.
	patch := "--- a/file\n+++ b/file\n@@ -1,3 +1,3 @@ GIT binary patch\n-GIT binary patch\n+GIT binary patch\n Binary files a/file and b/file differ\n-GIT binary patch\n+Binary files a/file and b/file differ\n\\ No newline at end of file\n"
	if hits, e := s.patch([]byte(patch)); e != nil || hits != 2 {
		t.Fatal("marker content mistaken for binary metadata")
	}
	if hits, e := s.patch([]byte("--- a/GIT binary patch\n+++ b/GIT binary patch\n@@ -0,0 +1 @@\n+GIT binary patch")); e != nil || hits != 1 {
		t.Fatal("insertion-only marker content refused")
	}
}
