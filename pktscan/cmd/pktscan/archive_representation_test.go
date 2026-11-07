package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Mutate physical USTAR bytes and repair the checksum so refusal must concern
// the unsupported representation rather than an incidental checksum failure.
func tarHeaderChange(t *testing.T, start, end int, value []byte) []byte {
	t.Helper()
	b := makeArchive(t, "tar", []member{{name: "note", data: "TOKEN\n"}})
	clear(b[start:end])
	copy(b[start:end], value)
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	sum := 0
	for _, c := range b[:512] {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func TestUSTARPhysicalFieldCoverage(t *testing.T) {
	marker := []byte("gh" + "p_" + strings.Repeat("0", 36))
	cases := []struct {
		name       string
		start, end int
		value      []byte
	}{
		{"linkname-inert", 157, 257, []byte("INERT")},
		{"linkname-blocked", 157, 257, marker},
		{"name-after-nul", 0, 100, append([]byte("note\x00"), marker...)},
		{"uname-after-nul", 265, 297, []byte("ok\x00INERT")},
		{"gname-after-nul", 297, 329, []byte("ok\x00INERT")},
		{"prefix-after-nul", 345, 500, append([]byte("dir\x00"), marker...)},
		{"reserved", 500, 512, []byte("INERT")},
		{"numeric-text", 108, 116, []byte("INERT")},
		{"numeric-after-nul", 100, 108, []byte("600\x00BAD")},
		{"device-on-regular", 329, 337, []byte("0000001\x00")},
		{"v7", 257, 265, nil},
		{"gnu-magic", 257, 265, []byte("ustar  \x00")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				d, p := setup(t)
				b := tarHeaderChange(t, tc.start, tc.end, tc.value)
				name := "packet.tar"
				if nested {
					b = makeArchive(t, "zip", []member{{name: "inner.tar", data: string(b)}})
					name = "packet.zip"
				}
				put(t, filepath.Join(d, name), b)
				assertRefused(t, d, p, "", errArchive)
			}
		})
	}
	// Supported metadata is classified, and ordinary empty linkname archives
	// still extract their original payload and report pattern counts.
	for _, owner := range []bool{false, true} {
		d, p := setup(t)
		b := makeArchive(t, "tar", []member{{name: "note", data: "TOKEN\n"}})
		if owner {
			b = tarHeaderChange(t, 265, 297, []byte("TOKEN"))
		}
		put(t, filepath.Join(d, "packet.tar"), b)
		r, e := scan(d, p, "")
		if e != nil || r.New.Files != 1 || r.New.HitLines != 1 || owner && r.Metadata.HitLines != 1 {
			t.Fatal("supported USTAR neighbor failed")
		}
		got, e := os.ReadFile(filepath.Join(d, outputDir, "files/packet.tar/note"))
		if e != nil || string(got) != "TOKEN\n" {
			t.Fatal("USTAR payload extraction changed")
		}
	}
}

// CreateRaw preserves a deliberately declared compressed extent. Both ZIP
// descriptor modes are exercised without relying on a decoder to rewrite it.
func rawExtentZIP(t *testing.T, payload, trailing []byte, descriptor bool, method uint16, badCRC, truncated bool) []byte {
	t.Helper()
	var compressed bytes.Buffer
	if method == zip.Deflate {
		w, e := flate.NewWriter(&compressed, flate.DefaultCompression)
		if e != nil {
			t.Fatal("fixture failed")
		}
		w.Write(payload)
		w.Close()
	} else {
		compressed.Write(payload)
	}
	data := compressed.Bytes()
	if truncated {
		data = data[:len(data)-1]
	}
	data = append(bytes.Clone(data), trailing...)
	h := &zip.FileHeader{Name: "note", Method: method, CRC32: crc32.ChecksumIEEE(payload), CompressedSize64: uint64(len(data)), UncompressedSize64: uint64(len(payload))}
	if descriptor {
		h.Flags = 8
	}
	if badCRC {
		h.CRC32 ^= 1
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, e := z.CreateRaw(h)
	if e != nil {
		t.Fatal("fixture failed")
	}
	w.Write(data)
	if z.Close() != nil {
		t.Fatal("fixture failed")
	}
	return b.Bytes()
}

func TestZIPExactCompressedConsumptionAndNeighbors(t *testing.T) {
	marker := []byte("gh" + "p_" + strings.Repeat("0", 36))
	for _, descriptor := range []bool{false, true} {
		for _, method := range []uint16{zip.Store, zip.Deflate} {
			for _, which := range []string{"valid", "trailing-inert", "trailing-blocked", "payload-blocked", "crc", "truncated"} {
				if which == "truncated" && method == zip.Store {
					continue
				}
				for _, wrap := range []string{"", "tar", "tgz"} {
					d, p := setup(t)
					payload, trailing := []byte("TOKEN\n"), []byte(nil)
					switch which {
					case "trailing-inert":
						trailing = []byte("INERT")
					case "trailing-blocked":
						trailing = marker
					case "payload-blocked":
						payload = marker
					}
					b := rawExtentZIP(t, payload, trailing, descriptor, method, which == "crc", which == "truncated")
					name := "packet.zip"
					if wrap != "" {
						b = makeArchive(t, wrap, []member{{name: "inner.zip", data: string(b)}})
						name = "outer." + wrap
					}
					put(t, filepath.Join(d, name), b)
					if which != "valid" {
						want := errArchive
						if which == "payload-blocked" {
							want = errSecret
						}
						assertRefused(t, d, p, "", want)
					} else {
						r, e := scan(d, p, "")
						if e != nil || r.New.Files != 1 || r.New.HitLines != 1 {
							t.Fatal("valid ZIP neighbor failed")
						}
						leaf := name + "/note"
						if wrap != "" {
							leaf = name + "/inner.zip/note"
						}
						got, e := os.ReadFile(filepath.Join(d, outputDir, "files", leaf))
						if e != nil || !bytes.Equal(got, payload) {
							t.Fatal("ZIP extraction changed")
						}
					}
				}
			}
		}
	}
}

func TestLogicalNamesCannotImpersonateGitProvenance(t *testing.T) {
	patch := []byte("--- old\n+++ new\n@@ -1 +1 @@\n-TOKEN\n+clean\n")
	for _, name := range []string{"nested/change.patch", "nested/.bundle/objects/change.patch"} {
		for _, nested := range []bool{false, true} {
			d, p := setup(t)
			logical := name
			if nested {
				put(t, filepath.Join(d, "packet.zip"), makeArchive(t, "zip", []member{{name: name, data: string(patch)}}))
				logical = "packet.zip/" + name
			} else {
				put(t, filepath.Join(d, name), patch)
			}
			base := filepath.Join(t.TempDir(), "known")
			put(t, base, []byte(logical+"\x00"))
			r, e := scan(d, p, base)
			if e != nil || r.Known.Files != 1 || r.Known.HitLines != 0 || r.Objects.Files != 0 || r.Metadata.Files != 0 || r.New.Files != 0 {
				t.Fatal("logical path changed ordinary patch scope")
			}
		}
	}
	for _, name := range []string{"ordinary/empty/", "inner/.bundle/source/empty/"} {
		d, p := setup(t)
		put(t, filepath.Join(d, "packet.zip"), makeArchive(t, "zip", []member{{name: name, mode: os.ModeDir | 0700}}))
		if _, e := scan(d, p, ""); e != nil {
			t.Fatal("empty directory refused")
		}
		i, e := os.Stat(filepath.Join(d, outputDir, "files/packet.zip", name))
		if e != nil || !i.IsDir() {
			t.Fatal("logical path suppressed extraction")
		}
	}
	// Genuine archive content from a Git blob retains full-object scanning,
	// even when a removed patch line would be excluded for an ordinary patch.
	repo := t.TempDir()
	fixtureGit(t, repo, "init", "--template=", ".")
	inner := makeArchive(t, "zip", []member{{name: "change.patch", data: string(patch)}, {name: "empty/", mode: os.ModeDir | 0700}})
	current := fixtureCommit(t, repo, "dir/nested.zip", string(inner))
	bundle := filepath.Join(t.TempDir(), "current.bundle")
	fixtureBundle(t, repo, bundle, "HEAD")
	raw, e := os.ReadFile(bundle)
	if e != nil {
		t.Fatal("fixture failed")
	}
	d, p := setup(t)
	put(t, filepath.Join(d, "source.bundle"), raw)
	var out, diag bytes.Buffer
	if run([]string{d, "--patterns", p, "--bundle-path", "source.bundle", "--current", current}, &out, &diag) != 0 || diag.Len() != 0 {
		t.Fatal("genuine Git neighbor refused")
	}
	var r result
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Objects.Files != 1 || r.Objects.HitLines != 1 || r.New.Files != 0 || r.Known.Files != 0 {
		t.Fatal("Git origin lost through archive")
	}
	if _, e := os.Stat(filepath.Join(d, outputDir, "files/source.bundle/.bundle/source")); !os.IsNotExist(e) {
		t.Fatal("Git source inventory was extracted")
	}
}
