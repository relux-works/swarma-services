package packetwalk

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type zipEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func zipPacket(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := z.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func tarPacket(t *testing.T, name string, data []byte, typ byte, compressed bool) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	h := &tar.Header{Name: name, Size: int64(len(data)), Typeflag: typ, Mode: 0600, Format: tar.FormatUSTAR}
	if typ != tar.TypeReg {
		h.Size = 0
		h.Linkname = "elsewhere"
	}
	if e := tw.WriteHeader(h); e != nil {
		t.Fatal(e)
	}
	if typ == tar.TypeReg {
		if _, e := tw.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if !compressed {
		return b.Bytes()
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, e := gz.Write(b.Bytes()); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}

func runPacket(t *testing.T, name string, b []byte, opts Options) (Report, []File, error) {
	t.Helper()
	d := t.TempDir()
	if e := os.WriteFile(filepath.Join(d, name), b, 0600); e != nil {
		t.Fatal(e)
	}
	r, e := os.OpenRoot(d)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	var files []File
	report, e := Walk(context.Background(), r, opts, func(ctx context.Context, f File) error {
		f.Bytes = bytes.Clone(f.Bytes)
		files = append(files, f)
		return nil
	})
	return report, files, e
}

func TestAdjacentValidNestedPackets(t *testing.T) {
	inner := tarPacket(t, "src/note.txt", []byte("synthetic marker\n"), tar.TypeReg, true)
	b := zipPacket(t, zipEntry{"inner.tar.gz", inner, 0}, zipEntry{"adjacent.txt", []byte("ordinary\n"), 0})
	r, files, e := runPacket(t, "outer.zip", b, Options{Limits: DefaultLimits()})
	if e != nil {
		t.Fatal(e)
	}
	if r.Containers != 2 || r.Leaves != 2 || len(files) != 2 || files[0].LogicalPath != "outer.zip/inner.tar.gz/src/note.txt" || files[1].LogicalPath != "outer.zip/adjacent.txt" {
		t.Fatalf("unexpected result: %+v", r)
	}
	if !bytes.Contains(files[0].Bytes, []byte("synthetic marker")) {
		t.Fatal("nested content not visited")
	}
	if r.CompressedBytes != int64(len(b)+len(inner)) {
		t.Fatal("compressed accounting")
	}
}

func TestMagicDetectedAndEmptyCounts(t *testing.T) {
	inner := zipPacket(t, zipEntry{"empty", nil, 0})
	r, f, e := runPacket(t, "renamed.txt", inner, Options{Limits: DefaultLimits()})
	if e != nil || r.Containers != 1 || r.Leaves != 1 || len(f) != 1 {
		t.Fatalf("magic/empty: %+v %v", r, e)
	}
}

func TestArchiveRefusals(t *testing.T) {
	valid := tarPacket(t, "ok", []byte("safe"), tar.TypeReg, true)
	corruptCRC := bytes.Clone(valid)
	corruptCRC[len(corruptCRC)-8] ^= 1
	cases := map[string][]byte{
		"traversal.zip":      zipPacket(t, zipEntry{"../outside", []byte("data"), 0}),
		"absolute.zip":       zipPacket(t, zipEntry{"/outside", []byte("data"), 0}),
		"backslash.zip":      zipPacket(t, zipEntry{"a\\b", []byte("data"), 0}),
		"duplicate.zip":      zipPacket(t, zipEntry{"same", nil, 0}, zipEntry{"same", nil, 0}),
		"prefix.zip":         zipPacket(t, zipEntry{"a", nil, 0}, zipEntry{"a/b", nil, 0}),
		"reverse-prefix.zip": zipPacket(t, zipEntry{"a/b", nil, 0}, zipEntry{"a", nil, 0}),
		"symlink.zip":        zipPacket(t, zipEntry{"link", []byte("target"), os.ModeSymlink | 0600}),
		"link.tar":           tarPacket(t, "link", nil, tar.TypeLink, false),
		"symlink.tar.gz":     tarPacket(t, "link", nil, tar.TypeSymlink, true),
		"bad-crc.tar.gz":     corruptCRC,
		"trailing.tar.gz":    append(bytes.Clone(valid), []byte("extra")...),
		"concat.tar.gz":      append(bytes.Clone(valid), valid...),
		"fake.zip":           []byte("not an archive"),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			r, _, e := runPacket(t, name, b, Options{Limits: DefaultLimits()})
			if e == nil || r != (Report{}) {
				t.Fatal("refusal must return zero report")
			}
		})
	}
}

func TestCumulativeBoundsAndAdjacentControl(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 4096)
	b := zipPacket(t, zipEntry{"first", data, 0}, zipEntry{"second", data, 0})
	for _, field := range []string{"file", "expanded", "compressed", "entries", "files", "containers", "depth", "time"} {
		t.Run(field, func(t *testing.T) {
			l := DefaultLimits()
			input := b
			switch field {
			case "file":
				l.FileBytes = 4095
			case "expanded":
				l.ExpandedBytes = int64(len(b)) + 8191
			case "compressed":
				l.CompressedBytes = int64(len(b)) - 1
			case "entries":
				l.Entries = 2
			case "files":
				l.Files = 2
			case "containers":
				l.Containers = 1
				input = zipPacket(t, zipEntry{"inner.zip", b, 0})
			case "depth":
				l.Depth = 1
				input = zipPacket(t, zipEntry{"inner.zip", b, 0})
			case "time":
				l.Duration = time.Nanosecond
			}
			r, _, e := runPacket(t, "packet.zip", input, Options{Limits: l})
			if !errors.Is(e, ErrLimit) || r != (Report{}) {
				t.Fatalf("expected bounded refusal, got %v %+v", e, r)
			}
		})
	}
	if _, _, e := runPacket(t, "packet.zip", b, Options{Limits: DefaultLimits()}); e != nil {
		t.Fatal("adjacent valid control:", e)
	}
}

func TestGzipStreamBombBound(t *testing.T) {
	b := tarPacket(t, "large", bytes.Repeat([]byte("x"), 1<<20), tar.TypeReg, true)
	l := DefaultLimits()
	l.StreamBytes = 4096
	if _, _, e := runPacket(t, "bomb.tgz", b, Options{Limits: l}); e != ErrLimit {
		t.Fatal(e)
	}
}

func TestNoBinarySuccess(t *testing.T) {
	for _, b := range [][]byte{{0, 1, 2}, {0xff}, []byte("valid\x00hidden")} {
		if r, _, e := runPacket(t, "binary", b, Options{Limits: DefaultLimits()}); e != ErrBinary || r != (Report{}) {
			t.Fatalf("binary accepted: %v", e)
		}
	}
}

func TestRootLinksAndVisitorTransaction(t *testing.T) {
	d := t.TempDir()
	if e := os.WriteFile(filepath.Join(d, "real"), []byte("safe"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("real", filepath.Join(d, "link")); e != nil {
		t.Fatal(e)
	}
	r, e := os.OpenRoot(d)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if report, e := Walk(context.Background(), r, Options{Limits: DefaultLimits()}, func(context.Context, File) error { return nil }); e != ErrInput || report != (Report{}) {
		t.Fatalf("link accepted %v", e)
	}
	if e := os.Remove(filepath.Join(d, "link")); e != nil {
		t.Fatal(e)
	}
	if report, e := Walk(context.Background(), r, Options{Limits: DefaultLimits()}, func(context.Context, File) error { return errors.New("sensitive diagnostic") }); e != ErrVisit || report != (Report{}) {
		t.Fatal("visitor error not sanitized")
	}
}

func TestLimitsValidation(t *testing.T) {
	for _, l := range []Limits{{}, {Duration: -1}, {Duration: time.Hour}} {
		if l.valid() {
			t.Fatal("invalid limits accepted")
		}
	}
	for _, p := range []string{"", "/a", "a//b", "a/../b", "a:b", "a\\b", strings.Repeat("x", 4097)} {
		if safePath(p) {
			t.Fatal("bad path accepted")
		}
	}
}
