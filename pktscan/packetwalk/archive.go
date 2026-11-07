package packetwalk

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"hash/crc32"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// namespace rejects duplicate records and file/directory prefix collisions.
// An implicit parent may subsequently have one explicit directory record.
type namespace struct{ files, dirs, explicit map[string]bool }

func newNamespace() *namespace {
	return &namespace{map[string]bool{}, map[string]bool{}, map[string]bool{}}
}
func (s *namespace) claim(name string, dir bool) bool {
	if !safePath(name) || s.explicit[name] || s.files[name] || !dir && s.dirs[name] {
		return false
	}
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[:i], "/")
		if s.files[parent] {
			return false
		}
		s.dirs[parent] = true
	}
	s.explicit[name] = true
	if dir {
		s.dirs[name] = true
	} else {
		s.files[name] = true
	}
	return true
}

func (w *walker) zip(name string, b []byte, depth int, origin Origin) error {
	// Bound the number of central directory records before archive/zip allocates
	// its file table. Reject ZIP64/multidisk, comments/trailing payloads and SFX.
	if len(b) < 22 {
		return ErrArchive
	}
	eocd := b[len(b)-22:]
	if string(eocd[:4]) != "PK\x05\x06" {
		return ErrArchive
	}
	u16 := func(p []byte) int { return int(p[0]) | int(p[1])<<8 }
	u32 := func(p []byte) int64 { return int64(p[0]) | int64(p[1])<<8 | int64(p[2])<<16 | int64(p[3])<<24 }
	count := u16(eocd[10:12])
	if u16(eocd[4:6]) != 0 || u16(eocd[6:8]) != 0 || u16(eocd[8:10]) != count ||
		count == 65535 || u16(eocd[20:22]) != 0 {
		return ErrArchive
	}
	if count > w.l.Entries-w.r.Entries {
		return ErrLimit
	}
	offset, size := u32(eocd[16:20]), u32(eocd[12:16])
	if offset+size != int64(len(b)-22) || offset > int64(len(b)-22) {
		return ErrArchive
	}
	// Independently walk record lengths so a lying EOCD count cannot allocate an
	// oversized table. archive/zip then verifies decompression and CRC.
	central := b[offset : offset+size]
	for n := 0; len(central) != 0; n++ {
		if n >= count || len(central) < 46 || string(central[:4]) != "PK\x01\x02" {
			return ErrArchive
		}
		length := 46 + u16(central[28:30]) + u16(central[30:32]) + u16(central[32:34])
		if length > len(central) {
			return ErrArchive
		}
		if u16(central[28:30]) > 4096 {
			return ErrLimit
		}
		central = central[length:]
		if len(central) == 0 && n+1 != count {
			return ErrArchive
		}
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil || len(zr.File) != count {
		return ErrArchive
	}
	// Require local records to cover the complete data region exactly. This
	// refuses SFX prefixes, gaps, overlaps, hidden records and trailing bytes.
	type segment struct{ start, end int64 }
	segments := make([]segment, 0, count)
	central = b[offset : offset+size]
	for _, z := range zr.File {
		start := u32(central[42:46])
		if z.Comment != "" || len(z.Extra) != 0 || start > offset-30 || string(b[start:start+4]) != "PK\x03\x04" {
			return ErrArchive
		}
		h := b[start : start+30]
		nl, xl := int64(u16(h[26:28])), int64(u16(h[28:30]))
		dataStart := start + 30 + nl + xl
		if xl != 0 || dataStart > offset || string(b[start+30:start+30+nl]) != z.Name || u16(h[6:8]) != int(z.Flags) || u16(h[8:10]) != int(z.Method) {
			return ErrArchive
		}
		if z.CompressedSize64 > uint64(offset-dataStart) {
			return ErrArchive
		}
		end := dataStart + int64(z.CompressedSize64)
		if z.Flags&8 != 0 {
			if offset-end < 12 {
				return ErrArchive
			}
			d := b[end:offset]
			if len(d) >= 16 && string(d[:4]) == "PK\x07\x08" {
				d = d[4:]
				end += 4
			}
			if uint32(u32(d[:4])) != z.CRC32 || uint64(u32(d[4:8])) != z.CompressedSize64 || uint64(u32(d[8:12])) != z.UncompressedSize64 {
				return ErrArchive
			}
			end += 12
		} else if uint32(u32(h[14:18])) != z.CRC32 || uint64(u32(h[18:22])) != z.CompressedSize64 || uint64(u32(h[22:26])) != z.UncompressedSize64 {
			return ErrArchive
		}
		segments = append(segments, segment{start, end})
		length := 46 + u16(central[28:30]) + u16(central[30:32]) + u16(central[32:34])
		central = central[length:]
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].start < segments[j].start })
	var end int64
	for _, s := range segments {
		if s.start != end || s.end < s.start || s.end > offset {
			return ErrArchive
		}
		end = s.end
	}
	if end != offset {
		return ErrArchive
	}
	ns := newNamespace()
	for _, z := range zr.File {
		if err = w.entry(); err != nil {
			return err
		}
		dir := z.Mode().IsDir()
		member := z.Name
		if dir {
			member = strings.TrimSuffix(member, "/")
		}
		if z.Flags&1 != 0 || z.Mode().Type() != 0 && z.Mode().Type() != fs.ModeDir ||
			!ns.claim(member, dir) || !safePath(name+"/"+member) {
			return ErrArchive
		}
		if z.UncompressedSize64 > uint64(w.l.FileBytes) || z.UncompressedSize64 > uint64(w.l.ExpandedBytes-w.r.ExpandedBytes) {
			return ErrLimit
		}
		if dir && z.UncompressedSize64 != 0 {
			return ErrArchive
		}
		// OpenRaw bounds the declared member extent. bytes.Reader implements
		// io.ByteReader, so flate does not buffer bytes past the actual end of
		// the stream. Checking Len after EOF detects residual compressed bytes.
		raw, e := z.OpenRaw()
		if e != nil {
			return ErrArchive
		}
		compressed, e := io.ReadAll(io.LimitReader(checkedReader{w, raw}, int64(z.CompressedSize64)+1))
		if e != nil || uint64(len(compressed)) != z.CompressedSize64 {
			return ErrArchive
		}
		input := bytes.NewReader(compressed)
		var r io.ReadCloser
		switch z.Method {
		case zip.Store:
			r = io.NopCloser(input)
		case zip.Deflate:
			r = flate.NewReader(input)
		default:
			return ErrArchive
		}
		data, e := w.read(r, int64(z.UncompressedSize64))
		ce := r.Close()
		if e != nil {
			return e
		}
		if ce != nil || input.Len() != 0 || crc32.ChecksumIEEE(data) != z.CRC32 {
			return ErrArchive
		}
		if e = w.path(name+"/"+member, dir, origin); e != nil {
			return e
		}
		if !dir {
			if e = w.payload(name+"/"+member, data, depth, origin); e != nil {
				return e
			}
		}
	}
	return w.check()
}

func (w *walker) tar(name string, b []byte, depth int, compressed bool, origin Origin) error {
	data := b
	if compressed {
		input := bytes.NewReader(b)
		gz, err := gzip.NewReader(input)
		if err != nil {
			return ErrArchive
		}
		gz.Multistream(false)
		if len(gz.Extra) != 0 {
			gz.Close()
			return ErrArchive
		}
		if gz.Name != "" || gz.Comment != "" {
			if err = w.leaf(File{LogicalPath: name + "/.archive/gzip", Bytes: []byte(gz.Name + "\n" + gz.Comment), ObjectType: "archive-metadata", Origin: ArchiveMetadata}); err != nil {
				gz.Close()
				return err
			}
		}
		remaining := w.l.StreamBytes - w.r.StreamBytes
		data, err = io.ReadAll(io.LimitReader(checkedReader{w, gz}, remaining+1))
		ce := gz.Close()
		if int64(len(data)) > remaining {
			return ErrLimit
		}
		if err != nil || ce != nil || input.Len() != 0 {
			return ErrArchive
		}
	}
	if err := charge(&w.r.StreamBytes, int64(len(data)), w.l.StreamBytes); err != nil {
		return err
	}
	// Validate the physical stream first, counting every header before tar's
	// parser. PAX/GNU extension records and sparse encodings are refused rather
	// than allowing hidden metadata allocations or uncounted records.
	if err := w.tarHeaders(data); err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	ns := newNamespace()
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrArchive
		}
		dir := h.Typeflag == tar.TypeDir
		member := h.Name
		if dir {
			member = strings.TrimSuffix(member, "/")
		}
		if !ns.claim(member, dir) || !safePath(name+"/"+member) || dir && h.Size != 0 {
			return ErrArchive
		}
		if h.Uname != "" || h.Gname != "" {
			if e = w.leaf(File{LogicalPath: name + "/.archive/owner", Bytes: []byte(h.Uname + "\n" + h.Gname), ObjectType: "archive-metadata", Origin: ArchiveMetadata}); e != nil {
				return e
			}
		}
		content, e := w.read(tr, h.Size)
		if e != nil {
			return e
		}
		if e = w.path(name+"/"+member, dir, origin); e != nil {
			return e
		}
		if !dir {
			if e = w.payload(name+"/"+member, content, depth, origin); e != nil {
				return e
			}
		}
	}
	return w.check()
}

func (w *walker) tarHeaders(b []byte) error {
	for len(b) >= 512 {
		if bytes.Equal(b[:512], make([]byte, 512)) {
			if len(b) < 1024 || len(b) > 1<<20 || len(bytes.Trim(b, "\x00")) != 0 {
				return ErrArchive
			}
			return nil
		}
		if err := w.entry(); err != nil {
			return err
		}
		typ := b[156]
		if typ != tar.TypeReg && typ != tar.TypeRegA && typ != tar.TypeDir {
			return ErrArchive
		}
		// Admit POSIX USTAR only. Every physical byte is either a supported
		// field or canonical padding; archive/tar must not silently discard an
		// inapplicable linkname, suffix after NUL, device number or extension.
		if string(b[257:265]) != "ustar\x0000" ||
			!allZero(b[157:257]) || !allZero(b[500:512]) {
			return ErrArchive
		}
		for _, field := range [][]byte{b[:100], b[265:297], b[297:329], b[345:500]} {
			if n := bytes.IndexByte(field, 0); n >= 0 && !allZero(field[n:]) {
				return ErrArchive
			}
		}
		for _, field := range [][]byte{b[100:108], b[108:116], b[116:124], b[136:148], b[148:156]} {
			if _, ok := tarOctal(field); !ok {
				return ErrArchive
			}
		}
		for _, field := range [][]byte{b[329:337], b[337:345]} {
			if n, ok := tarOctal(field); !ok || n != 0 {
				return ErrArchive
			}
		}
		size, ok := tarOctal(b[124:136])
		if !ok {
			return ErrArchive
		}
		if size > w.l.FileBytes {
			return ErrLimit
		}
		padded := ((size + 511) / 512) * 512
		if padded > int64(len(b)-512) {
			return ErrArchive
		}
		if len(bytes.Trim(b[512+size:512+padded], "\x00")) != 0 {
			return ErrArchive
		}
		b = b[512+padded:]
	}
	return ErrArchive
}

func allZero(b []byte) bool { return len(bytes.Trim(b, "\x00")) == 0 }

// Only nonnegative portable octal fields with surrounding NUL/space padding.
// No base-256, signs, embedded terminators or otherwise ignored text is admitted.
func tarOctal(b []byte) (int64, bool) {
	s := strings.Trim(string(b), " \x00")
	if s == "" {
		return 0, true
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 8, 64)
	return n, err == nil
}
