// pktscan scans synthetic or operator-provided packets without disclosing matches.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	outputDir      = ".pktscan-unpacked"
	maxEntries     = 4096
	maxArchives    = 32
	maxFile        = 16 << 20
	maxTotal       = 64 << 20
	maxLine        = 1 << 20
	maxPatterns    = 256
	maxPatternFile = 1 << 20
	maxPattern     = 4096
	maxPath        = 4096
)

// All outward errors are fixed strings. Never wrap an OS, archive or regexp error.
var (
	errArgs    = errors.New("invalid arguments")
	errInput   = errors.New("input refused")
	errPattern = errors.New("patterns refused")
	errBase    = errors.New("known-base list refused")
	errArchive = errors.New("archive refused")
	errLimit   = errors.New("limit exceeded")
	errOutput  = errors.New("output refused")
	errChanged = errors.New("input changed")
	errPatch   = errors.New("patch refused")
)

type counts struct {
	Files    int `json:"files"`
	HitFiles int `json:"hitfiles"`
	HitLines int `json:"hitlines"`
	PathHits int `json:"pathhits"`
}

type result struct {
	New   counts `json:"new"`
	Known counts `json:"known_base"`
}

type input struct {
	name string
	info fs.FileInfo
}
type scanner struct {
	patterns []*regexp.Regexp
	known    map[string]bool
	result   result
	bytes    int64
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, diagnostic io.Writer) (code int) {
	defer func() {
		if recover() != nil {
			_, _ = io.WriteString(diagnostic, "pktscan: operation failed\n")
			code = 1
		}
	}()
	if len(args) < 1 {
		_, _ = io.WriteString(diagnostic, "pktscan: invalid arguments\n")
		return 2
	}
	flags := flag.NewFlagSet("pktscan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	patternName := flags.String("patterns", "", "")
	baseName := flags.String("known-base", "", "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *patternName == "" {
		_, _ = io.WriteString(diagnostic, "pktscan: invalid arguments\n")
		return 2
	}
	r, err := scan(args[0], *patternName, *baseName)
	if err != nil {
		// Explicit allowlist also protects this boundary from future wrapped errors.
		message := "operation failed"
		switch err {
		case errArgs, errInput, errPattern, errBase, errArchive, errLimit, errOutput, errChanged, errPatch:
			message = err.Error()
		}
		_, _ = io.WriteString(diagnostic, "pktscan: "+message+"\n")
		return 1
	}
	if json.NewEncoder(out).Encode(r) != nil {
		_, _ = io.WriteString(diagnostic, "pktscan: output failed\n")
		return 1
	}
	return 0
}

func readConfig(name string, limit int64) ([]byte, fs.FileInfo, error) {
	i, err := os.Lstat(name)
	if err != nil || !i.Mode().IsRegular() || i.Size() > limit {
		return nil, nil, errInput
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, errInput
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(i, actual) || !actual.Mode().IsRegular() {
		return nil, nil, errInput
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(b)) > limit || !unchanged(i, after) {
		return nil, nil, errInput
	}
	return b, i, nil
}

func patterns(data []byte) ([]*regexp.Regexp, error) {
	if len(data) == 0 || len(data) > maxPatternFile || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errPattern
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxPatterns {
		return nil, errPattern
	}
	var compiled []*regexp.Regexp
	cost := 0
	for _, line := range lines {
		if len(line) == 0 || len(line) > maxPattern || unsupportedClass(line) {
			return nil, errPattern
		}
		tree, err := syntax.Parse(string(line), syntax.POSIX)
		if err != nil {
			return nil, errPattern
		}
		cost += patternCost(tree)
		if cost > 65536 {
			return nil, errPattern
		}
		r, err := regexp.CompilePOSIX(string(line))
		if err != nil {
			return nil, errPattern
		}
		compiled = append(compiled, r)
	}
	return compiled, nil
}

// Go treats unsupported POSIX collating/equivalence syntax as literals in some
// contexts. Refuse that syntax explicitly rather than silently changing meaning.
func unsupportedClass(pattern []byte) bool {
	inClass, first := false, false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' {
			i++
			if inClass {
				first = false
			}
			continue
		}
		if !inClass {
			if c == '[' {
				inClass, first = true, true
				if i+1 < len(pattern) && pattern[i+1] == '^' {
					i++
				}
			}
			continue
		}
		if c == '[' && i+1 < len(pattern) {
			if pattern[i+1] == '.' || pattern[i+1] == '=' {
				return true
			}
			if pattern[i+1] == ':' {
				if end := bytes.Index(pattern[i+2:], []byte(":]")); end >= 0 {
					i += end + 3
					first = false
					continue
				}
			}
		}
		if c == ']' && !first {
			inClass = false
		}
		first = false
	}
	return false
}

// Bound repetition expansion before CompilePOSIX simplifies and compiles it.
func patternCost(r *syntax.Regexp) int {
	const cap = 65537
	n := 1 + len(r.Rune)
	for _, child := range r.Sub {
		n += patternCost(child)
		if n >= cap {
			return cap
		}
	}
	if r.Op == syntax.OpRepeat {
		m := r.Max
		if m < 0 {
			m = r.Min + 1
		}
		if m > 0 && n > cap/m {
			return cap
		}
		n *= m + 1
	}
	if n > cap {
		return cap
	}
	return n
}

func knownPaths(data []byte) (map[string]bool, error) {
	known := make(map[string]bool)
	if len(data) == 0 {
		return known, nil
	}
	if data[len(data)-1] != 0 || len(data) > maxPatternFile {
		return nil, errBase
	}
	parts := bytes.Split(data[:len(data)-1], []byte{0})
	if len(parts) > maxEntries {
		return nil, errBase
	}
	for _, p := range parts {
		if !safePath(string(p)) || known[string(p)] {
			return nil, errBase
		}
		known[string(p)] = true
	}
	return known, nil
}

func scan(dir, patternName, baseName string) (res result, err error) {
	data, patternInfo, e := readConfig(patternName, maxPatternFile)
	if e != nil {
		return res, errPattern
	}
	compiled, e := patterns(data)
	if e != nil {
		return res, e
	}
	known := make(map[string]bool)
	var baseInfo fs.FileInfo
	if baseName != "" {
		data, baseInfo, e = readConfig(baseName, maxPatternFile)
		if e != nil {
			return res, errBase
		}
		known, e = knownPaths(data)
		if e != nil {
			return res, e
		}
	}
	i, e := os.Lstat(dir)
	if e != nil || !i.IsDir() {
		return res, errInput
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return res, errInput
	}
	defer root.Close()
	if _, e = root.Lstat(outputDir); !errors.Is(e, fs.ErrNotExist) {
		return res, errOutput
	}
	files, archives, e := inventory(root, patternInfo, baseInfo)
	if e != nil {
		return res, e
	}
	s := &scanner{patterns: compiled, known: known}
	var dest *os.Root
	complete := false
	if archives != 0 {
		if root.Mkdir(outputDir, 0700) != nil {
			return res, errOutput
		}
		// Only this exclusively created tree is ever removed. No preexisting tree is owned.
		defer func() {
			if dest != nil {
				_ = dest.Close()
			}
			if !complete && root.RemoveAll(outputDir) != nil {
				err = errOutput
			}
		}()
		if root.Mkdir(outputDir+"/stage", 0700) != nil {
			return res, errOutput
		}
		dest, e = root.OpenRoot(outputDir + "/stage")
		if e != nil {
			return res, errOutput
		}
	}
	x := &extractor{dest: dest, scan: s}
	for _, in := range files {
		f, e := openInput(root, in)
		if e != nil {
			return res, e
		}
		if kind := archiveKind(in.name); kind != "" {
			e = x.extract(f, in, kind)
		} else {
			e = s.file(f, in.name)
		}
		after, statErr := f.Stat()
		closeErr := f.Close()
		if e != nil {
			return res, e
		}
		if statErr != nil || closeErr != nil || !unchanged(in.info, after) {
			return res, errChanged
		}
	}
	if dest != nil {
		if dest.Close() != nil {
			dest = nil
			return res, errOutput
		}
		dest = nil
		if root.Rename(outputDir+"/stage", outputDir+"/files") != nil {
			return res, errOutput
		}
	}
	complete = true
	return s.result, nil
}

func inventory(root *os.Root, patternInfo, baseInfo fs.FileInfo) ([]input, int, error) {
	var files []input
	entries, archives := 0, 0
	var walk func(string) error
	walk = func(dir string) error {
		f, e := root.Open(dir)
		if e != nil {
			return errInput
		}
		// Unlike WalkDir/ReadDir(-1), never allocate an unbounded directory listing.
		children, e := f.ReadDir(maxEntries + 1 - entries)
		ce := f.Close()
		if (e != nil && e != io.EOF) || ce != nil {
			return errInput
		}
		entries += len(children)
		if entries > maxEntries {
			return errLimit
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			name := child.Name()
			if dir != "." {
				name = dir + "/" + name
			}
			if len(name) > maxPath {
				return errLimit
			}
			if !safePath(name) {
				return errInput
			}
			info, e := root.Lstat(name)
			if e != nil {
				return errInput
			}
			if info.IsDir() {
				if e := walk(name); e != nil {
					return e
				}
				continue
			}
			if !info.Mode().IsRegular() {
				return errInput
			}
			if os.SameFile(info, patternInfo) || (baseInfo != nil && os.SameFile(info, baseInfo)) {
				continue
			}
			if info.Size() > maxFile {
				return errLimit
			}
			files = append(files, input{name, info})
			if archiveKind(name) != "" {
				archives++
			}
			if archives > maxArchives {
				return errLimit
			}
		}
		return nil
	}
	if e := walk("."); e != nil {
		return nil, 0, e
	}
	return files, archives, nil
}

func unchanged(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime() == b.ModTime()
}

func openInput(root *os.Root, in input) (*os.File, error) {
	i, e := root.Lstat(in.name)
	if e != nil || !i.Mode().IsRegular() || !unchanged(in.info, i) {
		return nil, errChanged
	}
	f, e := root.Open(in.name)
	if e != nil {
		return nil, errInput
	}
	i, e = f.Stat()
	if e != nil || !i.Mode().IsRegular() || !unchanged(in.info, i) {
		f.Close()
		return nil, errChanged
	}
	return f, nil
}

func (s *scanner) match(b []byte) bool {
	for _, p := range s.patterns {
		if p.Match(b) {
			return true
		}
	}
	return false
}

func (s *scanner) file(r io.Reader, name string) error {
	data, e := io.ReadAll(io.LimitReader(r, maxFile+1))
	if e != nil {
		return errInput
	}
	if len(data) > maxFile || s.bytes+int64(len(data)) > maxTotal {
		return errLimit
	}
	s.bytes += int64(len(data))
	c := &s.result.New
	if s.known[name] {
		c = &s.result.Known
	}
	c.Files++
	if s.match([]byte(name)) {
		c.PathHits++
	}
	// Binary files remain in files/pathhits, but have no content hits.
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return nil
	}
	hits := 0
	if strings.HasSuffix(name, ".patch") || strings.HasSuffix(name, ".diff") {
		hits, e = s.patch(data)
		if e != nil {
			return e
		}
	} else {
		e = eachLine(data, func(line []byte) error {
			if s.match(line) {
				hits++
			}
			return nil
		})
		if e != nil {
			return e
		}
	}
	c.HitLines += hits
	if hits != 0 {
		c.HitFiles++
	}
	return nil
}

var hunk = regexp.MustCompilePOSIX(`^@@ -[0-9]+(,([0-9]+))? \+[0-9]+(,([0-9]+))? @@( .*)?$`)

func eachLine(data []byte, visit func([]byte) error) error {
	for len(data) != 0 {
		line, rest, _ := bytes.Cut(data, []byte{'\n'})
		if len(line) > maxLine {
			return errLimit
		}
		if e := visit(line); e != nil {
			return e
		}
		data = rest
	}
	return nil
}

func (s *scanner) patch(data []byte) (int, error) {
	old, added, hits := 0, 0, 0
	e := eachLine(data, func(line []byte) error {
		if old != 0 || added != 0 {
			if bytes.Equal(line, []byte(`\ No newline at end of file`)) {
				return nil
			}
			if len(line) == 0 {
				return errPatch
			}
			switch line[0] {
			case ' ':
				if old == 0 || added == 0 {
					return errPatch
				}
				old--
				added--
			case '-':
				if old == 0 {
					return errPatch
				}
				old--
			case '+':
				if added == 0 {
					return errPatch
				}
				added--
				if s.match(line[1:]) {
					hits++
				}
			default:
				return errPatch
			}
			return nil
		}
		if !bytes.HasPrefix(line, []byte("@@")) {
			return nil
		}
		parts := hunk.FindSubmatch(line)
		if parts == nil {
			return errPatch
		}
		old, added = 1, 1
		if parts[1] != nil {
			n, e := strconv.Atoi(string(parts[2]))
			if e != nil || n > maxTotal {
				return errPatch
			}
			old = n
		}
		if parts[3] != nil {
			n, e := strconv.Atoi(string(parts[4]))
			if e != nil || n > maxTotal {
				return errPatch
			}
			added = n
		}
		return nil
	})
	if e != nil {
		return 0, e
	}
	if old != 0 || added != 0 {
		return 0, errPatch
	}
	return hits, nil
}

func archiveKind(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".tar.gz"), strings.HasSuffix(n, ".tgz"):
		return "tgz"
	case strings.HasSuffix(n, ".tar"):
		return "tar"
	case strings.HasSuffix(n, ".zip"):
		return "zip"
	}
	return ""
}

func safePath(name string) bool {
	if name == "" || len(name) > maxPath || !utf8.ValidString(name) || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 128 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

type extractor struct {
	dest        *os.Root
	scan        *scanner
	entries     int
	bytes       int64
	streamBytes int64
}

func (x *extractor) member(archive, name string, mode fs.FileMode, size int64, r io.Reader) error {
	x.entries++
	if x.entries > maxEntries {
		return errLimit
	}
	if mode.IsDir() {
		name = strings.TrimSuffix(name, "/")
	}
	logical := archive + "/" + name
	if !safePath(logical) || (mode.Type() != 0 && mode.Type() != os.ModeDir) {
		return errArchive
	}
	if mode.IsDir() {
		if size != 0 {
			return errArchive
		}
		data, e := io.ReadAll(io.LimitReader(r, 1))
		if e != nil || len(data) != 0 {
			return errArchive
		}
		if x.dest.MkdirAll(logical, 0700) != nil {
			return errArchive
		}
		return nil
	}
	if archiveKind(name) != "" {
		return errArchive
	}
	if size < 0 || size > maxFile || size > maxTotal-x.bytes {
		return errLimit
	}
	data, e := io.ReadAll(io.LimitReader(r, size+1))
	if e != nil || int64(len(data)) != size {
		return errArchive
	}
	// Refuse nested containers even when their filename hides the type.
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")) || bytes.HasPrefix(data, []byte("PK\x07\x08")) || bytes.HasPrefix(data, []byte{0x1f, 0x8b}) || (len(data) >= 262 && string(data[257:262]) == "ustar") {
		return errArchive
	}
	x.bytes += size
	if x.dest.MkdirAll(path.Dir(logical), 0700) != nil {
		return errArchive
	}
	f, e := x.dest.OpenFile(logical, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errArchive
	}
	_, e = f.Write(data)
	ce := f.Close()
	if e != nil || ce != nil {
		return errOutput
	}
	return x.scan.file(bytes.NewReader(data), logical)
}

func (x *extractor) extract(f *os.File, in input, kind string) error {
	if kind == "zip" {
		zr, e := zip.NewReader(f, in.info.Size())
		if e != nil {
			return errArchive
		}
		if len(zr.File) > maxEntries-x.entries {
			return errLimit
		}
		for _, z := range zr.File {
			if z.UncompressedSize64 > maxFile {
				return errLimit
			}
			r, e := z.Open()
			if e != nil {
				return errArchive
			}
			e = x.member(in.name, z.Name, z.Mode(), int64(z.UncompressedSize64), r)
			ce := r.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return errArchive
			}
		}
		return nil
	}
	var reader io.Reader = f
	var gz *gzip.Reader
	if kind == "tgz" {
		var e error
		gz, e = gzip.NewReader(f)
		if e != nil {
			return errArchive
		}
		defer gz.Close()
		reader = gz
	}
	// Bound the entire tar stream, including padding and metadata, before tar parses it.
	allowance := maxTotal - x.streamBytes
	limited := &io.LimitedReader{R: reader, N: allowance + 1}
	tr := tar.NewReader(limited)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if limited.N <= 0 {
			return errLimit
		}
		if e != nil {
			return errArchive
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir {
			return errArchive
		}
		if e = x.member(in.name, h.Name, h.FileInfo().Mode(), h.Size, tr); e != nil {
			return e
		}
	}
	// Drain bounded trailing data: verifies gzip CRC/truncation and refuses concatenated payloads.
	trailing, e := io.ReadAll(io.LimitReader(limited, (1<<20)+1))
	if limited.N <= 0 {
		return errLimit
	}
	if e != nil {
		return errArchive
	}
	if len(trailing) > 1<<20 || len(bytes.Trim(trailing, "\x00")) != 0 {
		return errArchive
	}
	x.streamBytes += allowance + 1 - limited.N
	return nil
}
