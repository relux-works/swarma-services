// pktscan scans synthetic or operator-provided packets without disclosing matches.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/relux-works/swarma-services/pktscan/internal/secretclass"
	"github.com/relux-works/swarma-services/pktscan/packetwalk"
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
	errArgs     = errors.New("invalid arguments")
	errInput    = errors.New("input refused")
	errPattern  = errors.New("patterns refused")
	errBase     = errors.New("known-base list refused")
	errArchive  = errors.New("archive refused")
	errLimit    = errors.New("limit exceeded")
	errOutput   = errors.New("output refused")
	errChanged  = errors.New("input changed")
	errPatch    = errors.New("patch refused")
	errSecret   = errors.New("blocking secret class refused")
	errClassify = errors.New("secret classification incomplete")
	errBundle   = errors.New("bundle refused")
)

type counts struct {
	Files    int `json:"files"`
	HitFiles int `json:"hitfiles"`
	HitLines int `json:"hitlines"`
	PathHits int `json:"pathhits"`
}

type result struct {
	New              counts             `json:"new"`
	Known            counts             `json:"known_base"`
	Secrets          secretclass.Counts `json:"blocking"`
	Objects          counts             `json:"git_objects"`
	Metadata         counts             `json:"metadata"`
	Traversal        packetwalk.Report  `json:"traversal"`
	BaselineExcluded bool               `json:"baseline_content_excluded"`
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
	bundlePath := flags.String("bundle-path", "", "")
	current := flags.String("current", "", "")
	base := flags.String("base", "", "")
	baseBundle := flags.String("base-bundle", "", "")
	gitPath := flags.String("git", "/usr/bin/git", "")
	limits := packetwalk.DefaultLimits()
	flags.IntVar(&limits.Depth, "max-depth", limits.Depth, "")
	flags.IntVar(&limits.Files, "max-files", limits.Files, "")
	flags.IntVar(&limits.Entries, "max-entries", limits.Entries, "")
	flags.IntVar(&limits.Containers, "max-containers", limits.Containers, "")
	flags.IntVar(&limits.Commands, "max-commands", limits.Commands, "")
	flags.Int64Var(&limits.FileBytes, "max-file-bytes", limits.FileBytes, "")
	flags.Int64Var(&limits.CompressedBytes, "max-compressed-bytes", limits.CompressedBytes, "")
	flags.Int64Var(&limits.ExpandedBytes, "max-expanded-bytes", limits.ExpandedBytes, "")
	flags.Int64Var(&limits.StreamBytes, "max-stream-bytes", limits.StreamBytes, "")
	flags.Int64Var(&limits.CommandBytes, "max-command-bytes", limits.CommandBytes, "")
	flags.DurationVar(&limits.Duration, "timeout", limits.Duration, "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *patternName == "" {
		_, _ = io.WriteString(diagnostic, "pktscan: invalid arguments\n")
		return 2
	}
	if !limits.Valid() || limits.FileBytes > maxFile ||
		(*bundlePath == "") != (*current == "") || (*base == "") != (*baseBundle == "") ||
		(*base != "" && *current == "") || (*bundlePath != "" && !safePath(*bundlePath)) {
		_, _ = io.WriteString(diagnostic, "pktscan: invalid arguments\n")
		return 2
	}
	cfg := scanOptions{limits: limits, bundlePath: *bundlePath, current: *current, base: *base, baseBundle: *baseBundle, gitPath: *gitPath}
	r, err := scanWithOptions(args[0], *patternName, *baseName, cfg)
	if err != nil {
		// Explicit allowlist also protects this boundary from future wrapped errors.
		message := "operation failed"
		switch err {
		case errArgs, errInput, errPattern, errBase, errArchive, errLimit, errOutput, errChanged, errPatch, errSecret, errClassify, errBundle:
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

type scanOptions struct {
	limits                                         packetwalk.Limits
	bundlePath, current, base, baseBundle, gitPath string
}

func scan(dir, patternName, baseName string) (result, error) {
	return scanWithOptions(dir, patternName, baseName, scanOptions{limits: packetwalk.DefaultLimits()})
}

func classify(name string, data []byte) error {
	format := secretclass.Auto
	switch strings.ToLower(path.Ext(name)) {
	case ".json":
		format = secretclass.JSON
	case ".jsonl", ".ndjson":
		return errClassify
	}
	c, e := secretclass.Classify(data, format)
	if e != nil {
		if e == secretclass.ErrLimit {
			return errLimit
		}
		return errClassify
	}
	if c.Blocking() {
		return errSecret
	}
	return nil
}

func classifyPath(name string) error {
	// Paths are text, not serialized JSON; Auto can conservatively refuse a
	// JSON-looking path. Never turn that refusal into a clean result.
	return classify("", []byte(name))
}

func scanWithOptions(dir, patternName, baseName string, cfg scanOptions) (res result, err error) {
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
	files, _, e := inventory(root, patternInfo, baseInfo)
	if e != nil {
		return res, e
	}
	original := make(map[string]bool)
	for _, f := range files {
		original[f.name] = true
	}
	tmp := os.Getenv("TMPDIR")
	if !filepath.IsAbs(tmp) {
		return res, errOutput
	}
	ti, e := os.Lstat(tmp)
	if e != nil || !ti.IsDir() || ti.Mode().Perm() != 0700 {
		return res, errOutput
	}
	realDir, de := filepath.EvalSymlinks(dir)
	realTmp, te := filepath.EvalSymlinks(tmp)
	realDir, ae := filepath.Abs(realDir)
	rel, re := filepath.Rel(realDir, realTmp)
	if de != nil || te != nil || ae != nil || re != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return res, errOutput
	}
	stage, e := os.MkdirTemp(tmp, "pktscan-stage-")
	if e != nil {
		return res, errOutput
	}
	ownedOutput := false
	defer func() {
		if os.RemoveAll(stage) != nil {
			if ownedOutput {
				_ = root.RemoveAll(outputDir)
			}
			res = result{}
			err = errOutput
		}
	}()
	stageRoot, e := os.OpenRoot(stage)
	if e != nil {
		return res, errOutput
	}
	defer stageRoot.Close()
	extracted := func(name string) bool {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if original[parent] {
				return true
			}
		}
		return false
	}
	s := &scanner{patterns: compiled, known: known}
	var visitorErr error
	fail := func(e error) error {
		if e != nil {
			visitorErr = e
		}
		return e
	}
	opts := packetwalk.Options{Limits: cfg.limits, Exclude: []fs.FileInfo{patternInfo, baseInfo}}
	opts.Path = func(ctx context.Context, name string, directory bool, origin packetwalk.Origin) error {
		if e := classifyPath(name); e != nil {
			return fail(e)
		}
		if directory && origin != packetwalk.GitSourcePath && extracted(name) && stageRoot.MkdirAll(name, 0700) != nil {
			return fail(errOutput)
		}
		return ctx.Err()
	}
	opts.ValidateControl = func(ctx context.Context, f packetwalk.File) error {
		info, e := root.Lstat(f.LogicalPath)
		if e != nil {
			return fail(errInput)
		}
		if baseInfo != nil && os.SameFile(info, baseInfo) {
			paths, e := knownPaths(f.Bytes)
			if e != nil {
				return fail(errBase)
			}
			for p := range paths {
				if e = classifyPath(p); e != nil {
					return fail(e)
				}
			}
			return ctx.Err()
		}
		return fail(classify("", f.Bytes))
	}
	resolvedBundles := 0
	if cfg.current != "" {
		var baseline []byte
		if cfg.baseBundle != "" {
			// The baseline is trusted external scope evidence, never packet data.
			baseline, _, e = readConfig(cfg.baseBundle, maxFile)
			if e != nil {
				return res, errBundle
			}
			bi, be := os.Stat(cfg.baseBundle)
			if be != nil {
				return res, errBundle
			}
			for _, f := range files {
				if os.SameFile(bi, f.info) {
					return res, errBundle
				}
			}
			if os.SameFile(bi, patternInfo) || baseInfo != nil && os.SameFile(bi, baseInfo) {
				return res, errBundle
			}
		}
		opts.Git = &packetwalk.BundleOptions{GitPath: cfg.gitPath, TempDir: tmp,
			Resolve: func(ctx context.Context, name string) (packetwalk.BundleScope, error) {
				if name != cfg.bundlePath {
					return packetwalk.BundleScope{}, errBundle
				}
				resolvedBundles++
				return packetwalk.BundleScope{Current: cfg.current, Base: cfg.base, BaseBundle: baseline}, ctx.Err()
			}}
	}
	report, e := packetwalk.Walk(context.Background(), root, opts, func(ctx context.Context, f packetwalk.File) error {
		className := f.LogicalPath
		if f.FormatHint == "stream" {
			return fail(errClassify)
		}
		if f.FormatHint == "json" {
			className = "object.json"
		}
		if e := classify(className, f.Bytes); e != nil {
			return fail(e)
		}
		if e := classifyPath(f.LogicalPath); e != nil {
			return fail(e)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if f.Origin == packetwalk.ArchiveMetadata {
			return fail(s.full(f.Bytes, f.LogicalPath, &s.result.Metadata))
		}
		if f.Origin == packetwalk.GitMetadata || f.Origin == packetwalk.GitBlobContent {
			bucket := &s.result.Metadata
			if f.Origin == packetwalk.GitBlobContent {
				bucket = &s.result.Objects
			}
			if e := s.full(f.Bytes, f.LogicalPath, bucket); e != nil {
				return fail(e)
			}
		} else if e := s.file(bytes.NewReader(f.Bytes), f.LogicalPath); e != nil {
			return fail(e)
		}
		if extracted(f.LogicalPath) {
			if stageRoot.MkdirAll(path.Dir(f.LogicalPath), 0700) != nil {
				return fail(errOutput)
			}
			out, e := stageRoot.OpenFile(f.LogicalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return fail(errOutput)
			}
			_, e = out.Write(f.Bytes)
			ce := out.Close()
			if e != nil || ce != nil {
				return fail(errOutput)
			}
		}
		return nil
	})
	if e != nil {
		if visitorErr != nil {
			return res, visitorErr
		}
		switch e {
		case packetwalk.ErrLimit:
			return res, errLimit
		case packetwalk.ErrArchive:
			return res, errArchive
		case packetwalk.ErrBundle:
			return res, errBundle
		case packetwalk.ErrChanged:
			return res, errChanged
		case packetwalk.ErrCleanup:
			return res, errOutput
		default:
			return res, errInput
		}
	}
	if cfg.current != "" && resolvedBundles != 1 {
		return res, errBundle
	}
	if report.Containers != 0 {
		if root.Mkdir(outputDir, 0700) != nil {
			return res, errOutput
		}
		ownedOutput = true
		complete := false
		defer func() {
			if !complete && root.RemoveAll(outputDir) != nil {
				err = errOutput
			}
		}()
		if root.Mkdir(outputDir+"/stage", 0700) != nil {
			return res, errOutput
		}
		dest, e := root.OpenRoot(outputDir + "/stage")
		if e != nil {
			return res, errOutput
		}
		e = fs.WalkDir(stageRoot.FS(), ".", func(n string, d fs.DirEntry, er error) error {
			if er != nil {
				return errOutput
			}
			if n == "." {
				return nil
			}
			if d.IsDir() {
				if dest.MkdirAll(n, 0700) != nil {
					return errOutput
				}
				return nil
			}
			in, er := stageRoot.Open(n)
			if er != nil {
				return errOutput
			}
			out, er := dest.OpenFile(n, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if er != nil {
				in.Close()
				return errOutput
			}
			_, er = io.Copy(out, in)
			ce := out.Close()
			ie := in.Close()
			if er != nil || ce != nil || ie != nil {
				return errOutput
			}
			return nil
		})
		ce := dest.Close()
		if e != nil || ce != nil {
			return res, errOutput
		}
		if root.Rename(outputDir+"/stage", outputDir+"/files") != nil {
			return res, errOutput
		}
		complete = true
	}
	s.result.BaselineExcluded = cfg.base != ""
	s.result.Traversal = report
	return s.result, nil
}

func (s *scanner) full(data []byte, name string, c *counts) error {
	c.Files++
	if s.match([]byte(name)) {
		c.PathHits++
	}
	hits := 0
	if e := eachLine(data, func(line []byte) error {
		if s.match(line) {
			hits++
		}
		return nil
	}); e != nil {
		return e
	}
	c.HitLines += hits
	if hits != 0 {
		c.HitFiles++
	}
	return nil
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
	// Defensive refusal: the walker already rejects binary leaves.
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return errClassify
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
		// Binary diff records contain no supported text to scan. Check only
		// outside a live hunk: its prefixed content is ordinary added/old text.
		metadata := bytes.TrimSuffix(line, []byte{'\r'})
		if bytes.Equal(metadata, []byte("GIT binary patch")) ||
			bytes.HasPrefix(metadata, []byte("Binary files ")) && bytes.HasSuffix(metadata, []byte(" differ")) {
			return errPatch
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
