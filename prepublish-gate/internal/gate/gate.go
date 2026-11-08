package gate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Report struct {
	Completed             int `json:"completed"`
	Commits               int `json:"commits"`
	Signatures            int `json:"signatures"`
	Paths                 int `json:"paths"`
	AddedLines            int `json:"added_lines"`
	Messages              int `json:"messages"`
	Headers               int `json:"headers"`
	PrivateHits           int `json:"private_hits"`
	HygieneHits           int `json:"hygiene_hits"`
	HygieneExceptions     int `json:"hygiene_exceptions"`
	PublishedRefs         int `json:"published_refs"`
	ArgumentErrors        int `json:"argument_errors"`
	ScanErrors            int `json:"scan_errors"`
	HomeAdmissionErrors   int `json:"home_admission_errors"`
	TmpdirAdmissionErrors int `json:"tmpdir_admission_errors"`
	SignatureErrors       int `json:"signature_errors"`
	LeaseErrors           int `json:"lease_errors"`
	PublicationErrors     int `json:"publication_errors"`
	CleanupErrors         int `json:"cleanup_errors"`
	Commands              int `json:"commands"`
	CommandBytes          int `json:"command_bytes"`
}

type updates []string

func (u *updates) String() string { return "" }
func (u *updates) Set(s string) error {
	*u = append(*u, s)
	if len(*u) > 8 {
		return refused
	}
	return nil
}

type Config struct {
	Objects, Base, Candidate, Patterns, Exceptions, Signers, Principal string
	Remote, Repository, GHConfig, DefaultRef                           string
	Updates                                                            []string
	Publish, LocalDestination                                          bool
}

// Run is the sole CLI boundary: every emitted value is a count, even on error.
// Neither flag parsing nor child diagnostics can disclose caller bytes.
func Run(args []string, out io.Writer) (code int) {
	r := Report{}
	defer func() {
		if recover() != nil {
			r = Report{ScanErrors: 1}
			code = 1
		}
		if json.NewEncoder(out).Encode(r) != nil {
			code = 1
		}
	}()
	if len(args) == 0 || (args[0] != "check" && args[0] != "publish") {
		r.ArgumentErrors = 1
		return 2
	}
	f := flag.NewFlagSet("gate", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	c := Config{Publish: args[0] == "publish"}
	var u updates
	f.StringVar(&c.Objects, "objects", "", "")
	f.StringVar(&c.Base, "base", "", "")
	f.StringVar(&c.Candidate, "candidate", "", "")
	f.StringVar(&c.Patterns, "patterns", "", "")
	f.StringVar(&c.Exceptions, "exceptions", "", "")
	f.StringVar(&c.Signers, "allowed-signers", "", "")
	f.StringVar(&c.Principal, "principal", "", "")
	f.StringVar(&c.Remote, "remote", "", "")
	f.StringVar(&c.DefaultRef, "default-ref", "", "")
	f.StringVar(&c.Repository, "repository", "", "")
	f.Var(&u, "update", "")
	f.StringVar(&c.GHConfig, "gh-config-dir", "", "")
	f.BoolVar(&c.LocalDestination, "local-test-destination", false, "")
	confirm := f.Bool("execute-publication", false, "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || c.Publish != *confirm {
		r.ArgumentErrors = 1
		return 2
	}
	c.Updates = u
	r, code = Execute(context.Background(), c)
	return code
}

// Execute checks the complete bounded candidate and publishes only when the
// caller explicitly requests mutation. A fresh private Git repository pins all
// checked bytes; no mutable source ref is ever used by scan or push.
func Execute(ctx context.Context, c Config) (r Report, code int) {
	code = 1
	if !oidRE.MatchString(c.Base) || !oidRE.MatchString(c.Candidate) || c.Base == c.Candidate || c.Objects == "" || c.Patterns == "" || c.Signers == "" || !principalRE.MatchString(c.Principal) {
		r.ArgumentErrors = 1
		code = 2
		return
	}
	plan, e := validatePlan(c)
	if e != nil {
		r.ArgumentErrors = 1
		code = 2
		return
	}
	if c.GHConfig != "" && (!c.Publish || c.LocalDestination) {
		r.ArgumentErrors = 1
		code = 2
		return
	}
	if c.Publish && !c.LocalDestination {
		if !privateDir(c.GHConfig) {
			r.ArgumentErrors = 1
			code = 2
			return
		}
	}
	home, tmp := os.Getenv("HOME"), os.Getenv("TMPDIR")
	if !privateDir(home) {
		r.ScanErrors = 1
		r.HomeAdmissionErrors = 1
		return
	}
	if !privateDir(tmp) {
		r.ScanErrors = 1
		r.TmpdirAdmissionErrors = 1
		return
	}
	p, e := loadPolicy(c.Patterns, c.Exceptions)
	if e != nil {
		r.ScanErrors = 1
		return
	}
	signers, e := allowedSigners(c.Signers, c.Principal)
	if e != nil {
		r.SignatureErrors = 1
		return
	}
	state, e := os.MkdirTemp(tmp, "gate-")
	if e != nil {
		r.ScanErrors = 1
		return
	}
	defer func() {
		if os.RemoveAll(state) != nil {
			r.CleanupErrors = 1
			code = 1
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	p.ctx = ctx
	g := &runner{ctx: ctx, dir: filepath.Join(state, "repo.git"), home: home, tmp: state}
	defer func() { r.Commands = g.commands; r.CommandBytes = g.total }()
	if g.snapshot(c.Objects) != nil {
		r.ScanErrors = 1
		return
	}
	if g.inventory() != nil {
		r.ScanErrors = 1
		return
	}
	signerPath := filepath.Join(state, "allowed-signers")
	if os.WriteFile(signerPath, signers, 0600) != nil {
		r.SignatureErrors = 1
		return
	}
	// fsck rejects corrupt object IDs and incomplete closure, including baseline.
	// Ignore neither its exit code nor its bounded, redacted diagnostic stream.
	if _, e = g.git("fsck", "--strict", "--no-reflogs", "--no-dangling", c.Base, c.Candidate); e != nil {
		r.ScanErrors = 1
		return
	}
	commits, e := history(g, c.Base, c.Candidate)
	if e != nil {
		r.ScanErrors = 1
		return
	}
	for _, co := range commits {
		if _, e = g.git("-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen", "-c", "gpg.ssh.allowedSignersFile="+signerPath, "verify-commit", co.oid); e != nil {
			r.SignatureErrors = 1
			return
		}
		r.Signatures++
		for _, header := range co.headers {
			if e = p.match("header", header, &r); e != nil {
				r.ScanErrors = 1
				return
			}
			r.Headers++
		}
		if e = p.match("message", co.message, &r); e != nil {
			r.ScanErrors = 1
			return
		}
		r.Messages++
		if e = scanChange(g, p, co.parent, co.oid, &r); e != nil {
			r.ScanErrors = 1
			return
		}
		r.Commits++
	}
	r.Completed = 1
	if r.PrivateHits > 0 || r.HygieneHits > 0 {
		return
	}
	if !c.Publish {
		code = 0
		return
	}
	if e = publish(g, c, plan); e != nil {
		// Read-only preflight failures are distinguished from attempted push failures.
		if e == leaseFailure {
			r.LeaseErrors = 1
		} else {
			r.PublicationErrors = 1
		}
		return
	}
	r.PublishedRefs = len(plan)
	code = 0
	return
}

type commit struct {
	oid, parent string
	message     []byte
	headers     [][]byte
}

func history(g *runner, base, candidate string) ([]commit, error) {
	// An intentionally finite MVP: a nonempty, single-parent chain from base.
	// Merges, roots and histories beyond the limit refuse rather than under-scan.
	var result []commit
	current := candidate
	for current != base {
		if len(result) >= MaxCommits {
			return nil, refused
		}
		raw, e := g.object("commit", current, MaxRecord)
		if e != nil || !text(raw) {
			return nil, refused
		}
		a := bytes.SplitN(raw, []byte("\n\n"), 2)
		if len(a) != 2 {
			return nil, refused
		}
		var parents []string
		var headers [][]byte
		signatures := 0
		records := strings.Split(string(a[0]), "\n")
		for i := 0; i < len(records); i++ {
			line := records[i]
			if strings.HasPrefix(line, " ") || line == "" {
				return nil, refused
			}
			if strings.HasPrefix(line, "gpgsig ") {
				if line != "gpgsig -----BEGIN SSH SIGNATURE-----" {
					return nil, refused
				}
				signatures++
				var armor strings.Builder
				ended := false
				for i++; i < len(records); i++ {
					line = records[i]
					if line == " -----END SSH SIGNATURE-----" {
						ended = true
						break
					}
					if !strings.HasPrefix(line, " ") || len(line) < 2 {
						return nil, refused
					}
					armor.WriteString(line[1:])
				}
				if !ended || armor.Len() == 0 {
					return nil, refused
				}
				if _, e := base64.StdEncoding.Strict().DecodeString(armor.String()); e != nil {
					return nil, refused
				}
				continue
			}
			if strings.HasPrefix(line, "parent ") {
				parents = append(parents, strings.TrimPrefix(line, "parent "))
			}
			if strings.HasPrefix(line, "encoding ") && line != "encoding UTF-8" {
				return nil, refused
			}
			record := line
			for i+1 < len(records) && strings.HasPrefix(records[i+1], " ") {
				i++
				record += "\n" + records[i]
			}
			headers = append(headers, []byte(record))
		}
		if len(parents) != 1 || !oidRE.MatchString(parents[0]) {
			return nil, refused
		}
		if signatures > 1 {
			return nil, refused
		}
		result = append(result, commit{oid: current, parent: parents[0], message: a[1], headers: headers})
		current = parents[0]
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result, nil
}

type change struct{ oldMode, newMode, oldOID, newOID, status, path string }

func scanChange(g *runner, p policy, old, now string, r *Report) error {
	raw, e := g.git("diff-tree", "--no-commit-id", "--raw", "--no-abbrev", "-r", "-z", "--no-renames", old, now, "--")
	if e != nil {
		return refused
	}
	records := bytes.Split(raw, []byte{0})
	if len(records) == 0 || len(records[len(records)-1]) != 0 {
		return refused
	}
	records = records[:len(records)-1]
	if len(records)%2 != 0 || r.Paths+len(records)/2 > MaxPaths {
		return refused
	}
	for i := 0; i < len(records); i += 2 {
		fields := strings.Fields(string(records[i]))
		if len(fields) != 5 || len(fields[0]) != 7 || fields[0][0] != ':' {
			return refused
		}
		c := change{fields[0][1:], fields[1], fields[2], fields[3], fields[4], string(records[i+1])}
		if len(c.path) == 0 || len(c.path) > 4096 || !text([]byte(c.path)) || !oidRE.MatchString(c.oldOID) || !oidRE.MatchString(c.newOID) {
			return refused
		}
		for _, mode := range []string{c.oldMode, c.newMode} {
			if mode != "000000" && mode != "100644" && mode != "100755" {
				return refused
			}
		}
		if c.status != "A" && c.status != "D" && c.status != "M" {
			return refused
		}
		if p.match("path", []byte(c.path), r) != nil {
			return refused
		}
		r.Paths++
		// Validate complete old/new blobs even for deletions and unchanged binary
		// regions. No binary-to-text heuristic or source .gitattributes is trusted.
		for _, o := range []string{c.oldOID, c.newOID} {
			if o == strings.Repeat("0", 40) {
				continue
			}
			b, e := g.object("blob", o, MaxBlob)
			if e != nil || !text(b) {
				return refused
			}
			for _, l := range bytes.Split(b, []byte{'\n'}) {
				if len(l) > MaxRecord {
					return refused
				}
			}
		}
		// Diff object IDs directly in the private repository. Default Myers/text
		// output is parsed strictly; attributes, external diff and textconv are off.
		zero := strings.Repeat("0", 40)
		var before, after string
		before, after = c.oldOID, c.newOID
		// Hash the canonical empty blob with native Git once when an endpoint is absent.
		if before == zero || after == zero {
			empty := filepath.Join(g.tmp, "empty")
			if os.WriteFile(empty, nil, 0600) != nil {
				return refused
			}
			o, e := g.git("hash-object", "-w", empty)
			if e != nil {
				return refused
			}
			emptyOID := strings.TrimSpace(string(o))
			if !oidRE.MatchString(emptyOID) {
				return refused
			}
			if before == zero {
				before = emptyOID
			}
			if after == zero {
				after = emptyOID
			}
		}
		patch, e := g.git("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--no-indent-heuristic", "--diff-algorithm=myers", "--unified=0", before, after)
		if e != nil || added(p, patch, r) != nil {
			return refused
		}
	}
	return nil
}

// hunk consumes both side counts: malformed/truncated patches never look clean.
func added(p policy, b []byte, r *Report) error {
	if !text(b) {
		return refused
	}
	if len(b) == 0 {
		return nil
	}
	if b[len(b)-1] != '\n' {
		return refused
	}
	var left, right int
	inHunk := false
	seen := false
	for _, line := range bytes.Split(b[:len(b)-1], []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("@@ ")) {
			if inHunk && (left != 0 || right != 0) {
				return refused
			}
			a := strings.Fields(string(line))
			if len(a) < 4 || a[0] != "@@" || a[3] != "@@" {
				return refused
			}
			var e error
			left, e = hunkCount(a[1], '-')
			if e != nil {
				return refused
			}
			right, e = hunkCount(a[2], '+')
			if e != nil {
				return refused
			}
			inHunk = true
			seen = true
			continue
		}
		if !inHunk {
			if bytes.HasPrefix(line, []byte("diff --git ")) || bytes.HasPrefix(line, []byte("index ")) || bytes.HasPrefix(line, []byte("--- ")) || bytes.HasPrefix(line, []byte("+++ ")) {
				continue
			}
			return refused
		}
		if bytes.Equal(line, []byte("\\ No newline at end of file")) {
			continue
		}
		if len(line) == 0 {
			return refused
		}
		switch line[0] {
		case '+':
			right--
			if right < 0 {
				return refused
			}
			if p.match("line", line[1:], r) != nil {
				return refused
			}
			r.AddedLines++
		case '-':
			left--
			if left < 0 {
				return refused
			}
		case ' ':
			left--
			right--
			if left < 0 || right < 0 {
				return refused
			}
		default:
			return refused
		}
	}
	if !seen || left != 0 || right != 0 {
		return refused
	}
	return nil
}
func hunkCount(s string, prefix byte) (int, error) {
	if len(s) < 2 || s[0] != prefix {
		return 0, refused
	}
	a := strings.Split(s[1:], ",")
	if len(a) > 2 {
		return 0, refused
	}
	start, e := strconv.Atoi(a[0])
	if e != nil || start < 0 {
		return 0, refused
	}
	if len(a) == 1 {
		return 1, nil
	}
	n, e := strconv.Atoi(a[1])
	if e != nil || n < 0 || n > MaxCommand {
		return 0, refused
	}
	return n, nil
}

type update struct{ ref, old string }

func validatePlan(c Config) ([]update, error) {
	if len(c.Updates) > 8 {
		return nil, refused
	}
	if c.Remote == "" && c.Repository == "" && len(c.Updates) == 0 && c.DefaultRef == "" && !c.Publish && !c.LocalDestination {
		return nil, nil
	}
	if len(c.Updates) == 0 || !validBranchRef(c.DefaultRef) {
		return nil, refused
	}
	if c.LocalDestination {
		if c.Repository != "local-test" || !filepath.IsAbs(c.Remote) || filepath.Clean(c.Remote) != c.Remote {
			return nil, refused
		}
		i, e := os.Lstat(c.Remote)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return nil, refused
		}
	} else {
		if !repoRE.MatchString(c.Repository) || strings.Contains(c.Repository, "..") || strings.HasSuffix(c.Repository, ".git") || c.Remote != "https://github.com/"+c.Repository+".git" {
			return nil, refused
		}
	}
	var plan []update
	seen := map[string]bool{}
	for _, v := range c.Updates {
		a := strings.Split(v, "=")
		if len(a) != 2 || !validBranchRef(a[0]) || seen[a[0]] {
			return nil, refused
		}
		if a[1] != "absent" && a[1] != c.Base {
			return nil, refused
		}
		seen[a[0]] = true
		plan = append(plan, update{a[0], a[1]})
	}
	sort.Slice(plan, func(i, j int) bool { return plan[i].ref < plan[j].ref })
	return plan, nil
}

func validBranchRef(ref string) bool {
	if !refRE.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.Contains(ref, "@{") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") {
		return false
	}
	for _, part := range strings.Split(ref, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func planRefs(plan []update) []string {
	refs := make([]string, 0, len(plan))
	for _, u := range plan {
		refs = append(refs, u.ref)
	}
	return refs
}

var leaseFailure = refused // internal sentinel; mutation errors use a distinct value
var pushFailure = io.ErrClosedPipe
var abbrevRE = regexp.MustCompile(`^[0-9a-f]{4,40}$`)

func publish(g *runner, c Config, plan []update) error {
	for _, ref := range append([]string{c.DefaultRef}, planRefs(plan)...) {
		if _, e := g.git("check-ref-format", ref); e != nil {
			return leaseFailure
		}
	}
	protocol := "https"
	if c.LocalDestination {
		protocol = "file"
	}
	// Read the exact endpoint once; ignore unrelated remote refs. Every requested
	// ref must be explicitly present with the expected OID, or explicitly absent.
	args := []string{"-c", "protocol." + protocol + ".allow=always", "ls-remote", "--refs", c.Remote, c.DefaultRef}
	for _, u := range plan {
		if u.ref != c.DefaultRef {
			args = append(args, u.ref)
		}
	}
	b, e := g.git(args...)
	if e != nil {
		return leaseFailure
	}
	found := map[string]string{}
	if len(b) > 0 {
		for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			a := strings.Split(line, "\t")
			if len(a) != 2 || !oidRE.MatchString(a[0]) || found[a[1]] != "" {
				return leaseFailure
			}
			requested := a[1] == c.DefaultRef
			for _, u := range plan {
				if u.ref == a[1] {
					requested = true
				}
			}
			if !requested {
				return leaseFailure
			}
			found[a[1]] = a[0]
		}
	}
	if found[c.DefaultRef] != c.Base {
		return leaseFailure
	}
	for _, u := range plan {
		expected := u.old
		if expected == "absent" {
			expected = ""
		}
		if found[u.ref] != expected {
			return leaseFailure
		}
	}
	// Even a single update requests atomic support. There is exactly one push:
	// no retry, fallback, default force, refspec expansion, or mutable source ref.
	args = []string{"-c", "protocol." + protocol + ".allow=always", "push", "--porcelain", "--atomic", "--no-verify", "--recurse-submodules=no"}
	if !c.LocalDestination {
		// Reuse the explicitly selected existing GitHub CLI client. No credentials
		// are read by this program, supplied as arguments, or emitted as output.
		g.authDir = c.GHConfig
		args = append([]string{"-c", "credential.helper=!/usr/bin/gh auth git-credential"}, args...)
	}
	for _, u := range plan {
		old := u.old
		if old == "absent" {
			old = ""
		}
		args = append(args, "--force-with-lease="+u.ref+":"+old)
	}
	args = append(args, c.Remote)
	for _, u := range plan {
		args = append(args, c.Candidate+":"+u.ref)
	}
	b, e = g.git(args...)
	if e != nil || pushResult(b, c, plan) != nil {
		return pushFailure
	}
	return nil
}

// Exit status alone cannot bind success to the requested refs. Require one
// non-forced success record per exact refspec and the final Done marker. A
// malformed/missing response is uncertain publication, never reported success.
func pushResult(b []byte, c Config, plan []update) error {
	lines := strings.Split(string(b), "\n")
	if len(lines) != len(plan)+3 || lines[0] != "To "+c.Remote || lines[len(lines)-2] != "Done" || lines[len(lines)-1] != "" {
		return refused
	}
	expected := map[string]string{}
	for _, u := range plan {
		expected[c.Candidate+":"+u.ref] = u.old
	}
	for _, line := range lines[1 : len(lines)-2] {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return refused
		}
		old, ok := expected[fields[1]]
		if !ok || (old == "absent" && (fields[0] != "*" || fields[2] != "[new branch]")) || (old != "absent" && (fields[0] != " " || !strings.Contains(fields[2], "..") || strings.Contains(fields[2], "..."))) {
			return refused
		}
		if old != "absent" {
			ids := strings.Split(fields[2], "..")
			if len(ids) != 2 || !abbrevRE.MatchString(ids[0]) || !abbrevRE.MatchString(ids[1]) || !strings.HasPrefix(old, ids[0]) || !strings.HasPrefix(c.Candidate, ids[1]) {
				return refused
			}
		}
		delete(expected, fields[1])
	}
	if len(expected) != 0 {
		return refused
	}
	return nil
}
