// Package gate checks immutable Git candidates before explicit publication.
package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

const (
	MaxControl     = 64 << 10
	MaxPatterns    = 256
	MaxRecord      = 1 << 20
	MaxBlob        = 4 << 20
	MaxCommits     = 64
	MaxPaths       = 1024
	MaxCommands    = 4096
	MaxCommand     = 16 << 20
	MaxOutput      = 64 << 20
	MaxObjects     = 64 << 20
	MaxObjectFiles = 4096
)

var refused = errors.New("refused")
var poolLimitFailure = errors.New("object pool limit")
var unsupportedMergeFailure = errors.New("unsupported merge")
var oidRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var principalRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}$`)
var repoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
var refRE = regexp.MustCompile(`^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$`)

// Generic public hygiene rules only. Installation-specific names and identifier
// formats belong exclusively in the required caller-supplied private pattern file.
var hygiene = []*regexp.Regexp{
	regexp.MustCompile(`/(?:home|Users|root)/[^\s/]+`),
	regexp.MustCompile(`/run/user/[0-9]+/[^\s]+`),
	regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+local(?:$|[^a-z0-9_.-])`),
	regexp.MustCompile(`/var/` + `folders/[^\s/]+/[^\s/]+(?:/[^\s]*)?`),
	regexp.MustCompile(`/(?:private/)?tmp/[A-Za-z_][A-Za-z0-9_.-]*-[0-9]+(?:/[^\s]*|\b)`),
	regexp.MustCompile(`/tmp/` + `user/[0-9]+(?:/[^\s]*|\b)`),
	regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`),
	regexp.MustCompile(`[@!#][A-Za-z0-9_.=/-]+:[A-Za-z0-9.-]+`),
	regexp.MustCompile(`\$[A-Za-z0-9_-]{24,}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82,}`),
}
var ipv6Candidate = regexp.MustCompile(`[A-Za-z0-9_:.%+-]*:[A-Za-z0-9_:.%+-]*`)

type policy struct {
	privateRegex []*regexp.Regexp
	exceptions   map[string]bool
	ctx          context.Context
}

func text(b []byte) bool { return utf8.Valid(b) && !bytes.ContainsRune(b, 0) }

// Controls must be stable, regular, non-symlink absolute files. Private pattern
// values are never put into errors. The caller supplies quiescent trusted controls.
func safeControl(info os.FileInfo, private bool) bool {
	return ownedByEffectiveUID(info) && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 && (!private || info.Mode().Perm()&0077 == 0)
}

func privateDir(name string) bool {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return false
	}
	info, e := os.Lstat(name)
	return e == nil && info.IsDir() && info.Mode().Perm() == 0700 && ownedByEffectiveUID(info)
}

func readControl(name string, private bool) ([]byte, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, refused
	}
	i, e := os.Lstat(name)
	if e != nil || !safeControl(i, private) || i.Size() > MaxControl {
		return nil, refused
	}
	f, e := os.Open(name)
	if e != nil {
		return nil, refused
	}
	defer f.Close()
	j, e := f.Stat()
	if e != nil || !os.SameFile(i, j) || !safeControl(j, private) {
		return nil, refused
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxControl+1))
	k, se := f.Stat()
	if e != nil || se != nil || len(b) > MaxControl || !os.SameFile(i, k) || !safeControl(k, private) || i.Size() != k.Size() || !i.ModTime().Equal(k.ModTime()) || !text(b) {
		return nil, refused
	}
	return b, nil
}
func lines(b []byte) ([]string, error) {
	if len(b) == 0 || !text(b) || bytes.ContainsRune(b, '\r') {
		return nil, refused
	}
	s := strings.TrimSuffix(string(b), "\n")
	l := strings.Split(s, "\n")
	if len(l) > MaxPatterns {
		return nil, refused
	}
	for _, v := range l {
		if len(v) == 0 || len(v) > 1024 {
			return nil, refused
		}
	}
	return l, nil
}
func loadPolicy(patterns, exceptions string) (policy, error) {
	p := policy{exceptions: map[string]bool{}}
	b, e := readControl(patterns, true)
	if e != nil {
		return p, refused
	}
	l, e := lines(b)
	if e != nil {
		return p, refused
	}
	cost := 0
	for _, v := range l {
		if len(v) < 3 || v[1] != ':' {
			return p, refused
		}
		expression := v[2:]
		switch v[0] {
		case 'L':
			expression = regexp.QuoteMeta(expression)
		case 'R':
		default:
			return p, refused
		}
		tree, e := syntax.Parse(expression, syntax.Perl)
		if e != nil {
			return p, refused
		}
		size := regexpCost(tree)
		if size > 16384-cost {
			return p, refused
		}
		prog, e := syntax.Compile(tree.Simplify())
		if e != nil {
			return p, refused
		}
		cost += len(prog.Inst)
		if cost > 16384 {
			return p, refused
		}
		r, e := regexp.Compile(expression)
		if e != nil || r.MatchString("") {
			return p, refused
		}
		p.privateRegex = append(p.privateRegex, r)
	}
	if exceptions != "" {
		b, e = readControl(exceptions, false)
		if e != nil {
			return p, refused
		}
		l, e = lines(b)
		if e != nil {
			return p, refused
		}
		for _, v := range l {
			a := strings.Split(v, "\t")
			if len(a) != 2 || (a[0] != "line" && a[0] != "path" && a[0] != "message" && a[0] != "header") || len(a[1]) != 64 {
				return p, refused
			}
			h, e := hex.DecodeString(a[1])
			if e != nil || hex.EncodeToString(h) != a[1] || p.exceptions[v] {
				return p, refused
			}
			p.exceptions[v] = true
		}
	}
	return p, nil
}
func (p policy) match(kind string, b []byte, r *Report) error {
	if len(b) > MaxRecord || !text(b) {
		return refused
	}
	for _, x := range p.privateRegex {
		if p.ctx != nil && p.ctx.Err() != nil {
			return refused
		}
		if x.Match(b) {
			r.PrivateHits++
			break
		}
	}
	hit := false
	for _, x := range hygiene {
		if x.Match(b) {
			hit = true
			break
		}
	}
	// Validate colon-shaped candidates so ordinary timestamps are not treated
	// as addresses. The candidate count is itself a finite record-level bound.
	addresses := ipv6Candidate.FindAllIndex(b, 1025)
	if len(addresses) > 1024 {
		return refused
	}
	for _, span := range addresses {
		value := string(b[span[0]:span[1]])
		// A bare :: is also a language operator. Admit that operator inside
		// expressions; the unspecified address remains detected alone/bracketed.
		if value == "::" && strings.TrimSpace(string(b)) != "::" && !(span[0] > 0 && span[1] < len(b) && b[span[0]-1] == '[' && b[span[1]] == ']') {
			continue
		}
		if a, e := netip.ParseAddr(value); e == nil && a.Is6() {
			hit = true
			break
		}
	}
	if hit {
		h := sha256.Sum256(b)
		if p.exceptions[kind+"\t"+hex.EncodeToString(h[:])] {
			r.HygieneExceptions++
		} else {
			r.HygieneHits++
		}
	}
	return nil
}

func allowedSigners(name, principal string) ([]byte, error) {
	if !principalRE.MatchString(principal) {
		return nil, refused
	}
	b, e := readControl(name, false)
	if e != nil {
		return nil, refused
	}
	l, e := lines(b)
	if e != nil {
		return nil, refused
	}
	// Only an exact principal, no wildcard, comma list, options or certificate.
	// Native OpenSSH remains responsible for decoding and verifying public keys.
	for _, v := range l {
		a := strings.Fields(v)
		if len(a) != 3 || strings.Join(a, " ") != v || a[0] != principal || a[1] != "ssh-ed25519" || len(a[2]) > 128 {
			return nil, refused
		}
	}
	return b, nil
}

// Bound repeat expansion before Simplify allocates its expanded program.
func regexpCost(r *syntax.Regexp) int {
	n := 1
	for _, s := range r.Sub {
		n += regexpCost(s)
		if n > 16384 {
			return 16385
		}
	}
	if r.Op == syntax.OpRepeat {
		copies := r.Max
		if copies < 0 {
			copies = r.Min + 1
		}
		if copies > 0 && n > 16384/copies {
			return 16385
		}
		n *= copies
	}
	if r.Op == syntax.OpLiteral {
		n += len(r.Rune)
	}
	return n
}
