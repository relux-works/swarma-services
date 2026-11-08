package sourceauthority

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// originalGitHubReader is deliberately private and has no installation issuer.
// The composition owner must supply the SAME admitted phase used by the other
// provider legs, plus a qualified github.com connector. Neither is available
// through OriginalGitHubObjects today. A zero value refuses without I/O.
// It is not a standalone budget or a protected-source readiness assertion.
type originalGitHubReader struct {
	policy Policy
	phase  *acquisitionPhase
	busy   atomic.Bool
}

var _ OriginalGitHubObjects = (*originalGitHubReader)(nil)

func (r *originalGitHubReader) ReadOriginalGitHubObjects(ctx context.Context, q Query) (out GitHubOriginalObjects, err error) {
	if r == nil || r.phase == nil || r.phase.source == nil || r.phase.source.connector == nil {
		return out, unavailable("github_git_shared_phase_connector_missing")
	}
	p := r.phase
	if !r.busy.CompareAndSwap(false, true) {
		return out, unavailable("github_git_busy")
	}
	defer r.busy.Store(false)
	if ctx == nil || acquisitionExpired(ctx) || acquisitionExpired(p.ctx) {
		return out, unavailable("github_git_deadline")
	}
	d, _ := ctx.Deadline()
	pd, _ := p.ctx.Deadline()
	if d != pd || time.Until(d) > AuthorityBudget {
		return out, unavailable("github_git_shared_deadline")
	}
	policy := r.policy
	if !originalGitRepository(policy) || !validRequest(q.Request, policy) || (q.Phase != Prebuild && q.Phase != Presign) ||
		policy.Profile.CommitBytes <= 0 || policy.Profile.AncestryCommits <= 0 {
		return out, unavailable("github_git_binding")
	}
	// These are ceilings, never replacement installed defaults. The overall
	// inventory includes the target, so at most 255 path commits are returned.
	commitMax := int(min(int64(policy.Profile.CommitBytes), int64(acquisitionCommitMax), p.source.limits.commit))
	countMax := min(policy.Profile.AncestryCommits, 255) + 1
	if commitMax <= 0 || countMax <= 0 {
		return out, unavailable("github_git_profile")
	}
	// Fund fixed request/ref/parser scratch before constructing any protocol
	// request. This debits the existing phase, never a reader-local allowance.
	if err = p.originalGitCharge(128 << 10); err != nil {
		return out, err
	}
	defer func() {
		if err != nil || acquisitionExpired(ctx) || acquisitionExpired(p.ctx) {
			if err == nil {
				err = unavailable("github_git_canceled")
			}
			out = GitHubOriginalObjects{}
			p.mu.Lock()
			p.failed = true
			p.mu.Unlock()
		}
	}()
	// Request cancellation and the admitted phase both own the transport. Keep
	// the existing deadline and ledger. Join callbacks before the final material
	// cancellation check above runs, including when cancellation races return.
	transportCtx, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(p.ctx, func() { cancel(); close(joined) })
	defer func() {
		cancel()
		if !stop() {
			<-joined
		}
	}()
	advert, err := p.originalGitExchange(transportCtx, policy, nil, true)
	if err != nil {
		return out, err
	}
	if err = originalGitCapabilities(advert); err != nil {
		return out, err
	}
	refsRequest := originalGitRefsRequest(policy.DefaultBranch)
	refs, err := p.originalGitExchange(transportCtx, policy, refsRequest, false)
	if err != nil {
		return out, err
	}
	head, err := originalGitHead(refs, policy.DefaultBranch)
	if err != nil {
		return out, err
	}
	// No arbitrary want, URL, headers, command, shell or local Git invocation.
	request := originalGitPacket("command=fetch\n") + originalGitPacket("object-format=sha1\n") + "0001" +
		originalGitPacket("want "+head+"\n") + originalGitPacket("deepen "+strconv.Itoa(countMax)+"\n") +
		originalGitPacket("filter tree:0\n") + originalGitPacket("no-progress\n") + originalGitPacket("done\n") + "0000"
	wire, err := p.originalGitExchange(transportCtx, policy, []byte(request), false)
	if err != nil {
		return out, err
	}
	pack, err := originalGitPackSection(p, wire)
	if err != nil {
		return out, err
	}
	objects, err := originalGitUnpack(p, pack, commitMax, countMax)
	if err != nil {
		return out, err
	}
	target, ok := objects[q.Commit]
	if !ok {
		return out, unavailable("github_git_incomplete_history")
	}
	// A bounded DFS uses actual parent edges. Side branches need not be complete;
	// a complete path to the exact target must exist in the acquired inventory.
	if err = p.originalGitCharge(int64(countMax) * int64(countMax) * 32); err != nil {
		return out, err
	}
	path, ok := originalGitPath(objects, head, q.Commit, countMax)
	if !ok {
		return out, unavailable("github_git_broken_ancestry")
	}
	refEnd, err := p.originalGitExchange(transportCtx, policy, refsRequest, false)
	if err != nil {
		return out, err
	}
	end, err := originalGitHead(refEnd, policy.DefaultBranch)
	if err != nil || end != head {
		return out, unavailable("github_git_moved_ref")
	}
	if err = p.originalGitCharge(int64(len(path))*24 + 128); err != nil {
		return out, err
	}
	out = GitHubOriginalObjects{Repository: RepositoryRecord{policy.CanonicalRepository, policy.DefaultBranch, head}, Commit: target, LandingPath: make([][]byte, len(path))}
	for i, oid := range path {
		out.LandingPath[i] = objects[oid]
	}
	return out, nil
}

func originalGitRepository(p Policy) bool {
	parts := strings.Split(p.RepositoryName, "/")
	if len(parts) != 2 || p.CanonicalRepository != "https://github.com/"+p.RepositoryName || !lowerHex(p.SHA256, 64) {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 100 {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	b := p.DefaultBranch
	if b == "" || len(b) > 255 || strings.Contains(b, "..") || strings.Contains(b, "@{") || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") || strings.HasSuffix(b, ".") || strings.Contains(b, "//") {
		return false
	}
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_/.", c)) {
			return false
		}
	}
	for _, part := range strings.Split(b, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

// All parser allocations/work reservations debit the already admitted phase.
// Failed attempts and reservations are never refunded. No new deadline/budget.
func (p *acquisitionPhase) originalGitCharge(n int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n < 0 || p.closed || p.failed || p.uncertain || acquisitionExpired(p.ctx) || n > p.bytesLeft {
		return unavailable("github_git_aggregate")
	}
	p.bytesLeft -= n
	return nil
}

func originalGitPacket(s string) string { return originalGitLength(len(s)+4) + s }
func originalGitLength(n int) string {
	s := strconv.FormatInt(int64(n), 16)
	return strings.Repeat("0", 4-len(s)) + s
}

// Packet payloads alias a bounded, owned response; no provider-sized allocation.
func originalGitNext(b []byte) (payload, rest []byte, control int, err error) {
	if len(b) < 4 {
		return nil, nil, 0, unavailable("github_git_packet")
	}
	var n int
	for _, c := range b[:4] {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		default:
			return nil, nil, 0, unavailable("github_git_packet")
		}
	}
	if n <= 2 {
		return nil, b[4:], n, nil
	}
	if n < 4 || n > 65520 || n > len(b) {
		return nil, nil, 0, unavailable("github_git_packet")
	}
	return b[4:n], b[n:], -1, nil
}

func originalGitCapabilities(b []byte) error {
	line, b, c, err := originalGitNext(b)
	// HTTP v2 starts with the version packet, without the v0 service prelude.
	if err != nil || c != -1 || string(line) != "version 2\n" {
		return unavailable("github_git_version")
	}
	refs, fetch, format := false, false, false
	for n := 0; n < 32; n++ {
		line, rest, c, err := originalGitNext(b)
		b = rest
		if err != nil {
			return err
		}
		if c == 0 {
			if len(b) == 0 && refs && fetch && format {
				return nil
			}
			break
		}
		if c != -1 {
			break
		}
		s := strings.TrimSuffix(string(line), "\n")
		if s == "ls-refs" || strings.HasPrefix(s, "ls-refs=") {
			if refs {
				break
			}
			refs = true
		}
		if strings.HasPrefix(s, "fetch=") {
			if fetch {
				break
			}
			fields := strings.Fields(s[6:])
			shallow, filter := false, false
			for _, f := range fields {
				shallow = shallow || f == "shallow"
				filter = filter || f == "filter"
			}
			fetch = shallow && filter
		}
		if strings.HasPrefix(s, "object-format=") {
			if format || s != "object-format=sha1" {
				break
			}
			format = true
		}
	}
	return unavailable("github_git_capabilities")
}

func originalGitRefsRequest(branch string) []byte {
	return []byte(originalGitPacket("command=ls-refs\n") + originalGitPacket("object-format=sha1\n") + "0001" + originalGitPacket("symrefs\n") + originalGitPacket("ref-prefix HEAD\n") + originalGitPacket("ref-prefix refs/heads/"+branch+"\n") + "0000")
}

func originalGitHead(b []byte, branch string) (string, error) {
	head, ref := "", ""
	for n := 0; n < 256; n++ {
		line, rest, c, err := originalGitNext(b)
		b = rest
		if err != nil {
			return "", err
		}
		if c == 0 {
			if len(b) == 0 && head != "" && ref == head {
				return head, nil
			}
			break
		}
		if c != -1 || len(line) > 1024 || !bytes.HasSuffix(line, []byte{'\n'}) {
			break
		}
		f := strings.Fields(string(line))
		if len(f) < 2 || !lowerHex(f[0], 40) {
			break
		}
		switch f[1] {
		case "HEAD":
			if head != "" || len(f) != 3 || f[2] != "symref-target:refs/heads/"+branch {
				return "", unavailable("github_git_default_ref")
			}
			head = f[0]
		case "refs/heads/" + branch:
			if ref != "" || len(f) != 2 {
				return "", unavailable("github_git_default_ref")
			}
			ref = f[0]
		default:
			return "", unavailable("github_git_unexpected_ref")
		}
	}
	return "", unavailable("github_git_default_ref")
}

func originalGitPackSection(p *acquisitionPhase, b []byte) ([]byte, error) {
	// v2 optional shallow-info, then packfile, then sideband-1 pack bytes.
	line, rest, c, err := originalGitNext(b)
	b = rest
	if err != nil || c != -1 {
		return nil, unavailable("github_git_pack_section")
	}
	if string(line) == "shallow-info\n" {
		for n := 0; n <= 256; n++ {
			line, rest, c, err = originalGitNext(b)
			b = rest
			if err != nil {
				return nil, err
			}
			if c == 1 {
				break
			}
			if n == 256 || c != -1 || !(bytes.HasPrefix(line, []byte("shallow ")) && len(line) == 49 && line[48] == '\n' && lowerHex(string(line[8:48]), 40)) {
				return nil, unavailable("github_git_shallow")
			}
		}
		line, b, c, err = originalGitNext(b)
	}
	if err != nil || c != -1 || string(line) != "packfile\n" {
		return nil, unavailable("github_git_pack_section")
	}
	if err = p.originalGitCharge(int64(len(b))); err != nil {
		return nil, err
	}
	pack := make([]byte, 0, len(b))
	for n := 0; n < 1<<18; n++ {
		line, rest, c, err := originalGitNext(b)
		b = rest
		if err != nil {
			return nil, err
		}
		if c == 0 || c == 2 {
			if len(b) == 0 && len(pack) > 0 {
				return pack, nil
			}
			break
		}
		// Progress/fatal/unknown bands refuse; no error text is exposed.
		if c != -1 || len(line) < 2 || line[0] != 1 {
			break
		}
		pack = append(pack, line[1:]...)
	}
	return nil, unavailable("github_git_sideband")
}

// Git's SHA-1 format supports full commits and in-pack REF_DELTA commits only.
// Delta application reproduces exact original bytes, never synthesized metadata.
// Thin/external bases, other object kinds and incomplete/trailing packs refuse.
func originalGitUnpack(p *acquisitionPhase, pack []byte, commitMax, countMax int) (map[string][]byte, error) {
	if len(pack) < 32 || string(pack[:4]) != "PACK" || binary.BigEndian.Uint32(pack[4:8]) != 2 {
		return nil, unavailable("github_git_pack")
	}
	n := int64(binary.BigEndian.Uint32(pack[8:12]))
	if n <= 0 || n > int64(countMax) {
		return nil, unavailable("github_git_commit_count")
	}
	if err := p.originalGitCharge(int64(len(pack)) + n*256); err != nil {
		return nil, err
	}
	sum := sha1.Sum(pack[:len(pack)-20])
	if !bytes.Equal(sum[:], pack[len(pack)-20:]) {
		return nil, unavailable("github_git_pack_hash")
	}
	objects := make(map[string][]byte, int(n))
	type deltaObject struct {
		base string
		data []byte
	}
	deltas := make([]deltaObject, 0, int(n))
	reader := bytes.NewReader(pack[12 : len(pack)-20])
	for i := int64(0); i < n; i++ {
		first, err := reader.ReadByte()
		if err != nil {
			return nil, unavailable("github_git_pack")
		}
		kind := first >> 4 & 7
		size := uint64(first & 15)
		shift := uint(4)
		b := first
		for b&128 != 0 {
			if shift >= 63 {
				return nil, unavailable("github_git_size_overflow")
			}
			b, err = reader.ReadByte()
			if err != nil {
				return nil, unavailable("github_git_pack")
			}
			if uint64(b&127) > (^uint64(0) >> shift) {
				return nil, unavailable("github_git_size_overflow")
			}
			size |= uint64(b&127) << shift
			shift += 7
		}
		if kind != 1 && kind != 7 {
			return nil, unavailable("github_git_unsupported_pack_object")
		}
		if size == 0 || size > uint64(commitMax) {
			return nil, unavailable("github_git_commit_size")
		}
		// Inflate output, parser scratch/copies and object identity work are
		// reserved before zlib or commit parsing; reserve is never refunded.
		if err = p.originalGitCharge(int64(size)*64 + 65536); err != nil {
			return nil, err
		}
		var base string
		if kind == 7 {
			var oid [20]byte
			if _, err = io.ReadFull(reader, oid[:]); err != nil {
				return nil, unavailable("github_git_delta_base")
			}
			base = hex.EncodeToString(oid[:])
		}
		z, err := zlib.NewReader(reader)
		if err != nil {
			return nil, unavailable("github_git_zlib")
		}
		raw := make([]byte, int(size))
		_, err = io.ReadFull(z, raw)
		var probe [1]byte
		extra, eof := z.Read(probe[:])
		closeErr := z.Close()
		if err != nil || extra != 0 || eof != io.EOF || closeErr != nil {
			return nil, unavailable("github_git_incomplete_object")
		}
		if kind == 7 {
			deltas = append(deltas, deltaObject{base, raw})
			continue
		}
		c, err := parseCommit(raw)
		if err != nil {
			return nil, unavailable("github_git_commit")
		}
		if _, duplicate := objects[c.oid]; duplicate {
			return nil, unavailable("github_git_duplicate_object")
		}
		objects[c.oid] = raw
	}
	if reader.Len() != 0 {
		return nil, unavailable("github_git_trailing_pack")
	}
	// Bases may follow their users. At most n passes over n entries resolve
	// every acyclic in-pack chain; no recursion or external lookup is allowed.
	if err := p.originalGitCharge(n * n * 32); err != nil {
		return nil, err
	}
	left := len(deltas)
	for pass := int64(0); left > 0 && pass < n; pass++ {
		progress := false
		for i := range deltas {
			if err := p.originalGitCharge(0); err != nil {
				return nil, err
			}
			d := &deltas[i]
			if d.data == nil {
				continue
			}
			base, ok := objects[d.base]
			if !ok {
				continue
			}
			raw, err := originalGitApplyDelta(p, base, d.data, commitMax)
			if err != nil {
				return nil, err
			}
			c, err := parseCommit(raw)
			if err != nil {
				return nil, unavailable("github_git_commit")
			}
			if _, duplicate := objects[c.oid]; duplicate {
				return nil, unavailable("github_git_duplicate_object")
			}
			objects[c.oid] = raw
			d.data = nil
			left--
			progress = true
		}
		if !progress {
			return nil, unavailable("github_git_delta_unresolved")
		}
	}
	if left != 0 {
		return nil, unavailable("github_git_delta_unresolved")
	}
	return objects, nil
}

func originalGitPath(objects map[string][]byte, head, target string, max int) ([]string, bool) {
	seen := make(map[string]bool, len(objects))
	var visit func(string, int) ([]string, bool)
	visit = func(oid string, depth int) ([]string, bool) {
		if oid == target {
			return nil, true
		}
		if depth >= max || seen[oid] {
			return nil, false
		}
		seen[oid] = true
		raw, ok := objects[oid]
		if !ok {
			return nil, false
		}
		c, err := parseCommit(raw)
		if err != nil {
			return nil, false
		}
		for _, parent := range c.parents {
			if path, ok := visit(parent, depth+1); ok {
				return append([]string{oid}, path...), true
			}
		}
		return nil, false
	}
	return visit(head, 0)
}
