package sourceauthority

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Inspect actual stock upload-pack output, including each object's compressed
// boundary. Searching for a byte value would not establish a REF_DELTA fixture.
func originalStockPackKinds(t *testing.T, wire []byte) []byte {
	t.Helper()
	var pack []byte
	inPack := false
	for len(wire) > 0 {
		line, rest, control, err := originalGitNext(wire)
		if err != nil {
			t.Fatal("stock packet", err)
		}
		wire = rest
		if !inPack {
			inPack = control == -1 && string(line) == "packfile\n"
			continue
		}
		if control == 0 || control == 2 {
			if len(wire) != 0 {
				t.Fatal("stock trailing packets")
			}
			break
		}
		if control != -1 || len(line) < 2 || line[0] != 1 {
			t.Fatal("stock non-data band")
		}
		pack = append(pack, line[1:]...)
	}
	if !inPack || len(pack) < 32 || string(pack[:4]) != "PACK" || binary.BigEndian.Uint32(pack[4:8]) != 2 {
		t.Fatal("stock pack header")
	}
	sum := sha1.Sum(pack[:len(pack)-20])
	if !bytes.Equal(sum[:], pack[len(pack)-20:]) {
		t.Fatal("stock pack checksum")
	}
	count := binary.BigEndian.Uint32(pack[8:12])
	if count != 2 {
		t.Fatalf("expected two original commits, got %d objects", count)
	}
	r := bytes.NewReader(pack[12 : len(pack)-20])
	var kinds []byte
	for i := uint32(0); i < count; i++ {
		b, err := r.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		kind, size := b>>4&7, uint64(b&15)
		for shift := uint(4); b&128 != 0; shift += 7 {
			if shift >= 63 {
				t.Fatal("stock size overflow")
			}
			b, err = r.ReadByte()
			if err != nil {
				t.Fatal(err)
			}
			size |= uint64(b&127) << shift
		}
		if kind == 7 {
			var base [20]byte
			if _, err := io.ReadFull(r, base[:]); err != nil {
				t.Fatal(err)
			}
		} else if kind != 1 {
			t.Fatalf("unexpected stock object type %d", kind)
		}
		z, err := zlib.NewReader(r)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(z, 1<<20))
		closeErr := z.Close()
		if err != nil || closeErr != nil || uint64(n) != size || size >= 1<<20 {
			t.Fatal("stock object boundary/size", err, closeErr)
		}
		kinds = append(kinds, kind)
	}
	if r.Len() != 0 {
		t.Fatal("stock pack trailing bytes")
	}
	t.Logf("stock default-window object kinds: %v (7 = REF_DELTA)", kinds)
	t.Logf("stock default-window pack SHA-256: %x", sha256.Sum256(pack))
	return kinds
}

func TestOriginalGitDefaultWindowRawSignedAncestry(t *testing.T) {
	for _, beyondWindow := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete-history", true: "shallow-history"}[beyondWindow], func(t *testing.T) {
			originalGitDefaultWindowRawSignedAncestry(t, beyondWindow)
		})
	}
}

func originalGitDefaultWindowRawSignedAncestry(t *testing.T, beyondWindow bool) {
	l := originalGitLab(t, func(l *originalGitFixture) { originalGitStockFetchHistory(t, l, false, false, beyondWindow) })
	stock := l.stockFetch
	var kinds []byte
	l.stockFetch = func(request []byte) []byte {
		wire := stock(request)
		if beyondWindow {
			// Inspect the unmodified exchange, before the production parser.
			line, rest, control, err := originalGitNext(wire)
			if err != nil || control != -1 || string(line) != "shallow-info\n" {
				t.Fatal("stock Git did not cut history with shallow-info", err)
			}
			line, rest, control, err = originalGitNext(rest)
			if err != nil || control != -1 || string(line) != "shallow "+l.q.Commit {
				t.Fatal("expected exact stock shallow OID without LF", err)
			}
			_, _, control, err = originalGitNext(rest)
			if err != nil || control != 1 {
				t.Fatal("missing stock shallow delimiter", err)
			}
			t.Logf("stock shallow boundary: %s; wire SHA-256: %x", l.q.Commit, sha256.Sum256(wire))
		}
		kinds = originalStockPackKinds(t, wire)
		if !bytes.Contains(kinds, []byte{7}) {
			t.Error("default stock Git fixture did not emit REF_DELTA")
		}
		return wire
	}
	before := l.r.phase.bytesLeft
	deadline, _ := l.r.phase.ctx.Deadline()
	got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(kinds, []byte{7}) || !bytes.Equal(got.Commit, l.raw) || len(got.LandingPath) != 1 || !bytes.Equal(got.LandingPath[0], l.head) || got.Repository.DefaultHead != fixtureOID(l.head) {
		t.Fatal("delta fixture/raw identity/path lost")
	}
	for _, raw := range [][]byte{got.Commit, got.LandingPath[0]} {
		c, err := parseCommit(raw)
		if err != nil || c.tree != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
			t.Fatal("tree changed", err)
		}
		if _, err := verifyOwner(c, l.r.policy); err != nil {
			t.Fatal("original signature lost", err)
		}
	}
	if fixtureOID(got.Commit) != l.q.Commit || l.requests.Load() != 4 || l.r.phase.responsesLeft != 1020 || l.r.phase.bytesLeft >= before || l.r.phase.bytesLeft < 0 {
		t.Fatal("OID/shared accounting lost")
	}
	afterDeadline, _ := l.r.phase.ctx.Deadline()
	if !deadline.Equal(afterDeadline) {
		t.Fatal("shared deadline changed")
	}
	waitAcquisition(t, func() bool { return l.open.Load() == 0 && l.connector.live.Load() == 0 })
}

func originalDeltaPhase(t *testing.T) *acquisitionPhase {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return &acquisitionPhase{ctx: ctx, bytesLeft: acquisitionAggregateMax}
}

func originalDeltaSizes(base, result int) []byte {
	var out []byte
	for _, n := range []int{base, result} {
		for n >= 128 {
			out = append(out, byte(n&127)|128)
			n >>= 7
		}
		out = append(out, byte(n))
	}
	return out
}

func originalDeltaLiteral(base int, raw []byte) []byte {
	out := originalDeltaSizes(base, len(raw))
	for len(raw) > 0 {
		n := min(len(raw), 127)
		out = append(out, byte(n))
		out = append(out, raw[:n]...)
		raw = raw[n:]
	}
	return out
}

type originalDeltaEntry struct {
	kind byte
	base string
	data []byte
}

func originalDeltaPack(t *testing.T, entries ...originalDeltaEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(len(entries)))
	for _, e := range entries {
		n := len(e.data)
		first := e.kind<<4 | byte(n&15)
		n >>= 4
		if n > 0 {
			first |= 128
		}
		b.WriteByte(first)
		for n > 0 {
			v := byte(n & 127)
			n >>= 7
			if n > 0 {
				v |= 128
			}
			b.WriteByte(v)
		}
		if e.kind == 7 {
			oid, err := hex.DecodeString(e.base)
			if err != nil || len(oid) != 20 {
				t.Fatal("fixture base OID")
			}
			b.Write(oid)
		}
		z := zlib.NewWriter(&b)
		z.Write(e.data)
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}

func originalDeltaRefusal(t *testing.T, got map[string][]byte, err error, predicate string) {
	t.Helper()
	r, ok := err.(*Refusal)
	if got != nil || !ok || r.Predicate() != predicate {
		t.Fatalf("wanted %s without material, got %v", predicate, err)
	}
}

func TestOriginalGitDeltaPackResolution(t *testing.T) {
	a := []byte("tree " + strings.Repeat("1", 40) + "\n\nOriginal base commit.\n")
	b := bytes.Replace(a, []byte("base"), []byte("next"), 1)
	c := bytes.Replace(a, []byte("base"), []byte("last"), 1)
	full := originalDeltaEntry{kind: 1, data: a}
	db := originalDeltaEntry{7, fixtureOID(a), originalDeltaLiteral(len(a), b)}
	dc := originalDeltaEntry{7, fixtureOID(b), originalDeltaLiteral(len(b), c)}
	for _, tc := range []struct {
		name    string
		entries []originalDeltaEntry
	}{
		{"backward-chain", []originalDeltaEntry{full, db, dc}},
		{"forward-chain", []originalDeltaEntry{dc, db, full}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := originalDeltaPhase(t)
			objects, err := originalGitUnpack(p, originalDeltaPack(t, tc.entries...), 4096, 3)
			if err != nil || len(objects) != 3 {
				t.Fatal("chain refused", err)
			}
			for _, raw := range [][]byte{a, b, c} {
				if !bytes.Equal(objects[fixtureOID(raw)], raw) {
					t.Fatal("reconstructed bytes/OID changed")
				}
			}
			if p.bytesLeft >= acquisitionAggregateMax || p.bytesLeft < 0 {
				t.Fatal("missing shared debit")
			}
		})
	}
	for _, tc := range []struct {
		name, predicate string
		entries         []originalDeltaEntry
	}{
		{"missing-base", "github_git_delta_unresolved", []originalDeltaEntry{db}},
		{"wrong-base-oid", "github_git_delta_unresolved", []originalDeltaEntry{full, {7, strings.Repeat("0", 40), db.data}}},
		{"self-cycle", "github_git_delta_unresolved", []originalDeltaEntry{{7, fixtureOID(b), originalDeltaLiteral(len(b), b)}}},
		{"two-cycle", "github_git_delta_unresolved", []originalDeltaEntry{db, {7, fixtureOID(b), originalDeltaLiteral(len(b), a)}}},
		{"duplicate-result", "github_git_duplicate_object", []originalDeltaEntry{full, {7, fixtureOID(a), originalDeltaLiteral(len(a), a)}}},
		{"invalid-reconstructed-commit", "github_git_commit", []originalDeltaEntry{full, {7, fixtureOID(a), originalDeltaLiteral(len(a), []byte("not a commit"))}}},
		{"ofs-delta", "github_git_unsupported_pack_object", []originalDeltaEntry{{kind: 6, data: a}}},
		{"blob", "github_git_unsupported_pack_object", []originalDeltaEntry{{kind: 3, data: a}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := originalGitUnpack(originalDeltaPhase(t), originalDeltaPack(t, tc.entries...), 4096, 3)
			originalDeltaRefusal(t, got, err, tc.predicate)
		})
	}
	pack := originalDeltaPack(t, full, db)
	for _, tc := range []struct {
		name, predicate string
		pack            []byte
		max, count      int
		budget          int64
	}{
		{"count", "github_git_commit_count", pack, 4096, 1, acquisitionAggregateMax},
		{"input-size", "github_git_commit_size", pack, len(a) - 1, 2, acquisitionAggregateMax},
		{"ledger", "github_git_aggregate", pack, 4096, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := originalDeltaPhase(t)
			p.bytesLeft = tc.budget
			got, err := originalGitUnpack(p, tc.pack, tc.max, tc.count)
			originalDeltaRefusal(t, got, err, tc.predicate)
		})
	}
	// Exhaust the aggregate total at the last reservation. The separate exact
	// resolution-reservation control below pins that earlier debit independently.
	p := originalDeltaPhase(t)
	if _, err := originalGitUnpack(p, pack, 4096, 2); err != nil {
		t.Fatal(err)
	}
	used := acquisitionAggregateMax - p.bytesLeft
	p = originalDeltaPhase(t)
	p.bytesLeft = used - 1
	got, err := originalGitUnpack(p, pack, 4096, 2)
	originalDeltaRefusal(t, got, err, "github_git_aggregate")
	if p.bytesLeft < 0 {
		t.Fatal("ledger underflow")
	}
}

func TestOriginalGitDeltaInstructions(t *testing.T) {
	base := []byte("abcdefghij")
	for _, tc := range []struct {
		name             string
		base, data, want []byte
	}{
		{"copy-and-insert", base, append(originalDeltaSizes(10, 7), 0x91, 2, 4, 3, 'X', 'Y', 'Z'), []byte("cdefXYZ")},
		{"default-copy-size", bytes.Repeat([]byte{'a'}, 65536), append(originalDeltaSizes(65536, 65536), 0x80), bytes.Repeat([]byte{'a'}, 65536)},
		{"high-offset", append(bytes.Repeat([]byte{'a'}, 65536), 'z'), append(originalDeltaSizes(65537, 1), 0x94, 1, 1), []byte("z")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := originalGitApplyDelta(originalDeltaPhase(t), tc.base, tc.data, 1<<20)
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatal("valid delta refused", err)
			}
		})
	}
	for _, tc := range []struct {
		name, predicate string
		data            []byte
	}{
		{"base-mismatch", "github_git_delta_base_size", originalDeltaSizes(9, 1)},
		{"truncated-base-size", "github_git_delta_base_size", []byte{128}},
		{"base-overflow", "github_git_delta_base_size", bytes.Repeat([]byte{255}, 10)},
		{"result-overflow", "github_git_delta_result_size", append([]byte{10}, bytes.Repeat([]byte{255}, 10)...)},
		{"zero-result", "github_git_delta_result_size", originalDeltaSizes(10, 0)},
		{"oversize-result", "github_git_delta_result_size", originalDeltaSizes(10, 4097)},
		{"truncated-result-size", "github_git_delta_result_size", []byte{10, 128}},
		{"zero-opcode", "github_git_delta_instruction", append(originalDeltaSizes(10, 1), 0)},
		{"truncated-literal", "github_git_delta_instruction", append(originalDeltaSizes(10, 2), 2, 'x')},
		{"literal-overrun", "github_git_delta_instruction", append(originalDeltaSizes(10, 1), 2, 'x', 'y')},
		{"truncated-copy", "github_git_delta_instruction", append(originalDeltaSizes(10, 1), 0x91, 0)},
		{"copy-offset", "github_git_delta_copy", append(originalDeltaSizes(10, 1), 0x91, 11, 1)},
		{"copy-length", "github_git_delta_copy", append(originalDeltaSizes(10, 11), 0x90, 11)},
		{"copy-result-overrun", "github_git_delta_copy", append(originalDeltaSizes(10, 1), 0x90, 2)},
		{"copy-uint32-offset", "github_git_delta_copy", append(originalDeltaSizes(10, 1), 0x9f, 255, 255, 255, 255, 1)},
		{"short-result", "github_git_delta_result_size", append(originalDeltaSizes(10, 2), 1, 'x')},
		{"trailing-instruction", "github_git_delta_instruction", append(originalDeltaSizes(10, 1), 1, 'x', 1, 'y')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := originalGitApplyDelta(originalDeltaPhase(t), base, tc.data, 4096)
			r, ok := err.(*Refusal)
			if got != nil || !ok || r.Predicate() != tc.predicate {
				t.Fatalf("wanted %s, got %v", tc.predicate, err)
			}
		})
	}
	p := originalDeltaPhase(t)
	p.bytesLeft = 1
	got, err := originalGitApplyDelta(p, base, originalDeltaLiteral(10, []byte("x")), 4096)
	originalDeltaBytesRefusal(t, got, err, "github_git_aggregate")
	if p.bytesLeft != 1 {
		t.Fatal("refused output reservation changed ledger")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p = originalDeltaPhase(t)
	p.ctx = ctx
	got, err = originalGitApplyDelta(p, base, originalDeltaLiteral(10, []byte("x")), 4096)
	originalDeltaBytesRefusal(t, got, err, "github_git_aggregate")
}

func TestOriginalGitDeltaCorruptionAndTruncation(t *testing.T) {
	a := []byte("tree " + strings.Repeat("1", 40) + "\n\nBase.\n")
	b := bytes.Replace(a, []byte("Base"), []byte("Next"), 1)
	pack := originalDeltaPack(t, originalDeltaEntry{1, "", a}, originalDeltaEntry{7, fixtureOID(a), originalDeltaLiteral(len(a), b)})
	corrupt := append([]byte(nil), pack...)
	corrupt[len(corrupt)-1] ^= 1
	got, err := originalGitUnpack(originalDeltaPhase(t), corrupt, 4096, 2)
	originalDeltaRefusal(t, got, err, "github_git_pack_hash")
	// Every truncated prefix is refused even with a freshly correct pack hash.
	// This covers object headers, base OIDs, delta headers, zlib data/trailers.
	// Both fixture object sizes use exactly two pack-header bytes. Compute
	// their compressed boundaries from a separately encoded single-object pack.
	firstEnd := len(originalDeltaPack(t, originalDeltaEntry{1, "", a})) - 20
	deltaStart := firstEnd + 2 + 20
	if len(a) < 16 || len(a) >= 2048 || len(originalDeltaLiteral(len(a), b)) < 16 || len(originalDeltaLiteral(len(a), b)) >= 2048 {
		t.Fatal("fixture no longer uses two-byte object headers")
	}
	for cut := 12; cut < len(pack)-20; cut++ {
		prefix := append([]byte(nil), pack[:cut]...)
		sum := sha1.Sum(prefix)
		prefix = append(prefix, sum[:]...)
		predicate := "github_git_incomplete_object"
		switch {
		case cut < 14, cut >= firstEnd && cut < firstEnd+2:
			predicate = "github_git_pack"
		case cut < 16, cut >= deltaStart && cut < deltaStart+2:
			predicate = "github_git_zlib"
		case cut >= firstEnd+2 && cut < deltaStart:
			predicate = "github_git_delta_base"
		}
		t.Run("prefix-"+strconv.Itoa(cut), func(t *testing.T) {
			got, err := originalGitUnpack(originalDeltaPhase(t), prefix, 4096, 2)
			originalDeltaRefusal(t, got, err, predicate)
		})
	}
	// Corrupt every compressed/header byte and reseal; mutations either refuse
	// or produce exact commits at their independently recomputed content OIDs.
	for at := 12; at < len(pack)-20; at++ {
		bad := append([]byte(nil), pack...)
		bad[at] ^= 0x80
		sum := sha1.Sum(bad[:len(bad)-20])
		copy(bad[len(bad)-20:], sum[:])
		objects, err := originalGitUnpack(originalDeltaPhase(t), bad, 4096, 2)
		if err == nil {
			for oid, raw := range objects {
				if oid != fixtureOID(raw) {
					t.Fatal("corruption bypassed identity")
				}
			}
		} else if objects != nil {
			t.Fatal("corruption leaked partial map")
		}
	}
}
