package moduleinput

import (
	"math"
	"strings"
	"testing"
)

// These boundary additions reject overflow without changing the failed budget.
func TestOverflowSafeBudget(t *testing.T) {
	for _, tc := range []struct {
		total, n, limit uint64
		ok              bool
	}{
		{0, MaxFileBytes, MaxFileBytes, true},
		{0, MaxFileBytes + 1, MaxFileBytes, false},
		{MaxDataBytes - 1, 1, MaxDataBytes, true},
		{MaxDataBytes, 1, MaxDataBytes, false},
		{math.MaxUint64 - 1, 1, math.MaxUint64, true},
		{math.MaxUint64 - 1, 2, math.MaxUint64, false},
		{math.MaxUint64, 1, math.MaxUint64, false},
		{math.MaxUint64, 0, MaxDataBytes, false},
	} {
		n := tc.total
		ok := budget(&n, tc.n, tc.limit)
		if ok != tc.ok {
			t.Fatalf("budget(%d,%d,%d)=%v", tc.total, tc.n, tc.limit, ok)
		}
		if !ok && n != tc.total {
			t.Fatal("failed addition mutated budget")
		}
	}
}

// This preflight accepts a 1 GiB length budget and rejects +1 before copying;
// it does not construct or verify a successful 1 GiB snapshot.
func TestBoundsBeforeSnapshot(t *testing.T) {
	// Shared backing storage exercises the actual input-length accounting at
	// 1 GiB without allocating a 1 GiB test snapshot. This directly tests the
	// same preflight called before any input-sized allocation by Verify.
	b := make([]byte, MaxFileBytes+1)
	in := Input{GoModSHA256: strings.Repeat("0", 64), GoSumSHA256: strings.Repeat("0", 64)}
	for i := 0; i < 16; i++ {
		in.Files = append(in.Files, File{Bytes: b[:MaxFileBytes]})
	}
	if e := checkBounds(in); e != nil {
		t.Fatal("exact total bound", e)
	}
	in.Files = append(in.Files, File{Bytes: b[:1]})
	if e := checkBounds(in); e == nil {
		t.Fatal("total bound+1 accepted")
	}
	v, e := Verify(in)
	if e == nil || v != nil {
		t.Fatal("oversized total exposed snapshot")
	}
	in.Files = in.Files[:1]
	in.Files[0].Bytes = b
	if e := checkBounds(in); e == nil {
		t.Fatal("file bound+1 accepted")
	}
	in.Files = nil
	in.GoMod = b[:MaxFileBytes]
	if e := checkBounds(in); e != nil {
		t.Fatal("exact source bound", e)
	}
	in.GoMod = b
	if e := checkBounds(in); e == nil {
		t.Fatal("source bound+1 accepted")
	}
}
