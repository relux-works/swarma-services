package packetwalk

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

func syntheticPack(t *testing.T, typ byte, raw []byte, declared int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	if e := binary.Write(&b, binary.BigEndian, uint32(2)); e != nil {
		t.Fatal(e)
	}
	if e := binary.Write(&b, binary.BigEndian, uint32(1)); e != nil {
		t.Fatal(e)
	}
	first := byte(declared&15) | typ<<4
	n := declared >> 4
	if n != 0 {
		first |= 128
	}
	b.WriteByte(first)
	for n != 0 {
		c := byte(n & 127)
		n >>= 7
		if n != 0 {
			c |= 128
		}
		b.WriteByte(c)
	}
	if typ == 7 {
		b.Write(make([]byte, 20))
	}
	z := zlib.NewWriter(&b)
	if _, e := z.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}

func TestPackPreflightBombAndDeltaTargets(t *testing.T) {
	l := DefaultLimits()
	l.FileBytes = 4096
	l.StreamBytes = 8192
	for _, test := range []struct {
		name string
		pack []byte
		want error
	}{
		{"valid-blob", syntheticPack(t, 3, []byte("safe"), 4), nil},
		{"claimed-bomb", syntheticPack(t, 3, []byte("safe"), 1<<20), ErrLimit},
		{"actual-bomb", syntheticPack(t, 3, bytes.Repeat([]byte("x"), 1<<20), 4), ErrBundle},
		// REF_DELTA source size 1, reconstructed size 16384, no instructions.
		{"delta-target-bomb", syntheticPack(t, 7, []byte{1, 128, 128, 1}, 4), ErrLimit},
		{"delta-base-bomb", syntheticPack(t, 7, []byte{128, 128, 1, 1}, 4), ErrLimit},
		{"tag", syntheticPack(t, 4, []byte("tag"), 3), ErrBundle},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := &walker{ctx: context.Background(), l: l}
			if e := w.preflightPack(test.pack); e != test.want {
				t.Fatalf("want %v got %v", test.want, e)
			}
			if w.r.Commands != 0 {
				t.Fatal("preflight started a tool")
			}
		})
	}
}

func TestPackPreflightIntegrityAndBudget(t *testing.T) {
	p := syntheticPack(t, 3, []byte("safe"), 4)
	bad := bytes.Clone(p)
	bad[len(bad)-1] ^= 1
	w := &walker{ctx: context.Background(), l: DefaultLimits()}
	if e := w.preflightPack(bad); e != ErrBundle {
		t.Fatal(e)
	}
	w.l.ExpandedBytes = 3
	if e := w.preflightPack(p); e != ErrLimit {
		t.Fatal(e)
	}
	if _, _, ok := deltaSize(bytes.Repeat([]byte{128}, 16)); ok {
		t.Fatal("unbounded varint accepted")
	}
}
