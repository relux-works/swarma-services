package curatorclient_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/relux-works/swarma-services/signer/internal/curatorclient"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

func TestWireVectors(t *testing.T) {
	cases := []struct {
		name    string
		opcode  byte
		prepare func() ([]byte, error)
		body    string
	}{
		{"sign", 1, func() ([]byte, error) { return curatorclient.SignFrame(commit, 1) },
			`{"version":1,"product_id":"curator","repository":"curator-core","commit":"` + commit + `","request_id":"` + commit + `-1"}`},
		{"inspect", 2, func() ([]byte, error) { return curatorclient.InspectFrame(commit + "-1") },
			`{"version":1,"request_id":"` + commit + `-1"}`},
		{"fetch", 3, func() ([]byte, error) { return curatorclient.FetchFrame("0123456789abcdef0123456789abcdef") },
			`{"version":1,"operation_id":"0123456789abcdef0123456789abcdef"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.prepare()
			if err != nil {
				t.Fatal(err)
			}
			want := append([]byte{c.opcode, 0, 0, 0, byte(len(c.body))}, []byte(c.body)...)
			if !bytes.Equal(got, want) {
				t.Fatalf("frame = %x; want %x", got, want)
			}
			if int(binary.BigEndian.Uint32(got[1:5])) != len(got)-5 {
				t.Fatal("wrong body length")
			}
			// Independent calls must not share frame storage.
			got[5] = 0
			again, err := c.prepare()
			if err != nil || !bytes.Equal(again, want) {
				t.Fatal("frame aliases a previous result")
			}
		})
	}
}

func TestCanonicalAttempts(t *testing.T) {
	for _, c := range []struct {
		n      uint64
		suffix string
	}{
		{1, "1"}, {9, "9"}, {10, "10"}, {math.MaxUint64, "18446744073709551615"},
	} {
		id, err := curatorclient.RequestID(commit, c.n)
		if err != nil || id != commit+"-"+c.suffix || len(id) > 64 {
			t.Fatalf("attempt %d: %q, %v", c.n, id, err)
		}
		// Re-deriving after loss/restart has no random or process-dependent input.
		again, err := curatorclient.RequestID(commit, c.n)
		if err != nil || again != id {
			t.Fatal("unstable correlation")
		}
	}
	if id, err := curatorclient.RequestID(commit, 0); id != "" || !errors.Is(err, curatorclient.ErrRequest) {
		t.Fatal("accepted zero attempt")
	}
	if frame, err := curatorclient.SignFrame(commit, 0); frame != nil || !errors.Is(err, curatorclient.ErrRequest) {
		t.Fatal("encoded zero attempt")
	}
}

func TestCommitRefusals(t *testing.T) {
	bad := []string{"", commit[:39], commit + "0", strings.ToUpper(commit), "refs/heads/main", strings.Repeat("é", 20)}
	for i := range commit {
		bad = append(bad, commit[:i]+"g"+commit[i+1:])
	}
	for _, value := range bad {
		if frame, err := curatorclient.SignFrame(value, 1); frame != nil || !errors.Is(err, curatorclient.ErrRequest) {
			t.Fatalf("accepted invalid commit of length %d", len(value))
		}
	}
}

func TestInspectGrammar(t *testing.T) {
	for _, value := range []string{"a", "Az09_-", strings.Repeat("a", 64)} {
		if _, err := curatorclient.InspectFrame(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 65), "a b", "a/b", "é", "a\x00", "a\n", `a","version":2`} {
		if frame, err := curatorclient.InspectFrame(value); frame != nil || !errors.Is(err, curatorclient.ErrRequest) {
			t.Fatal("accepted invalid request ID")
		}
	}
	// Change every byte independently: non-ASCII and all punctuation except
	// underscore/hyphen must refuse rather than be escaped into a request.
	for n := 0; n < 256; n++ {
		c := byte(n)
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
		_, err := curatorclient.InspectFrame(string([]byte{c}))
		if (err == nil) != valid {
			t.Fatalf("request ID byte %d: %v", n, err)
		}
	}
}

func TestOperationRefusals(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("é", 16)} {
		if frame, err := curatorclient.FetchFrame(value); frame != nil || !errors.Is(err, curatorclient.ErrRequest) {
			t.Fatal("accepted invalid operation ID")
		}
	}
}
