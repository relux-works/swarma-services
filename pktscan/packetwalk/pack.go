package packetwalk

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"io"
)

// preflightPack bounds every physical compressed stream and each delta's declared
// reconstructed size BEFORE external Git can inflate or resolve it. Git remains
// responsible for object hashes, delta instruction validity and connectivity.
// StreamBytes charges inflated pack representations; ExpandedBytes additionally
// charges declared reconstructed sizes (then charges actual visited objects).
func (w *walker) preflightPack(pack []byte) error {
	if len(pack) < 32 || string(pack[:4]) != "PACK" {
		return ErrBundle
	}
	version := binary.BigEndian.Uint32(pack[4:8])
	if version != 2 && version != 3 {
		return ErrBundle
	}
	count := binary.BigEndian.Uint32(pack[8:12])
	if uint64(count) > uint64(w.l.Entries-w.r.Entries) {
		return ErrLimit
	}
	sum := sha1.Sum(pack[:len(pack)-20])
	if !bytes.Equal(sum[:], pack[len(pack)-20:]) {
		return ErrBundle
	}
	r := bytes.NewReader(pack[12 : len(pack)-20])
	for i := uint32(0); i < count; i++ {
		if e := w.entry(); e != nil {
			return e
		}
		first, e := r.ReadByte()
		if e != nil {
			return ErrBundle
		}
		typ := int(first>>4) & 7
		size := uint64(first & 15)
		shift := uint(4)
		c := first
		for c&128 != 0 {
			if shift >= 63 {
				return ErrBundle
			}
			c, e = r.ReadByte()
			if e != nil {
				return ErrBundle
			}
			size |= uint64(c&127) << shift
			shift += 7
		}
		if size > uint64(w.l.FileBytes) || size > uint64(w.l.StreamBytes-w.r.StreamBytes) {
			return ErrLimit
		}
		switch typ {
		case 1, 2, 3: // commit, tree, blob
		case 4:
			return ErrBundle // annotated tags are outside the commit closure contract
		case 6:
			// OFS_DELTA's base distance has a different encoding; Git validates its
			// value. Bound bytes here so malformed continuations cannot spin.
			for n := 0; ; n++ {
				if n >= 10 {
					return ErrBundle
				}
				c, e = r.ReadByte()
				if e != nil {
					return ErrBundle
				}
				if c&128 == 0 {
					break
				}
			}
		case 7:
			if r.Len() < 20 {
				return ErrBundle
			}
			if _, e = r.Seek(20, io.SeekCurrent); e != nil {
				return ErrBundle
			}
		default:
			return ErrBundle
		}
		zr, e := zlib.NewReader(r)
		if e != nil {
			return ErrBundle
		}
		data, e := io.ReadAll(io.LimitReader(checkedReader{w, zr}, int64(size)+1))
		ce := zr.Close()
		if w.check() != nil {
			return ErrLimit
		}
		if e != nil || ce != nil || uint64(len(data)) != size {
			return ErrBundle
		}
		if e = charge(&w.r.StreamBytes, int64(size), w.l.StreamBytes); e != nil {
			return e
		}
		result := size
		if typ == 6 || typ == 7 {
			base, n, ok := deltaSize(data)
			if !ok || base > uint64(w.l.FileBytes) {
				return ErrLimit
			}
			var good bool
			result, _, good = deltaSize(data[n:])
			if !good {
				return ErrBundle
			}
		}
		if result > uint64(w.l.FileBytes) {
			return ErrLimit
		}
		if e = charge(&w.r.ExpandedBytes, int64(result), w.l.ExpandedBytes); e != nil {
			return e
		}
	}
	if r.Len() != 0 {
		return ErrBundle
	}
	return w.check()
}

func deltaSize(b []byte) (uint64, int, bool) {
	var n uint64
	for i, c := range b {
		if i >= 9 {
			return 0, 0, false
		}
		n |= uint64(c&127) << uint(i*7)
		if c&128 == 0 {
			return n, i + 1, true
		}
	}
	return 0, 0, false
}
