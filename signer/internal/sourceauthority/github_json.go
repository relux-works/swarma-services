package sourceauthority

import "unicode/utf8"

// encoding/json replaces invalid UTF-8 and lone UTF-16 surrogates. Reject them
// in the original bytes so the body that is hashed is the actual decoded body.
func validGitHubJSONStrings(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	in := false
	hex4 := func(b []byte) (uint16, bool) {
		if len(b) < 4 {
			return 0, false
		}
		var n uint16
		for _, c := range b[:4] {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n += uint16(c - '0')
			case c >= 'a' && c <= 'f':
				n += uint16(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				n += uint16(c - 'A' + 10)
			default:
				return 0, false
			}
		}
		return n, true
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '"' {
			in = !in
			continue
		}
		if !in || c != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		n, ok := hex4(raw[i+1:])
		if !ok {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, ok := hex4(raw[i+3:])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !in
}
