package manifestbody

import (
	"bytes"
	"unicode/utf16"
	"unicode/utf8"
)

// parser traverses only the four fixed object shapes. Unknown values are never
// skipped or recursively allocated. err records the first encountered refusal.
type parser struct {
	raw []byte
	pos int
	err *BodyShapeRefusal
	sum uint64
}

func (p *parser) fail(r BodyShapeReason) {
	if p.err == nil {
		p.err = &BodyShapeRefusal{r}
	}
}
func space(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
func delimiter(c byte) bool {
	return space(c) || c == ',' || c == ']' || c == '}' || c == ':' || c == '[' || c == '{' || c == '"'
}
func (p *parser) ws() {
	for p.pos < len(p.raw) && space(p.raw[p.pos]) {
		p.pos++
	}
}
func (p *parser) peek() byte {
	p.ws()
	if p.pos == len(p.raw) {
		return 0
	}
	return p.raw[p.pos]
}
func (p *parser) take(c byte) bool {
	if p.err != nil {
		return false
	}
	if p.peek() != c {
		p.fail(ReasonJSONSyntax)
		return false
	}
	p.pos++
	return true
}
func (p *parser) literal(s string) bool {
	if !bytes.HasPrefix(p.raw[p.pos:], []byte(s)) {
		p.fail(ReasonJSONSyntax)
		return false
	}
	p.pos += len(s)
	if p.pos < len(p.raw) && !delimiter(p.raw[p.pos]) {
		p.fail(ReasonJSONSyntax)
		return false
	}
	return true
}

// wrongType recognizes primitive syntax without walking wrong-type containers.
// Multiple faults inside a wrong-type container have no stronger precedence.
func (p *parser) wrongType() {
	c := p.peek()
	switch c {
	case '{', '[':
		p.fail(ReasonValueType)
	case '"':
		p.str(1024, ReasonValueType)
		p.fail(ReasonValueType)
	case 't':
		if p.literal("true") {
			p.fail(ReasonValueType)
		}
	case 'f':
		if p.literal("false") {
			p.fail(ReasonValueType)
		}
	case 'n':
		if p.literal("null") {
			p.fail(ReasonValueType)
		}
	default:
		start := p.pos
		for p.pos < len(p.raw) && !delimiter(p.raw[p.pos]) {
			p.pos++
		}
		if validJSONNumber(p.raw[start:p.pos]) {
			p.fail(ReasonValueType)
		} else {
			p.fail(ReasonJSONSyntax)
		}
	}
}
func validJSONNumber(b []byte) bool {
	i := 0
	if i < len(b) && b[i] == '-' {
		i++
	}
	if i == len(b) {
		return false
	}
	if b[i] == '0' {
		i++
	} else {
		if b[i] < '1' || b[i] > '9' {
			return false
		}
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
	}
	if i < len(b) && b[i] == '.' {
		i++
		start := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			i++
		}
		start := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	return i == len(b)
}

func (p *parser) number() uint64 {
	if p.err != nil {
		return 0
	}
	c := p.peek()
	if !(c >= '0' && c <= '9' || c == '+' || c == '-') {
		p.wrongType()
		return 0
	}
	start := p.pos
	for p.pos < len(p.raw) && !delimiter(p.raw[p.pos]) {
		p.pos++
	}
	b := p.raw[start:p.pos]
	if len(b) == 0 || b[0] < '0' || b[0] > '9' || len(b) > 1 && b[0] == '0' {
		p.fail(ReasonIntegerSpelling)
		return 0
	}
	// Establish spelling before accumulation, so a long noncanonical token is
	// IntegerSpelling rather than an accidental overflow classification.
	for _, c := range b {
		if c < '0' || c > '9' {
			p.fail(ReasonIntegerSpelling)
			return 0
		}
	}
	var n uint64
	const max = uint64(9223372036854775807)
	for _, c := range b {
		d := uint64(c - '0')
		if n > (max-d)/10 {
			p.fail(ReasonScalarBound)
			return 0
		}
		n = n*10 + d
	}
	return n
}
func hexDigit(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c - 'a' + 10), true
	case c >= 'A' && c <= 'F':
		return rune(c - 'A' + 10), true
	}
	return 0, false
}
func (p *parser) hex4() rune {
	if len(p.raw)-p.pos < 4 {
		p.fail(ReasonJSONSyntax)
		return 0
	}
	var r rune
	for i := 0; i < 4; i++ {
		v, ok := hexDigit(p.raw[p.pos])
		if !ok {
			p.fail(ReasonJSONSyntax)
			return 0
		}
		p.pos++
		r = r*16 + v
	}
	return r
}

// str completes lexical Unicode validation while retaining at most max decoded
// bytes. Even a long member name is lexically checked before member lookup.
func (p *parser) str(max int, overflow BodyShapeReason) string {
	if p.err != nil {
		return ""
	}
	if p.peek() != '"' {
		p.wrongType()
		return ""
	}
	p.pos++
	out := make([]byte, 0, min(max, 64))
	tooLong := false
	put := func(b []byte) {
		if tooLong || len(b) > max-len(out) {
			tooLong = true
			return
		}
		out = append(out, b...)
	}
	for p.pos < len(p.raw) && p.err == nil {
		c := p.raw[p.pos]
		p.pos++
		switch {
		case c == '"':
			if tooLong {
				p.fail(overflow)
			}
			return string(out)
		case c < 0x20:
			p.fail(ReasonJSONSyntax)
		case c == '\\':
			if p.pos == len(p.raw) {
				p.fail(ReasonJSONSyntax)
				break
			}
			e := p.raw[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				put([]byte{e})
			case 'b':
				put([]byte{'\b'})
			case 'f':
				put([]byte{'\f'})
			case 'n':
				put([]byte{'\n'})
			case 'r':
				put([]byte{'\r'})
			case 't':
				put([]byte{'\t'})
			case 'u':
				r := p.hex4()
				if p.err != nil {
					break
				}
				if r >= 0xD800 && r <= 0xDBFF {
					if !bytes.HasPrefix(p.raw[p.pos:], []byte(`\u`)) {
						p.fail(ReasonJSONEncoding)
						break
					}
					p.pos += 2
					low := p.hex4()
					if p.err != nil {
						break
					}
					if low < 0xDC00 || low > 0xDFFF {
						p.fail(ReasonJSONEncoding)
						break
					}
					r = utf16.DecodeRune(r, low)
				} else if r >= 0xDC00 && r <= 0xDFFF {
					p.fail(ReasonJSONEncoding)
					break
				}
				put(utf8.AppendRune(nil, r))
			default:
				p.fail(ReasonJSONSyntax)
			}
		case c < utf8.RuneSelf:
			put([]byte{c})
		default:
			// The whole-body pre-pass already established valid UTF-8.
			_, n := utf8.DecodeRune(p.raw[p.pos-1:])
			put(p.raw[p.pos-1 : p.pos-1+n])
			p.pos += n - 1
		}
	}
	p.fail(ReasonJSONSyntax)
	return ""
}

func (p *parser) object(names []string, field func(int)) {
	if p.err != nil {
		return
	}
	if p.peek() != '{' {
		p.wrongType()
		return
	}
	p.pos++
	var seen uint64
	if p.peek() != '}' {
		for p.err == nil {
			if p.peek() != '"' {
				p.fail(ReasonJSONSyntax)
				return
			}
			name := p.str(32, ReasonMemberSet)
			if p.err != nil {
				return
			}
			idx := -1
			for i, n := range names {
				if name == n {
					idx = i
					break
				}
			}
			if idx < 0 {
				p.fail(ReasonMemberSet)
				return
			}
			bit := uint64(1) << idx
			if seen&bit != 0 {
				p.fail(ReasonDecodedDuplicateName)
				return
			}
			seen |= bit
			if !p.take(':') {
				return
			}
			field(idx)
			if p.err != nil {
				return
			}
			if p.peek() == '}' {
				break
			}
			if !p.take(',') {
				return
			}
		}
	}
	if !p.take('}') {
		return
	}
	if seen != (uint64(1)<<len(names))-1 {
		p.fail(ReasonMemberSet)
	}
}
func (p *parser) array(max int, element func()) {
	if p.err != nil {
		return
	}
	if p.peek() != '[' {
		p.wrongType()
		return
	}
	p.pos++
	if p.peek() != ']' {
		for n := 0; p.err == nil; n++ {
			// A comma followed by punctuation or EOF introduces no element.
			// Recognize a JSON value start before applying the count bound.
			switch p.peek() {
			case '{', '[', '"', 't', 'f', 'n', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			default:
				p.fail(ReasonJSONSyntax)
				return
			}
			if n >= max {
				p.fail(ReasonScalarBound)
				return
			}
			element()
			if p.err != nil {
				return
			}
			if p.peek() == ']' {
				break
			}
			if !p.take(',') {
				return
			}
		}
	}
	p.take(']')
}
