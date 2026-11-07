// Package secretclass classifies bounded, complete file contents without retaining
// or returning matched values. It performs no I/O and does not authorize export.
package secretclass

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	MaxBytes  = 16 << 20
	MaxString = 1 << 20
	MaxDepth  = 128
	MaxValues = 65536
)

// Format must be selected from the complete logical file, before line/diff
// filtering. JSON includes scalar documents. Auto recognizes JSON object, array
// and string starts regardless of filename, otherwise scanning text token shapes.
type Format uint8

const (
	JSON Format = iota + 1
	Auto
)

// Counts contains blocking-class counts only. Zero counts with a non-nil error
// are a refusal, never a clean classification. Counts are not line counts.
type Counts struct {
	GitHubTokens int `json:"github_tokens"`
	SecretFields int `json:"secret_fields"`
}

func (c Counts) Blocking() bool { return c.GitHubTokens != 0 || c.SecretFields != 0 }

// All errors are fixed and contain no input, key, value, offset or parser detail.
var (
	ErrFormat   = errors.New("secret classification format refused")
	ErrEncoding = errors.New("secret classification encoding refused")
	ErrJSON     = errors.New("secret classification JSON refused")
	ErrLimit    = errors.New("secret classification limit exceeded")
)

// Classify requires the entire file, not an unchecked prefix. JSON is parsed
// fully, including duplicate members and all nested values; strings and keys are
// decoded once using JSON escapes. Any refusal discards all partial counts.
// Auto accepts UTF-8 without NUL; UTF-16/32, binary and BOM-prefixed input refuse.
// There is no base64, URL, HTML, compressed or recursive string decoding.
func Classify(data []byte, format Format) (Counts, error) {
	if format != JSON && format != Auto {
		return Counts{}, ErrFormat
	}
	if len(data) > MaxBytes {
		return Counts{}, ErrLimit
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return Counts{}, ErrEncoding
	}
	if format == Auto {
		trimmed := bytes.TrimLeft(data, " \t\r\n")
		if len(trimmed) != 0 && (trimmed[0] == '{' || trimmed[0] == '[' || trimmed[0] == '"') {
			format = JSON
		}
	}
	if format == Auto {
		// Match the host scanner's line bound, without allocating line slices.
		line := 0
		for _, b := range data {
			if b == '\n' {
				line = 0
			} else {
				line++
				if line > MaxString {
					return Counts{}, ErrLimit
				}
			}
		}
		return Counts{GitHubTokens: tokenCount(string(data))}, nil
	}
	// encoding/json replaces unpaired UTF-16 surrogate escapes with U+FFFD.
	// Refuse those inputs before decoding, rather than silently losing bytes.
	if !pairedSurrogates(data) {
		return Counts{}, ErrEncoding
	}
	p := parser{decoder: json.NewDecoder(bytes.NewReader(data))}
	p.decoder.UseNumber()
	if _, err := p.value(0); err != nil {
		return Counts{}, err
	}
	if _, err := p.decoder.Token(); err != io.EOF {
		return Counts{}, ErrJSON
	}
	return p.counts, nil
}

type parser struct {
	decoder *json.Decoder
	counts  Counts
	values  int
}

// value returns whether the immediate value is nonempty. null, "", [] and {}
// are empty; numbers (including zero), booleans, whitespace strings, and any
// container with at least one member are nonempty. Duplicate keys stay visible.
func (p *parser) value(depth int) (bool, error) {
	p.values++
	if p.values > MaxValues {
		return false, ErrLimit
	}
	t, err := p.decoder.Token()
	if err != nil {
		return false, ErrJSON
	}
	switch v := t.(type) {
	case nil:
		return false, nil
	case string:
		if err := p.string(v); err != nil {
			return false, err
		}
		return v != "", nil
	case bool, json.Number:
		return true, nil
	case json.Delim:
		if v != '{' && v != '[' {
			return false, ErrJSON
		}
		if depth >= MaxDepth {
			return false, ErrLimit
		}
		nonempty := false
		for p.decoder.More() {
			nonempty = true
			secret := false
			if v == '{' {
				key, err := p.decoder.Token()
				if err != nil {
					return false, ErrJSON
				}
				name, ok := key.(string)
				if !ok {
					return false, ErrJSON
				}
				if err := p.string(name); err != nil {
					return false, err
				}
				secret = secretName(name)
			}
			populated, err := p.value(depth + 1)
			if err != nil {
				return false, err
			}
			if secret && populated {
				p.counts.SecretFields++
			}
		}
		end, err := p.decoder.Token()
		if err != nil || (v == '{' && end != json.Delim('}')) || (v == '[' && end != json.Delim(']')) {
			return false, ErrJSON
		}
		return nonempty, nil
	}
	return false, ErrJSON
}

func (p *parser) string(s string) error {
	if len(s) > MaxString {
		return ErrLimit
	}
	p.counts.GitHubTokens += tokenCount(s)
	return nil
}

func secretName(s string) bool {
	// ASCII names only: EqualFold's additional Unicode equivalences are not used.
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	switch strings.ToLower(s) {
	case "temp_clone_token", "token", "secret":
		return true
	}
	return false
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// Conservative shape matching, not provider authentication: gh[pousr]_ plus
// at least 36 ASCII alphanumerics, or github_pat_ plus at least 82 ASCII
// alphanumerics/underscores. Longer runs and embedded shapes also block.
// Checksums, live status, account identity and entropy are deliberately ignored.
func tokenCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		start, minimum, underscore := 0, 36, false
		if strings.HasPrefix(s[i:], "github_pat_") {
			start, minimum, underscore = i+11, 82, true
		} else if len(s)-i >= 4 && s[i] == 'g' && s[i+1] == 'h' && strings.ContainsRune("pousr", rune(s[i+2])) && s[i+3] == '_' {
			start = i + 4
		} else {
			continue
		}
		end := start
		for end < len(s) && end-start < minimum && (alnum(s[end]) || underscore && s[end] == '_') {
			end++
		}
		if end-start >= minimum {
			n++
		}
		// Do not skip a short/long body: it can contain another prefixed shape.
	}
	return n
}

// This preflight examines escapes inside strings only. Ordinary malformed JSON
// is left to the decoder; invalid hex or a lone surrogate is refused here.
func pairedSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		v, ok := hex4(data[i+1:])
		if !ok {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if len(data)-i <= 6 || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, ok := hex4(data[i+3:])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func hex4(s []byte) (uint16, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var v uint16
	for _, b := range s[:4] {
		v <<= 4
		switch {
		case b >= '0' && b <= '9':
			v += uint16(b - '0')
		case b >= 'a' && b <= 'f':
			v += uint16(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			v += uint16(b - 'A' + 10)
		default:
			return 0, false
		}
	}
	return v, true
}
