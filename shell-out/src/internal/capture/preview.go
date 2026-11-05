package capture

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const previewBytes = 4096
const previewLines = 40

type StreamStats struct {
	Observed int64  `json:"observed_bytes"`
	Saved    int64  `json:"saved_bytes"`
	Lines    int64  `json:"lines"`
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}
type stream struct {
	mu               sync.Mutex
	dst              io.Writer
	limit            int64
	stats            StreamStats
	head, tail       []byte
	binary, controls bool
	utfPending       []byte
	lastByte         byte
}

func newStream(dst io.Writer, limit int64) *stream {
	return &stream{dst: dst, limit: limit, stats: StreamStats{Complete: true}}
}
func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Observed += int64(len(p))
	if len(p) > 0 {
		s.lastByte = p[len(p)-1]
	}
	// Validate UTF-8 across write boundaries without retaining the output.
	check := p
	if len(s.utfPending) > 0 {
		check = append(s.utfPending, p...)
	}
	s.utfPending = nil
	for len(check) > 0 {
		if !utf8.FullRune(check) {
			s.utfPending = append([]byte(nil), check...)
			break
		}
		r, n := utf8.DecodeRune(check)
		if r == utf8.RuneError && n == 1 {
			s.binary = true
		}
		check = check[n:]
	}
	s.stats.Lines += int64(bytes.Count(p, []byte{'\n'}))
	for _, c := range p {
		if c == 0 {
			s.binary = true
		}
		if c < 32 && c != '\n' || c == 127 {
			s.controls = true
		}
	}
	if len(s.head) < previewBytes {
		n := min(len(p), previewBytes-len(s.head))
		s.head = append(s.head, p[:n]...)
	}
	if len(p) >= previewBytes {
		s.tail = append(s.tail[:0], p[len(p)-previewBytes:]...)
	} else {
		s.tail = append(s.tail, p...)
		if len(s.tail) > previewBytes {
			s.tail = append([]byte(nil), s.tail[len(s.tail)-previewBytes:]...)
		}
	}
	if s.stats.Error == "" {
		n := min(int64(len(p)), max(int64(0), s.limit-s.stats.Saved))
		wrote, e := s.dst.Write(p[:int(n)])
		s.stats.Saved += int64(wrote)
		if e != nil {
			s.stats.Error = e.Error()
		} else if int64(wrote) != n {
			s.stats.Error = io.ErrShortWrite.Error()
		} else if n < int64(len(p)) {
			s.stats.Error = "capture byte limit reached"
		}
		if s.stats.Error != "" {
			s.stats.Complete = false
		}
	}
	// Continue draining after a disk failure: command outcome remains independent.
	return len(p), nil
}
func (s *stream) fail(e error) {
	if e == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Complete = false
	if s.stats.Error == "" {
		s.stats.Error = e.Error()
	}
}
func (s *stream) snapshot() StreamStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	if st.Observed > 0 && s.lastByte != '\n' {
		st.Lines++
	}
	return st
}
func escaped(p []byte, limit, lines int) string {
	var b strings.Builder
	line := 0
	for len(p) > 0 && line < lines {
		r, n := utf8.DecodeRune(p)
		var piece string
		if r == utf8.RuneError && n == 1 {
			piece = fmt.Sprintf("\\x%02x", p[0])
		} else if r == '\n' {
			piece = "\n"
			line++
		} else if r == '\t' {
			piece = "\\t"
		} else if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			piece = fmt.Sprintf("\\u%04x", r)
		} else {
			piece = string(r)
		}
		if b.Len()+len(piece) > limit {
			break
		}
		b.WriteString(piece)
		p = p[n:]
	}
	return b.String()
}
func (s *stream) preview(progress bool) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binary || !progress && len(s.utfPending) > 0 {
		return []byte(fmt.Sprintf("[binary output: %d observed bytes]\n", s.stats.Observed))
	}
	logicalLines := s.stats.Lines
	if s.stats.Observed > 0 && s.lastByte != '\n' {
		logicalLines++
	}
	if !progress && s.stats.Observed <= previewBytes && logicalLines <= previewLines && utf8.Valid(s.head) && !s.controls {
		// C1 and direction controls still require escaping.
		clean := escaped(s.head, previewBytes*4, previewLines+1)
		if clean == string(s.head) {
			return append([]byte(nil), s.head...)
		}
	}
	if progress {
		return []byte("[tail preview]\n" + escaped(s.tail, 1024, 10) + "\n")
	}
	if s.stats.Observed <= previewBytes && logicalLines <= previewLines {
		return []byte(escaped(s.head, previewBytes, previewLines) + "\n[escaped preview]\n")
	}
	head := escaped(s.head, previewBytes/2, previewLines/2)
	// Keep the last lines, with a byte bound even for one giant line.
	tail := s.tail
	end := len(tail)
	if end > 0 && tail[end-1] == '\n' {
		end--
	}
	count := 0
	for i := end - 1; i >= 0; i-- {
		if tail[i] == '\n' {
			count++
			if count == previewLines/2 {
				tail = tail[i+1:]
				break
			}
		}
	}
	if len(tail) > previewBytes/2 {
		tail = tail[len(tail)-previewBytes/2:]
	}
	return []byte(head + "\n[... bounded preview; inspect private logs ...]\n" + escaped(tail, previewBytes/2, previewLines/2) + "\n")
}
