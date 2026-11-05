package capture

import (
	"errors"
	"io"
	"sync"
	"time"
)

const PresentationTimeout = 150 * time.Millisecond

type packet struct {
	data    []byte
	barrier chan struct{}
}

// Presentation serializes a bounded queue of best-effort writes. A blocked
// caller-owned writer cannot block child lifecycle management. One worker may
// remain blocked until that writer is released; the CLI process can still exit.
// Write/Flush/Close must be called serially by the presentation owner.
type Presentation struct {
	queue chan packet
	mu    sync.Mutex
	err   error
}

func NewPresentation(w io.Writer) *Presentation {
	p := &Presentation{queue: make(chan packet, 4)}
	go func() {
		for item := range p.queue {
			if item.barrier != nil {
				close(item.barrier)
				continue
			}
			n, e := w.Write(item.data)
			if e == nil && n != len(item.data) {
				e = io.ErrShortWrite
			}
			if e != nil {
				p.mu.Lock()
				if p.err == nil {
					p.err = e
				}
				p.mu.Unlock()
			}
		}
	}()
	return p
}
func (p *Presentation) Write(data []byte) (int, error) {
	select {
	case p.queue <- packet{data: append([]byte(nil), data...)}:
		return len(data), nil
	default:
		return 0, errors.New("presentation queue full")
	}
}
func (p *Presentation) Flush() error {
	timer := time.NewTimer(PresentationTimeout)
	defer timer.Stop()
	done := make(chan struct{})
	select {
	case p.queue <- packet{barrier: done}:
	case <-timer.C:
		return errors.New("presentation deadline; output consumer blocked")
	}
	select {
	case <-done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.err
	case <-timer.C:
		return errors.New("presentation deadline; output consumer blocked")
	}
}
func (p *Presentation) Close() { close(p.queue) }
func presentation(w io.Writer) (*Presentation, func()) {
	if p, ok := w.(*Presentation); ok {
		return p, func() {}
	}
	p := NewPresentation(w)
	return p, p.Close
}
