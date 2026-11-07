package artifactsnapshot

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Close unblocks the real pipe read but reports its cleanup result only once.
// Later closes deliberately return only net.ErrClosed, as an adapter may do.
type firstCloseConn struct {
	net.Conn
	calls         atomic.Int32
	reads         chan struct{}
	readUnblocked chan struct{}
	closeDone     chan struct{}
	releaseClose  chan struct{}
	firstErr      error
	holdClose     bool
}

func (c *firstCloseConn) Read(p []byte) (int, error) {
	c.reads <- struct{}{}
	n, err := c.Conn.Read(p)
	if err != nil {
		if !c.holdClose {
			<-c.closeDone
		}
		close(c.readUnblocked)
	}
	return n, err
}

func (c *firstCloseConn) Close() error {
	if c.calls.Add(1) != 1 {
		return net.ErrClosed
	}
	_ = c.Conn.Close()
	if c.holdClose {
		<-c.releaseClose
	}
	defer close(c.closeDone)
	return c.firstErr
}

// Each phase pairs successful and failed first closes. The held callback makes
// Read return before Close does, exercising reconciliation as well as retention.
func TestCancellationFirstClose(t *testing.T) {
	for _, phase := range []struct {
		name    string
		payload string
	}{{"first", ""}, {"second", "a"}, {"eof", "aa"}} {
		for _, hold := range []bool{false, true} {
			for _, fail := range []bool{false, true} {
				name := phase.name + map[bool]string{false: "/completed", true: "/running"}[hold] + map[bool]string{false: "/success", true: "/failure"}[fail]
				t.Run(name, func(t *testing.T) {
					parent := privateParent(t)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					reader, writer := net.Pipe()
					defer writer.Close()
					injected := errors.New("first connection close cleanup failure")
					conn := &firstCloseConn{
						Conn: reader, reads: make(chan struct{}, 4),
						readUnblocked: make(chan struct{}), closeDone: make(chan struct{}),
						releaseClose: make(chan struct{}), holdClose: hold,
					}
					if fail {
						conn.firstErr = injected
					}
					var releaseOnce sync.Once
					release := func() { releaseOnce.Do(func() { close(conn.releaseClose) }) }
					defer release()
					type outcome struct {
						snapshot *Snapshot
						err      error
					}
					done := make(chan outcome, 1)
					go func() {
						r := receipt([]byte("a"))
						s, err := Verify(ctx, parent, conn, r, r)
						done <- outcome{s, err}
					}()
					if phase.payload != "" {
						if err := writer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
							t.Fatal(err)
						}
						if _, err := writer.Write([]byte(phase.payload)); err != nil {
							t.Fatal(err)
						}
					}
					for i := 0; i <= len(phase.payload); i++ {
						select {
						case <-conn.reads:
						case <-time.After(time.Second):
							t.Fatal("intended blocked read not reached")
						}
					}
					cancel()
					select {
					case <-conn.readUnblocked:
					case <-time.After(time.Second):
						t.Fatal("cancellation did not unblock read")
					}
					if hold {
						select {
						case got := <-done:
							if got.snapshot != nil {
								_ = got.snapshot.Close()
							}
							t.Fatalf("returned before cancellation Close completed: %v", got.err)
						case <-time.After(25 * time.Millisecond):
						}
					}
					release()
					select {
					case got := <-done:
						if got.snapshot != nil {
							_ = got.snapshot.Close()
							t.Fatal("cancellation published snapshot")
						}
						if !errors.Is(got.err, context.Canceled) || errors.Is(got.err, ErrCleanup) != fail || errors.Is(got.err, injected) != fail {
							t.Fatalf("lost cancellation/cleanup classification or cause: %v; failure=%v", got.err, fail)
						}
						select {
						case <-conn.closeDone:
						default:
							t.Fatal("cancellation Close still running after return")
						}
					case <-time.After(time.Second):
						t.Fatal("verification did not finish within cancellation bound")
					}
					emptyParent(t, parent)
				})
			}
		}
	}
}
