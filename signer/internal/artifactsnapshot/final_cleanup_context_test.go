package artifactsnapshot

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type finalCleanupConn struct {
	net.Conn
	action    func()
	cause     error
	closes    atomic.Int32
	deadlines []time.Time
}

func (c *finalCleanupConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	c.action()
	return errors.Join(err, c.cause)
}

func (c *finalCleanupConn) SetReadDeadline(d time.Time) error {
	c.deadlines = append(c.deadlines, d)
	return c.Conn.SetReadDeadline(d)
}

// Cancellation happens inside the mandatory final Close, after valid real
// streams, private copies and EOF. The same original context governs return.
func TestFinalCleanupOriginalContext(t *testing.T) {
	independent := errors.New("independent adapter cleanup failure")
	jobCause := errors.New("original job stopped during final cleanup")
	for _, closeCase := range []struct {
		name string
		err  error
		bad  bool
	}{
		{"nil", nil, false},
		{"closed", net.ErrClosed, false},
		{"pipe", io.ErrClosedPipe, false},
		{"benign_join", errors.Join(net.ErrClosed, io.ErrClosedPipe), false},
		{"independent", independent, true},
		{"mixed_join", errors.Join(net.ErrClosed, independent), true},
	} {
		for _, mode := range []string{"active", "cancel", "deadline"} {
			t.Run(closeCase.name+"/"+mode, func(t *testing.T) {
				budget := 2 * time.Second
				if mode == "deadline" {
					budget = 100 * time.Millisecond
				}
				deadline := time.Now().Add(budget)
				base, stopDeadline := context.WithDeadlineCause(context.Background(), deadline, jobCause)
				defer stopDeadline()
				ctx, cancel := context.WithCancelCause(base)
				defer cancel(nil)
				reader, writer := net.Pipe()
				conn := &finalCleanupConn{Conn: reader, cause: closeCase.err}
				conn.action = func() {
					if ctx.Err() != nil {
						t.Error("context stopped before final Close control")
					}
					switch mode {
					case "cancel":
						cancel(jobCause)
					case "deadline":
						<-ctx.Done()
					}
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					defer writer.Close()
					_, _ = writer.Write([]byte("aa"))
				}()
				parent := privateParent(t)
				r := receipt([]byte("a"))
				snapshot, err := Verify(ctx, parent, conn, r, r)
				if snapshot != nil {
					defer snapshot.Close()
				}
				if conn.closes.Load() != 1 {
					t.Errorf("final cleanup closed connection %d times", conn.closes.Load())
				}
				if len(conn.deadlines) != 2 {
					t.Errorf("read budget count = %d, want two", len(conn.deadlines))
				}
				for _, got := range conn.deadlines {
					if !got.Equal(deadline) {
						t.Errorf("original deadline changed: got %v want %v", got, deadline)
					}
				}
				if errors.Is(err, ErrCleanup) != closeCase.bad || errors.Is(err, independent) != closeCase.bad {
					t.Errorf("cleanup classification/cause lost: %v", err)
				}
				if mode != "active" {
					if ctx.Err() == nil || snapshot != nil || !errors.Is(err, ctx.Err()) || !errors.Is(err, jobCause) {
						t.Errorf("original context lost: snapshot=%v err=%v context=%v cause=%v", snapshot != nil, err, ctx.Err(), context.Cause(ctx))
					}
				} else if closeCase.bad {
					if snapshot != nil {
						t.Error("cleanup failure published snapshot")
					}
				} else {
					if snapshot == nil || err != nil {
						t.Errorf("active positive failed: %v", err)
					} else {
						var got [1]byte
						if n, err := snapshot.ReadAt(got[:], 0); n != 1 || err != nil || got[0] != 'a' {
							t.Errorf("invalid snapshot bytes: %q %v", got, err)
						}
					}
				}
				if mode == "active" && errors.Is(err, jobCause) {
					t.Error("active control acquired cancellation cause")
				}
				emptyParent(t, parent)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("peer leaked")
				}
			})
		}
	}
}
