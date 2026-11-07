package artifactsnapshot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type finalCloseErrorConn struct {
	net.Conn
	cause error
}

func (c *finalCloseErrorConn) Close() error {
	_ = c.Conn.Close()
	return c.cause
}

// Pair purely benign trees with independent cleanup failures in both Close
// paths. Wrapping a join or changing branch order must not hide a failure.
func TestConnectionCloseErrorTree(t *testing.T) {
	injected := errors.New("adapter resource cleanup failed")
	for _, tc := range []struct {
		name   string
		cause  error
		failed bool
	}{
		{"nil", nil, false},
		{"ordinary_cleanup", injected, true},
		{"closed", net.ErrClosed, false},
		{"pipe", io.ErrClosedPipe, false},
		{"wrapped_closed", fmt.Errorf("adapter: %w", net.ErrClosed), false},
		{"wrapped_pipe", fmt.Errorf("adapter: %w", io.ErrClosedPipe), false},
		{"joined_benign", errors.Join(net.ErrClosed, io.ErrClosedPipe), false},
		{"nested_benign", fmt.Errorf("adapter: %w", errors.Join(net.ErrClosed, fmt.Errorf("pipe: %w", io.ErrClosedPipe))), false},
		{"joined_closed_cleanup", errors.Join(net.ErrClosed, injected), true},
		{"joined_pipe_cleanup", errors.Join(io.ErrClosedPipe, injected), true},
		{"cleanup_first", errors.Join(injected, net.ErrClosed), true},
		{"nested_cleanup", errors.Join(io.ErrClosedPipe, fmt.Errorf("adapter: %w", errors.Join(net.ErrClosed, injected))), true},
	} {
		for _, cancelled := range []bool{false, true} {
			path := "final"
			if cancelled {
				path = "cancellation"
			}
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				parent := privateParent(t)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				reader, writer := net.Pipe()
				defer writer.Close()
				type outcome struct {
					snapshot *Snapshot
					err      error
				}
				done := make(chan outcome, 1)
				var conn net.Conn = &finalCloseErrorConn{reader, tc.cause}
				var first *firstCloseConn
				if cancelled {
					first = &firstCloseConn{
						Conn: reader, firstErr: tc.cause, reads: make(chan struct{}, 1),
						readUnblocked: make(chan struct{}), closeDone: make(chan struct{}),
					}
					conn = first
				}
				go func() {
					r := receipt([]byte("a"))
					s, err := Verify(ctx, parent, conn, r, r)
					done <- outcome{s, err}
				}()
				if cancelled {
					select {
					case <-first.reads:
					case <-time.After(time.Second):
						t.Fatal("blocked read not reached")
					}
					cancel()
				} else {
					if err := writer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := writer.Write([]byte("aa")); err != nil {
						t.Fatal(err)
					}
					_ = writer.Close() // Real peer EOF after two complete streams.
				}
				select {
				case got := <-done:
					if got.snapshot != nil {
						defer got.snapshot.Close()
					}
					if errors.Is(got.err, ErrCleanup) != tc.failed || errors.Is(got.err, injected) != tc.failed {
						t.Fatalf("cleanup classification/cause: %v; want failure=%v", got.err, tc.failed)
					}
					if cancelled {
						if got.snapshot != nil || !errors.Is(got.err, context.Canceled) {
							t.Fatalf("cancellation result: snapshot=%v err=%v", got.snapshot != nil, got.err)
						}
						if first.calls.Load() != 2 {
							t.Fatalf("expected callback and final Close; got %d", first.calls.Load())
						}
						select {
						case <-first.closeDone:
						default:
							t.Fatal("callback still running after return")
						}
					} else if tc.failed {
						if got.snapshot != nil {
							t.Fatal("cleanup failure published snapshot")
						}
					} else if got.snapshot == nil || got.err != nil {
						t.Fatalf("benign Close refused: snapshot=%v err=%v", got.snapshot != nil, got.err)
					}
				case <-time.After(time.Second):
					t.Fatal("verification did not finish")
				}
				emptyParent(t, parent)
			})
		}
	}
}
