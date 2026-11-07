package artifactsnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func receipt(data []byte) Receipt {
	sum := sha256.Sum256(data)
	return Receipt{hex.EncodeToString(sum[:]), int64(len(data))}
}

func privateParent(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return parent
}

func emptyParent(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("operation staging not cleaned: entries=%d error=%v", len(entries), err)
	}
}

func exchange(t *testing.T, parent string, data []byte, first, second Receipt) (*Snapshot, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, writer := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer writer.Close()
		_, _ = writer.Write(data)
	}()
	snapshot, err := Verify(ctx, parent, reader, first, second)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("builder connection not closed")
	}
	return snapshot, err
}

// Both real streams cross the copy buffer boundary; the owned read-only snapshot
// remains readable after all temporary names disappear and supports concurrent reads.
func TestVerifiedSnapshot(t *testing.T) {
	data := bytes.Repeat([]byte("unsigned-artifact\x00"), 4001)
	r := receipt(data)
	parent := privateParent(t)
	s, err := exchange(t, parent, append(append([]byte{}, data...), data...), r, r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	emptyParent(t, parent)
	if s.Receipt() != r {
		t.Fatal("receipt changed")
	}
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			got := make([]byte, len(data))
			if n, err := s.ReadAt(got, 0); err != nil || n != len(data) || !bytes.Equal(got, data) {
				t.Errorf("snapshot differs: size=%d error=%v", n, err)
			}
		}()
	}
	group.Wait()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed snapshot readable: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// Claims alone never admit bytes: each stream's hash, complete length and final
// EOF are checked; all refusals leave no snapshot or partial staging.
func TestStreamRefusals(t *testing.T) {
	data := []byte("artifact")
	r := receipt(data)
	valid := append(append([]byte{}, data...), data...)
	cases := []struct {
		name string
		data []byte
		err  error
	}{
		{"short_first", data[:len(data)-1], ErrStream},
		{"missing_second", data, ErrStream},
		{"short_second", valid[:len(valid)-1], ErrStream},
		{"wrong_first_hash", []byte("Artifactartifact"), ErrMismatch},
		{"wrong_second_hash", []byte("artifactArtifact"), ErrMismatch},
		{"wrong_both_hashes", []byte("ArtifactArtifact"), ErrMismatch},
		{"extra_byte", append(append([]byte{}, valid...), 0), ErrStream},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := privateParent(t)
			s, err := exchange(t, parent, tc.data, r, r)
			if s != nil || !errors.Is(err, tc.err) {
				t.Fatalf("snapshot=%v error=%v; want %v", s != nil, err, tc.err)
			}
			emptyParent(t, parent)
		})
	}
}

// Invalid, unequal or noncanonical receipt fields refuse before reading data.
func TestReceiptRefusals(t *testing.T) {
	r := receipt([]byte("a"))
	cases := []struct {
		name string
		r    Receipt
		err  error
	}{
		{"zero", Receipt{r.SHA256, 0}, ErrReceipt},
		{"negative", Receipt{r.SHA256, -1}, ErrReceipt},
		{"over_limit", Receipt{r.SHA256, MaxBytes + 1}, ErrReceipt},
		{"short_hash", Receipt{r.SHA256[:63], 1}, ErrReceipt},
		{"uppercase", Receipt{strings.ToUpper(r.SHA256), 1}, ErrReceipt},
		{"nonhex", Receipt{strings.Repeat("g", 64), 1}, ErrReceipt},
		{"unequal_size", Receipt{r.SHA256, 2}, ErrMismatch},
		{"unequal_hash", receipt([]byte("b")), ErrMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := privateParent(t)
			s, err := exchange(t, parent, nil, r, tc.r)
			if s != nil || !errors.Is(err, tc.err) {
				t.Fatalf("snapshot=%v error=%v; want %v", s != nil, err, tc.err)
			}
			emptyParent(t, parent)
		})
	}
	if !valid(Receipt{r.SHA256, MaxBytes}) {
		t.Fatal("inclusive protocol size ceiling refused")
	}
}

// The comparison examines real copied bytes rather than equating hash claims.
// This independent direct control can detect an omitted comparison even though
// obtaining a real SHA256 collision is outside the fixture's practical scope.
func TestCopiedBytesComparison(t *testing.T) {
	a := bytes.Repeat([]byte("a"), 70000)
	b := append([]byte{}, a...)
	if err := equal(context.Background(), bytes.NewReader(a), bytes.NewReader(b), int64(len(a))); err != nil {
		t.Fatal(err)
	}
	b[65536] = 'b'
	if err := equal(context.Background(), bytes.NewReader(a), bytes.NewReader(b), int64(len(a))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("different copied bytes accepted: %v", err)
	}
	if err := equal(context.Background(), bytes.NewReader(a), bytes.NewReader(a[:len(a)-1]), int64(len(a))); !errors.Is(err, ErrStorage) {
		t.Fatalf("short private copy accepted: %v", err)
	}
}

// Private staging rejects symlink roots and permissive roots without touching
// existing unrelated files in the parent.
func TestPrivateStorage(t *testing.T) {
	root := privateParent(t)
	other := filepath.Join(root, "unrelated")
	if err := os.WriteFile(other, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	r := receipt([]byte("a"))
	s, err := exchange(t, root, []byte("aa"), r, r)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if got, err := os.ReadFile(other); err != nil || string(got) != "retain" {
		t.Fatal("unrelated file changed")
	}
	link := filepath.Join(privateParent(t), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{link, link + "/", link + "/.", "relative", other, filepath.Join(root, "missing")} {
		s, err := exchange(t, parent, nil, r, r)
		if s != nil || !errors.Is(err, ErrStorage) {
			t.Fatalf("unsafe root accepted: snapshot=%v error=%v", s != nil, err)
		}
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	s, err = exchange(t, root, nil, r, r)
	if s != nil || !errors.Is(err, ErrStorage) {
		t.Fatalf("permissive root accepted: %v", err)
	}
}

// Cancellation closes a blocked peer without waiting for the 60s stream budget.
// The same applies to the EOF wait after two otherwise valid artifact streams.
func TestCancellation(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("a"), []byte("aa")} {
		t.Run(string(rune('0'+len(payload))), func(t *testing.T) {
			parent := privateParent(t)
			ctx, cancel := context.WithCancel(context.Background())
			ctx, deadlineCancel := context.WithTimeout(ctx, 5*time.Second)
			defer deadlineCancel()
			defer cancel()
			reader, writer := net.Pipe()
			defer writer.Close()
			observed := &readObservedConn{Conn: reader, reads: make(chan struct{}, 4)}
			done := make(chan error, 1)
			go func() {
				s, err := Verify(ctx, parent, observed, receipt([]byte("a")), receipt([]byte("a")))
				if s != nil {
					_ = s.Close()
					err = errors.New("cancelled verification returned snapshot")
				}
				done <- err
			}()
			if len(payload) > 0 {
				if _, err := writer.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			// Observe entry to the intended blocked read before cancellation.
			for i := 0; i <= len(payload); i++ {
				select {
				case <-observed.reads:
				case <-time.After(time.Second):
					t.Fatal("intended read was not reached")
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("wrong cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled read remains blocked")
			}
			emptyParent(t, parent)
		})
	}
}

type readObservedConn struct {
	net.Conn
	reads chan struct{}
}

func (c *readObservedConn) Read(p []byte) (int, error) {
	c.reads <- struct{}{}
	return c.Conn.Read(p)
}

type deadlineConn struct {
	net.Conn
	deadlines []time.Time
	fail      bool
}

func (c *deadlineConn) SetReadDeadline(d time.Time) error {
	c.deadlines = append(c.deadlines, d)
	if c.fail {
		return errors.New("deadline unsupported")
	}
	return c.Conn.SetReadDeadline(d)
}

// Both absolute stream deadlines are capped by the original job; EOF does not
// get a third deadline. A stalled peer must refuse even without cancelling ctx.
func TestDeadlines(t *testing.T) {
	parent := privateParent(t)
	r := receipt([]byte("a"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	job, _ := ctx.Deadline()
	reader, writer := net.Pipe()
	c := &deadlineConn{Conn: reader}
	go func() { defer writer.Close(); _, _ = writer.Write([]byte("aa")) }()
	s, err := Verify(ctx, parent, c, r, r)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if len(c.deadlines) != 2 || !c.deadlines[0].Equal(job) || !c.deadlines[1].Equal(job) {
		t.Fatalf("deadlines extended: %v", c.deadlines)
	}
	// A longer original job still gets only two absolute 60s stream budgets,
	// even when each stream needs multiple copy-buffer reads.
	data := bytes.Repeat([]byte("a"), 70000)
	longCtx, longCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer longCancel()
	reader, writer = net.Pipe()
	c = &deadlineConn{Conn: reader}
	go func() { defer writer.Close(); _, _ = writer.Write(append(append([]byte{}, data...), data...)) }()
	before := time.Now()
	s, err = Verify(longCtx, parent, c, receipt(data), receipt(data))
	after := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if len(c.deadlines) != 2 {
		t.Fatalf("per-read or EOF deadline renewal: %d", len(c.deadlines))
	}
	for _, d := range c.deadlines {
		if d.Before(before.Add(StreamBudget)) || d.After(after.Add(StreamBudget)) {
			t.Fatalf("wrong stream budget: %v", d.Sub(before))
		}
	}

	for _, fail := range []bool{false, true} {
		reader, writer := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		c := &deadlineConn{Conn: reader, fail: fail}
		s, err := Verify(ctx, parent, c, r, r)
		cancel()
		_ = writer.Close()
		if s != nil || err == nil {
			t.Fatal("stalled/unsupported-deadline peer admitted")
		}
		if fail && !errors.Is(err, ErrDeadline) {
			t.Fatalf("wrong deadline failure: %v", err)
		}
		emptyParent(t, parent)
	}
}

// Missing, renewed beyond the job ceiling and already expired deadlines refuse.
func TestJobDeadlineRequired(t *testing.T) {
	r := receipt([]byte("a"))
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	long, cancelLong := context.WithTimeout(context.Background(), 601*time.Second)
	defer cancelLong()
	for _, ctx := range []context.Context{nil, context.Background(), expired, long} {
		reader, writer := net.Pipe()
		s, err := Verify(ctx, privateParent(t), reader, r, r)
		_ = writer.Close()
		if s != nil || err == nil {
			t.Fatal("invalid job deadline admitted")
		}
	}
}

var _ io.ReaderAt = (*Snapshot)(nil)

type cleanupConn struct {
	net.Conn
	beforeRead func()
	closeError bool
}

func (c *cleanupConn) Read(p []byte) (int, error) {
	if c.beforeRead != nil {
		f := c.beforeRead
		c.beforeRead = nil
		f()
	}
	return c.Conn.Read(p)
}

func (c *cleanupConn) Close() error {
	err := c.Conn.Close()
	if c.closeError {
		return errors.New("fixture connection cleanup failed")
	}
	return err
}

// Failure to remove operation-owned staging or close the exchange is explicit;
// neither case publishes an otherwise verified snapshot.
func TestCleanupFailures(t *testing.T) {
	for _, storageFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "connection", true: "storage"}[storageFailure], func(t *testing.T) {
			parent := privateParent(t)
			reader, writer := net.Pipe()
			c := &cleanupConn{Conn: reader, closeError: !storageFailure}
			var operationDir string
			if storageFailure {
				c.beforeRead = func() {
					entries, err := os.ReadDir(parent)
					if err != nil || len(entries) != 1 {
						t.Fatalf("private directory not created: %v", err)
					}
					operationDir = filepath.Join(parent, entries[0].Name())
					if err := os.Chmod(operationDir, 0500); err != nil {
						t.Fatal(err)
					}
				}
				t.Cleanup(func() {
					_ = os.Chmod(operationDir, 0700)
					_ = os.RemoveAll(operationDir)
				})
			}
			go func() { defer writer.Close(); _, _ = writer.Write([]byte("aa")) }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r := receipt([]byte("a"))
			s, err := Verify(ctx, parent, c, r, r)
			if s != nil || !errors.Is(err, ErrCleanup) {
				t.Fatalf("cleanup failure hidden: snapshot=%v error=%v", s != nil, err)
			}
			if storageFailure && !errors.Is(err, ErrStorage) {
				t.Fatalf("original storage failure lost: %v", err)
			}
			if !storageFailure {
				emptyParent(t, parent)
			}
		})
	}
}
