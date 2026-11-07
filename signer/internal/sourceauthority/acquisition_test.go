package sourceauthority

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// All network activity is loopback synthetic TLS inside the offline sandbox.
// A fixture certificate is transport trust only, never provider admission.
func acquisitionFixture(t *testing.T, h http.HandlerFunc, limits acquisitionLimits) (*sourceAcquisition, *atomic.Int32) {
	t.Helper()
	var open atomic.Int32
	s := httptest.NewUnstartedServer(h)
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			open.Add(1)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			open.Add(-1)
		}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	a, err := newSourceAcquisition(acquisitionInstallation{
		provider: "synthetic", origin: s.URL, roots: roots, limits: limits,
		endpoints: map[string]acquisitionEndpoint{
			"metadata": {path: "/body", kind: metadataResponse},
			"commit":   {path: "/body", kind: rawCommitResponse},
			"neighbor": {path: "/neighbor", kind: metadataResponse},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, &open
}
func smallAcquisitionLimits() acquisitionLimits {
	return acquisitionLimits{header: 4096, metadata: 16, commit: 8, aggregate: 128, responses: 8}
}
func acquisitionTestPhase(t *testing.T, a *sourceAcquisition, bytes int64, responses int) *acquisitionPhase {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	p, err := a.begin(ctx, bytes, responses)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.close)
	return p
}
func waitAcquisition(t *testing.T, ready func() bool) {
	t.Helper()
	d := time.Now().Add(time.Second)
	for !ready() {
		if time.Now().After(d) {
			t.Fatal("cleanup/fixture barrier timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func refuseAcquisition(t *testing.T, got acquiredResponse, err error) {
	t.Helper()
	if err == nil || got.body != nil || got.status != 0 {
		t.Fatalf("failure returned material: bytes=%d status=%d error=%v", len(got.body), got.status, err)
	}
}

func TestAcquisitionBodyBoundaries(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		for _, endpoint := range []string{"commit", "metadata"} {
			limit := 8
			if endpoint == "metadata" {
				limit = 16
			}
			for _, n := range []int{0, limit - 1, limit, limit + 1} {
				t.Run(fmt.Sprintf("%s/chunked=%t/bytes=%d", endpoint, chunked, n), func(t *testing.T) {
					a, open := acquisitionFixture(t, func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodGet || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
							t.Error("unexpected request authority or encoding")
						}
						if chunked {
							w.WriteHeader(200)
							w.(http.Flusher).Flush()
						} else {
							w.Header().Set("Content-Length", strconv.Itoa(n))
						}
						_, _ = io.WriteString(w, strings.Repeat("x", n))
					}, smallAcquisitionLimits())
					p := acquisitionTestPhase(t, a, 128, 8)
					got, err := p.acquire(endpoint, 64, 4096)
					if n > limit {
						refuseAcquisition(t, got, err)
						want := int64(128)
						if chunked {
							want -= int64(limit + 1)
						}
						if p.bytesLeft != want {
							t.Fatalf("overflow/declared accounting: %d want %d", p.bytesLeft, want)
						}
					} else if err != nil || string(got.body) != strings.Repeat("x", n) || got.status != 200 || p.bytesLeft != 128-int64(n) {
						t.Fatalf("bounded neighbor failed: bytes=%d left=%d error=%v", len(got.body), p.bytesLeft, err)
					}
					waitAcquisition(t, func() bool { return open.Load() == 0 })
				})
			}
		}
	}
}

func TestAcquisitionRemainingBudgets(t *testing.T) {
	for _, tc := range []struct {
		name            string
		length          int
		aggregate, body int64
		chunked         bool
		success         bool
		used            int64
	}{
		{"body-stricter", 5, 128, 4, false, false, 0},
		{"aggregate-stricter-declared", 5, 4, 16, false, false, 0},
		{"aggregate-no-unfunded-probe", 5, 4, 16, true, false, 4},
		{"probe-funded", 5, 5, 4, true, false, 5},
		{"aggregate-exact-declared", 4, 4, 16, false, true, 4},
		// HTTP framing may prove EOF alongside the last four payload bytes.
		{"chunked-exact-framed-eof", 4, 4, 16, true, true, 4},
		{"chunked-neighbor", 4, 5, 16, true, true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.chunked {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				} else {
					w.Header().Set("Content-Length", strconv.Itoa(tc.length))
				}
				_, _ = io.WriteString(w, strings.Repeat("x", tc.length))
			}, smallAcquisitionLimits())
			p := acquisitionTestPhase(t, a, tc.aggregate, 8)
			got, err := p.acquire("metadata", tc.body, 4096)
			if tc.success {
				if err != nil || len(got.body) != tc.length {
					t.Fatalf("neighbor: %v", err)
				}
			} else {
				refuseAcquisition(t, got, err)
			}
			if p.bytesLeft != tc.aggregate-tc.used {
				t.Fatalf("used %d want %d", tc.aggregate-p.bytesLeft, tc.used)
			}
		})
	}
	var calls atomic.Int32
	a, _ := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "a") }, smallAcquisitionLimits())
	p := acquisitionTestPhase(t, a, 128, 1)
	if _, err := p.acquire("metadata", 16, 4096); err != nil {
		t.Fatal(err)
	}
	got, err := p.acquire("metadata", 16, 4096)
	refuseAcquisition(t, got, err)
	if calls.Load() != 1 || p.responsesLeft != 0 {
		t.Fatal("response budget bypassed")
	}
}

func TestAcquisitionRefusalsAndErrorBodies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		encoding string
		n        int
		used     int64
	}{
		{"error-body", 403, "", 7, 7}, {"error-overflow", 500, "", 17, 17},
		{"redirect", 302, "", 3, 3}, {"gzip", 200, "gzip", 3, 0},
		{"encoding-list", 200, "identity, gzip", 3, 0}, {"partial", 206, "", 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var neighbors atomic.Int32
			a, open := acquisitionFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/neighbor" {
					neighbors.Add(1)
				}
				w.Header().Set("Location", "/neighbor")
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
				w.(http.Flusher).Flush()
				_, _ = io.WriteString(w, strings.Repeat("x", tc.n))
			}, smallAcquisitionLimits())
			p := acquisitionTestPhase(t, a, 128, 8)
			got, err := p.acquire("metadata", 16, 4096)
			refuseAcquisition(t, got, err)
			if p.bytesLeft != 128-tc.used || neighbors.Load() != 0 {
				t.Fatalf("error/redirect accounting: left=%d followed=%d", p.bytesLeft, neighbors.Load())
			}
			got, err = p.acquire("neighbor", 16, 4096)
			refuseAcquisition(t, got, err)
			if p.responsesLeft != 7 {
				t.Fatal("failed phase retried")
			}
			waitAcquisition(t, func() bool { return open.Load() == 0 })
		})
	}
}

func TestAcquisitionMalformedHTTPAndHeaders(t *testing.T) {
	for _, wire := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nab",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\nab\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Proof\r\n\r\n1\r\na\r\n0\r\nX-Proof: x\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-Proof: x\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Range: bytes 0-1/5\r\nContent-Length: 2\r\n\r\nab",
		"HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 3000) + "\r\nContent-Length: 1\r\n\r\na",
		"HTTP/1.1 103 Early Hints\r\nLink: </neighbor>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
		"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n",
	} {
		t.Run(fmt.Sprintf("wire-%d", len(wire)), func(t *testing.T) {
			a, _ := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				c, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				_, _ = io.WriteString(c, wire)
			}, smallAcquisitionLimits())
			p := acquisitionTestPhase(t, a, 128, 8)
			got, err := p.acquire("metadata", 16, 4096)
			refuseAcquisition(t, got, err)
		})
	}
	a, _ := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Extra", strings.Repeat("x", 300))
		_, _ = io.WriteString(w, "a")
	}, smallAcquisitionLimits())
	p := acquisitionTestPhase(t, a, 128, 8)
	got, err := p.acquire("metadata", 16, 256)
	refuseAcquisition(t, got, err)
}

func TestAcquisitionActualCeilingStreams(t *testing.T) {
	for _, endpoint := range []string{"commit", "metadata"} {
		limit := acquisitionCommitMax
		if endpoint == "metadata" {
			limit = acquisitionBodyMax
		}
		for _, n := range []int{limit - 1, limit, limit + 1} {
			t.Run(fmt.Sprintf("%s/%d", endpoint, n), func(t *testing.T) {
				limits := acquisitionLimits{header: acquisitionHeaderMax, metadata: acquisitionBodyMax, commit: acquisitionCommitMax, aggregate: 64 << 20, responses: 4}
				a, open := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					block := strings.Repeat("x", 8192)
					for left := n; left > 0; {
						take := min(left, len(block))
						if _, err := io.WriteString(w, block[:take]); err != nil {
							return
						}
						left -= take
					}
				}, limits)
				p := acquisitionTestPhase(t, a, 64<<20, 4)
				got, err := p.acquire(endpoint, int64(limit), acquisitionHeaderMax)
				if n > limit {
					refuseAcquisition(t, got, err)
				} else if err != nil || len(got.body) != n || got.body[0] != 'x' || got.body[n-1] != 'x' {
					t.Fatalf("actual ceiling neighbor failed: size=%d error=%v", len(got.body), err)
				}
				if p.bytesLeft != 64<<20-int64(n) {
					t.Fatalf("actual ceiling accounting: left=%d", p.bytesLeft)
				}
				waitAcquisition(t, func() bool { return open.Load() == 0 })
			})
		}
	}
}

func TestAcquisitionInstallationOwnership(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/body" {
			t.Error("mutable endpoint escaped installation")
		}
		_, _ = io.WriteString(w, strconv.Itoa(int(calls.Add(1))))
	}))
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	endpoints := map[string]acquisitionEndpoint{"metadata": {path: "/body", kind: metadataResponse}}
	config := acquisitionInstallation{provider: "synthetic", origin: s.URL, roots: roots, limits: smallAcquisitionLimits(), endpoints: endpoints}
	a, err := newSourceAcquisition(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoints["metadata"] = acquisitionEndpoint{path: "/other", kind: rawCommitResponse}
	delete(endpoints, "metadata")
	config.origin = "https://other.invalid"
	config.limits.metadata = 0
	if a.roots == roots {
		t.Fatal("public TLS roots not defensively owned")
	}
	p := acquisitionTestPhase(t, a, 128, 8)
	first, err := p.acquire("metadata", 16, 4096)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.acquire("metadata", 16, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.body) != "1" || string(second.body) != "2" {
		t.Fatal("response byte ownership lost")
	}
	second.body[0] = 'z'
	if string(first.body) != "1" {
		t.Fatal("response storage aliases")
	}
}

func TestAcquisitionDoesNotInheritContextHooks(t *testing.T) {
	a, _ := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "a") }, smallAcquisitionLimits())
	var hooks atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { hooks.Add(1) }})
	p, err := a.begin(ctx, 128, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if _, err = p.acquire("metadata", 16, 4096); err != nil {
		t.Fatal(err)
	}
	if hooks.Load() != 0 {
		t.Fatal("untrusted context supplied transport hooks")
	}
}

func TestAcquisitionCancellationAndNoQueue(t *testing.T) {
	for _, closePhase := range []bool{false, true} {
		t.Run(fmt.Sprintf("close-phase=%t", closePhase), func(t *testing.T) {
			started, canceled, late := make(chan struct{}), make(chan struct{}), make(chan struct{})
			a, open := acquisitionFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
				close(canceled)
				// Deliberately attempt completion after cancellation.
				_, _ = io.WriteString(w, "late")
				close(late)
			}, smallAcquisitionLimits())
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			p, err := a.begin(ctx, 128, 8)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			deadline, _ := p.ctx.Deadline()
			want, _ := ctx.Deadline()
			if !deadline.Equal(want) {
				t.Fatal("deadline renewed")
			}
			type result struct {
				r acquiredResponse
				e error
			}
			done := make(chan result, 1)
			go func() { r, e := p.acquire("metadata", 16, 4096); done <- result{r, e} }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("blocked body read not reached")
			}
			if other, e := a.begin(ctx, 128, 8); e == nil {
				other.close()
				t.Fatal("occupied adapter queued/admitted")
			}
			got, e := p.acquire("neighbor", 16, 4096)
			refuseAcquisition(t, got, e)
			if closePhase {
				p.close()
			} else {
				cancel()
			}
			select {
			case r := <-done:
				refuseAcquisition(t, r.r, r.e)
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt blocked read")
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("active body connection not closed")
			}
			select {
			case <-late:
			case <-time.After(time.Second):
				t.Fatal("late fixture completion hung")
			}
			waitAcquisition(t, func() bool { return open.Load() == 0 })
			p.close()
			fresh := acquisitionTestPhase(t, a, 128, 8)
			fresh.close()
		})
	}
}

func TestAcquisitionAbsoluteDeadline(t *testing.T) {
	var calls atomic.Int32
	a, open := acquisitionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, "a")
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, smallAcquisitionLimits())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p, err := a.begin(ctx, 128, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if _, err = p.acquire("metadata", 16, 4096); err != nil {
		t.Fatal(err)
	}
	got, err := p.acquire("metadata", 16, 4096)
	refuseAcquisition(t, got, err)
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatal("operation did not preserve absolute deadline")
	}
	waitAcquisition(t, func() bool { return open.Load() == 0 })
}

func TestAcquisitionProtectedConfiguration(t *testing.T) {
	for _, origin := range []string{"http://fixture.invalid", "https://Fixture.invalid", "https://fixture.invalid/", "https://user@fixture.invalid", "https://fixture.invalid:443", "https://fixture.invalid:0444", "https://fixture.invalid?x=y", "https://fixture.invalid#x", "https://fixture.invalid.", "https://fixture..invalid", "https://fixture.invalid:"} {
		_, err := newSourceAcquisition(acquisitionInstallation{provider: "synthetic", origin: origin, limits: smallAcquisitionLimits(), endpoints: map[string]acquisitionEndpoint{"a": {path: "/a", kind: metadataResponse}}})
		if err == nil {
			t.Fatalf("noncanonical origin admitted: %s", origin)
		}
	}
	for _, p := range []string{"//other.invalid/a", "/a/../b", "/a/./b", "/a%2fb", "/a?x=y", "/a#x", "/a\\b", "/a/", "relative", "/a\n"} {
		if canonicalAcquisitionPath(p) {
			t.Fatalf("noncanonical path admitted: %q", p)
		}
	}
	var calls atomic.Int32
	a, _ := acquisitionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/body" {
			t.Error("installation changed")
		}
		_, _ = io.WriteString(w, "a")
	}, smallAcquisitionLimits())
	if p, err := a.begin(context.Background(), 128, 8); err == nil {
		p.close()
		t.Fatal("missing deadline accepted")
	}
	long, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if p, err := a.begin(long, 128, 8); err == nil {
		p.close()
		t.Fatal("fresh overlong budget accepted")
	}
	p := acquisitionTestPhase(t, a, 128, 8)
	got, err := p.acquire("https://other.invalid/", 16, 4096)
	refuseAcquisition(t, got, err)
	if calls.Load() != 0 {
		t.Fatal("unknown endpoint reached network")
	}
	if _, err = p.acquire("metadata", 16, 4096); err != nil {
		t.Fatal(err)
	}
}

func TestAcquisitionCeilings(t *testing.T) {
	base := acquisitionLimits{header: acquisitionHeaderMax, metadata: acquisitionBodyMax, commit: acquisitionCommitMax, aggregate: acquisitionAggregateMax, responses: acquisitionResponsesMax}
	makeConfig := func(l acquisitionLimits) acquisitionInstallation {
		return acquisitionInstallation{provider: "synthetic", origin: "https://fixture.invalid", limits: l, endpoints: map[string]acquisitionEndpoint{"a": {path: "/a", kind: metadataResponse}}}
	}
	if _, err := newSourceAcquisition(makeConfig(base)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		l := base
		switch i {
		case 0:
			l.header++
		case 1:
			l.metadata++
		case 2:
			l.commit++
		case 3:
			l.aggregate++
		case 4:
			l.responses++
		}
		if _, err := newSourceAcquisition(makeConfig(l)); err == nil {
			t.Fatal("ceiling raised")
		}
	}
	for i := 0; i < 5; i++ {
		l := base
		switch i {
		case 0:
			l.header = 0
		case 1:
			l.metadata = 0
		case 2:
			l.commit = 0
		case 3:
			l.aggregate = 0
		case 4:
			l.responses = 0
		}
		if _, err := newSourceAcquisition(makeConfig(l)); err == nil {
			t.Fatal("implicit allocation accepted")
		}
	}
}

func TestAcquisitionRepeatedCleanup(t *testing.T) {
	a, open := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "a") }, smallAcquisitionLimits())
	// Warm the runtime/TLS before taking process-local leak measurements.
	for i := 0; i < 2; i++ {
		p := acquisitionTestPhase(t, a, 128, 8)
		if _, err := p.acquire("metadata", 16, 4096); err != nil {
			t.Fatal(err)
		}
		p.close()
	}
	waitAcquisition(t, func() bool { return open.Load() == 0 })
	fdBefore, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	gBefore := runtime.NumGoroutine()
	for i := 0; i < 24; i++ {
		p := acquisitionTestPhase(t, a, 128, 8)
		if _, err := p.acquire("metadata", 16, 4096); err != nil {
			t.Fatal(err)
		}
		p.close()
	}
	waitAcquisition(t, func() bool { return open.Load() == 0 && runtime.NumGoroutine() <= gBefore })
	fdAfter, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(fdAfter) > len(fdBefore) {
		t.Fatalf("file descriptors grew: %d -> %d", len(fdBefore), len(fdAfter))
	}
	t.Logf("synthetic TLS cleanup: connections=%d goroutines=%d->%d fds=%d->%d", open.Load(), gBefore, runtime.NumGoroutine(), len(fdBefore), len(fdAfter))
}
