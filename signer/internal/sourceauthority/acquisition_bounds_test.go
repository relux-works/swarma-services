package sourceauthority

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func rawAcquisitionFixture(t *testing.T, wire string, reservation int64) (*acquisitionPhase, *sourceAcquisition) {
	t.Helper()
	limits := smallAcquisitionLimits()
	limits.header = reservation
	a, _ := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		c, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, wire)
	}, limits)
	return acquisitionTestPhase(t, a, 128, 8), a
}

func TestAcquisitionHeaderRepresentation(t *testing.T) {
	var many strings.Builder
	many.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&many, "H%04d: x\r\n", i)
	}
	many.WriteString("\r\na")
	if len(many.String())-1 != 30038 {
		t.Fatal("many-field fixture changed")
	}
	p, _ := rawAcquisitionFixture(t, many.String(), acquisitionHeaderMax)
	got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
	refuseAcquisition(t, got, e)
	if p.bytesLeft != 128 {
		t.Fatal("header refusal read payload")
	}
	// Wire-cap neighbors, with sparse scalar storage and no map amplification.
	capacity := (acquisitionHeaderMax - acquisitionParserFixed) / 16
	base := "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Sparse: "
	for _, delta := range []int{-1, 0, 1} {
		n := capacity + delta - len(base) - 4
		wire := base + strings.Repeat("x", n) + "\r\n\r\na"
		t.Run(fmt.Sprintf("sparse/%d", delta), func(t *testing.T) {
			p, _ := rawAcquisitionFixture(t, wire, acquisitionHeaderMax)
			got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
			if delta <= 0 {
				if e != nil || string(got.body) != "a" {
					t.Fatalf("sparse neighbor: %v", e)
				}
			} else {
				refuseAcquisition(t, got, e)
			}
		})
	}
	// The parser retains its HTTP semantics: LF, folding, duplicate equal lengths,
	// mixed-case keys and repeated values all pass through the standard parser.
	for _, wire := range []string{
		"HTTP/1.1 200 OK\nContent-Length: 1\nX-Fold: a\n b\n\na",
		"HTTP/1.1 200 OK\r\ncontent-length: 1\r\nContent-Length: 1\r\nX-Repeat: a\r\nX-Repeat: b\r\n\r\na",
	} {
		p, _ := rawAcquisitionFixture(t, wire, acquisitionHeaderMax)
		got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
		if e != nil || string(got.body) != "a" {
			t.Fatalf("HTTP semantics: %v", e)
		}
	}
}

func TestAcquisitionParserAllocationReservation(t *testing.T) {
	// Exercise maximum sparse wire, many distinct/duplicate fields, folded
	// scalars and malformed diagnostics. Input construction is outside accounting.
	cases := []string{}
	for _, kind := range []string{"distinct", "duplicate", "fold", "malformed"} {
		for n := 0; n <= 140; n++ {
			var b strings.Builder
			b.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n")
			for i := 0; i < n; i++ {
				switch kind {
				case "distinct":
					fmt.Fprintf(&b, "H%03d: x\r\n", i)
				case "duplicate":
					b.WriteString("X: x\r\n")
				case "fold":
					b.WriteString(" x\r\n")
				case "malformed":
					b.WriteString("X: \x01\r\n")
				}
			}
			b.WriteString("\r\na")
			cases = append(cases, b.String())
		}
	}
	for _, n := range []int{100, 1000, 3900, 4000, 5000} {
		cases = append(cases, "HTTP/1.1 200 OK\r\nX: "+strings.Repeat("x", n)+"\r\nContent-Length: 1\r\n\r\na")
	}
	maxAllocated := uint64(0)
	accepted := 0
	for _, wire := range cases {
		parse := func() {
			r := bufio.NewReaderSize(strings.NewReader(wire), 64)
			h, e := acquisitionHeaders(r, acquisitionHeaderMax)
			if e != nil {
				return
			}
			_, _ = http.ReadResponse(bufio.NewReaderSize(io.MultiReader(bytes.NewReader(h), r), 64), nil)
		}
		if _, e := acquisitionHeaders(bufio.NewReaderSize(strings.NewReader(wire), 64), acquisitionHeaderMax); e == nil {
			accepted++
		}
		parse()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		const runs = 4
		for i := 0; i < runs; i++ {
			parse()
		}
		runtime.ReadMemStats(&after)
		allocation := (after.TotalAlloc - before.TotalAlloc) / runs
		if allocation > maxAllocated {
			maxAllocated = allocation
		}
		if allocation > acquisitionHeaderMax {
			t.Fatalf("parser allocation %d exceeds reservation; fixture bytes %d", allocation, len(wire))
		}
	}
	t.Logf("parser_cases=%d admitted_preflights=%d maximum_allocated_bytes=%d reservation=%d", len(cases), accepted, maxAllocated, acquisitionHeaderMax)
}

func TestAcquisitionTrailersBeforeAllocation(t *testing.T) {
	var fields strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&fields, "H%04d: x\r\n", i)
	}
	for _, wire := range []string{
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: " + strings.ReplaceAll(fields.String(), ": x\r\n", ",") + "\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n" + fields.String() + "\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX: " + strings.Repeat("x", 30000) + "\r\n\r\n",
	} {
		p, _ := rawAcquisitionFixture(t, wire, acquisitionHeaderMax)
		got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
		refuseAcquisition(t, got, e)
	}
	for _, suffix := range []string{"", "\r\n", "\r\n0\r\n", "\r\n0\r\n\n", "\r\n0\r\n\r\n"} {
		wire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd" + suffix
		p, _ := rawAcquisitionFixture(t, wire, acquisitionHeaderMax)
		got, e := p.acquire("metadata", 4, acquisitionHeaderMax)
		if suffix == "\r\n0\r\n\r\n" {
			if e != nil || string(got.body) != "abcd" {
				t.Fatalf("exact chunk neighbor: %v", e)
			}
		} else {
			refuseAcquisition(t, got, e)
		}
	}
}

func TestAcquisitionHandshakeCancellationJoins(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	fdsBefore, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	gBefore := runtime.NumGoroutine()
	for attempt := 0; attempt < 40; attempt++ {
		ln, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		hello, serverDone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(serverDone)
			c, e := ln.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			var b [1]byte
			if _, e = io.ReadFull(c, b[:]); e != nil {
				return
			}
			close(hello)
			_, _ = io.Copy(io.Discard, c)
		}()
		a, e := newSourceAcquisition(acquisitionInstallation{provider: "synthetic", origin: "https://" + ln.Addr().String(), limits: smallAcquisitionLimits(), endpoints: map[string]acquisitionEndpoint{"metadata": {path: "/body", kind: metadataResponse}}})
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		p, e := a.begin(ctx, 128, 8)
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
			if e == nil || got.body != nil {
				t.Error("canceled TLS returned material")
			}
		}()
		select {
		case <-hello:
		case <-time.After(time.Second):
			t.Fatal("no client hello")
		}
		if fresh, e := a.begin(ctx, 128, 8); e == nil {
			fresh.close()
			t.Fatal("overlap admitted")
		}
		p.close() // Cancellation retains the gate until acquire's cleanup completes.
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("TLS cleanup failed within original phase")
		}
		freshCtx, freshCancel := context.WithTimeout(context.Background(), time.Second)
		fresh, e := a.begin(freshCtx, 128, 8)
		if e != nil {
			t.Fatal("joined TLS did not release gate")
		}
		fresh.close()
		freshCancel()
		stack := make([]byte, 128<<10)
		n := runtime.Stack(stack, true)
		for _, worker := range []string{"net/http.(*Transport).dialConnFor", "crypto/tls.(*Conn).clientHandshake", "crypto/tls.(*Conn).HandshakeContext"} {
			if strings.Contains(string(stack[:n]), worker) {
				t.Fatalf("gate released with prior TLS worker: %s", worker)
			}
		}
		_ = ln.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Fatal("socket not closed")
		}
	}
	waitAcquisition(t, func() bool { return runtime.NumGoroutine() <= gBefore })
	fdsAfter, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	if len(fdsAfter) > len(fdsBefore) {
		t.Fatalf("fd leak: %d -> %d", len(fdsBefore), len(fdsAfter))
	}
	t.Logf("stalled_TLS_attempts=40 outstanding_TLS_workers_at_gate_reuse=0 goroutines=%d->%d fds=%d->%d", gBefore, runtime.NumGoroutine(), len(fdsBefore), len(fdsAfter))
	// A responsive neighboring adapter remains usable after the stalled fixture.
	a, _ := acquisitionFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }, smallAcquisitionLimits())
	p := acquisitionTestPhase(t, a, 128, 8)
	got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
	if e != nil || string(got.body) != "ok" {
		t.Fatalf("responsive neighbor: %v", e)
	}
}

// Accept consumes exactly one stalled pre-TLS connection, synchronously in the
// fixture server's accept goroutine. Later connections use the normal TLS server.
type acquisitionStallFirst struct {
	net.Listener
	hello, stopped chan struct{}
	first          bool
}

func (l *acquisitionStallFirst) Accept() (net.Conn, error) {
	if !l.first {
		l.first = true
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		var b [1]byte
		if _, e = io.ReadFull(c, b[:]); e == nil {
			close(l.hello)
			_, _ = io.Copy(io.Discard, c)
		}
		_ = c.Close()
		close(l.stopped)
	}
	return l.Listener.Accept()
}
func TestAcquisitionResponsiveReuseAfterHandshakeCancellation(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	fixture := &acquisitionStallFirst{Listener: s.Listener, hello: make(chan struct{}), stopped: make(chan struct{})}
	s.Listener = fixture
	s.StartTLS()
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	a, e := newSourceAcquisition(acquisitionInstallation{provider: "synthetic", origin: s.URL, roots: roots, limits: smallAcquisitionLimits(), endpoints: map[string]acquisitionEndpoint{"metadata": {path: "/body", kind: metadataResponse}}})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, e := a.begin(ctx, 128, 8)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
		if e == nil || got.body != nil {
			t.Error("stalled TLS succeeded")
		}
	}()
	select {
	case <-fixture.hello:
	case <-time.After(time.Second):
		t.Fatal("fixture not stalled")
	}
	p.close()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not join")
	}
	fresh := acquisitionTestPhase(t, a, 128, 8)
	got, e := fresh.acquire("metadata", 16, acquisitionHeaderMax)
	if e != nil || string(got.body) != "ok" {
		t.Fatalf("same adapter responsive neighbor: %v", e)
	}
	select {
	case <-fixture.stopped:
	case <-time.After(time.Second):
		t.Fatal("prior socket retained")
	}
}

func TestAcquisitionUnknownDialLifetimeRetainsGate(t *testing.T) {
	// A closed loopback listener gives an inert failed-dial control.
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	origin := "https://" + ln.Addr().String()
	_ = ln.Close()
	a, e := newSourceAcquisition(acquisitionInstallation{provider: "synthetic", origin: origin, limits: smallAcquisitionLimits(), endpoints: map[string]acquisitionEndpoint{"metadata": {path: "/body", kind: metadataResponse}}})
	if e != nil {
		t.Fatal(e)
	}
	p := acquisitionTestPhase(t, a, 128, 8)
	got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
	refuseAcquisition(t, got, e)
	p.close()
	if !p.uncertain || !a.busy.Load() {
		t.Fatal("unknown dial cleanup lost its gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if fresh, e := a.begin(ctx, 128, 8); e == nil {
		fresh.close()
		t.Fatal("unknown lifetime reused")
	}
}

func TestAcquisitionHeaderCountNeighbors(t *testing.T) {
	last := ""
	next := ""
	lastCount := 0
	for n := 0; n < 150; n++ {
		var b strings.Builder
		b.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "H%03d: x\r\n", i)
		}
		b.WriteString("\r\na")
		wire := b.String()
		if _, e := acquisitionHeaders(bufio.NewReaderSize(strings.NewReader(wire), 64), acquisitionHeaderMax); e != nil {
			next = wire
			break
		}
		last = wire
		lastCount = n + 1
	}
	if last == "" || next == "" {
		t.Fatal("missing count boundary")
	}
	p, _ := rawAcquisitionFixture(t, last, acquisitionHeaderMax)
	got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
	if e != nil || string(got.body) != "a" {
		t.Fatalf("count neighbor refused: %v", e)
	}
	p, _ = rawAcquisitionFixture(t, next, acquisitionHeaderMax)
	got, e = p.acquire("metadata", 16, acquisitionHeaderMax)
	refuseAcquisition(t, got, e)
	t.Logf("count boundary: admitted_fields=%d refused_fields=%d", lastCount, lastCount+1)
	// Even a short input cannot silently exceed an unfunded fixed reservation.
	p, _ = rawAcquisitionFixture(t, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na", acquisitionHeaderMax)
	got, e = p.acquire("metadata", 16, acquisitionParserFixed)
	refuseAcquisition(t, got, e)
}

func TestAcquisitionResolverLifetimeRetainsGate(t *testing.T) {
	// The sandbox hosts file maps this reserved example to loopback. No provider
	// lookup or external network is available. The fixture certificate names it.
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	_, port, e := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	if e != nil {
		t.Fatal(e)
	}
	a, e := newSourceAcquisition(acquisitionInstallation{provider: "synthetic", origin: "https://example.com:" + port, roots: roots, limits: smallAcquisitionLimits(), endpoints: map[string]acquisitionEndpoint{"metadata": {path: "/body", kind: metadataResponse}}})
	if e != nil {
		t.Fatal(e)
	}
	p := acquisitionTestPhase(t, a, 128, 8)
	got, e := p.acquire("metadata", 16, acquisitionHeaderMax)
	if e != nil || string(got.body) != "ok" {
		t.Fatalf("offline hosts/TLS control: %v", e)
	}
	got, e = p.acquire("metadata", 16, acquisitionHeaderMax)
	refuseAcquisition(t, got, e)
	p.close()
	if !p.uncertain || !a.busy.Load() {
		t.Fatal("resolver path released uncertain lifecycle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if fresh, e := a.begin(ctx, 128, 8); e == nil {
		fresh.close()
		t.Fatal("resolver lifetime reused")
	}
}
