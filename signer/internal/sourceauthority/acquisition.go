package sourceauthority

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	acquisitionHeaderMax    = 64 << 10
	acquisitionParserFixed  = 32 << 10
	acquisitionBodyMax      = 16 << 20
	acquisitionCommitMax    = 1 << 20
	acquisitionAggregateMax = 512 << 20
	acquisitionResponsesMax = 1024
)

type acquisitionKind uint8

const (
	metadataResponse acquisitionKind = iota + 1
	rawCommitResponse
)

// These private values belong to protected source installation, never Request.
// No real provider installation or credentials are supplied by this component.
type acquisitionEndpoint struct {
	path string
	kind acquisitionKind
}
type acquisitionLimits struct {
	header, metadata, commit, aggregate int64
	responses                           int
}
type acquisitionInstallation struct {
	provider, origin string
	endpoints        map[string]acquisitionEndpoint
	limits           acquisitionLimits
	// Optional public CA roots, owned by installation. Nil uses system TLS roots.
	roots *x509.CertPool
}
type installedEndpoint struct {
	url  string
	kind acquisitionKind
}

// sourceAcquisition is the concrete transport owned by a future trusted Source.
// It neither implements Source nor manufactures an Observation. There is no
// public client, transport injection, callback, URL or header request option.
type sourceAcquisition struct {
	provider  string
	endpoints map[string]installedEndpoint
	limits    acquisitionLimits
	roots     *x509.CertPool
	busy      atomic.Bool
}

func newSourceAcquisition(c acquisitionInstallation) (*sourceAcquisition, error) {
	l := c.limits
	if !ascii(c.provider, 128) || l.header <= 0 || l.header > acquisitionHeaderMax ||
		l.metadata <= 0 || l.metadata > acquisitionBodyMax || l.commit <= 0 || l.commit > acquisitionCommitMax ||
		l.aggregate <= 0 || l.aggregate > acquisitionAggregateMax || l.responses <= 0 || l.responses > acquisitionResponsesMax ||
		len(c.endpoints) == 0 || len(c.endpoints) > acquisitionResponsesMax {
		return nil, unavailable("acquisition_configuration")
	}
	u, err := url.Parse(c.origin)
	if err != nil || !canonicalAcquisitionOrigin(u, c.origin) {
		return nil, unavailable("acquisition_configuration")
	}
	a := &sourceAcquisition{provider: c.provider, limits: l, endpoints: make(map[string]installedEndpoint, len(c.endpoints))}
	if c.roots != nil {
		a.roots = c.roots.Clone()
	}
	for name, e := range c.endpoints {
		if !ascii(name, 128) || !canonicalAcquisitionPath(e.path) || (e.kind != metadataResponse && e.kind != rawCommitResponse) {
			return nil, unavailable("acquisition_configuration")
		}
		a.endpoints[name] = installedEndpoint{c.origin + e.path, e.kind}
	}
	return a, nil
}

func canonicalAcquisitionOrigin(u *url.URL, original string) bool {
	if u == nil || !ascii(original, 512) || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.Host != strings.ToLower(u.Host) || original != "https://"+u.Host {
		return false
	}
	h := u.Hostname()
	if h == "" || strings.HasSuffix(h, ".") {
		return false
	}
	// Keep the accepted spelling deliberately narrow; no escapes, Unicode,
	// IPv6 zone IDs, user info, query or alternate URL interpretation.
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || n == 443 {
			return false
		}
	} else if strings.Contains(u.Host, ":") {
		return false
	}
	return true
}

func canonicalAcquisitionPath(p string) bool {
	if !ascii(p, 2048) || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "//") {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/-._~", c)) {
			return false
		}
	}
	return true
}

// A phase owns the adapter gate through cleanup. Its deadline is inherited
// exactly from the enclosing authority phase; subcalls never renew 30 seconds.
type acquisitionPhase struct {
	source                           *sourceAcquisition
	ctx                              context.Context
	cancel                           context.CancelFunc
	mu                               sync.Mutex
	active, closed, failed, released bool
	uncertain                        bool
	bytesLeft                        int64
	responsesLeft                    int
}

// Preserve the phase's cancellation/deadline, without inheriting caller trace
// hooks or context-based transport/credential options at this private boundary.
type acquisitionContext struct{ context.Context }

func (acquisitionContext) Value(any) any { return nil }

// Socket deadlines and context timer callbacks can become observable in either
// order. Admission and material return use the actual absolute deadline too.
func acquisitionExpired(ctx context.Context) bool {
	d, ok := ctx.Deadline()
	return !ok || ctx.Err() != nil || !time.Now().Before(d)
}

func (a *sourceAcquisition) begin(ctx context.Context, bytesLeft int64, responsesLeft int) (*acquisitionPhase, error) {
	if a == nil || ctx == nil {
		return nil, unavailable("acquisition_unavailable")
	}
	d, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || time.Until(d) <= 0 || time.Until(d) > AuthorityBudget ||
		bytesLeft <= 0 || responsesLeft <= 0 || !a.busy.CompareAndSwap(false, true) {
		return nil, unavailable("acquisition_unavailable")
	}
	child, cancel := context.WithCancel(acquisitionContext{ctx})
	return &acquisitionPhase{source: a, ctx: child, cancel: cancel,
		bytesLeft: min(bytesLeft, a.limits.aggregate), responsesLeft: min(responsesLeft, a.limits.responses)}, nil
}

func (p *acquisitionPhase) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cancel()
	p.releaseLocked()
}
func (p *acquisitionPhase) releaseLocked() {
	if p.closed && !p.active && !p.released && !p.uncertain {
		p.released = true
		p.source.busy.Store(false)
	}
}

// Only bounded owned bytes and minimal public transport metadata cross this
// private boundary. Error bodies and arbitrary headers are never returned.
type acquiredResponse struct {
	body   []byte
	status int
}

// acquire takes an installed endpoint key and stricter remaining byte/header
// reservations from its trusted component. No URL/header/client is accepted.
// A failed transfer poisons this phase; no automatic or caller retry follows.
func (p *acquisitionPhase) acquire(endpoint string, bodyLeft, headerLeft int64) (out acquiredResponse, err error) {
	if p == nil {
		return out, unavailable("acquisition_unavailable")
	}
	p.mu.Lock()
	e, ok := p.source.endpoints[endpoint]
	if !ok || p.active || p.closed || p.failed || p.uncertain || acquisitionExpired(p.ctx) || bodyLeft <= 0 || headerLeft <= 0 || p.bytesLeft <= 0 || p.responsesLeft <= 0 {
		p.mu.Unlock()
		return out, unavailable("acquisition_unavailable")
	}
	p.active = true
	p.responsesLeft-- // Attempts, including errors, consume the finite inventory.
	limit := p.source.limits.metadata
	if e.kind == rawCommitResponse {
		limit = p.source.limits.commit
	}
	limit = min(limit, bodyLeft, p.bytesLeft)
	headerLimit := min(headerLeft, p.source.limits.header)
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if acquisitionExpired(p.ctx) || p.closed {
			err = unavailable("acquisition_canceled")
		}
		if err != nil {
			out = acquiredResponse{}
			p.failed = true
		}
		p.active = false
		p.releaseLocked()
	}()
	if headerLimit <= acquisitionParserFixed {
		return out, unavailable("acquisition_headers")
	}

	// Own the single socket and all cancellation work. No Transport dial,
	// persistConn, pooling, retry, proxy or TLS worker can outlive this call.
	req, makeErr := http.NewRequest(http.MethodGet, e.url, nil)
	if makeErr != nil {
		return out, unavailable("acquisition_request")
	}
	req.Close = true
	req.Header.Set("Accept-Encoding", "identity")
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	address := host
	if net.ParseIP(host) == nil {
		// Public resolver APIs do not expose a join for their internal workers.
		// Retain this adapter gate permanently on this path, even on success,
		// rather than assert a worker lifetime we cannot prove. This transfer
		// may finish; no further transfer or phase is admitted on this adapter.
		p.mu.Lock()
		p.uncertain = true
		p.mu.Unlock()
		resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
		addresses, lookupErr := resolver.LookupHost(p.ctx, host)
		if lookupErr != nil || acquisitionExpired(p.ctx) || len(addresses) == 0 {
			return out, unavailable("acquisition_resolution_lifetime")
		}
		address = addresses[0]
	}
	// A numeric destination avoids resolver singleflight and parallel racers.
	raw, dialErr := (&net.Dialer{FallbackDelay: -1}).DialContext(p.ctx, "tcp", net.JoinHostPort(address, port))
	if dialErr != nil {
		// DialContext may return before its internal cancellation callback
		// exits. There is no public join. Retain the gate on every dial error.
		if raw != nil {
			_ = raw.Close()
		}
		p.mu.Lock()
		p.uncertain = true
		p.mu.Unlock()
		return out, unavailable("acquisition_dial_lifetime")
	}
	deadline, _ := p.ctx.Deadline()
	if setErr := raw.SetDeadline(deadline); setErr != nil {
		_ = raw.Close()
		return out, unavailable("acquisition_transport")
	}
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(p.ctx, func() { _ = raw.Close(); close(cancelDone) })
	defer func() {
		// Close the underlying socket directly: no TLS close-notify timeout or
		// response-body draining is allowed to extend the absolute phase.
		_ = raw.Close()
		if !stop() {
			<-cancelDone
		}
	}()
	conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.source.roots,
		ServerName: host, NextProtos: []string{"http/1.1"}})
	// Handshake runs in this goroutine. The joined callback above interrupts
	// every blocked read/write, including handshake and request headers.
	if handshakeErr := conn.Handshake(); handshakeErr != nil {
		return out, unavailable("acquisition_transport")
	}
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
		return out, unavailable("acquisition_protocol")
	}
	if writeErr := req.Write(conn); writeErr != nil {
		return out, unavailable("acquisition_transport")
	}
	reader := bufio.NewReaderSize(conn, 64)
	header, headerErr := acquisitionHeaders(reader, headerLimit)
	if headerErr != nil {
		return out, headerErr
	}
	// Only preflighted, reserved bytes reach the standard response parser.
	// MultiReader preserves buffered body bytes without copying them.
	parsed := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(header), reader), 64)
	resp, parseErr := http.ReadResponse(parsed, req)
	if parseErr != nil || resp == nil || resp.Body == nil {
		return out, unavailable("acquisition_protocol")
	}
	var bodyReader io.Reader = resp.Body
	chunked := len(resp.TransferEncoding) != 0 && resp.Body != http.NoBody
	if chunked {
		// ReadResponse has validated transfer coding. Use the same standard
		// chunk decoder, but never invoke net/http's allocating trailer parser.
		bodyReader = httputil.NewChunkedReader(parsed)
	}
	if acquisitionExpired(p.ctx) {
		return out, unavailable("acquisition_canceled")
	}
	if resp.StatusCode < 200 || resp.ProtoMajor != 1 || resp.ProtoMinor > 1 {
		return out, unavailable("acquisition_protocol")
	}
	enc := resp.Header.Values("Content-Encoding")
	if resp.Uncompressed || len(enc) > 1 || len(enc) == 1 && !strings.EqualFold(enc[0], "identity") {
		return out, unavailable("acquisition_encoding")
	}
	if resp.ContentLength < -1 || resp.ContentLength > limit {
		return out, unavailable("acquisition_size")
	}
	if resp.StatusCode == http.StatusPartialContent || len(resp.Header.Values("Content-Range")) != 0 {
		return out, unavailable("acquisition_partial")
	}
	if len(resp.Trailer) != 0 {
		return out, unavailable("acquisition_trailer")
	}
	// Do not allocate from a provider-declared length. Fixed scratch and bounded
	// append growth cap storage; the single overflow byte consumes aggregate too.
	var body []byte
	var scratch [32 << 10]byte
	var total int64
	for {
		if acquisitionExpired(p.ctx) {
			return out, unavailable("acquisition_canceled")
		}
		want := min(int64(len(scratch)), limit-total)
		if want == 0 {
			want = 1
		}
		p.mu.Lock()
		remaining := p.bytesLeft
		p.mu.Unlock()
		// An exact exhausted aggregate cannot fund an EOF/overflow probe.
		// Refuse rather than reading an uncharged byte or claiming completeness.
		if remaining <= 0 {
			return out, unavailable("acquisition_aggregate")
		}
		want = min(want, remaining)
		n, readErr := bodyReader.Read(scratch[:want])
		p.mu.Lock()
		p.bytesLeft -= int64(n)
		p.mu.Unlock()
		if acquisitionExpired(p.ctx) {
			return out, unavailable("acquisition_canceled")
		}
		total += int64(n)
		if total > limit {
			return out, unavailable("acquisition_size")
		}
		if n > 0 {
			// Explicit capacity avoids append's geometric allocation above cap.
			if int64(cap(body)) < total {
				capacity := min(limit, max(total, int64(cap(body))*2))
				grown := make([]byte, len(body), int(capacity))
				copy(grown, body)
				body = grown
			}
			body = append(body, scratch[:n]...)
		}
		if readErr == io.EOF {
			if chunked {
				// Trailer fields are forbidden. Inspect the empty terminator
				// in place, before any field/map/string allocation.
				line, trailerErr := parsed.ReadSlice('\n')
				if trailerErr != nil || !bytes.Equal(line, []byte("\r\n")) {
					return out, unavailable("acquisition_trailer")
				}
			}
			break
		}
		if readErr != nil {
			return out, unavailable("acquisition_body")
		}
	}
	if resp.ContentLength >= 0 && total != resp.ContentLength {
		return out, unavailable("acquisition_partial")
	}
	if len(resp.Trailer) != 0 {
		return out, unavailable("acquisition_trailer")
	}
	if resp.StatusCode != http.StatusOK {
		return out, unavailable("acquisition_status")
	}
	return acquiredResponse{body: body, status: resp.StatusCode}, nil
}

// acquisitionHeaders reserves the wire copy, scalar/copy scratch and parser
// representation BEFORE allowing any byte into ReadResponse. The standard
// parser still defines HTTP syntax (including folding and duplicate lengths).
// Counting physical lines also bounds folded-line scratch, duplicate values,
// map growth and malformed-line diagnostics. It is deliberately conservative:
// 32 KiB fixed state (including cold parser/diagnostic machinery), the full
// wire-buffer capacity, eight bytes of scalar/copy
// space per wire byte and 384 bytes per physical field line. At most 128 such
// lines enter the parser. These allowances cover the supported standard
// parser's map buckets/growth, string/value descriptors, line and fold copies,
// status/framing state and two 64-byte reader buffers. TLS and payload storage
// have separate lifetimes/limits; no trailer MIME parser is ever entered.
func acquisitionHeaders(r *bufio.Reader, reservation int64) ([]byte, error) {
	const fixed = int64(acquisitionParserFixed)
	if reservation <= fixed {
		return nil, unavailable("acquisition_headers")
	}
	capacity := (reservation - fixed) / 16
	wire := make([]byte, 0, int(capacity))
	lines, fields, lineStart := 0, int64(0), 0
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, unavailable("acquisition_headers")
		}
		// Reserve a field line on its FIRST byte, before any dynamic parser state.
		if len(wire) == lineStart && lines > 0 && b != '\r' && b != '\n' {
			fields++
		}
		if fields > 128 || int64(len(wire)+1) > capacity ||
			fixed+capacity+8*int64(len(wire)+1)+384*fields > reservation {
			return nil, unavailable("acquisition_headers")
		}
		wire = append(wire, b) // Capacity was charged once; append cannot grow it.
		if b == '\n' {
			line := wire[lineStart:]
			// Trailer declarations can expand a second map from a single
			// comma-separated scalar. Refuse before ReadResponse allocates it.
			if lines > 0 {
				if colon := bytes.IndexByte(line, ':'); colon >= 0 && bytes.EqualFold(line[:colon], []byte("Trailer")) {
					return nil, unavailable("acquisition_trailer")
				}
			}
			if lines > 0 && (len(line) == 1 || len(line) == 2 && line[0] == '\r') {
				return wire, nil
			}
			lines++
			lineStart = len(wire)
		}
	}
}
