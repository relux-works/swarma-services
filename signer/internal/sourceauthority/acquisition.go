package sourceauthority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
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
	bytesLeft                        int64
	responsesLeft                    int
}

// Preserve the phase's cancellation/deadline, without inheriting caller trace
// hooks or context-based transport/credential options at this private boundary.
type acquisitionContext struct{ context.Context }

func (acquisitionContext) Value(any) any { return nil }

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
	if p.closed && !p.active && !p.released {
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
	if !ok || p.active || p.closed || p.failed || p.ctx.Err() != nil || bodyLeft <= 0 || headerLeft <= 0 || p.bytesLeft <= 0 || p.responsesLeft <= 0 {
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
		if p.ctx.Err() != nil || p.closed {
			err = unavailable("acquisition_canceled")
		}
		if err != nil {
			out = acquiredResponse{}
			p.failed = true
		}
		p.active = false
		p.releaseLocked()
	}()
	if headerLimit < 64 {
		return out, unavailable("acquisition_headers")
	}

	// A new non-pooling HTTP/1 transport prevents connection reuse/retry and
	// persistent idle workers. Proxy discovery and compression are disabled.
	// Reserve half the header budget for trailers. net/http bounds HTTP/1
	// trailers by its read buffer; keep that buffer within this reservation.
	t := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{}).DialContext,
		DisableKeepAlives: true, DisableCompression: true,
		MaxResponseHeaderBytes: headerLimit / 2, ReadBufferSize: int(min(headerLimit/2, 4096)),
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.source.roots, NextProtos: []string{"http/1.1"}},
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	defer t.CloseIdleConnections()
	req, makeErr := http.NewRequestWithContext(p.ctx, http.MethodGet, e.url, nil)
	if makeErr != nil {
		return out, unavailable("acquisition_request")
	}
	req.Header.Set("Accept-Encoding", "identity")
	// GET needs no informational handshake. Refuse it rather than permitting
	// an uncounted stream of preliminary responses or renewed header budgets.
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(_ int, _ textproto.MIMEHeader) error { return unavailable("acquisition_informational") },
	}))
	// RoundTrip performs exactly one exchange and never follows redirects.
	resp, roundErr := t.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
				err = unavailable("acquisition_close")
			}
		}()
	}
	if roundErr != nil || resp == nil || resp.Body == nil {
		return out, unavailable("acquisition_transport")
	}
	if p.ctx.Err() != nil {
		return out, unavailable("acquisition_canceled")
	}
	if resp.StatusCode < 200 {
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
		if p.ctx.Err() != nil {
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
		n, readErr := resp.Body.Read(scratch[:want])
		p.mu.Lock()
		p.bytesLeft -= int64(n)
		p.mu.Unlock()
		if p.ctx.Err() != nil {
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
