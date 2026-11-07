package sourceauthority

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
)

// This private extension has exactly two canonical Git protocol endpoints. It
// does not change acquisition.go, issue a numeric destination capability, or
// accept a callback/client/URL. The current qualified API-only connector refuses
// github.com. A composition owner must qualify that separate destination before
// making this component reachable. All transfer work is synchronous except the
// socket-closing cancellation callback, which is joined before returning.
func (p *acquisitionPhase) originalGitExchange(ctx context.Context, policy Policy, body []byte, discovery bool) (out []byte, err error) {
	if p == nil || p.source == nil || ctx == nil || !originalGitRepository(policy) {
		return nil, unavailable("github_git_transport_binding")
	}
	p.mu.Lock()
	if p.active || p.closed || p.failed || p.uncertain || p.responsesLeft <= 0 || acquisitionExpired(ctx) || acquisitionExpired(p.ctx) || p.source.connector == nil || p.source.auth != nil {
		p.mu.Unlock()
		return nil, unavailable("github_git_transport_admission")
	}
	p.active = true
	p.responsesLeft--
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if acquisitionExpired(ctx) || acquisitionExpired(p.ctx) || p.closed {
			err = unavailable("github_git_canceled")
		}
		if err != nil {
			out = nil
			p.failed = true
		}
		p.active = false
		p.releaseLocked()
	}()
	headerLimit := min(p.source.limits.header, int64(acquisitionHeaderMax))
	limit := min(p.source.limits.metadata, int64(acquisitionBodyMax))
	if discovery {
		limit = min(limit, 64<<10)
	}
	if headerLimit <= acquisitionParserFixed || limit <= 0 || len(body) > 2048 || discovery != (body == nil) {
		return nil, unavailable("github_git_transport_limits")
	}
	// Conservative parser/request/TLS scratch reservation is taken from the
	// admitted aggregate before opening a socket. This is component accounting;
	// installation-wide TLS/work qualification remains an owner integration gate.
	if err = p.originalGitCharge(headerLimit + int64(len(body))*4 + 4<<20); err != nil {
		return nil, err
	}
	method, suffix := http.MethodPost, "/git-upload-pack"
	if discovery {
		method, suffix = http.MethodGet, "/info/refs?service=git-upload-pack"
	}
	req, err := http.NewRequest(method, "https://github.com/"+policy.RepositoryName+".git"+suffix, bytes.NewReader(body))
	if err != nil {
		return nil, unavailable("github_git_request")
	}
	req.Close = true
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Git-Protocol", "version=2")
	if !discovery {
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	}
	raw, err := p.source.connector.connect(ctx, "github.com", "443")
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, unavailable("github_git_connector_unqualified")
	}
	var closeOnce sync.Once
	closeRaw := func() { closeOnce.Do(func() { _ = raw.Close() }) }
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { closeRaw(); close(joined) })
	defer func() {
		closeRaw()
		if !stop() {
			<-joined
		}
	}()
	deadline, _ := ctx.Deadline()
	if err = raw.SetDeadline(deadline); err != nil {
		return nil, unavailable("github_git_transport")
	}
	conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.source.roots, ServerName: "github.com", NextProtos: []string{"http/1.1"}})
	if err = conn.Handshake(); err != nil {
		return nil, unavailable("github_git_tls")
	}
	if protocol := conn.ConnectionState().NegotiatedProtocol; protocol != "" && protocol != "http/1.1" {
		return nil, unavailable("github_git_http_version")
	}
	if err = req.Write(conn); err != nil {
		return nil, unavailable("github_git_write")
	}
	reader := bufio.NewReaderSize(conn, 64)
	header, err := acquisitionHeaders(reader, headerLimit)
	if err != nil {
		return nil, err
	}
	parsed := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(header), reader), 64)
	resp, err := http.ReadResponse(parsed, req)
	if err != nil || resp == nil || resp.Body == nil {
		return nil, unavailable("github_git_http")
	}
	// Redirects are responses, never followed. No auth, cookies, proxy, retry,
	// credentials, alternate host, DNS, hooks, filters or ambient Git configuration.
	contentType := "application/x-git-upload-pack-result"
	if discovery {
		contentType = "application/x-git-upload-pack-advertisement"
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor > 1 || resp.StatusCode != 200 || len(resp.Header.Values("Content-Type")) != 1 || resp.Header.Get("Content-Type") != contentType ||
		resp.ContentLength < -1 || resp.ContentLength > limit || len(resp.Trailer) != 0 || len(resp.Header.Values("Content-Range")) != 0 {
		return nil, unavailable("github_git_http_response")
	}
	enc := resp.Header.Values("Content-Encoding")
	if resp.Uncompressed || len(enc) > 1 || len(enc) == 1 && !strings.EqualFold(enc[0], "identity") {
		return nil, unavailable("github_git_encoding")
	}
	var input io.Reader = resp.Body
	chunked := len(resp.TransferEncoding) != 0 && resp.Body != http.NoBody
	if chunked {
		input = httputil.NewChunkedReader(parsed)
	}
	var scratch [32 << 10]byte
	for {
		if acquisitionExpired(ctx) || acquisitionExpired(p.ctx) {
			return nil, unavailable("github_git_canceled")
		}
		want := min(int64(len(scratch)), limit-int64(len(out)))
		if want == 0 {
			want = 1
		}
		// Charge capacity, wire/parse work, and the overflow/EOF probe BEFORE
		// reading. Nonrefundable overreservation also covers failed/short reads.
		if err = p.originalGitCharge(want*4 + int64(len(out))); err != nil {
			return nil, err
		}
		n, readErr := input.Read(scratch[:want])
		if n > 0 {
			if int64(len(out)+n) > limit {
				return nil, unavailable("github_git_transfer_size")
			}
			// Exact capacity avoids implicit growth above the admitted reservation.
			grown := make([]byte, len(out)+n)
			copy(grown, out)
			copy(grown[len(out):], scratch[:n])
			out = grown
		}
		if readErr == io.EOF {
			if chunked {
				line, e := parsed.ReadSlice('\n')
				if e != nil || !bytes.Equal(line, []byte("\r\n")) {
					return nil, unavailable("github_git_trailer")
				}
			}
			break
		}
		if readErr != nil {
			return nil, unavailable("github_git_incomplete_transfer")
		}
		if n == 0 {
			return nil, unavailable("github_git_no_progress")
		}
	}
	if resp.ContentLength >= 0 && int64(len(out)) != resp.ContentLength {
		return nil, unavailable("github_git_incomplete_transfer")
	}
	return out, nil
}
