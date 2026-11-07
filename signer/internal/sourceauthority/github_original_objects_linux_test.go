package sourceauthority

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type originalGitFixtureConnector struct {
	target            netip.AddrPort
	calls             atomic.Int32
	live              atomic.Int32
	opened            atomic.Int32
	closed            atomic.Int32
	doubleClose       atomic.Int32
	afterCloseEntered chan struct{}
	afterCloseRelease <-chan struct{}
}

type originalGitTrackedConn struct {
	net.Conn
	owner  *originalGitFixtureConnector
	closes atomic.Int32
}

func (c *originalGitTrackedConn) Close() error {
	first := c.closes.Add(1) == 1
	if first {
		c.owner.closed.Add(1)
	} else {
		c.owner.doubleClose.Add(1)
	}
	err := c.Conn.Close()
	if first && c.owner.afterCloseEntered != nil {
		close(c.owner.afterCloseEntered)
		<-c.owner.afterCloseRelease
	}
	return err
}

func (c *originalGitFixtureConnector) connect(ctx context.Context, host, port string) (net.Conn, error) {
	c.calls.Add(1)
	c.live.Add(1)
	defer c.live.Add(-1)
	if host != "github.com" || port != "443" {
		return nil, unavailable("fixture_git_origin")
	}
	conn, err := ownedNumericDial(ctx, c.target.Addr(), c.target.Port())
	if conn == nil {
		return nil, err
	}
	c.opened.Add(1)
	return &originalGitTrackedConn{Conn: conn, owner: c}, err
}

func originalGitFixturePack(t *testing.T, objects ...[]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(len(objects)))
	for _, raw := range objects {
		n := len(raw)
		first := byte(0x10 | n&15)
		n >>= 4
		if n > 0 {
			first |= 128
		}
		b.WriteByte(first)
		for n > 0 {
			v := byte(n & 127)
			n >>= 7
			if n > 0 {
				v |= 128
			}
			b.WriteByte(v)
		}
		z := zlib.NewWriter(&b)
		z.Write(raw)
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}
func originalGitFixtureResult(pack []byte) []byte {
	out := originalGitPacket("packfile\n")
	for len(pack) > 0 {
		n := min(len(pack), 60000)
		out += originalGitPacket(string(append([]byte{1}, pack[:n]...)))
		pack = pack[n:]
	}
	return []byte(out + "0000")
}
func originalGitFixtureRefs(head, branch string) []byte {
	return []byte(originalGitPacket(head+" HEAD symref-target:refs/heads/"+branch+"\n") + originalGitPacket(head+" refs/heads/"+branch+"\n") + "0000")
}
func originalGitFixtureAdvert(t *testing.T) []byte {
	t.Helper()
	// Generate reference bytes independently of the reader's packet encoder.
	// Git runs only in this offline test fixture, with an ordinary empty SHA-1
	// repository and no ambient configuration, helpers or network access.
	dir := t.TempDir()
	git := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C",
			"GIT_PROJECT_ROOT=" + dir, "GIT_HTTP_EXPORT_ALL=1", "GIT_PROTOCOL=version=2", "REQUEST_METHOD=GET", "QUERY_STRING=service=git-upload-pack", "PATH_INFO=/fixture.git/info/refs"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("offline Git HTTP fixture: %v", err)
		}
		return out
	}
	git("init", "--bare", "--quiet", "--object-format=sha1", dir+"/fixture.git")
	git("-C", dir+"/fixture.git", "config", "uploadpack.allowFilter", "true")
	response := git("http-backend")
	_, advert, ok := bytes.Cut(response, []byte("\r\n\r\n"))
	if !ok || !bytes.HasPrefix(advert, []byte("000eversion 2\n")) {
		t.Fatal("installed Git did not produce an HTTP v2 advertisement")
	}
	return advert
}

type originalGitFixture struct {
	r                   *originalGitHubReader
	q                   Query
	ctx                 context.Context
	cancel              context.CancelFunc
	connector           *originalGitFixtureConnector
	requests            atomic.Int32
	open                atomic.Int32
	head, raw           []byte
	refs, advert, fetch []byte
	move                bool
	status              int
	truncate            bool
	stall               bool
	stallAt             int32
	stallBody           bool
}

func originalGitLab(t *testing.T, mutate func(*originalGitFixture)) *originalGitFixture {
	t.Helper()
	f := validFixture(t)
	_, key, pub := fixtureKey(t)
	head := fixtureSign(t, []byte("tree "+strings.Repeat("2", 40)+"\nparent "+f.r.Commit+"\nauthor Fixture <fixture@example.invalid> 1740000001 +0000\ncommitter Fixture <fixture@example.invalid> 1740000001 +0000\n\nExact parent fixture.\n"), key, pub, "sha512")
	l := &originalGitFixture{q: Query{Request: f.r, Phase: Prebuild}, raw: f.s.observation.Commit, head: head, status: 200}
	l.ctx, l.cancel = context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(l.cancel)
	l.refs = originalGitFixtureRefs(fixtureOID(head), "main")
	l.advert = originalGitFixtureAdvert(t)
	l.fetch = originalGitFixtureResult(originalGitFixturePack(t, head, l.raw))
	l.r = &originalGitHubReader{policy: f.p}
	if mutate != nil {
		mutate(l)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(77), DNSNames: []string{"github.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nrequest := l.requests.Add(1)
		if r.Host != "github.com" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Git-Protocol") != "version=2" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("request authority/host/encoding changed")
		}
		if l.stall || nrequest == l.stallAt {
			// A POST body must be consumed before the HTTP server can monitor
			// peer closure while this handler is blocked on its request context.
			if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 2049)); err != nil {
				return
			}
			if l.stallBody {
				w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
				w.Header().Set("Content-Length", strconv.Itoa(len(l.advert)))
				w.WriteHeader(200)
				w.Write(l.advert[:1])
				w.(http.Flusher).Flush()
			}
			<-r.Context().Done()
			return
		}
		var response []byte
		ctype := "application/x-git-upload-pack-result"
		switch r.URL.RequestURI() {
		case "/fixture-owner/fixture-source.git/info/refs?service=git-upload-pack":
			if r.Method != "GET" {
				t.Error("discovery method")
			}
			response = l.advert
			ctype = "application/x-git-upload-pack-advertisement"
		case "/fixture-owner/fixture-source.git/git-upload-pack":
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-git-upload-pack-request" {
				t.Error("RPC method/type")
			}
			request, err := io.ReadAll(io.LimitReader(r.Body, 2049))
			if err != nil || len(request) > 2048 {
				t.Error("request bound")
			}
			if bytes.Contains(request, []byte("command=ls-refs")) {
				response = l.refs
				if l.move && l.requests.Load() == 4 {
					response = originalGitFixtureRefs(strings.Repeat("a", 40), "main")
				}
			} else {
				if !bytes.Contains(request, []byte("want "+fixtureOID(l.head))) || !bytes.Contains(request, []byte("filter tree:0\n")) {
					t.Error("fetch binding/filter")
				}
				response = l.fetch
			}
		default:
			t.Error("noncanonical Git endpoint")
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", ctype)
		n := len(response)
		if l.truncate {
			n++
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.WriteHeader(l.status)
		w.Write(response)
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			l.open.Add(1)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			l.open.Add(-1)
		}
	}
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	s.StartTLS()
	t.Cleanup(func() { s.CloseClientConnections(); s.Close() })
	addr, err := netip.ParseAddrPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	l.connector = &originalGitFixtureConnector{target: addr}
	a := &sourceAcquisition{limits: acquisitionLimits{header: acquisitionHeaderMax, metadata: acquisitionBodyMax, commit: acquisitionCommitMax, aggregate: acquisitionAggregateMax, responses: acquisitionResponsesMax}, connector: l.connector, roots: roots}
	p, err := a.begin(l.ctx, acquisitionAggregateMax, acquisitionResponsesMax)
	if err != nil {
		t.Fatal(err)
	}
	l.r.phase = p
	t.Cleanup(p.close)
	return l
}

func TestOriginalGitProtocolRawSignedAncestry(t *testing.T) {
	l := originalGitLab(t, nil)
	got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Commit, l.raw) || len(got.LandingPath) != 1 || !bytes.Equal(got.LandingPath[0], l.head) || got.Repository.DefaultHead != fixtureOID(l.head) {
		t.Fatal("raw identity/path lost")
	}
	c, err := parseCommit(got.Commit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifyOwner(c, l.r.policy); err != nil {
		t.Fatal("original signature lost", err)
	}
	if c.oid != l.q.Commit || c.tree != strings.Repeat("1", 40) {
		t.Fatal("content OID/tree changed")
	}
	if l.requests.Load() != 4 || l.r.phase.responsesLeft != 1020 || l.r.phase.bytesLeft >= acquisitionAggregateMax {
		t.Fatal("attempt/byte accounting missing")
	}
	waitAcquisition(t, func() bool { return l.open.Load() == 0 && l.connector.live.Load() == 0 })
}

func TestOriginalGitRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*originalGitFixture)
	}{
		{"wrong-repository", func(l *originalGitFixture) { l.q.Repository = "other" }},
		{"wrong-installed-repository", func(l *originalGitFixture) { l.r.policy.CanonicalRepository = "https://github.com/other/repo" }},
		{"wrong-policy-digest", func(l *originalGitFixture) { l.q.PolicySHA256 = strings.Repeat("0", 64) }},
		{"wrong-head", func(l *originalGitFixture) { l.q.Commit = strings.Repeat("0", 40) }},
		{"wrong-default-ref", func(l *originalGitFixture) { l.refs = originalGitFixtureRefs(fixtureOID(l.head), "other") }},
		{"moved-ref", func(l *originalGitFixture) { l.move = true }},
		{"bad-pack-oid", func(l *originalGitFixture) {
			p := originalGitFixturePack(t, l.head, l.raw)
			p[len(p)-1] ^= 1
			l.fetch = originalGitFixtureResult(p)
		}},
		{"broken-parent", func(l *originalGitFixture) {
			l.head = bytes.Replace(l.head, []byte(l.q.Commit), []byte(strings.Repeat("0", 40)), 1)
			l.refs = originalGitFixtureRefs(fixtureOID(l.head), "main")
			l.fetch = originalGitFixtureResult(originalGitFixturePack(t, l.head, l.raw))
		}},
		{"oversized-commit", func(l *originalGitFixture) { l.r.policy.Profile.CommitBytes = len(l.raw) - 1 }},
		{"lower-history-limit", func(l *originalGitFixture) {
			l.fetch = originalGitFixtureResult(originalGitFixturePack(t, l.head, l.raw, []byte("extra")))
			l.r.policy.Profile.AncestryCommits = 1
		}},
		{"incomplete-transfer", func(l *originalGitFixture) { l.truncate = true }},
		{"incomplete-object", func(l *originalGitFixture) {
			p := originalGitFixturePack(t, l.head, l.raw)
			p = p[:len(p)-21]
			sum := sha1.Sum(p)
			l.fetch = originalGitFixtureResult(append(p, sum[:]...))
		}},
		{"redirect", func(l *originalGitFixture) { l.status = 302 }},
		{"sha256-not-supported", func(l *originalGitFixture) { l.advert = bytes.Replace(l.advert, []byte("sha1"), []byte("sha2"), 1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := originalGitLab(t, tc.change)
			got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q)
			if err == nil || got.Commit != nil || got.LandingPath != nil || got.Repository.Canonical != "" {
				t.Fatal("refusal leaked material", err)
			}
			waitAcquisition(t, func() bool { return l.open.Load() == 0 && l.connector.live.Load() == 0 })
		})
	}
}

func TestOriginalGitMissingAdmissionAndBudget(t *testing.T) {
	var r originalGitHubReader
	if _, err := r.ReadOriginalGitHubObjects(context.Background(), Query{}); err == nil {
		t.Fatal("zero component admitted")
	}
	l := originalGitLab(t, nil)
	l.cancel()
	if got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q); err == nil || got.Commit != nil || l.connector.calls.Load() != 0 {
		t.Fatal("pre-canceled reader admitted")
	}
	for _, tc := range []struct {
		name     string
		bytes    int64
		attempts int
	}{{"aggregate", 1, 1024}, {"attempts", acquisitionAggregateMax, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			l := originalGitLab(t, nil)
			l.r.phase.bytesLeft = tc.bytes
			l.r.phase.responsesLeft = tc.attempts
			got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q)
			if err == nil || got.Commit != nil {
				t.Fatal("budget bypass")
			}
			if l.r.phase.bytesLeft < 0 || l.r.phase.responsesLeft < 0 {
				t.Fatal("counter underflow")
			}
			if tc.name == "attempts" && l.connector.calls.Load() != 1 {
				t.Fatal("extra attempt")
			}
		})
	}
}

func TestOriginalGitOverflowAndMalformedPackets(t *testing.T) {
	l := originalGitLab(t, nil)
	for _, packet := range [][]byte{[]byte("ffffx"), []byte("0003"), []byte("zzzz"), []byte("0005"), []byte("000")} {
		if _, _, _, err := originalGitNext(packet); err == nil {
			t.Fatal("packet accepted")
		}
	}
	p := []byte("PACK")
	p = binary.BigEndian.AppendUint32(p, 2)
	p = binary.BigEndian.AppendUint32(p, 1)
	p = append(p, 0x90)
	p = append(p, bytes.Repeat([]byte{0xff}, 10)...)
	sum := sha1.Sum(p)
	p = append(p, sum[:]...)
	if _, err := originalGitUnpack(l.r.phase, p, 1<<20, 256); err == nil {
		t.Fatal("size overflow accepted")
	}
}

func TestOriginalGitCancellationJoinsTransport(t *testing.T) {
	l := originalGitLab(t, func(l *originalGitFixture) { l.stall = true })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for l.requests.Load() == 0 {
			select {
			case <-l.ctx.Done():
				return
			default:
				time.Sleep(time.Millisecond)
			}
		}
		l.cancel()
	}()
	got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q)
	<-done
	if err == nil || got.Commit != nil {
		t.Fatal("canceled reader returned material")
	}
	waitAcquisition(t, func() bool { return l.open.Load() == 0 && l.connector.live.Load() == 0 })
	if l.r.phase.active {
		t.Fatal("transport not joined")
	}
}

func TestOriginalGitHTTPV2AdvertisementNeighbors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"version-1", func(b []byte) []byte { return bytes.Replace(b, []byte("version 2\n"), []byte("version 1\n"), 1) }},
		{"version-3", func(b []byte) []byte { return bytes.Replace(b, []byte("version 2\n"), []byte("version 3\n"), 1) }},
		{"v0-prelude", func(b []byte) []byte {
			return append([]byte(originalGitPacket("# service=git-upload-pack\n")+"0000"), b...)
		}},
		{"missing-filter", func(b []byte) []byte { return bytes.Replace(b, []byte("filter"), []byte("xxxxxx"), 1) }},
		{"missing-shallow", func(b []byte) []byte { return bytes.Replace(b, []byte("shallow"), []byte("xxxxxxx"), 1) }},
		{"missing-ls-refs", func(b []byte) []byte { return bytes.Replace(b, []byte("ls-refs"), []byte("xxxxxxx"), 1) }},
		{"unsupported-format", func(b []byte) []byte {
			return bytes.Replace(b, []byte("object-format=sha1"), []byte("object-format=sha2"), 1)
		}},
		{"trailing-data", func(b []byte) []byte { return append(b, 'X') }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := originalGitLab(t, func(l *originalGitFixture) { l.advert = tc.change(l.advert) })
			got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q)
			if err == nil || got.Commit != nil || l.requests.Load() != 1 {
				t.Fatal("invalid adjacent advertisement reached material acquisition", err)
			}
		})
	}
}

func TestOriginalGitShallowSuffixNeighbors(t *testing.T) {
	for _, suffix := range []string{"\n", "X", "\r", "", "\r\n", "\x00"} {
		t.Run(strconv.Quote(suffix), func(t *testing.T) {
			l := originalGitLab(t, func(l *originalGitFixture) {
				prefix := originalGitPacket("shallow-info\n") + originalGitPacket("shallow "+l.q.Commit+suffix) + "0001"
				l.fetch = append([]byte(prefix), l.fetch...)
			})
			got, err := l.r.ReadOriginalGitHubObjects(l.ctx, l.q)
			if suffix == "\n" {
				if err != nil || !bytes.Equal(got.Commit, l.raw) || l.requests.Load() != 4 {
					t.Fatal("valid shallow neighbor refused", err)
				}
			} else if err == nil || got.Commit != nil || got.LandingPath != nil || got.Repository.Canonical != "" || l.requests.Load() != 3 {
				t.Fatal("malformed shallow suffix reached material/ref refresh", err)
			}
		})
	}
}

func TestOriginalGitRequestCancellationJoinsTransport(t *testing.T) {
	for _, tc := range []struct {
		name        string
		at          int32
		body, phase bool
	}{
		{"child-discovery", 1, false, false},
		{"child-body", 1, true, false},
		{"child-refs", 2, false, false},
		{"child-fetch", 3, false, false},
		{"child-refresh", 4, false, false},
		{"phase-independent-request", 1, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := originalGitLab(t, func(l *originalGitFixture) { l.stallAt = tc.at; l.stallBody = tc.body })
			ctx, cancel := context.WithCancel(l.ctx)
			if tc.phase {
				cancel()
				deadline, _ := l.ctx.Deadline()
				ctx, cancel = context.WithDeadline(context.Background(), deadline)
			}
			defer cancel()
			done := make(chan struct{})
			var got GitHubOriginalObjects
			var err error
			go func() { defer close(done); got, err = l.r.ReadOriginalGitHubObjects(ctx, l.q) }()
			waitAcquisition(t, func() bool { return l.requests.Load() == tc.at })
			start := time.Now()
			if tc.phase {
				l.cancel()
			} else {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(500 * time.Millisecond):
				l.cancel()
				<-done
				t.Fatal("request cancellation did not promptly join transport")
			}
			t.Logf("cancellation to joined return: %s", time.Since(start))
			if !tc.phase && l.ctx.Err() != nil {
				t.Fatal("child control canceled its phase")
			}
			if err == nil || got.Commit != nil || got.LandingPath != nil || got.Repository.Canonical != "" {
				t.Fatal("canceled reader returned material")
			}
			waitAcquisition(t, func() bool { return l.open.Load() == 0 && l.connector.live.Load() == 0 })
			if l.r.phase.active || !l.r.phase.failed || l.connector.opened.Load() != l.connector.closed.Load() || l.connector.doubleClose.Load() != 0 {
				t.Fatal("transport/callback ownership was not joined exactly once")
			}
			attempts, budget := l.r.phase.responsesLeft, l.r.phase.bytesLeft
			if attempts != 1024-int(tc.at) || budget >= acquisitionAggregateMax || budget < 0 {
				t.Fatal("shared ledger changed")
			}
			if _, err := l.r.ReadOriginalGitHubObjects(ctx, l.q); err == nil || l.connector.calls.Load() != tc.at {
				t.Fatal("canceled phase reused")
			}
		})
	}
}

func TestOriginalGitFixtureIgnoresAmbientConfig(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/unavailable-fixture-config")
	t.Setenv("HOME", t.TempDir())
	if err := os.WriteFile(os.Getenv("HOME")+"/.gitconfig", []byte("not valid Git configuration\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := originalGitCapabilities(originalGitFixtureAdvert(t)); err != nil {
		t.Fatal(err)
	}
}

func TestOriginalGitCancellationWaitsForCloseCallback(t *testing.T) {
	l := originalGitLab(t, func(l *originalGitFixture) { l.stall = true })
	entered, release := make(chan struct{}), make(chan struct{})
	l.connector.afterCloseEntered, l.connector.afterCloseRelease = entered, release
	ctx, cancel := context.WithCancel(l.ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		got, err := l.r.ReadOriginalGitHubObjects(ctx, l.q)
		if err == nil || got.Commit != nil {
			t.Error("cancellation returned material")
		}
	}()
	waitAcquisition(t, func() bool { return l.requests.Load() == 1 })
	cancel()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("socket-close callback did not run")
	}
	// The socket is already closed and its read has unblocked, but callback
	// completion is deliberately held. Return must wait for that completion.
	select {
	case <-done:
		close(release)
		t.Fatal("reader returned with an unjoined close callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader did not join released callback")
	}
	if l.connector.doubleClose.Load() != 0 || l.connector.closed.Load() != 1 {
		t.Fatal("socket closed more than once")
	}
}
