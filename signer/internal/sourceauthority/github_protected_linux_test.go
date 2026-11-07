package sourceauthority

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

var providerFixtureCertificate tls.Certificate

// The sandbox's system-root store contains ONLY this synthetic public root.
// The actual public constructor keeps nil RootCAs and the canonical hostname.
// No production trust option or source/authority field replacement is used.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "provider-public-root-")
	if err != nil {
		os.Exit(2)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		os.RemoveAll(dir)
		os.Exit(2)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic provider root"}, DNSNames: []string{"api.github.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
	if err != nil {
		os.RemoveAll(dir)
		os.Exit(2)
	}
	providerFixtureCertificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	root := filepath.Join(dir, "public.pem")
	if os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600) != nil {
		os.RemoveAll(dir)
		os.Exit(2)
	}
	os.Setenv("SSL_CERT_FILE", root)
	os.Setenv("SSL_CERT_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type fixtureOwnedConnector struct {
	target netip.AddrPort
	active atomic.Int32
	calls  atomic.Int32
}

func (c *fixtureOwnedConnector) connect(ctx context.Context, host, port string) (net.Conn, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	c.calls.Add(1)
	if host != "api.github.com" || port != "443" {
		return nil, unavailable("fixture_origin")
	}
	return ownedNumericDial(ctx, c.target.Addr(), c.target.Port())
}

type fixtureCurrentMembers struct {
	mu    sync.Mutex
	value GitHubCurrentMembers
	reads int
}

func (c *fixtureCurrentMembers) CurrentGitHubMembers(ctx context.Context) (GitHubCurrentMembers, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if ctx.Err() != nil {
		return GitHubCurrentMembers{}, ctx.Err()
	}
	v := c.value
	v.Members.Reviewers = append([]GitHubMember(nil), v.Members.Reviewers...)
	return v, nil
}

type fixtureOriginalObjects struct{ prior githubGitReader }

func (c fixtureOriginalObjects) ReadOriginalGitHubObjects(ctx context.Context, q Query) (GitHubOriginalObjects, error) {
	v, e := c.prior.readGit(ctx, q)
	return GitHubOriginalObjects{v.Repository, v.Commit, v.LandingPath}, e
}

type fixtureEffectiveChecks struct{ prior githubCheckReader }

func (c fixtureEffectiveChecks) ReadEffectiveGitHubChecks(ctx context.Context, q Query) (GitHubEffectiveChecks, error) {
	v, e := c.prior.readChecks(ctx, q)
	return GitHubEffectiveChecks{v.Policy, v.Inventory}, e
}

type providerLab struct {
	l          *protectedGitHubLab
	c          ProtectedGitHubPRInstallation
	connector  *fixtureOwnedConnector
	current    *fixtureCurrentMembers
	mu         sync.Mutex
	graph      []byte
	status     int
	afterGraph func()
	graphReads atomic.Int32
	requests   atomic.Int32
	open       atomic.Int32
}

func newProviderLab(t *testing.T) *providerLab {
	return newProviderLabPostingMode(t, false)
}

func newProviderLabPostingMode(t *testing.T, shared bool) *providerLab {
	t.Helper()
	l := newProtectedGitHubLab(t)
	if shared {
		l.source.members.Reviewers[0] = l.source.members.Producer
		l.proof.account = l.source.members.Producer
	}
	f := &providerLab{l: l, graph: graphBytes(graphNode(l.proof)), status: 200}
	f.current = &fixtureCurrentMembers{value: GitHubCurrentMembers{"current-fixture", Current, l.source.members}}
	pr := map[string]any{"number": l.proof.binding.PR, "state": "closed", "draft": false, "merged": true, "user": map[string]any{"id": 1, "login": "producer", "type": "User"}, "head": map[string]any{"sha": l.request.Commit, "repo": map[string]any{"full_name": "fork/source", "html_url": "https://github.com/fork/source"}}, "base": map[string]any{"ref": "main", "sha": l.proof.binding.Base, "repo": map[string]any{"full_name": l.source.policy.RepositoryName, "html_url": l.proof.binding.Repository, "private": false}}}
	reviews := []any{map[string]any{"id": l.proof.binding.ReviewID, "node_id": l.proof.nodeID, "commit_id": l.request.Commit, "state": "COMMENTED", "body": l.proof.body, "submitted_at": "2026-11-07T00:00:00Z", "user": map[string]any{"id": l.proof.account.ID, "login": l.proof.account.Login, "type": "User"}}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Host != "api.github.com" || r.Header.Get("Authorization") != "Bearer synthetic-fixture-only" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("request origin/auth binding")
		}
		if r.URL.Path == "/graphql" {
			f.graphReads.Add(1)
			raw, e := io.ReadAll(io.LimitReader(r.Body, 2049))
			var v map[string]json.RawMessage
			if e != nil || len(raw) > 2048 || r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || json.Unmarshal(raw, &v) != nil || len(v) != 2 {
				t.Error("GraphQL shape")
			}
			var query string
			var variables map[string]string
			if json.Unmarshal(v["query"], &query) != nil || query != githubOriginalReviewQuery || json.Unmarshal(v["variables"], &variables) != nil || len(variables) != 1 || variables["id"] != l.proof.nodeID {
				t.Error("query/original-only variables")
			}
			f.mu.Lock()
			body := bytes.Clone(f.graph)
			status := f.status
			hook := f.afterGraph
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
			w.WriteHeader(status)
			w.Write(body)
			return
		}
		if r.Method != "GET" {
			t.Error("REST method")
		}
		if strings.HasSuffix(r.URL.Path, "/reviews") {
			json.NewEncoder(w).Encode(reviews)
		} else {
			json.NewEncoder(w).Encode(pr)
		}
	}))
	server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			f.open.Add(1)
		}
		if s == http.StateClosed || s == http.StateHijacked {
			f.open.Add(-1)
		}
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{providerFixtureCertificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	target, err := netip.ParseAddrPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	f.connector = &fixtureOwnedConnector{target: target}
	f.c = ProtectedGitHubPRInstallation{Installed: l.installed, AcceptedSHA256: l.digest, Number: l.source.number, Clock: l.clock, Membership: f.current, Objects: fixtureOriginalObjects{l.source.git}, Checks: fixtureEffectiveChecks{l.source.checks}, Authentication: &GitHubInstallationAuth{repository: l.source.policy.CanonicalRepository, header: "Bearer synthetic-fixture-only", qualified: true}, Connector: &QualifiedGitHubConnector{owned: f.connector, qualified: true}}
	s, err := OpenProtectedGitHubPRSource(context.Background(), f.c)
	if err != nil {
		t.Fatal("actual protected source constructor", err)
	}
	l.source = s.(*githubPRSource)
	return f
}

func TestProtectedProviderConstructorRefusesUnqualified(t *testing.T) {
	f := newProviderLab(t)
	for _, fault := range []string{"auth", "auth-unqualified", "connector", "connector-unqualified", "members", "git", "checks", "digest", "number", "auth-repository", "auth-header"} {
		t.Run(fault, func(t *testing.T) {
			c := f.c
			switch fault {
			case "auth":
				c.Authentication = nil
			case "auth-unqualified":
				c.Authentication = &GitHubInstallationAuth{}
			case "connector":
				c.Connector = nil
			case "connector-unqualified":
				c.Connector = &QualifiedGitHubConnector{owned: f.connector}
			case "members":
				c.Membership = nil
			case "git":
				c.Objects = nil
			case "checks":
				c.Checks = nil
			case "digest":
				c.AcceptedSHA256 = strings.Repeat("f", 64)
			case "number":
				c.Number = 0
			case "auth-repository":
				a := *c.Authentication
				a.repository = "https://github.com/other/repo"
				c.Authentication = &a
			case "auth-header":
				a := *c.Authentication
				a.header = "Bearer x\r\ninjected: yes"
				c.Authentication = &a
			}
			if s, e := OpenProtectedGitHubPRSource(context.Background(), c); e == nil || s != nil {
				t.Fatal("unqualified installation accepted")
			}
		})
	}
	if f.requests.Load() != 0 {
		t.Fatal("constructor probed provider")
	}
}

func TestProtectedProviderActualAdmissionAndRereads(t *testing.T) {
	f := newProviderLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := NewWithPolicySource(ctx, f.l.installed, f.l.digest, f.l.source, f.l.clock)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		q, e := a.BeforeSign(ctx, f.l.request)
		if e != nil {
			t.Fatal("admission", e)
		}
		if e = q.checkFinalEffectContext(ctx); e != nil {
			t.Fatal("final reread", e)
		}
		if f.l.source.transport.busy.Load() || f.connector.active.Load() != 0 {
			t.Fatal("gate released before join")
		}
	}
	if f.graphReads.Load() != 6 || f.requests.Load() != 18 {
		t.Fatalf("reads graph=%d all=%d", f.graphReads.Load(), f.requests.Load())
	}
	waitAcquisition(t, func() bool { return f.open.Load() == 0 })
}

func TestProtectedProviderHTTPGraphQLAndCurrentRefusals(t *testing.T) {
	for _, fault := range []string{"control", "http", "deleted", "partial", "errors", "edit", "timestamp", "policy-replaced", "member-revoked", "member-replaced"} {
		t.Run(fault, func(t *testing.T) {
			f := newProviderLab(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			a, e := NewWithPolicySource(ctx, f.l.installed, f.l.digest, f.l.source, f.l.clock)
			if e != nil {
				t.Fatal(e)
			}
			q, e := a.BeforeSign(ctx, f.l.request)
			if e != nil {
				t.Fatal("paired admission", e)
			}
			f.mu.Lock()
			switch fault {
			case "http":
				f.status = 403
			case "deleted":
				f.graph = []byte(`{"data":{"node":null}}`)
			case "partial":
				f.graph = []byte(`{"data":{}}`)
			case "errors":
				f.graph = []byte(`{"data":null,"errors":[{"message":"synthetic"}]}`)
			case "edit":
				n := graphNode(f.l.proof)
				n["lastEditedAt"] = "2026-11-07T01:00:00Z"
				f.graph = graphBytes(n)
			case "timestamp":
				n := graphNode(f.l.proof)
				n["submittedAt"] = "2026-11-07T00:00:01Z"
				f.graph = graphBytes(n)
			case "policy-replaced":
				f.afterGraph = func() { f.l.changePolicy(t, "replaced") }
			case "member-revoked":
				f.afterGraph = func() { f.current.mu.Lock(); f.current.value.State = PolicyState("revoked"); f.current.mu.Unlock() }
			case "member-replaced":
				f.afterGraph = func() {
					f.current.mu.Lock()
					f.current.value.Generation = "next"
					f.current.value.Members.Reviewers[0].Login = "replacement"
					f.current.mu.Unlock()
				}
			}
			f.mu.Unlock()
			e = q.checkFinalEffectContext(ctx)
			if (e == nil) != (fault == "control") {
				t.Fatal("wrong final decision", e)
			}
			if f.connector.active.Load() != 0 || f.l.source.transport.busy.Load() {
				t.Fatal("unjoined final transfer")
			}
		})
	}
}

func TestProtectedProviderActualAuditEffectsAndRecovery(t *testing.T) {
	for _, recovering := range []bool{false, true} {
		t.Run(strconv.FormatBool(recovering), func(t *testing.T) {
			f := newProviderLab(t)
			a, _ := newProtectedGitHubAuditFixture(t, f.l)
			if recovering {
				a.backend.signErr = errAuditFixture
			}
			if e := a.run(t); (e != nil) != recovering {
				t.Fatal("effect", e)
			}
			a.backend.signErr = nil
			if recovering {
				op, e := a.signer.Reconcile(a.id())
				if e != nil || op.State != signingaudit.Succeeded {
					t.Fatal("recovery", e)
				}
			}
			if e := a.signer.Fetch(a.id()); e != nil {
				t.Fatal("release", e)
			}
			if a.backend.signs != 1 || a.backend.verifies != 1 || a.backend.releases != 1 || f.graphReads.Load() < 6 {
				t.Fatal("missing actual effects/observations")
			}
			if f.l.source.transport.busy.Load() || f.connector.active.Load() != 0 {
				t.Fatal("unjoined effects")
			}
			assertSnapshotClosed(t, a.e)
		})
	}
}

func TestProtectedProviderActualAuditedAdjacentRefusals(t *testing.T) {
	for _, fault := range []string{"control", "policy", "membership", "original-deleted", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f := newProviderLab(t)
			a, _ := newProtectedGitHubAuditFixture(t, f.l)
			f.mu.Lock()
			f.afterGraph = func() {
				count := f.graphReads.Load()
				if count == 2 {
					switch fault {
					case "policy":
						f.l.changePolicy(t, "replaced")
					case "membership":
						f.current.mu.Lock()
						f.current.value.State = Revoked
						f.current.mu.Unlock()
					case "cancel":
						a.cancel()
					}
				}
				if count == 1 && fault == "original-deleted" {
					f.mu.Lock()
					f.graph = []byte(`{"data":{"node":null}}`)
					f.mu.Unlock()
				}
			}
			f.mu.Unlock()
			e := a.run(t)
			if (e == nil) != (fault == "control") {
				t.Fatal("audited effect decision", e)
			}
			if fault != "control" && (a.e.buildCalls != 0 || a.backend.signs != 0 || a.backend.verifies != 0 || a.backend.releases != 0) {
				t.Fatal("refusal crossed effect entry")
			}
			if f.connector.active.Load() != 0 || f.l.source.transport.busy.Load() {
				t.Fatal("effect refusal left live acquisition")
			}
		})
	}
}

func TestProtectedGraphQLBoundsAndAttempts(t *testing.T) {
	for _, n := range []int{24575, 24576, 24577} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			f := newProviderLab(t)
			f.mu.Lock()
			f.graph = bytes.Repeat([]byte("x"), n)
			f.mu.Unlock()
			p := acquisitionTestPhase(t, f.l.source.transport, acquisitionAggregateMax, 2)
			g := f.l.source.graphql.(*githubGraphQLTransport)
			raw, e := g.readPhase(p, githubGraphQLRequest{githubOriginalReviewQuery, "PRR_lab", 24576, acquisitionHeaderMax, 1})
			if (e == nil) != (n <= 24576) || e != nil && raw != nil || e == nil && (len(raw) != n || cap(raw) > 24576) {
				t.Fatal("raw bound", len(raw), cap(raw), e)
			}
			if p.responsesLeft != 1 {
				t.Fatal("attempt not consumed")
			}
			p.close()
			if f.l.source.transport.busy.Load() {
				t.Fatal("gate retained with owned connector")
			}
		})
	}
	f := newProviderLab(t)
	g := f.l.source.graphql.(*githubGraphQLTransport)
	for _, bad := range []githubGraphQLRequest{{"query X {viewer{login}}", "PRR_lab", 24576, acquisitionHeaderMax, 1}, {githubOriginalReviewQuery, "", 24576, acquisitionHeaderMax, 1}, {githubOriginalReviewQuery, strings.Repeat("x", 257), 24576, acquisitionHeaderMax, 1}, {githubOriginalReviewQuery, "PRR_lab", 24577, acquisitionHeaderMax, 1}, {githubOriginalReviewQuery, "PRR_lab", 24576, acquisitionHeaderMax, 2}, {githubOriginalReviewQuery, "PRR_lab", 24576, 32768, 1}, {githubOriginalReviewQuery, strings.Repeat("<", 256), 24576, acquisitionHeaderMax, 1}} {
		p := acquisitionTestPhase(t, f.l.source.transport, acquisitionAggregateMax, 2)
		if raw, e := g.readPhase(p, bad); e == nil || raw != nil || f.requests.Load() != 0 {
			t.Fatal("invalid query allocated/sent")
		}
		p.close()
	}
	p := acquisitionTestPhase(t, f.l.source.transport, 2, 2)
	if raw, e := g.readPhase(p, githubGraphQLRequest{githubOriginalReviewQuery, "PRR_lab", 24576, acquisitionHeaderMax, 1}); e == nil || raw != nil {
		t.Fatal("aggregate ignored")
	}
	if p.responsesLeft != 1 {
		t.Fatal("failed attempt not charged")
	}
	p.close()
}

func TestProtectedAuthenticationCannotLeaveExactOrigin(t *testing.T) {
	f := newProviderLab(t)
	for _, rendering := range []string{fmt.Sprintf("%v", f.c.Authentication), fmt.Sprintf("%+v", *f.c.Authentication), fmt.Sprintf("%#v", f.c.Authentication)} {
		if strings.Contains(rendering, "Bearer") || strings.Contains(rendering, "synthetic-fixture-only") {
			t.Fatal("capability diagnostic exposed header")
		}
	}
	for _, origin := range []string{"https://other.invalid/graphql", "https://api.github.com:444/graphql", "http://api.github.com/graphql", "https://api.github.com.evil.invalid/graphql"} {
		f.l.source.transport.endpoints["foreign"] = installedEndpoint{origin, metadataResponse}
		p := acquisitionTestPhase(t, f.l.source.transport, acquisitionAggregateMax, 2)
		if out, e := p.acquire("foreign", 16, acquisitionHeaderMax); e == nil || out.body != nil {
			t.Fatal("auth escaped origin")
		}
		p.close()
	}
	if f.connector.calls.Load() != 0 || f.requests.Load() != 0 {
		t.Fatal("origin checked after connection")
	}
	// The concrete production connector never accepts caller hosts, noncanonical
	// ports or local/private destinations as canonical numeric pins.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, pin := range []string{"127.0.0.1", "10.1.2.3", "::1", "fe80::1"} {
		if c, e := (ownedGitHubConnector{address: netip.MustParseAddr(pin)}).connect(ctx, "api.github.com", "443"); e == nil || c != nil {
			t.Fatal("unqualified numeric pin")
		}
	}
	for _, pair := range [][2]string{{"other.invalid", "443"}, {"api.github.com", "444"}} {
		if c, e := (ownedGitHubConnector{address: netip.MustParseAddr("192.0.2.1")}).connect(ctx, pair[0], pair[1]); e == nil || c != nil {
			t.Fatal("noncanonical connector request")
		}
	}
}

// A real blocked kernel connect (full loopback accept queue) exercises the
// synchronous owned dial cancellation path without any remote connection.
func TestOwnedConnectorBlockedDialJoins(t *testing.T) {
	fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(fd)
	if e = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); e != nil {
		t.Fatal(e)
	}
	if e = syscall.Listen(fd, 0); e != nil {
		t.Fatal(e)
	}
	sa, e := syscall.Getsockname(fd)
	if e != nil {
		t.Fatal(e)
	}
	port := uint16(sa.(*syscall.SockaddrInet4).Port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, e := ownedNumericDial(ctx, netip.MustParseAddr("127.0.0.1"), port)
	if e != nil {
		t.Fatal("queue control", e)
	}
	defer first.Close()
	blocked, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	start := time.Now()
	conn, e := ownedNumericDial(blocked, netip.MustParseAddr("127.0.0.1"), port)
	if conn != nil {
		conn.Close()
		t.Fatal("queue did not block")
	}
	if e == nil || time.Since(start) > 150*time.Millisecond {
		t.Fatal("dial cancellation not bounded", e)
	}
}

func TestProtectedGraphQLTLSHeadersBodyCancellationAndReuse(t *testing.T) {
	for _, stage := range []string{"tls", "headers", "body", "oversized-headers", "status", "wrong-host", "untrusted-root", "success"} {
		t.Run(stage, func(t *testing.T) {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			target, e := netip.ParseAddrPort(listener.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			connector := &fixtureOwnedConnector{target: target}
			a, e := newSourceAcquisition(acquisitionInstallation{provider: "synthetic", origin: "https://api.github.com", endpoints: map[string]acquisitionEndpoint{"graphql": {path: "/graphql", kind: metadataResponse}}, limits: acquisitionLimits{acquisitionHeaderMax, acquisitionBodyMax, acquisitionCommitMax, acquisitionAggregateMax, acquisitionResponsesMax}, connector: connector, auth: &GitHubInstallationAuth{repository: "fixture", header: "Bearer synthetic-fixture-only"}})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			arrived, done := make(chan struct{}), make(chan struct{})
			certificate := providerFixtureCertificate
			if stage == "wrong-host" || stage == "untrusted-root" {
				public, key, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				name := "other.invalid"
				if stage == "untrusted-root" {
					name = "api.github.com"
				}
				leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				parent, e := x509.ParseCertificate(providerFixtureCertificate.Certificate[0])
				if e != nil {
					t.Fatal(e)
				}
				var signer any = providerFixtureCertificate.PrivateKey
				if stage == "untrusted-root" {
					parent = leaf
					signer = key
				}
				der, e := x509.CreateCertificate(rand.Reader, leaf, parent, public, signer)
				if e != nil {
					t.Fatal(e)
				}
				certificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
			}
			go func() {
				defer close(done)
				raw, e := listener.Accept()
				if e != nil {
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(time.Second))
				if stage == "tls" {
					close(arrived)
					<-ctx.Done()
					return
				}
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if conn.Handshake() != nil {
					close(arrived)
					return
				}
				req, e := http.ReadRequest(bufio.NewReader(conn))
				if e != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				switch stage {
				case "headers":
					close(arrived)
					<-ctx.Done()
				case "body":
					io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
					close(arrived)
					<-ctx.Done()
				case "oversized-headers":
					io.WriteString(conn, "HTTP/1.1 200 OK\r\nX: "+strings.Repeat("x", 4096)+"\r\n\r\n")
					close(arrived)
				case "status":
					io.WriteString(conn, "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: https://other.invalid/\r\n\r\n")
					close(arrived)
				default:
					io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
					close(arrived)
				}
			}()
			cancelJoined := make(chan struct{})
			go func() {
				defer close(cancelJoined)
				select {
				case <-arrived:
					if stage == "tls" || stage == "headers" || stage == "body" {
						cancel()
					}
				case <-ctx.Done():
				}
			}()
			p, e := a.begin(ctx, acquisitionAggregateMax, 2)
			if e != nil {
				t.Fatal(e)
			}
			g := &githubGraphQLTransport{source: a}
			body, e := g.readPhase(p, githubGraphQLRequest{githubOriginalReviewQuery, "PRR_lab", 24576, acquisitionHeaderMax, 1})
			if (e == nil) != (stage == "success") || e != nil && body != nil {
				t.Fatal("wrong transport result", e)
			}
			p.close()
			cancel()
			<-done
			<-cancelJoined
			if a.busy.Load() || connector.active.Load() != 0 {
				t.Fatal("work survived gate")
			}
			// A new phase after every owned failure is permitted; no uncertainty
			// was asserted or cleared. No exchange is automatically retried.
			nextCtx, nextCancel := context.WithTimeout(context.Background(), time.Second)
			defer nextCancel()
			next, e := a.begin(nextCtx, 10, 1)
			if e != nil {
				t.Fatal("joined gate not reusable", e)
			}
			next.close()
			if connector.calls.Load() != 1 {
				t.Fatal("hidden retry")
			}
		})
	}
}
