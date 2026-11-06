package sourceauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every private key is generated in memory for one isolated synthetic fixture.
// It is never serialized, read from disk, logged or used for real source.
func fixtureKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Independent fixture encoder: do not use the product's SSH writer.
	var wire bytes.Buffer
	fixtureString(&wire, []byte("ssh-ed25519"))
	fixtureString(&wire, pub)
	return pub, private, wire.Bytes()
}
func fixtureString(w *bytes.Buffer, b []byte) {
	if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		panic(err)
	}
	w.Write(b)
}
func fixtureFingerprint(wire []byte) string {
	h := sha256.Sum256(wire)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}
func fixtureOID(raw []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "commit %d\x00", len(raw))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func fixtureSign(t *testing.T, unsigned []byte, private ed25519.PrivateKey, public []byte, algorithm string) []byte {
	t.Helper()
	var digest []byte
	switch algorithm {
	case "sha256":
		h := sha256.Sum256(unsigned)
		digest = h[:]
	case "sha512":
		h := sha512.Sum512(unsigned)
		digest = h[:]
	default:
		t.Fatal("invalid fixture hash")
	}
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, b := range [][]byte{[]byte("git"), nil, []byte(algorithm), digest} {
		fixtureString(&signed, b)
	}
	signature := ed25519.Sign(private, signed.Bytes())
	var encodedSig bytes.Buffer
	fixtureString(&encodedSig, []byte("ssh-ed25519"))
	fixtureString(&encodedSig, signature)
	var container bytes.Buffer
	container.WriteString("SSHSIG")
	binary.Write(&container, binary.BigEndian, uint32(1))
	for _, b := range [][]byte{public, []byte("git"), nil, []byte(algorithm), encodedSig.Bytes()} {
		fixtureString(&container, b)
	}
	armor := pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: container.Bytes()})
	separator := bytes.Index(unsigned, []byte("\n\n"))
	if separator < 0 {
		t.Fatal("invalid fixture commit")
	}
	var result bytes.Buffer
	result.Write(unsigned[:separator+1])
	result.WriteString("gpgsig ")
	result.Write(bytes.ReplaceAll(bytes.TrimSuffix(armor, []byte{'\n'}), []byte{'\n'}, []byte{'\n', ' '}))
	result.WriteByte('\n')
	result.Write(unsigned[separator+1:])
	return result.Bytes()
}

type fixtureClock struct {
	mu     sync.Mutex
	r      Reading
	err    error
	reads  int
	onRead func(*fixtureClock)
}

func (c *fixtureClock) Read() (Reading, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.onRead != nil {
		c.onRead(c)
	}
	return c.r, c.err
}
func (c *fixtureClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.r.Wall = c.r.Wall.Add(d)
	c.r.Monotonic += d
}

type fixtureSource struct {
	observation Observation
	queries     []Query
	err         error
	change      func(context.Context, Query, *Observation)
}

func (s *fixtureSource) Read(ctx context.Context, q Query) (Observation, error) {
	s.queries = append(s.queries, q)
	o := copyObservation(s.observation)
	o.Binding = q
	if s.change != nil {
		s.change(ctx, q, &o)
	}
	return o, s.err
}
func copyObservation(o Observation) Observation {
	o.Commit = bytes.Clone(o.Commit)
	o.LandingPath = append([][]byte(nil), o.LandingPath...)
	for i := range o.LandingPath {
		o.LandingPath[i] = bytes.Clone(o.LandingPath[i])
	}
	o.Reviews.Records = append([]PlatformReview(nil), o.Reviews.Records...)
	o.CheckPolicy.Required = append([]CheckIdentity(nil), o.CheckPolicy.Required...)
	o.Checks.Records = append([]CheckRecord(nil), o.Checks.Records...)
	o.Lookup.Scopes = append([]ScopeRead(nil), o.Lookup.Scopes...)
	for i := range o.Lookup.Scopes {
		o.Lookup.Scopes[i].Events = append([]Event(nil), o.Lookup.Scopes[i].Events...)
	}
	return o
}

type fixture struct {
	p        Policy
	r        Request
	s        *fixtureSource
	c        *fixtureClock
	unsigned []byte
}

func validFixture(t *testing.T) *fixture {
	t.Helper()
	_, private, public := fixtureKey(t)
	const repo = "https://github.com/fixture-owner/fixture-source"
	p := Policy{Product: "fixture", Alias: "fixture-source", CanonicalRepository: repo, RepositoryName: "fixture-owner/fixture-source", DefaultBranch: "main", SHA256: strings.Repeat("a", 64), MatrixOrigin: "fixture.invalid", ProducerSender: "@producer:fixture.invalid", ReviewerSenders: []string{"@reviewer:fixture.invalid"}, Scopes: []string{"!review:fixture.invalid"}, OwnerKeys: []OwnerKey{{Repository: repo, Fingerprint: fixtureFingerprint(public), PublicKey: public}}, Profile: Profile{CommitBytes: 1 << 20, AncestryCommits: 256, PlatformReviews: 256, CheckRecords: 256}}
	unsigned := []byte("tree " + strings.Repeat("1", 40) + "\nauthor Fixture <fixture@example.invalid> 1740000000 +0000\ncommitter Fixture <fixture@example.invalid> 1740000000 +0000\n\nSynthetic authority fixture.\n")
	raw := fixtureSign(t, unsigned, private, public, "sha512")
	now := int64(1740000100)
	r := Request{OperationID: strings.Repeat("b", 32), Nonce: strings.Repeat("c", 64), Product: p.Product, Repository: p.Alias, Commit: fixtureOID(raw), PolicySHA256: p.SHA256}
	o := Observation{ObservedAt: now, ExpiresAt: now + 300, PolicySHA256: p.SHA256, PolicyState: Current, Commit: raw, Repository: RepositoryRecord{Canonical: repo, DefaultBranch: "main", DefaultHead: r.Commit}, PR: PullRequest{Repository: repo, Head: r.Commit, Base: strings.Repeat("2", 40), State: "merged", Number: 17}, Producer: ProducerHandoff{Origin: p.MatrixOrigin, Scope: p.Scopes[0], Event: "$producer", Sender: p.ProducerSender, Repository: repo, Head: r.Commit, PR: 17, State: "intact"}, Reviews: ReviewInventory{Coverage: Complete, SelectedID: "review-17", Records: []PlatformReview{{Repository: repo, ID: "review-17", Head: r.Commit, Base: strings.Repeat("2", 40), PR: 17, Kind: "COMMENT", State: "active", SubmittedAt: now - 10}}}, CheckPolicy: CheckPolicy{Repository: repo, Ref: "configured-required-checks-v1", State: "required", Required: []CheckIdentity{{"unit", "app-17"}, {"race", "app-17"}}}, Checks: CheckInventory{Coverage: Complete, Repository: repo, Head: r.Commit, Records: []CheckRecord{{Identity: CheckIdentity{"unit", "app-17"}, ID: "check-unit", Repository: repo, Head: r.Commit, State: "completed", Result: "success"}, {Identity: CheckIdentity{"race", "app-17"}, ID: "check-race", Repository: repo, Head: r.Commit, State: "completed", Result: "success"}}}}
	o.Lookup = Lookup{WindowStart: now - 10 - 86400, WindowEnd: now - 10 + 300, ObservedAt: now, Scopes: []ScopeRead{{Origin: p.MatrixOrigin, Scope: p.Scopes[0], FrontierSHA256: strings.Repeat("d", 64), Coverage: Complete, Pages: 1, Events: []Event{{ID: "$verdict", Sender: p.ReviewerSenders[0], State: "intact", ServerAt: now - 11}}}}}
	f := &fixture{p: p, r: r, s: &fixtureSource{observation: o}, c: &fixtureClock{r: Reading{Wall: time.Unix(now, 0), Monotonic: time.Second, Epoch: "fixture-process-1"}}, unsigned: unsigned}
	f.rebindHead(r.Commit)
	return f
}
func (f *fixture) rebindHead(head string) {
	f.r.Commit = head
	o := &f.s.observation
	o.Repository.DefaultHead = head
	o.PR.Head = head
	o.Producer.Head = head
	o.Checks.Head = head
	for i := range o.Checks.Records {
		o.Checks.Records[i].Head = head
	}
	o.Reviews.Records[0].Head = head
	body := fmt.Sprintf("ACCEPT: independent source review of %s PR #%d.\nPR %s/pull/%d\nExact head %s, base %s.\n\nNon-blocking notes: synthetic source-only control; no live authority.\n", f.p.RepositoryName, o.PR.Number, f.p.CanonicalRepository, o.PR.Number, head, o.PR.Base)
	o.Lookup.Scopes[0].Events[0].Body = body
	f.rebindDigest()
}
func (f *fixture) rebindDigest() {
	o := &f.s.observation
	h := sha256.Sum256([]byte(o.Lookup.Scopes[0].Events[0].Body))
	o.Reviews.Records[0].Body = fmt.Sprintf("Independent source review: **ACCEPT** for exact head `%s` (base `%s`).\n\nVerdict record digest: sha256:%x\n", o.PR.Head, o.PR.Base, h)
}
func (f *fixture) authority(t *testing.T) *Authority {
	t.Helper()
	a, err := New(f.p, f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func qualifyFixture(t *testing.T, f *fixture) *Qualification {
	t.Helper()
	q, err := f.authority(t).BeforeBuild(context.Background(), f.r)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// Git/OpenSSH is an independent cryptographic/encoding oracle. It consumes only
// the synthetic signed object and public allowed_signers fixture, never a key.
// Claim: Git/OpenSSH verifies the synthetic signed object and agrees with its exact object identity and qualification.
func TestGitOpenSSHPositiveControl(t *testing.T) {
	f := validFixture(t)
	dir := t.TempDir()
	command := func(input []byte, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git fixture oracle: %v: %s", err, out)
		}
		return out
	}
	command(nil, "init", "--bare", dir)
	got := strings.TrimSpace(string(command(f.s.observation.Commit, "-C", dir, "hash-object", "-t", "commit", "-w", "--stdin")))
	if got != f.r.Commit {
		t.Fatal("Git object identity disagrees")
	}
	allowed := filepath.Join(t.TempDir(), "allowed_signers")
	public := "fixture@example.invalid ssh-ed25519 " + base64.StdEncoding.EncodeToString(f.p.OwnerKeys[0].PublicKey) + "\n"
	if err := os.WriteFile(allowed, []byte(public), 0600); err != nil {
		t.Fatal(err)
	}
	out := command(nil, "-C", dir, "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", f.r.Commit)
	if !bytes.Contains(out, []byte("Good \"git\" signature")) {
		t.Fatalf("missing independent Git signature verification: %s", out)
	}
	qualifyFixture(t, f)
}
