package sourceauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type reviewLab struct {
	p                  Policy
	b                  GitHubReviewBinding
	reviewer, producer ed25519.PrivateKey
}

func newReviewLab(t *testing.T) reviewLab {
	t.Helper()
	_, producer, producerPublic := fixtureKey(t)
	_, reviewer, reviewerPublic := fixtureKey(t)
	p := Policy{Product: "keyvault", Alias: "swarma-keyvault", CanonicalRepository: GitHubRepository, RepositoryName: "relux-works/swarma-keyvault", DefaultBranch: "main", SHA256: strings.Repeat("a", 64), Scopes: []string{GitHubReviewScope}, ReviewerSenders: []string{}, OwnerKeys: []OwnerKey{{GitHubRepository, fixtureFingerprint(producerPublic), producerPublic}}, ReviewerKeys: []OwnerKey{{GitHubRepository, fixtureFingerprint(reviewerPublic), reviewerPublic}}, Profile: Profile{1 << 20, 256, 256, 256}}
	return reviewLab{p, GitHubReviewBinding{GitHubRepository, "main", strings.Repeat("1", 40), strings.Repeat("2", 40), 17}, reviewer, producer}
}

// Independent test encoder, including canonical OpenSSH 70-column armor. Keys
// are generated in memory per test; no private material is serialized or logged.
func labSSHSIG(t *testing.T, v []byte, private ed25519.PrivateKey, public []byte, namespace, hash string) []byte {
	t.Helper()
	var digest []byte
	if hash == "sha512" {
		h := sha512.Sum512(v)
		digest = h[:]
	} else {
		h := sha256.Sum256(v)
		digest = h[:]
	}
	var payload bytes.Buffer
	payload.WriteString("SSHSIG")
	for _, x := range [][]byte{[]byte(namespace), nil, []byte(hash), digest} {
		fixtureString(&payload, x)
	}
	sig := ed25519.Sign(private, payload.Bytes())
	var sigBlob bytes.Buffer
	fixtureString(&sigBlob, []byte("ssh-ed25519"))
	fixtureString(&sigBlob, sig)
	var binarySig bytes.Buffer
	binarySig.WriteString("SSHSIG")
	binary.Write(&binarySig, binary.BigEndian, uint32(1))
	for _, x := range [][]byte{public, []byte(namespace), nil, []byte(hash), sigBlob.Bytes()} {
		fixtureString(&binarySig, x)
	}
	encoded := base64.StdEncoding.EncodeToString(binarySig.Bytes())
	armor := "-----BEGIN SSH SIGNATURE-----\n"
	for start := 0; start < len(encoded); start += 70 {
		stop := start + 70
		if stop > len(encoded) {
			stop = len(encoded)
		}
		armor += encoded[start:stop] + "\n"
	}
	return []byte(armor + "-----END SSH SIGNATURE-----\n")
}
func (l reviewLab) verdict(b GitHubReviewBinding) []byte {
	return []byte(fmt.Sprintf("ACCEPT: independent source review of relux-works/swarma-keyvault PR #%d\nPR %s/pull/%d\nExact head %s, base %s.\nScope %s.\n", b.PR, b.Repository, b.PR, b.Head, b.Base, GitHubReviewScope))
}
func labComment(b GitHubReviewBinding, v, armor []byte) []byte {
	h := sha256.Sum256(v)
	prefix := fmt.Sprintf("Independent source review: **ACCEPT** for exact head `%s` (base `%s`).\nVerdict record digest: `sha256:%x`\n\n", b.Head, b.Base, h)
	return append(append(append([]byte(prefix), v...), '\n'), armor...)
}
func (l reviewLab) signed(t *testing.T) []byte {
	v := l.verdict(l.b)
	return labComment(l.b, v, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512"))
}
func labValid(t *testing.T, l reviewLab) {
	t.Helper()
	got, err := VerifyGitHubReview(l.p, l.b, l.signed(t))
	if err != nil || got.Fingerprint != l.p.ReviewerKeys[0].Fingerprint || got.BodySHA256 == "" {
		t.Fatalf("genuine signed lab control failed: %v", err)
	}
}

func TestSignedReviewPairedRefusals(t *testing.T) {
	cases := []string{"verdict_namespace_git", "producer_signed_verdict", "unsigned", "other_head", "other_base", "other_repo", "other_base_branch", "other_PR", "other_scope", "sha256", "unadopted", "changed_payload", "suffix", "CRLF", "duplicate_block", "oversize", "noncanonical_armor"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			l := newReviewLab(t)
			labValid(t, l)
			b := l.b
			v := l.verdict(b)
			comment := l.signed(t)
			switch name {
			case "verdict_namespace_git":
				comment = labComment(b, v, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, "git", "sha512"))
			case "producer_signed_verdict":
				comment = labComment(b, v, labSSHSIG(t, v, l.producer, l.p.OwnerKeys[0].PublicKey, ReviewNamespace, "sha512"))
			case "unsigned":
				comment = labComment(b, v, nil)
			case "other_head":
				signed := b
				signed.Head = strings.Repeat("3", 40)
				v = l.verdict(signed)
				comment = labComment(b, v, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512"))
			case "other_base":
				signed := b
				signed.Base = strings.Repeat("3", 40)
				v = l.verdict(signed)
				comment = labComment(b, v, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512"))
			case "other_repo":
				b.Repository = "https://github.com/other/repo"
			case "other_base_branch":
				b.BaseBranch = "release"
			case "other_PR":
				b.PR++
			case "other_scope":
				v = bytes.ReplaceAll(v, []byte(GitHubReviewScope), []byte("github.com/relux-works/swarma-keyvault@release"))
				comment = labComment(b, v, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512"))
			case "sha256":
				comment = labComment(b, v, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha256"))
			case "unadopted":
				_, private, public := fixtureKey(t)
				comment = labComment(b, v, labSSHSIG(t, v, private, public, ReviewNamespace, "sha512"))
			case "changed_payload":
				comment = bytes.Replace(comment, []byte("Scope "), []byte("scope "), 1)
			case "suffix":
				comment = append(comment, 'x')
			case "CRLF":
				comment = bytes.ReplaceAll(comment, []byte{'\n'}, []byte{'\r', '\n'})
			case "duplicate_block":
				comment = append(comment, labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512")...)
			case "oversize":
				comment = bytes.Repeat([]byte{'x'}, MaxReviewCommentBytes+1)
			case "noncanonical_armor":
				comment = bytes.Replace(comment, []byte("-----END SSH SIGNATURE-----\n"), []byte("\n-----END SSH SIGNATURE-----\n"), 1)
			}
			if _, err := VerifyGitHubReview(l.p, b, comment); err == nil {
				t.Fatal("negative control accepted")
			} else {
				t.Logf("paired signed control passes; refusal: %v", err)
			}
			labValid(t, l)
		})
	}
}

func TestReviewerPolicyLoadPairedRefusals(t *testing.T) {
	for _, name := range []string{"producer_equal", "any_producer_equal", "duplicate", "invalid", "unadopted_repo", "missing", "five", "fingerprint", "wrong_scope", "wrong_repo", "wrong_branch", "matrix_set"} {
		t.Run(name, func(t *testing.T) {
			l := newReviewLab(t)
			labValid(t, l)
			p := l.p
			switch name {
			case "producer_equal":
				p.ReviewerKeys = []OwnerKey{p.OwnerKeys[0]}
			case "any_producer_equal":
				extra := p.ReviewerKeys[0]
				extra.Repository = "https://github.com/other/repo"
				p.OwnerKeys = append(append([]OwnerKey{}, p.OwnerKeys...), extra)
			case "duplicate":
				p.ReviewerKeys = append(append([]OwnerKey{}, p.ReviewerKeys...), p.ReviewerKeys[0])
			case "invalid":
				p.ReviewerKeys = []OwnerKey{{GitHubRepository, "bad", []byte{1}}}
			case "unadopted_repo":
				k := p.ReviewerKeys[0]
				k.Repository = "https://github.com/other/repo"
				p.ReviewerKeys = []OwnerKey{k}
			case "missing":
				p.ReviewerKeys = nil
			case "five":
				p.ReviewerKeys = make([]OwnerKey, 5)
			case "fingerprint":
				k := p.ReviewerKeys[0]
				k.Fingerprint = k.Fingerprint[:12]
				p.ReviewerKeys = []OwnerKey{k}
			case "wrong_scope":
				p.Scopes = []string{"!room:fixture.invalid"}
			case "wrong_repo":
				p.CanonicalRepository = "https://github.com/other/repo"
			case "wrong_branch":
				p.DefaultBranch = "release"
			case "matrix_set":
				p.MatrixOrigin = "fixture.invalid"
			}
			if err := ValidateGitHubPolicy(p); err == nil {
				t.Fatal("invalid native policy admitted")
			} else {
				t.Logf("paired signed control passes; policy-load refusal: %v", err)
			}
			labValid(t, l)
		})
	}
}

func TestMatrixLegacyGuardAndReviewerCopies(t *testing.T) {
	f := validFixture(t)
	qualifyFixture(t, f)
	p := f.p
	p.MatrixOrigin = ""
	p.ProducerSender = ""
	p.ReviewerSenders = nil
	if _, err := New(p, f.s, f.c); err == nil {
		t.Fatal("unset Matrix IDs defaulted")
	}
	_, _, public := fixtureKey(t)
	f.p.ReviewerKeys = []OwnerKey{{f.p.CanonicalRepository, fixtureFingerprint(public), public}}
	a := f.authority(t)
	f.p.ReviewerKeys[0].PublicKey[0] ^= 1
	if _, err := a.BeforeBuild(context.Background(), f.r); err != nil {
		t.Fatal("reviewer pin was not copied", err)
	}
	f.p.ReviewerKeys = []OwnerKey{f.p.OwnerKeys[0]}
	if _, err := New(f.p, f.s, f.c); err == nil {
		t.Fatal("Matrix policy accepted equal producer/reviewer keys")
	}
}

func TestCommitReviewNamespacePairedRefusal(t *testing.T) {
	f := validFixture(t)
	qualifyFixture(t, f)
	_, private, public := fixtureKey(t)
	p := f.p
	p.OwnerKeys = []OwnerKey{{p.CanonicalRepository, fixtureFingerprint(public), public}}
	// Both signatures are real over exactly the unsigned commit; only the domain
	// changes. Reviewer-domain commit must never qualify as a git-domain commit.
	for _, namespace := range []string{"git", ReviewNamespace, "git"} {
		armor := labSSHSIG(t, f.unsigned, private, public, namespace, "sha512")
		sep := bytes.Index(f.unsigned, []byte("\n\n"))
		raw := append([]byte{}, f.unsigned[:sep+1]...)
		raw = append(raw, []byte("gpgsig ")...)
		raw = append(raw, bytes.ReplaceAll(bytes.TrimSuffix(armor, []byte{'\n'}), []byte{'\n'}, []byte{'\n', ' '})...)
		raw = append(raw, '\n')
		raw = append(raw, f.unsigned[sep+1:]...)
		c, err := parseCommit(raw)
		if err != nil {
			t.Fatal(err)
		}
		_, err = verifyOwner(c, p)
		if (namespace == "git") != (err == nil) {
			t.Fatalf("namespace separation failed: %s %v", namespace, err)
		}
		f.p = p
		f.s.observation.Commit = raw
		f.rebindHead(fixtureOID(raw))
		for _, phase := range []Phase{Prebuild, Presign} {
			a := f.authority(t)
			var boundaryErr error
			if phase == Prebuild {
				_, boundaryErr = a.BeforeBuild(context.Background(), f.r)
			} else {
				_, boundaryErr = a.BeforeSign(context.Background(), f.r)
			}
			if (namespace == "git") != (boundaryErr == nil) {
				t.Fatalf("boundary namespace separation failed: %s %s %v", phase, namespace, boundaryErr)
			}
			t.Logf("phase=%s namespace=%s result=%v", phase, namespace, boundaryErr)
		}
	}
}

func TestReviewOpenSSHOracle(t *testing.T) {
	l := newReviewLab(t)
	labValid(t, l)
	v := l.verdict(l.b)
	armor := labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512")
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	signature := filepath.Join(dir, "review.sig")
	if err := os.WriteFile(allowed, []byte("review-lab namespaces=\"swarma-source-review\" ssh-ed25519 "+base64.StdEncoding.EncodeToString(l.p.ReviewerKeys[0].PublicKey)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signature, armor, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "review-lab", "-n", ReviewNamespace, "-s", signature)
	cmd.Stdin = bytes.NewReader(v)
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("Good \"swarma-source-review\" signature")) {
		t.Fatalf("independent OpenSSH oracle failed: %v %s", err, out)
	}
}

func TestReviewerPinCardinalityAndEveryPin(t *testing.T) {
	l := newReviewLab(t)
	labValid(t, l)
	private := []ed25519.PrivateKey{l.reviewer}
	for i := 1; i < MaxReviewerKeys; i++ {
		_, sk, pub := fixtureKey(t)
		private = append(private, sk)
		l.p.ReviewerKeys = append(l.p.ReviewerKeys, OwnerKey{GitHubRepository, fixtureFingerprint(pub), pub})
	}
	if err := ValidateGitHubPolicy(l.p); err != nil {
		t.Fatal("four distinct pins refused", err)
	}
	v := l.verdict(l.b)
	for i, key := range l.p.ReviewerKeys {
		body := labComment(l.b, v, labSSHSIG(t, v, private[i], key.PublicKey, ReviewNamespace, "sha512"))
		got, err := VerifyGitHubReview(l.p, l.b, body)
		if err != nil || got.Fingerprint != key.Fingerprint {
			t.Fatalf("configured pin %d failed: %v", i, err)
		}
	}
}

func TestReviewSSHSIGBinaryBounds(t *testing.T) {
	l := newReviewLab(t)
	v := l.verdict(l.b)
	good := labSSHSIG(t, v, l.reviewer, l.p.ReviewerKeys[0].PublicKey, ReviewNamespace, "sha512")
	// Decode only the independently generated lab control, then perturb framing.
	lines := bytes.Split(good, []byte{'\n'})
	raw, err := base64.StdEncoding.DecodeString(string(bytes.Join(lines[1:len(lines)-2], nil)))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"unknown_version":    func(b []byte) []byte { binary.BigEndian.PutUint32(b[6:10], 2); return b },
		"huge_length":        func(b []byte) []byte { binary.BigEndian.PutUint32(b[10:14], 0xffffffff); return b },
		"truncated":          func(b []byte) []byte { return b[:len(b)-1] },
		"trailing_binary":    func(b []byte) []byte { return append(b, 0) },
		"over_decoded_limit": func(b []byte) []byte { return append(b, make([]byte, MaxSSHSIGBytes+1)...) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			labValid(t, l)
			armor := canonicalReviewArmor(mutate(bytes.Clone(raw)))
			if _, err := VerifyGitHubReview(l.p, l.b, labComment(l.b, v, armor)); err == nil {
				t.Fatal("invalid SSHSIG accepted")
			} else {
				t.Logf("paired signed control passes; bounded parser refusal: %v", err)
			}
			labValid(t, l)
		})
	}
	// Every truncation is finite and must refuse, with a real control on both sides.
	labValid(t, l)
	for i := 0; i < len(raw); i++ {
		if _, err := VerifyGitHubReview(l.p, l.b, labComment(l.b, v, canonicalReviewArmor(raw[:i]))); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
	labValid(t, l)
}
