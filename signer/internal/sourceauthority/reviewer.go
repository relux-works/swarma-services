package sourceauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
)

const (
	GitHubRepository       = "https://github.com/relux-works/swarma-keyvault"
	GitHubReviewScope      = "github.com/relux-works/swarma-keyvault@main"
	ReviewNamespace        = "swarma-source-review"
	MaxReviewerKeys        = 4
	MaxReviewCommentBytes  = 8192
	MaxVerdictBytes        = 2048
	MaxSignatureArmorBytes = 2048
	MaxSSHSIGBytes         = 512
)

// GitHubReviewBinding comes from the trusted adapter's current exact PR read.
// Base is an object ID; BaseBranch is the provider's branch name. Neither is a
// caller option. This helper establishes no inventory/landing/check coverage.
type GitHubReviewBinding struct {
	Repository, BaseBranch, Head, Base string
	PR                                 uint64
	ReviewID                           uint64
}

// ReviewerVerdict is a local cryptographic result, never a release grant.
type ReviewerVerdict struct{ Fingerprint, BodySHA256 string }

// ValidateReviewerKeys is shared with the native policy loader. Reviewer pins
// use the OwnerKey public triple but occupy a distinct role. Matrix legacy
// policies may omit them; the GitHub route requires one through four.
func ValidateReviewerKeys(p Policy, required bool) error {
	if len(p.ReviewerKeys) > MaxReviewerKeys || (required && len(p.ReviewerKeys) == 0) {
		return unavailable("reviewer_policy")
	}
	for i, k := range p.ReviewerKeys {
		if k.Repository != p.CanonicalRepository || len(k.PublicKey) != 51 || k.Fingerprint != fingerprint(k.PublicKey) {
			return unavailable("reviewer_policy")
		}
		if _, ok := sshEd25519Public(k.PublicKey); !ok {
			return unavailable("reviewer_policy")
		}
		for _, producer := range p.OwnerKeys {
			if bytes.Equal(k.PublicKey, producer.PublicKey) || k.Fingerprint == producer.Fingerprint {
				return unavailable("reviewer_producer_key")
			}
		}
		for _, previous := range p.ReviewerKeys[:i] {
			if bytes.Equal(k.PublicKey, previous.PublicKey) || k.Fingerprint == previous.Fingerprint {
				return unavailable("duplicate_reviewer_key")
			}
		}
	}
	return nil
}

// ValidateGitHubPolicy is explicit: empty Matrix fields never select a route.
// The protected codec must call this before admitting GitHub configuration.
// Runtime SHA256 remains the digest of the exact installed bytes, supplied by
// the loader only after checking the externally expected digest.
func ValidateGitHubPolicy(p Policy) error {
	if !lowerHex(p.SHA256, 64) || !validPolicyPayload(p, GitHubPRPolicyRoute) || p.CanonicalRepository != GitHubRepository || p.RepositoryName != "relux-works/swarma-keyvault" || p.DefaultBranch != "main" || len(p.Scopes) != 1 || p.Scopes[0] != GitHubReviewScope || p.MatrixOrigin != "" || p.ProducerSender != "" || len(p.ReviewerSenders) != 0 {
		return unavailable("github_policy")
	}
	return ValidateReviewerKeys(p, true)
}

func ValidateGitHubReviewBinding(p Policy, b GitHubReviewBinding) error {
	if err := ValidateGitHubPolicy(p); err != nil {
		return err
	}
	if b.Repository != p.CanonicalRepository || b.BaseBranch != p.DefaultBranch || !lowerHex(b.Head, 40) || !lowerHex(b.Base, 40) || b.PR == 0 || b.PR > 9223372036854775807 || b.ReviewID == 0 || b.ReviewID > 9223372036854775807 {
		return rejected("github_review_binding")
	}
	return nil
}

// VerifyGitHubReview verifies exact COMMENT bytes without trusting the posting
// login. This local binding primitive must run inside an enclosing finite phase
// budget. It establishes no history, source qualification or release authority.
func VerifyGitHubReview(p Policy, b GitHubReviewBinding, comment []byte) (ReviewerVerdict, error) {
	var result ReviewerVerdict
	if err := ValidateGitHubReviewBinding(p, b); err != nil {
		return result, err
	}
	if len(comment) == 0 || len(comment) > MaxReviewCommentBytes {
		return result, rejected("review_comment")
	}
	// Two fixed transport lines, blank separator, five exact verdict lines,
	// blank separator, then one canonical SSHSIG block. No trimming occurs.
	lines := bytes.SplitN(comment, []byte{'\n'}, 10)
	if len(lines) != 10 || len(lines[2]) != 0 || len(lines[8]) != 0 {
		return result, rejected("review_comment")
	}
	start := len(lines[0]) + len(lines[1]) + 3
	length := 5
	for _, line := range lines[3:8] {
		length += len(line)
	}
	v := comment[start : start+length]
	if len(v) > MaxVerdictBytes {
		return result, rejected("review_verdict")
	}
	digest := sha256.Sum256(v)
	digestText := hex.EncodeToString(digest[:])
	expectedPrefix := fmt.Sprintf("Independent source review: **ACCEPT** for exact head `%s` (base `%s`).", b.Head, b.Base)
	if string(lines[0]) != expectedPrefix || string(lines[1]) != "Verdict record digest: `sha256:"+digestText+"`" {
		return result, rejected("review_digest")
	}
	key, err := verifyReviewerSSHSIG(v, lines[9], p)
	if err != nil {
		return result, err
	}
	expected := fmt.Sprintf("ACCEPT: independent source review of %s PR #%d\nPR %s/pull/%d\nExact head %s, base %s.\nScope %s.\nOriginal delivery %s/pull/%d#pullrequestreview-%d.\n", p.RepositoryName, b.PR, p.CanonicalRepository, b.PR, b.Head, b.Base, p.Scopes[0], p.CanonicalRepository, b.PR, b.ReviewID)
	if !bytes.Equal(v, []byte(expected)) {
		return result, rejected("review_verdict_binding")
	}
	return ReviewerVerdict{key, digestText}, nil
}

func canonicalReviewArmor(binary []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(binary)
	armor := []byte("-----BEGIN SSH SIGNATURE-----\n")
	for len(encoded) > 70 {
		armor = append(armor, encoded[:70]...)
		armor = append(armor, '\n')
		encoded = encoded[70:]
	}
	armor = append(armor, encoded...)
	armor = append(armor, '\n')
	return append(armor, []byte("-----END SSH SIGNATURE-----\n")...)
}

func verifyReviewerSSHSIG(verdict, armor []byte, p Policy) (string, error) {
	if len(verdict) == 0 || len(verdict) > MaxVerdictBytes || len(armor) == 0 || len(armor) > MaxSignatureArmorBytes {
		return "", rejected("review_signature")
	}
	const begin = "-----BEGIN SSH SIGNATURE-----\n"
	const end = "-----END SSH SIGNATURE-----\n"
	if !bytes.HasPrefix(armor, []byte(begin)) || !bytes.HasSuffix(armor, []byte(end)) {
		return "", rejected("review_signature")
	}
	encoded := armor[len(begin) : len(armor)-len(end)]
	// Bound decoded allocation before Decode, even for malicious armor.
	compact := bytes.ReplaceAll(encoded, []byte{'\n'}, nil)
	if len(compact) > base64.StdEncoding.EncodedLen(MaxSSHSIGBytes) {
		return "", rejected("review_signature")
	}
	decodedLength := base64.StdEncoding.DecodedLen(len(compact))
	if bytes.HasSuffix(compact, []byte("=")) {
		decodedLength--
	}
	if bytes.HasSuffix(compact, []byte("==")) {
		decodedLength--
	}
	if decodedLength < 0 || decodedLength > MaxSSHSIGBytes {
		return "", rejected("review_signature")
	}
	var decoded [MaxSSHSIGBytes]byte
	n, err := base64.StdEncoding.Strict().Decode(decoded[:], compact)
	binary := decoded[:n]
	if err != nil || !bytes.Equal(canonicalReviewArmor(binary), armor) || !bytes.HasPrefix(binary, []byte("SSHSIG")) {
		return "", rejected("review_signature")
	}
	r := sshReader{b: binary[6:]}
	version := r.uint32()
	public, namespace, reserved, hashAlgorithm, signature := r.str(), r.str(), r.str(), r.str(), r.str()
	if r.bad || len(r.b) != 0 || version != 1 || string(namespace) != ReviewNamespace || len(reserved) != 0 || string(hashAlgorithm) != "sha512" {
		return "", rejected("review_signature")
	}
	pub, ok := sshEd25519Public(public)
	if !ok {
		return "", rejected("review_signature")
	}
	id := fingerprint(public)
	admitted := false
	for _, k := range p.ReviewerKeys {
		if k.Repository == p.CanonicalRepository && k.Fingerprint == id && bytes.Equal(k.PublicKey, public) {
			admitted = true
		}
	}
	if !admitted {
		return "", rejected("reviewer_key")
	}
	sr := sshReader{b: signature}
	algorithm, sig := sr.str(), sr.str()
	if sr.bad || len(sr.b) != 0 || string(algorithm) != "ssh-ed25519" || len(sig) != ed25519.SignatureSize {
		return "", rejected("review_signature")
	}
	digest := sha512.Sum512(verdict)
	payload := []byte("SSHSIG")
	for _, field := range [][]byte{namespace, reserved, hashAlgorithm, digest[:]} {
		payload = sshString(payload, field)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return "", rejected("review_signature")
	}
	return id, nil
}

// VerifyGitHubReviewRecord binds cryptography to the ACTUAL containing provider
// record. It proves no history, completeness, acquisition or release authority.
func VerifyGitHubReviewRecord(p Policy, b GitHubReviewBinding, r PlatformReview) (ReviewerVerdict, error) {
	if r.ID != strconv.FormatUint(b.ReviewID, 10) || r.Repository != b.Repository || r.PR != b.PR || r.Head != b.Head || r.Base != b.Base || r.Kind != "COMMENT" || r.State != "active" || r.SubmittedAt <= 0 {
		return ReviewerVerdict{}, rejected("review_original_record")
	}
	return VerifyGitHubReview(p, b, []byte(r.Body))
}

// BindGitHubReviewInventory selects only a unique cryptographically original
// CURRENT record. This is a bounded local binding primitive, never qualification:
// Complete here describes only the current inventory, not deleted-record,
// revision, dismissal or withdrawal history. GraphQL independently checks the
// selected original at admission and immediately before each final effect.
func BindGitHubReviewInventory(p Policy, b GitHubReviewBinding, inventory ReviewInventory) (PlatformReview, ReviewerVerdict, error) {
	var selected PlatformReview
	var verdict ReviewerVerdict
	if ValidateGitHubPolicy(p) != nil || inventory.Coverage != Complete || len(inventory.Records) > p.Profile.PlatformReviews || len(inventory.Records) > 256 {
		return selected, verdict, unavailable("github_current_inventory")
	}
	seen := make(map[string]PlatformReview)
	total, originals := 0, 0
	for _, r := range inventory.Records {
		id, err := strconv.ParseUint(r.ID, 10, 63)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != r.ID || r.Repository != b.Repository || r.PR != b.PR {
			return selected, verdict, unavailable("github_current_inventory")
		}
		if len(r.Body) > MaxBodyBytes-total {
			return selected, verdict, unavailable("github_current_inventory_capacity")
		}
		total += len(r.Body)
		if previous, ok := seen[r.ID]; ok {
			if previous != r {
				return selected, verdict, unavailable("github_current_inventory_conflict")
			}
			continue
		}
		seen[r.ID] = r
		if r.State == "active" && r.Kind == "CHANGES_REQUESTED" {
			return selected, verdict, rejected("review_withdrawal_or_blocking")
		}
		actual := b
		actual.ReviewID = id
		v, err := VerifyGitHubReview(p, actual, []byte(r.Body))
		if err == nil {
			originals++
			selected = r
			verdict = v
		}
	}
	if originals != 1 {
		return PlatformReview{}, ReviewerVerdict{}, rejected("review_original_uniqueness")
	}
	copies := 0
	for _, r := range seen {
		if r.Body == selected.Body {
			copies++
		}
	}
	if copies != 1 {
		return PlatformReview{}, ReviewerVerdict{}, rejected("review_original_copied")
	}
	actual := b
	id, _ := strconv.ParseUint(selected.ID, 10, 63)
	actual.ReviewID = id
	verified, err := VerifyGitHubReviewRecord(p, actual, selected)
	if err != nil {
		return PlatformReview{}, ReviewerVerdict{}, err
	}
	return selected, verified, nil
}
