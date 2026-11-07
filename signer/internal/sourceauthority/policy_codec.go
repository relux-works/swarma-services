package sourceauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/relux-works/swarma-services/signer/internal/policyccj"
)

const MaxPolicyBytes = 64 << 10

// PolicyRoute is a trusted launch/installation choice, never request input or
// an inferred default. It does not select a signature format or provider mapper.
type PolicyRoute string

const (
	MatrixPolicyRoute   PolicyRoute = "matrix"
	GitHubPRPolicyRoute PolicyRoute = "github-pr"
)

// PolicySource is a trusted constructor-bound installation dependency, never
// release caller input. Snapshot must read current installed state and obey ctx.
type PolicySource interface {
	Snapshot(context.Context) (*PolicySnapshot, error)
}

// NewWithPolicySource requires the expected exact-byte digest supplied from the
// admission record at launch. It never learns admission from the installed file.
// No successful read is cached across qualification phases.
func NewWithPolicySource(ctx context.Context, installed PolicySource, expectedSHA256 string, source Source, clock Clock) (*Authority, error) {
	if installed == nil || ctx == nil || !lowerHex(expectedSHA256, 64) {
		return nil, unavailable("policy_configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityBudget)
	defer cancel()
	if ctx.Err() != nil {
		return nil, unavailable("policy_deadline")
	}
	s, err := installed.Snapshot(ctx)
	if err != nil || s == nil || ctx.Err() != nil {
		return nil, unavailable("policy_read")
	}
	if s.SHA256() != expectedSHA256 {
		return nil, rejected("policy_admission_digest")
	}
	a, err := NewForRoute(s.PolicyCopy(), s.route, source, clock)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, unavailable("policy_deadline")
	}
	a.installed, a.installedDigest = installed, expectedSHA256
	return a, nil
}

func checkInstalled(ctx context.Context, installed PolicySource, digest string) error {
	if ctx == nil || ctx.Err() != nil {
		return unavailable("policy_deadline")
	}
	if installed == nil {
		return nil
	}
	s, err := installed.Snapshot(ctx)
	if err != nil || s == nil || ctx.Err() != nil {
		return unavailable("policy_read")
	}
	if s.SHA256() != digest {
		return rejected("policy_revoked_or_changed")
	}
	return nil
}

// EncodePolicy serializes the configuration fields, excluding SHA256, using their
// exact Go field names, []byte's standard padded base64 and CCJ-1 canonical
// bytes. There is no wrapper, version, grant, adoption or authority object.
// SHA256 is derived only after serialization and is never an input to these bytes.
func EncodePolicy(p Policy) ([]byte, error) {
	return EncodePolicyForRoute(p, MatrixPolicyRoute)
}

// EncodePolicyForRoute explicitly selects configuration validity. GitHub-PR
// payloads keep the three unused Matrix fields present and empty. This codec
// alone grants no GitHub verification or reviewer-signature authority.
func EncodePolicyForRoute(p Policy, route PolicyRoute) ([]byte, error) {
	// Every nonempty string/owner array member costs at least four canonical
	// bytes. Bound collections before the unchanged core validator allocates.
	if len(p.ReviewerSenders) > MaxPolicyBytes/4 || len(p.OwnerKeys) > MaxPolicyBytes/4 {
		return nil, unavailable("policy_capacity")
	}
	if !validPolicyPayload(p, route) {
		return nil, unavailable("policy_configuration")
	}
	if len(p.ReviewerKeys) == 0 {
		p.ReviewerKeys = nil
	}
	if p.ReviewerSenders == nil {
		p.ReviewerSenders = []string{}
	}
	b, err := json.Marshal(p)
	// Go's temporary string escaping can be up to six times CCJ-1's length.
	// Enforce the actual canonical byte limit after canonicalization below.
	if err != nil || len(b) > 6*MaxPolicyBytes {
		return nil, unavailable("policy_capacity")
	}
	v, err := policyccj.Parse(b, "policy_encoding")
	if err != nil {
		return nil, unavailable("policy_encoding")
	}
	b, err = policyccj.Marshal(v, "policy_encoding")
	if err != nil || len(b) > MaxPolicyBytes {
		return nil, unavailable("policy_encoding")
	}
	return b, nil
}

// DecodePolicy requires exact canonical bytes and the closed native field
// mapping at every depth. Round-trip equality rejects omitted/extra fields,
// wrong case, null aliases and noncanonical base64 as well as CCJ-1 violations.
func DecodePolicy(raw []byte) (Policy, error) {
	return DecodePolicyForRoute(raw, MatrixPolicyRoute)
}

// DecodePolicyForRoute never infers a route from missing identity fields.
func DecodePolicyForRoute(raw []byte, route PolicyRoute) (Policy, error) {
	var p Policy
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return p, unavailable("policy_capacity")
	}
	v, err := policyccj.Parse(raw, "policy_encoding")
	if err != nil {
		return p, unavailable("policy_encoding")
	}
	canonical, err := policyccj.Marshal(v, "policy_encoding")
	if err != nil || !bytes.Equal(raw, canonical) {
		return p, unavailable("policy_encoding")
	}
	if json.Unmarshal(raw, &p) != nil {
		return Policy{}, unavailable("policy_encoding")
	}
	b, err := EncodePolicyForRoute(p, route)
	if err != nil || !bytes.Equal(raw, b) {
		return Policy{}, unavailable("policy_configuration")
	}
	h := sha256.Sum256(raw)
	p.SHA256 = hex.EncodeToString(h[:])
	return p, nil
}

// PolicySnapshot owns immutable bytes. Accessors return fresh independently
// owned data, never mutable aliases into the protected snapshot.
type PolicySnapshot struct {
	raw    []byte
	digest string
	route  PolicyRoute
}

func (s *PolicySnapshot) SHA256() string {
	if s == nil {
		return ""
	}
	return s.digest
}
func (s *PolicySnapshot) RawCopy() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.raw)
}
func (s *PolicySnapshot) PolicyCopy() Policy {
	if s == nil {
		return Policy{}
	}
	p, _ := DecodePolicyForRoute(s.raw, s.route)
	return p
}

func policySnapshot(raw []byte) (*PolicySnapshot, error) {
	return policySnapshotForRoute(raw, MatrixPolicyRoute)
}

func policySnapshotForRoute(raw []byte, route PolicyRoute) (*PolicySnapshot, error) {
	if _, err := DecodePolicyForRoute(raw, route); err != nil {
		return nil, err
	}
	h := sha256.Sum256(raw)
	return &PolicySnapshot{bytes.Clone(raw), hex.EncodeToString(h[:]), route}, nil
}
