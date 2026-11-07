// This contributor fixture uses only synthetic public data and in-memory
// adapters. It never acquires evidence or qualifies a real source.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	sa "github.com/relux-works/swarma-services/signer/internal/sourceauthority"
)

type refusingSource struct{ reads int }

func (s *refusingSource) Read(ctx context.Context, _ sa.Query) (sa.Observation, error) {
	s.reads++
	if err := ctx.Err(); err != nil {
		return sa.Observation{}, err
	}
	return sa.Observation{}, sa.ErrUnavailable
}

type fixtureClock struct{}

func (fixtureClock) Read() (sa.Reading, error) {
	return sa.Reading{Wall: time.Unix(1800000000, 0), Monotonic: time.Second, Epoch: "fixture"}, nil
}

var _ sa.Source = (*refusingSource)(nil)
var _ sa.Clock = fixtureClock{}

func run() error {
	// Public test-vector bytes only. No private key is generated or loaded.
	public, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		return err
	}
	wire := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), public...)
	hash := sha256.Sum256(wire)
	const repository = "https://example.invalid/source"
	policy := sa.Policy{
		Product: "fixture", Alias: "fixture-source", CanonicalRepository: repository,
		RepositoryName: "fixture/source", DefaultBranch: "main", SHA256: strings.Repeat("a", 64),
		MatrixOrigin: "example.invalid", ProducerSender: "fixture-producer",
		ReviewerSenders: []string{"fixture-reviewer"}, Scopes: []string{"fixture-scope"},
		OwnerKeys: []sa.OwnerKey{{Repository: repository, PublicKey: wire,
			Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])}},
		Profile: sa.Profile{CommitBytes: 1024, AncestryCommits: 1, PlatformReviews: 1, CheckRecords: 1},
	}
	source := &refusingSource{}
	authority, err := sa.New(policy, source, fixtureClock{})
	if err != nil {
		return err
	}
	request := sa.Request{OperationID: strings.Repeat("b", 32), Nonce: strings.Repeat("c", 64),
		Product: policy.Product, Repository: policy.Alias, Commit: strings.Repeat("d", 40), PolicySHA256: policy.SHA256}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	qualification, err := authority.BeforeBuild(ctx, request)
	var refusal *sa.Refusal
	if qualification != nil || !errors.Is(err, sa.ErrUnavailable) || !errors.As(err, &refusal) ||
		refusal.Predicate() != "source_read" || source.reads != 1 {
		return errors.New("expected unavailable source refusal after one adapter read")
	}
	// Change only the request alias: this must refuse before consulting Source.
	request.Repository = "different-fixture-source"
	qualification, err = authority.BeforeBuild(ctx, request)
	if qualification != nil || !errors.Is(err, sa.ErrRejected) || !errors.As(err, &refusal) ||
		refusal.Predicate() != "request_binding" || source.reads != 1 {
		return errors.New("expected binding refusal without another adapter read")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
	fmt.Println("fixture adapter wired; source_read refused; request_binding refused")
}
