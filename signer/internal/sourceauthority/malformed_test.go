package sourceauthority

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// Claim: Malformed or quoted platform digests cannot supply an authoritative exact digest line.
func TestMalformedDigestAndExactLineNeighbors(t *testing.T) {
	for _, value := range []string{"", "`", "``", "sha256:", "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65), "`sha256:" + strings.Repeat("a", 64), "``sha256:" + strings.Repeat("a", 64) + "``", "sha256:" + strings.Repeat("a", 64) + " ", "sha256:" + strings.Repeat("a", 64) + "\x00"} {
		t.Run(value, func(t *testing.T) {
			f := validFixture(t)
			first := strings.Split(f.s.observation.Reviews.Records[0].Body, "\n")[0]
			f.s.observation.Reviews.Records[0].Body = first + "\nVerdict record digest: " + value
			predicate := "platform_digest"
			if strings.ContainsRune(value, 0) {
				predicate = "platform_format"
			}
			assertRefusal(t, f, ErrRejected, predicate)
		})
	}
	t.Run("quoted_digest_does_not_supply_authoritative_line", func(t *testing.T) {
		f := validFixture(t)
		f.s.observation.Reviews.Records[0].Body = strings.Replace(f.s.observation.Reviews.Records[0].Body, "Verdict record digest:", "> Verdict record digest:", 1)
		assertRefusal(t, f, ErrRejected, "platform_digest")
	})
}

// Claim: Truncated or unsupported SSHSIG framing never verifies as an admitted owner signature.
func TestMalformedSSHLengthsNeverAuthorize(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("SSHSIG"), append([]byte("SSHSIG"), 0, 0, 0, 1, 255, 255, 255, 255), append([]byte("SSHSIG"), 0, 0, 0, 2)} {
		t.Run(strings.Repeat("x", len(raw)), func(t *testing.T) {
			f := validFixture(t)
			c, err := parseCommit(f.s.observation.Commit)
			if err != nil {
				t.Fatal(err)
			}
			c.signature = pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: raw})
			if _, err = verifyOwner(c, f.p); !errors.Is(err, ErrRejected) {
				t.Fatal("malformed SSHSIG authorized")
			}
		})
	}
}

// Claim: Mutating an actual signature byte refuses at the cryptographic predicate despite an admitted key.
func TestCryptographicSignatureCannotBeAClaimedFingerprint(t *testing.T) {
	f := validFixture(t)
	c, err := parseCommit(f.s.observation.Commit)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(c.signature)
	// Keep a real admitted public key, namespace, algorithm and signature length;
	// change one actual signature byte, rather than failing an unrelated parser.
	raw := bytes.Clone(block.Bytes)
	raw[len(raw)-1] ^= 1
	block.Bytes = raw
	c.signature = pem.EncodeToMemory(block)
	if _, err = verifyOwner(c, f.p); !errors.Is(err, ErrRejected) {
		t.Fatal("mutated actual signature authorized")
	}
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Predicate() != "commit_signature" {
		t.Fatal("wrong cryptographic predicate", err)
	}
}

// Claim: Altered SSHSIG namespace, reserved bytes, hash, version or algorithm never verifies.
func TestSSHSIGNamespaceAndHashAreBound(t *testing.T) {
	for _, field := range []string{"namespace", "reserved", "hash", "version", "algorithm"} {
		t.Run(field, func(t *testing.T) {
			f := validFixture(t)
			c, err := parseCommit(f.s.observation.Commit)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(c.signature)
			r := sshReader{b: block.Bytes[6:]}
			version := r.uint32()
			pub, namespace, reserved, hash, signature := r.str(), r.str(), r.str(), r.str(), r.str()
			switch field {
			case "namespace":
				namespace = []byte("file")
			case "reserved":
				reserved = []byte("extension")
			case "hash":
				hash = []byte("sha1")
			case "version":
				version = 2
			case "algorithm":
				signature = bytes.Replace(signature, []byte("ssh-ed25519"), []byte("ssh-invalid"), 1)
			}
			var wire bytes.Buffer
			wire.WriteString("SSHSIG")
			binary.Write(&wire, binary.BigEndian, version)
			for _, b := range [][]byte{pub, namespace, reserved, hash, signature} {
				fixtureString(&wire, b)
			}
			c.signature = pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: wire.Bytes()})
			if _, err = verifyOwner(c, f.p); !errors.Is(err, ErrRejected) {
				t.Fatal("modified SSHSIG metadata authorized")
			}
		})
	}
}

// Claim: Every changed response binding field refuses at both boundaries.
func TestEveryResponseBindingFieldIsChecked(t *testing.T) {
	for _, field := range []string{"operation", "nonce", "product", "repository", "commit", "policy", "phase"} {
		t.Run(field, func(t *testing.T) {
			f := validFixture(t)
			f.s.change = func(_ context.Context, _ Query, o *Observation) {
				switch field {
				case "operation":
					o.Binding.OperationID = strings.Repeat("0", 32)
				case "nonce":
					o.Binding.Nonce = strings.Repeat("0", 64)
				case "product":
					o.Binding.Product += "-other"
				case "repository":
					o.Binding.Repository += "-other"
				case "commit":
					o.Binding.Commit = strings.Repeat("0", 40)
				case "policy":
					o.Binding.PolicySHA256 = strings.Repeat("0", 64)
				case "phase":
					o.Binding.Phase = "fetch"
				}
			}
			assertRefusal(t, f, ErrRejected, "response_binding")
		})
	}
}
