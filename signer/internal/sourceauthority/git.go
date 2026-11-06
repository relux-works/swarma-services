package sourceauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1" // Git SHA-1 object identity is the explicitly supported format.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"strings"
)

type gitCommit struct {
	oid, tree           string
	parents             []string
	unsigned, signature []byte
}

// parseCommit hashes the FULL signed object and removes only the Git gpgsig
// header (including its continuation lines) for signature verification. Message
// bytes and all other headers retain their original spelling and newlines.
func parseCommit(raw []byte) (gitCommit, error) {
	var c gitCommit
	h := sha1.New()
	h.Write([]byte("commit " + strconv.Itoa(len(raw)) + "\x00"))
	h.Write(raw)
	c.oid = hex.EncodeToString(h.Sum(nil))
	end := bytes.Index(raw, []byte("\n\n"))
	if end < 0 || bytes.IndexByte(raw[:end], 0) >= 0 {
		return c, rejected("commit_shape")
	}
	lines := bytes.SplitAfter(raw[:end+1], []byte{'\n'})
	var sigSeen, continuingSig bool
	var lastKey string
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' {
			if lastKey == "" {
				return c, rejected("commit_shape")
			}
			if continuingSig {
				c.signature = append(c.signature, line[1:]...)
			} else {
				c.unsigned = append(c.unsigned, line...)
			}
			continue
		}
		at := bytes.IndexByte(line, ' ')
		if at < 1 || line[len(line)-1] != '\n' {
			return c, rejected("commit_shape")
		}
		key, value := string(line[:at]), string(line[at+1:len(line)-1])
		lastKey, continuingSig = key, key == "gpgsig"
		switch key {
		case "tree":
			if c.tree != "" || !lowerHex(value, 40) {
				return c, rejected("commit_shape")
			}
			c.tree = value
		case "parent":
			if !lowerHex(value, 40) {
				return c, rejected("commit_shape")
			}
			c.parents = append(c.parents, value)
		case "gpgsig":
			if sigSeen {
				return c, rejected("commit_signature")
			}
			sigSeen = true
			c.signature = append(c.signature, line[at+1:]...)
		}
		if !continuingSig {
			c.unsigned = append(c.unsigned, line...)
		}
	}
	if c.tree == "" {
		return c, rejected("commit_shape")
	}
	c.unsigned = append(c.unsigned, raw[end+1:]...)
	return c, nil
}

type sshReader struct {
	b   []byte
	bad bool
}

func (r *sshReader) uint32() uint32 {
	if len(r.b) < 4 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[:4])
	r.b = r.b[4:]
	return v
}
func (r *sshReader) str() []byte {
	n := r.uint32()
	if r.bad || uint64(n) > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	v := r.b[:int(n)]
	r.b = r.b[int(n):]
	return v
}
func sshString(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}
func sshEd25519Public(b []byte) (ed25519.PublicKey, bool) {
	r := sshReader{b: b}
	algorithm, key := r.str(), r.str()
	return ed25519.PublicKey(key), !r.bad && len(r.b) == 0 && string(algorithm) == "ssh-ed25519" && len(key) == ed25519.PublicKeySize
}
func fingerprint(b []byte) string {
	h := sha256.Sum256(b)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

func verifyOwner(c gitCommit, policy Policy) (string, error) {
	if len(c.signature) == 0 {
		return "", rejected("unsigned_commit")
	}
	block, rest := pem.Decode(c.signature)
	if block == nil || block.Type != "SSH SIGNATURE" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.HasPrefix(c.signature, []byte("-----BEGIN SSH SIGNATURE-----\n")) {
		return "", rejected("commit_signature")
	}
	if !bytes.HasPrefix(block.Bytes, []byte("SSHSIG")) {
		return "", rejected("commit_signature")
	}
	r := sshReader{b: block.Bytes[6:]}
	version := r.uint32()
	public, namespace, reserved, hashAlgorithm, signature := r.str(), r.str(), r.str(), r.str(), r.str()
	if r.bad || len(r.b) != 0 || version != 1 || string(namespace) != "git" || len(reserved) != 0 {
		return "", rejected("commit_signature")
	}
	pub, ok := sshEd25519Public(public)
	if !ok {
		return "", rejected("unsupported_owner_signature")
	}
	keyID := fingerprint(public)
	admitted := false
	for _, k := range policy.OwnerKeys {
		if k.Repository == policy.CanonicalRepository && k.Fingerprint == keyID && bytes.Equal(k.PublicKey, public) {
			admitted = true
		}
	}
	if !admitted {
		return "", rejected("owner_key")
	}
	sigReader := sshReader{b: signature}
	algorithm, sig := sigReader.str(), sigReader.str()
	if sigReader.bad || len(sigReader.b) != 0 || string(algorithm) != "ssh-ed25519" || len(sig) != ed25519.SignatureSize {
		return "", rejected("commit_signature")
	}
	var digest []byte
	switch string(hashAlgorithm) {
	case "sha256":
		h := sha256.Sum256(c.unsigned)
		digest = h[:]
	case "sha512":
		h := sha512.Sum512(c.unsigned)
		digest = h[:]
	default:
		return "", rejected("unsupported_owner_signature")
	}
	payload := []byte("SSHSIG")
	for _, b := range [][]byte{namespace, reserved, hashAlgorithm, digest} {
		payload = sshString(payload, b)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return "", rejected("commit_signature")
	}
	return keyID, nil
}

func verifyLanding(o Observation, c gitCommit) (string, error) {
	expected := o.Repository.DefaultHead
	if expected == c.oid {
		if len(o.LandingPath) != 0 {
			return "", rejected("landing_path")
		}
		return "equal", nil
	}
	if len(o.LandingPath) == 0 {
		return "", rejected("unlanded_commit")
	}
	for i, raw := range o.LandingPath {
		ancestor, err := parseCommit(raw)
		if err != nil {
			return "", err
		}
		if ancestor.oid != expected {
			return "", rejected("landing_path")
		}
		next := c.oid
		if i+1 < len(o.LandingPath) {
			n, err := parseCommit(o.LandingPath[i+1])
			if err != nil {
				return "", err
			}
			next = n.oid
		}
		found := false
		for _, parent := range ancestor.parents {
			if parent == next {
				found = true
			}
		}
		if !found {
			return "", rejected("unlanded_commit")
		}
		expected = next
	}
	return "ancestor", nil
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
