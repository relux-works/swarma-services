package curatorclient

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxResponseBody = 16384
const maxArtifactBytes = 268435456

// ErrResponse contains no peer-controlled text. Failure leaves the caller's
// durable intent unchanged; it never establishes refusal or permits signing.
var ErrResponse = errors.New("invalid Curator response")

// Pins are digests of actual independently admitted bytes, never values learned
// from this response. Empty pins cannot authorize decoding a success receipt.
type Pins struct {
	Policy, Recipe, Toolchain, Input, Certificate, Requirement string
}

// Exchange is a caller-owned snapshot of the retained request and bindings.
// Session is a local exchange identity, not a wire field or peer credential.
// The transport must authenticate the peer before invoking DecodeResponse.
// OperationID may be absent on sign/inspect until the first summary is retained.
// Fetch requires both OperationID and the exact previously retained Receipt.
type Exchange struct {
	Session                        string
	RequestOpcode                  byte
	RequestID, Commit, OperationID string
	Pins                           Pins
	Receipt                        *Receipt
}

// Receipt is exactly C3's external receipt, without internal provider provenance.
// Decoding it proves neither durable history nor artifact/native verification.
type Receipt struct {
	ProductID         string `json:"product_id"`
	Repository        string `json:"repository"`
	Commit            string `json:"commit"`
	PolicySHA256      string `json:"policy_sha256"`
	RecipeSHA256      string `json:"recipe_sha256"`
	ToolchainSHA256   string `json:"toolchain_sha256"`
	InputSHA256       string `json:"input_sha256"`
	Target            string `json:"target"`
	UnsignedSHA256    string `json:"unsigned_sha256"`
	SignedSHA256      string `json:"signed_sha256"`
	UnsignedBytes     int64  `json:"unsigned_bytes"`
	SignedBytes       int64  `json:"signed_bytes"`
	CertificateSHA256 string `json:"certificate_sha256"`
	RequirementSHA256 string `json:"requirement_sha256"`
	AuditSequence     int64  `json:"audit_sequence"`
	AuditDigest       string `json:"audit_digest"`
}

type Source struct {
	ProductID  string `json:"product_id"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

type Refusal struct {
	Code, Retry, Message string
}

type Summary struct {
	RequestID, OperationID, State string
	Source                        Source
	Phase                         string
	Receipt                       *Receipt
	Refusal                       *Refusal
}

type FetchHeader struct {
	OperationID   string
	Receipt       Receipt
	ArtifactBytes int64
}

// Response has exactly one non-nil variant on success. Retry is only a wire
// hint; in a summary same_request means inspect. No variant authorizes effects.
type Response struct {
	Summary *Summary
	Refusal *Refusal
	Fetch   *FetchHeader
}

// DecodeResponse consumes exactly one bounded control frame, never artifact
// bytes. The caller supplies the local identity of the receiving exchange;
// replay onto a different exchange is rejected before decoding. Stream length,
// EOF, deadlines, peer custody, hash/native checks and persistence remain with
// the caller. An opcode 65 fetch refusal must not erase retained success.
func DecodeResponse(frame []byte, exchange Exchange, session string) (Response, error) {
	fail := func() (Response, error) { return Response{}, ErrResponse }
	if !identifier(exchange.Session) || session != exchange.Session ||
		!lowerHex(exchange.Commit, 40) || exchange.RequestOpcode < 1 || exchange.RequestOpcode > 3 {
		return fail()
	}
	if exchange.RequestOpcode != 3 && !identifier(exchange.RequestID) {
		return fail()
	}
	if exchange.OperationID != "" && !lowerHex(exchange.OperationID, 32) {
		return fail()
	}
	if exchange.RequestOpcode == 3 && (exchange.OperationID == "" || exchange.Receipt == nil) {
		return fail()
	}
	if len(frame) < 5 {
		return fail()
	}
	size := binary.BigEndian.Uint32(frame[1:5])
	if size == 0 || size > MaxResponseBody || uint64(size) != uint64(len(frame)-5) {
		return fail()
	}
	raw := frame[5:]
	if !strictJSON(raw) {
		return fail()
	}
	switch frame[0] {
	case 64:
		if exchange.RequestOpcode == 3 {
			return fail()
		}
		obj, ok := object(raw, "version", "request_id", "operation_id", "state", "source", "outcome")
		if !ok || string(obj["version"]) != "1" {
			return fail()
		}
		s := Summary{RequestID: textValue(obj["request_id"]), OperationID: textValue(obj["operation_id"]), State: textValue(obj["state"])}
		if s.RequestID != exchange.RequestID || !lowerHex(s.OperationID, 32) ||
			(exchange.OperationID != "" && s.OperationID != exchange.OperationID) {
			return fail()
		}
		src, ok := object(obj["source"], "product_id", "repository", "commit")
		if !ok {
			return fail()
		}
		s.Source = Source{textValue(src["product_id"]), textValue(src["repository"]), textValue(src["commit"])}
		if s.Source != (Source{"curator", "curator-core", exchange.Commit}) {
			return fail()
		}
		switch s.State {
		case "pending":
			out, ok := object(obj["outcome"], "kind", "phase")
			if !ok || textValue(out["kind"]) != s.State {
				return fail()
			}
			s.Phase = textValue(out["phase"])
			if !oneOf(s.Phase, "qualifying", "acquiring", "building", "signing", "reconciling") {
				return fail()
			}
		case "succeeded":
			out, ok := object(obj["outcome"], "kind", "receipt")
			if !ok || textValue(out["kind"]) != s.State {
				return fail()
			}
			receipt, ok := decodeReceipt(out["receipt"], exchange)
			if !ok {
				return fail()
			}
			s.Receipt = &receipt
		case "refused", "uncertain":
			out, ok := object(obj["outcome"], "kind", "code", "retry", "message")
			if !ok || textValue(out["kind"]) != s.State {
				return fail()
			}
			refusal, ok := decodeRefusal(out)
			if !ok {
				return fail()
			}
			if s.State == "uncertain" {
				if refusal.Code != "outcome_uncertain" || refusal.Retry != "inspect" {
					return fail()
				}
			} else if !oneOf(refusal.Code, "authority_rejected", "authority_unavailable", "build_failed", "build_isolation_failed", "artifact_rejected", "audit_unavailable") {
				return fail()
			}
			s.Refusal = &refusal
		default:
			return fail()
		}
		if exchange.Receipt != nil && s.State != "succeeded" {
			return fail()
		}
		return Response{Summary: &s}, nil
	case 65:
		obj, ok := object(raw, "version", "code", "retry", "message")
		if !ok || string(obj["version"]) != "1" {
			return fail()
		}
		refusal, ok := decodeRefusal(obj)
		if !ok {
			return fail()
		}
		return Response{Refusal: &refusal}, nil
	case 66:
		if exchange.RequestOpcode != 3 {
			return fail()
		}
		obj, ok := object(raw, "version", "operation_id", "receipt", "artifact_bytes")
		if !ok || string(obj["version"]) != "1" || textValue(obj["operation_id"]) != exchange.OperationID {
			return fail()
		}
		receipt, ok := decodeReceipt(obj["receipt"], exchange)
		if !ok {
			return fail()
		}
		size, ok := integer(obj["artifact_bytes"], maxArtifactBytes)
		if !ok || size != receipt.SignedBytes {
			return fail()
		}
		return Response{Fetch: &FetchHeader{exchange.OperationID, receipt, size}}, nil
	default:
		return fail()
	}
}

func decodeReceipt(raw []byte, exchange Exchange) (Receipt, bool) {
	obj, ok := object(raw, "product_id", "repository", "commit", "policy_sha256", "recipe_sha256", "toolchain_sha256", "input_sha256", "target", "unsigned_sha256", "signed_sha256", "unsigned_bytes", "signed_bytes", "certificate_sha256", "requirement_sha256", "audit_sequence", "audit_digest")
	if !ok {
		return Receipt{}, false
	}
	var r Receipt
	if json.Unmarshal(raw, &r) != nil {
		return Receipt{}, false
	}
	if r.ProductID != "curator" || r.Repository != "curator-core" || r.Commit != exchange.Commit || r.Target != "darwin/arm64" {
		return Receipt{}, false
	}
	for _, hash := range []string{r.PolicySHA256, r.RecipeSHA256, r.ToolchainSHA256, r.InputSHA256, r.UnsignedSHA256, r.SignedSHA256, r.CertificateSHA256, r.RequirementSHA256, r.AuditDigest} {
		if !lowerHex(hash, 64) {
			return Receipt{}, false
		}
	}
	for _, name := range []string{"unsigned_bytes", "signed_bytes"} {
		if _, ok := integer(obj[name], maxArtifactBytes); !ok {
			return Receipt{}, false
		}
	}
	if _, ok := integer(obj["audit_sequence"], 1<<63-1); !ok {
		return Receipt{}, false
	}
	if (Pins{r.PolicySHA256, r.RecipeSHA256, r.ToolchainSHA256, r.InputSHA256, r.CertificateSHA256, r.RequirementSHA256}) != exchange.Pins {
		return Receipt{}, false
	}
	if exchange.Receipt != nil && r != *exchange.Receipt {
		return Receipt{}, false
	}
	return r, true
}

func decodeRefusal(obj map[string]json.RawMessage) (Refusal, bool) {
	r := Refusal{textValue(obj["code"]), textValue(obj["retry"]), textValue(obj["message"])}
	// Empty message is permitted, but null and non-string messages are not.
	var message string
	if json.Unmarshal(obj["message"], &message) != nil || bytes.Equal(obj["message"], []byte("null")) || len(message) > 256 {
		return Refusal{}, false
	}
	if !oneOf(r.Retry, "never", "same_request", "inspect", "later") ||
		!oneOf(r.Code, "invalid_request", "unsupported_version", "not_allowlisted", "admission_required", "request_conflict", "busy", "request_not_found", "authority_rejected", "authority_unavailable", "build_failed", "build_isolation_failed", "artifact_rejected", "audit_unavailable", "signature_failed", "outcome_uncertain", "release_revoked", "artifact_expired", "artifact_unavailable") {
		return Refusal{}, false
	}
	return r, true
}

func object(raw []byte, names ...string) (map[string]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) != len(names) {
		return nil, false
	}
	for _, name := range names {
		if _, ok := obj[name]; !ok {
			return nil, false
		}
	}
	return obj, true
}
func textValue(raw []byte) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}
func integer(raw []byte, max int64) (int64, bool) {
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil && n > 0 && n <= max && strconv.FormatInt(n, 10) == string(raw)
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

// Token walking preserves decoded member identity, and bounds nesting before
// typed decoding. The wire grammar has no arrays and at most four objects deep.
func strictJSON(raw []byte) bool {
	if !validStrings(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !walkObject(d, 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func walkObject(d *json.Decoder, depth int) bool {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') || depth >= 4 {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		// Decode each value's raw bytes, then walk nested objects without coercion.
		var value json.RawMessage
		if d.Decode(&value) != nil || len(value) == 0 {
			return false
		}
		if value[0] == '{' {
			sub := json.NewDecoder(bytes.NewReader(value))
			sub.UseNumber()
			if !walkObject(sub, depth+1) {
				return false
			}
		} else if value[0] == '[' || bytes.Equal(value, []byte("null")) {
			return false
		}
	}
	token, err = d.Token()
	return err == nil && token == json.Delim('}')
}

// encoding/json otherwise replaces malformed UTF-8 and lone UTF-16 surrogates.
func validStrings(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	in := false
	hex4 := func(b []byte) (uint64, bool) {
		if len(b) < 4 {
			return 0, false
		}
		n, err := strconv.ParseUint(string(b[:4]), 16, 16)
		return n, err == nil
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			in = !in
			continue
		}
		if !in || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		n, ok := hex4(raw[i+1:])
		if !ok {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, ok := hex4(raw[i+3:])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !in
}
