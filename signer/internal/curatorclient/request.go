// Package curatorclient prepares version-1 requests for the Curator delivery
// lane. It does not connect, authenticate, persist intent, or authorize sending.
package curatorclient

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
)

// ErrRequest means the supplied correlation or source value is invalid.
// It contains no caller-controlled text.
var ErrRequest = errors.New("invalid Curator request")

// RequestID derives the C5 correlation value. The caller must recover the
// durable attempt number; a timeout, missing record, or missing operation never
// authorizes incrementing it. Advancement requires a durably recorded refused
// summary for the preceding attempt. This function establishes no such fact.
func RequestID(commit string, attempt uint64) (string, error) {
	if !lowerHex(commit, 40) || attempt == 0 {
		return "", ErrRequest
	}
	return commit + "-" + strconv.FormatUint(attempt, 10), nil
}

// SignFrame prepares an opcode 1 frame for the fixed curator/curator-core
// pairing. The commit selects source, never an uploaded binary or recipe.
// Before sending, the delivery lane must durably persist intent and principal
// bindings under its exclusive tuple lock and authenticate the service peer.
func SignFrame(commit string, attempt uint64) ([]byte, error) {
	id, err := RequestID(commit, attempt)
	if err != nil {
		return nil, err
	}
	return frame(1, struct {
		Version    int    `json:"version"`
		Product    string `json:"product_id"`
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		RequestID  string `json:"request_id"`
	}{1, "curator", "curator-core", commit, id})
}

// InspectFrame prepares an opcode 2 caller-scoped lookup. After an ambiguous
// send, request_not_found must hold the operation for custody reconciliation;
// it permits neither a new ID nor retransmission of the sign request.
func InspectFrame(requestID string) ([]byte, error) {
	if !identifier(requestID) {
		return nil, ErrRequest
	}
	return frame(2, struct {
		Version   int    `json:"version"`
		RequestID string `json:"request_id"`
	}{1, requestID})
}

// FetchFrame prepares an opcode 3 request for an existing operation. Fetch
// requires current qualification and does not authorize another signature.
func FetchFrame(operationID string) ([]byte, error) {
	if !lowerHex(operationID, 32) {
		return nil, ErrRequest
	}
	return frame(3, struct {
		Version     int    `json:"version"`
		OperationID string `json:"operation_id"`
	}{1, operationID})
}

func frame(opcode byte, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > 4096 {
		return nil, ErrRequest
	}
	result := make([]byte, 5+len(raw))
	result[0] = opcode
	binary.BigEndian.PutUint32(result[1:5], uint32(len(raw)))
	copy(result[5:], raw)
	return result, nil
}

func lowerHex(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for i := range s {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
