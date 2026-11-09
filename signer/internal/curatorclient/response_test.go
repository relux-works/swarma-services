package curatorclient

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"
const testOperation = "0123456789abcdef0123456789abcdef"
const testRequest = testCommit + "-1"
const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The fixture spells out the normative wire member set independently of the
// exported structs, so struct changes cannot silently change the test protocol.
func receiptJSON() string {
	return `{"product_id":"curator","repository":"curator-core","commit":"` + testCommit + `","policy_sha256":"` + testDigest + `","recipe_sha256":"` + testDigest + `","toolchain_sha256":"` + testDigest + `","input_sha256":"` + testDigest + `","target":"darwin/arm64","unsigned_sha256":"` + testDigest + `","signed_sha256":"` + testDigest + `","unsigned_bytes":1,"signed_bytes":268435456,"certificate_sha256":"` + testDigest + `","requirement_sha256":"` + testDigest + `","audit_sequence":9223372036854775807,"audit_digest":"` + testDigest + `"}`
}
func summaryJSON(state, outcome string) string {
	return `{"version":1,"request_id":"` + testRequest + `","operation_id":"` + testOperation + `","state":"` + state + `","source":{"product_id":"curator","repository":"curator-core","commit":"` + testCommit + `"},"outcome":` + outcome + `}`
}
func successJSON() string {
	return summaryJSON("succeeded", `{"kind":"succeeded","receipt":`+receiptJSON()+`}`)
}
func pendingJSON() string { return summaryJSON("pending", `{"kind":"pending","phase":"qualifying"}`) }
func fetchJSON() string {
	return `{"version":1,"operation_id":"` + testOperation + `","receipt":` + receiptJSON() + `,"artifact_bytes":268435456}`
}
func refusalJSON(code, retry string) string {
	return `{"version":1,"code":"` + code + `","retry":"` + retry + `","message":"unavailable"}`
}
func wire(op byte, body string) []byte {
	result := make([]byte, 5+len(body))
	result[0] = op
	binary.BigEndian.PutUint32(result[1:5], uint32(len(body)))
	copy(result[5:], body)
	return result
}
func exchangeFixture(op byte) Exchange {
	x := Exchange{Session: "exchange_1", RequestOpcode: op, RequestID: testRequest, Commit: testCommit,
		Pins: Pins{testDigest, testDigest, testDigest, testDigest, testDigest, testDigest}}
	if op == 3 {
		x.OperationID = testOperation
		var receipt Receipt
		if err := json.Unmarshal([]byte(receiptJSON()), &receipt); err != nil {
			panic(err)
		}
		x.Receipt = &receipt
	}
	return x
}
func decodeOK(t *testing.T, op byte, body string, x Exchange) Response {
	t.Helper()
	result, err := DecodeResponse(wire(op, body), x, x.Session)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func decodeBad(t *testing.T, frame []byte, x Exchange, session string) {
	t.Helper()
	result, err := DecodeResponse(frame, x, session)
	if err != ErrResponse || result.Summary != nil || result.Refusal != nil || result.Fetch != nil {
		t.Fatal("rejection must return only ErrResponse and zero result")
	}
}

func TestResponseVariantsAndNeighbors(t *testing.T) {
	for _, requestOp := range []byte{1, 2} {
		x := exchangeFixture(requestOp)
		for _, phase := range []string{"qualifying", "acquiring", "building", "signing", "reconciling"} {
			got := decodeOK(t, 64, strings.ReplaceAll(pendingJSON(), "qualifying", phase), x)
			if got.Summary.Phase != phase || got.Refusal != nil || got.Fetch != nil {
				t.Fatal("pending projection")
			}
		}
		got := decodeOK(t, 64, successJSON(), x)
		if got.Summary.Receipt.AuditSequence != 1<<63-1 || got.Summary.Receipt.SignedBytes != maxArtifactBytes {
			t.Fatal("integer precision lost")
		}
		x.OperationID = testOperation
		x.Receipt = got.Summary.Receipt
		decodeOK(t, 64, successJSON(), x)
	}
	for _, code := range []string{"authority_rejected", "authority_unavailable", "build_failed", "build_isolation_failed", "artifact_rejected", "audit_unavailable"} {
		body := summaryJSON("refused", `{"kind":"refused","code":"`+code+`","retry":"inspect","message":""}`)
		got := decodeOK(t, 64, body, exchangeFixture(1))
		if got.Summary.Refusal.Code != code || got.Summary.Receipt != nil {
			t.Fatal("refused projection")
		}
	}
	uncertain := summaryJSON("uncertain", `{"kind":"uncertain","code":"outcome_uncertain","retry":"inspect","message":"held"}`)
	decodeOK(t, 64, uncertain, exchangeFixture(2))
	got := decodeOK(t, 66, fetchJSON(), exchangeFixture(3))
	if got.Fetch.ArtifactBytes != maxArtifactBytes || got.Summary != nil || got.Refusal != nil {
		t.Fatal("fetch projection")
	}
	// The decoder never changes the retained snapshot, including on a later refusal.
	x := exchangeFixture(3)
	before := *x.Receipt
	decodeOK(t, 65, refusalJSON("release_revoked", "later"), x)
	if *x.Receipt != before {
		t.Fatal("retained success changed")
	}
}

func TestFiniteRefusals(t *testing.T) {
	codes := []string{"invalid_request", "unsupported_version", "not_allowlisted", "admission_required", "request_conflict", "busy", "request_not_found", "authority_rejected", "authority_unavailable", "build_failed", "build_isolation_failed", "artifact_rejected", "audit_unavailable", "signature_failed", "outcome_uncertain", "release_revoked", "artifact_expired", "artifact_unavailable"}
	for _, code := range codes {
		for _, op := range []byte{1, 2, 3} {
			got := decodeOK(t, 65, refusalJSON(code, "inspect"), exchangeFixture(op))
			if got.Refusal.Code != code {
				t.Fatal("code projection")
			}
		}
	}
	for _, retry := range []string{"never", "same_request", "inspect", "later"} {
		decodeOK(t, 65, refusalJSON("authority_unavailable", retry), exchangeFixture(1))
	}
}

func TestResponseCorrelation(t *testing.T) {
	x := exchangeFixture(1)
	for name, body := range map[string]string{
		"request":        strings.Replace(successJSON(), testRequest, testCommit+"-2", 1),
		"source":         strings.Replace(successJSON(), testCommit+`"}`, strings.Repeat("a", 40)+`"}`, 1),
		"receipt_source": strings.Replace(successJSON(), `"commit":"`+testCommit+`","policy`, `"commit":"`+strings.Repeat("a", 40)+`","policy`, 1),
		"product":        strings.Replace(successJSON(), `"product_id":"curator"`, `"product_id":"neighbor"`, 1),
		"repository":     strings.Replace(successJSON(), `"repository":"curator-core"`, `"repository":"neighbor"`, 1),
	} {
		t.Run(name, func(t *testing.T) { decodeBad(t, wire(64, body), x, x.Session) })
	}
	decodeBad(t, wire(64, successJSON()), x, "exchange_2")
	x.OperationID = strings.Repeat("a", 32)
	decodeBad(t, wire(64, successJSON()), x, x.Session)
	x = exchangeFixture(3)
	decodeBad(t, wire(66, strings.Replace(fetchJSON(), testOperation, strings.Repeat("a", 32), 1)), x, x.Session)
	for _, name := range []string{"Policy", "Recipe", "Toolchain", "Input", "Certificate", "Requirement"} {
		t.Run(name, func(t *testing.T) {
			x := exchangeFixture(1)
			switch name {
			case "Policy":
				x.Pins.Policy = strings.Repeat("a", 64)
			case "Recipe":
				x.Pins.Recipe = strings.Repeat("a", 64)
			case "Toolchain":
				x.Pins.Toolchain = strings.Repeat("a", 64)
			case "Input":
				x.Pins.Input = strings.Repeat("a", 64)
			case "Certificate":
				x.Pins.Certificate = strings.Repeat("a", 64)
			case "Requirement":
				x.Pins.Requirement = strings.Repeat("a", 64)
			}
			decodeBad(t, wire(64, successJSON()), x, x.Session)
		})
	}
	x = exchangeFixture(1)
	x.Pins = Pins{}
	decodeBad(t, wire(64, successJSON()), x, x.Session)
	// Fetch compares every retained receipt member, including historical audit and
	// artifact fields that are deliberately absent from the protected pin set.
	var members map[string]any
	if err := json.Unmarshal([]byte(receiptJSON()), &members); err != nil {
		t.Fatal(err)
	}
	for name := range members {
		t.Run("retained_"+name, func(t *testing.T) {
			x := exchangeFixture(3)
			body := fetchJSON()
			old, _ := json.Marshal(members[name])
			replacement := `"` + strings.Repeat("a", 64) + `"`
			switch name {
			case "product_id", "repository", "target":
				replacement = `"neighbor"`
			case "commit":
				replacement = `"` + strings.Repeat("a", 40) + `"`
			case "unsigned_bytes", "signed_bytes", "audit_sequence":
				replacement = "2"
			}
			// Avoid float64's rounding of audit_sequence in this mutation fixture.
			if name == "audit_sequence" {
				old = []byte("9223372036854775807")
			}
			body = strings.Replace(body, `"`+name+`":`+string(old), `"`+name+`":`+replacement, 1)
			if body == fetchJSON() {
				t.Fatal("mutation did not apply")
			}
			decodeBad(t, wire(66, body), x, x.Session)
		})
	}
	x = exchangeFixture(3)
	x.Receipt = nil
	decodeBad(t, wire(66, fetchJSON()), x, x.Session)
	x = exchangeFixture(1)
	x.Receipt = exchangeFixture(3).Receipt
	decodeBad(t, wire(64, pendingJSON()), x, x.Session)
}

func TestClosedResponseGrammar(t *testing.T) {
	base := successJSON()
	cases := map[string]string{
		"unknown":             strings.Replace(base, `"version":1`, `"version":1,"success":true`, 1),
		"case":                strings.Replace(base, `"version"`, `"Version"`, 1),
		"duplicate":           strings.Replace(base, `"version":1`, `"version":1,"version":1`, 1),
		"decoded_duplicate":   strings.Replace(base, `"request_id":`, `"request\u005fid":"`+testRequest+`","request_id":`, 1),
		"source_duplicate":    strings.Replace(base, `"repository":"curator-core"`, `"repository":"curator-core","repositor\u0079":"curator-core"`, 1),
		"outcome_duplicate":   strings.Replace(base, `"kind":"succeeded"`, `"kind":"succeeded","kind":"succeeded"`, 1),
		"receipt_duplicate":   strings.Replace(base, `"signed_bytes":268435456`, `"signed_bytes":268435456,"signed_bytes":268435456`, 1),
		"provider_provenance": strings.Replace(base, `"target":`, `"provider":{},"target":`, 1),
		"missing":             strings.Replace(base, `"version":1,`, "", 1),
		"null":                strings.Replace(base, `"signed_bytes":268435456`, `"signed_bytes":null`, 1),
		"wrong_type":          strings.Replace(base, `"signed_bytes":268435456`, `"signed_bytes":"268435456"`, 1),
		"bool":                strings.Replace(base, `"signed_bytes":268435456`, `"signed_bytes":true`, 1),
		"array":               strings.Replace(base, `"signed_bytes":268435456`, `"signed_bytes":[]`, 1),
		"negative":            strings.Replace(base, `"unsigned_bytes":1`, `"unsigned_bytes":-1`, 1),
		"zero":                strings.Replace(base, `"unsigned_bytes":1`, `"unsigned_bytes":0`, 1),
		"plus":                strings.Replace(base, `"unsigned_bytes":1`, `"unsigned_bytes":+1`, 1),
		"fraction":            strings.Replace(base, `"unsigned_bytes":1`, `"unsigned_bytes":1.0`, 1),
		"exponent":            strings.Replace(base, `"unsigned_bytes":1`, `"unsigned_bytes":1e0`, 1),
		"leading_zero":        strings.Replace(base, `"unsigned_bytes":1`, `"unsigned_bytes":01`, 1),
		"oversize":            strings.Replace(base, `"signed_bytes":268435456`, `"signed_bytes":268435457`, 1),
		"audit_overflow":      strings.Replace(base, `9223372036854775807`, `9223372036854775808`, 1),
		"audit_zero":          strings.Replace(base, `9223372036854775807`, `0`, 1),
		"version":             strings.Replace(base, `"version":1`, `"version":2`, 1),
		"version_fraction":    strings.Replace(base, `"version":1`, `"version":1.0`, 1),
		"target":              strings.Replace(base, "darwin/arm64", "linux/amd64", 1),
		"hash_upper":          strings.Replace(base, testDigest, strings.ToUpper(testDigest), 1),
		"hash_short":          strings.Replace(base, testDigest, testDigest[1:], 1),
		"unknown_state":       strings.ReplaceAll(base, "succeeded", "success"),
		"variant_mismatch":    strings.Replace(base, `"kind":"succeeded"`, `"kind":"pending"`, 1),
		"extra_variant":       strings.Replace(base, `"kind":"succeeded"`, `"kind":"succeeded","phase":"signing"`, 1),
		"trailing":            base + ` {}`,
		"bom":                 "\xef\xbb\xbf" + base,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) { x := exchangeFixture(1); decodeBad(t, wire(64, body), x, x.Session) })
	}
	// Each field is required, independently of the fixture's struct layout.
	for _, path := range []string{"root", "source", "outcome", "receipt"} {
		var root map[string]json.RawMessage
		_ = json.Unmarshal([]byte(base), &root)
		obj := root
		switch path {
		case "source":
			obj = nil
			_ = json.Unmarshal(root["source"], &obj)
		case "outcome":
			obj = nil
			_ = json.Unmarshal(root["outcome"], &obj)
		case "receipt":
			var out map[string]json.RawMessage
			_ = json.Unmarshal(root["outcome"], &out)
			obj = nil
			_ = json.Unmarshal(out["receipt"], &obj)
		}
		for name := range obj {
			t.Run("missing_"+path+"_"+name, func(t *testing.T) {
				var root map[string]json.RawMessage
				if err := json.Unmarshal([]byte(base), &root); err != nil {
					t.Fatal(err)
				}
				var copyObj map[string]json.RawMessage
				raw, _ := json.Marshal(obj)
				_ = json.Unmarshal(raw, &copyObj)
				delete(copyObj, name)
				changed, _ := json.Marshal(copyObj)
				body := base
				switch path {
				case "root":
					body = string(changed)
				case "source":
					root["source"] = changed
					raw, _ = json.Marshal(root)
					body = string(raw)
				case "outcome":
					root["outcome"] = changed
					raw, _ = json.Marshal(root)
					body = string(raw)
				case "receipt":
					var out map[string]json.RawMessage
					_ = json.Unmarshal(root["outcome"], &out)
					out["receipt"] = changed
					raw, _ = json.Marshal(out)
					root["outcome"] = raw
					raw, _ = json.Marshal(root)
					body = string(raw)
				}
				x := exchangeFixture(1)
				decodeBad(t, wire(64, body), x, x.Session)
			})
		}
	}
}

func TestResponseFramesAndVariantExclusion(t *testing.T) {
	x := exchangeFixture(1)
	good := wire(64, pendingJSON())
	for i := 0; i < len(good); i++ {
		decodeBad(t, good[:i], x, x.Session)
	}
	for _, op := range []byte{0, 1, 2, 3, 63, 66, 67, 255} {
		decodeBad(t, wire(op, pendingJSON()), x, x.Session)
	}
	decodeBad(t, append(good, 0), x, x.Session)
	huge := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(huge[1:5], ^uint32(0))
	decodeBad(t, huge, x, x.Session)
	decodeBad(t, wire(64, strings.Repeat(" ", MaxResponseBody+1)), x, x.Session)
	padded := pendingJSON() + strings.Repeat(" ", MaxResponseBody-len(pendingJSON()))
	decodeOK(t, 64, padded, x)
	// Escapes/whitespace change encoding, not semantic request identity.
	escaped := strings.Replace(pendingJSON(), `"version"`, `"\u0076ersion"`, 1)
	escaped = strings.Replace(escaped, `"curator"`, `"\u0063urator"`, 1)
	decodeOK(t, 64, " \n"+escaped+" \t", x)
	decodeBad(t, wire(64, successJSON()), exchangeFixture(3), "exchange_1")
	decodeBad(t, wire(66, fetchJSON()), exchangeFixture(2), "exchange_1")
	decodeBad(t, wire(66, strings.Replace(fetchJSON(), `"artifact_bytes":268435456`, `"artifact_bytes":1`, 1)), exchangeFixture(3), "exchange_1")
}

func TestRefusalAndUnicodeControls(t *testing.T) {
	good := refusalJSON("busy", "later")
	x := exchangeFixture(1)
	for name, body := range map[string]string{
		"unknown_code":   strings.Replace(good, "busy", "unknown", 1),
		"unknown_retry":  strings.Replace(good, "later", "retry_sign", 1),
		"echo":           strings.Replace(good, `"version":1`, `"version":1,"request_id":"`+testRequest+`"`, 1),
		"null_message":   strings.Replace(good, `"unavailable"`, `null`, 1),
		"number_message": strings.Replace(good, `"unavailable"`, `1`, 1),
		"long_message":   strings.Replace(good, "unavailable", strings.Repeat("é", 129), 1),
		"high_surrogate": strings.Replace(good, "unavailable", `\ud800`, 1),
		"low_surrogate":  strings.Replace(good, "unavailable", `\udc00`, 1),
		"bad_pair":       strings.Replace(good, "unavailable", `\ud800\u0041`, 1),
		"utf8":           strings.Replace(good, "unavailable", string([]byte{0xff}), 1),
	} {
		t.Run(name, func(t *testing.T) { decodeBad(t, wire(65, body), x, x.Session) })
	}
	for _, message := range []string{strings.Repeat("é", 128), `\ud83d\ude00`, `\\ud800`, ""} {
		decodeOK(t, 65, strings.Replace(good, "unavailable", message, 1), x)
	}
	for _, state := range []string{"refused", "uncertain"} {
		body := summaryJSON(state, `{"kind":"`+state+`","code":"signature_failed","retry":"inspect","message":"held"}`)
		decodeBad(t, wire(64, body), x, x.Session)
	}
	uncertain := summaryJSON("uncertain", `{"kind":"uncertain","code":"outcome_uncertain","retry":"never","message":"held"}`)
	decodeBad(t, wire(64, uncertain), x, x.Session)
	// Bytes resembling null inside a valid literal have no special meaning.
	decodeOK(t, 65, strings.Replace(good, "unavailable", "null", 1), x)
}

func TestInvalidExchange(t *testing.T) {
	for _, change := range []func(*Exchange){
		func(x *Exchange) { x.Session = "" }, func(x *Exchange) { x.Session = strings.Repeat("s", 65) },
		func(x *Exchange) { x.RequestOpcode = 0 }, func(x *Exchange) { x.RequestOpcode = 4 },
		func(x *Exchange) { x.RequestID = "" }, func(x *Exchange) { x.RequestID = "unknown!" },
		func(x *Exchange) { x.Commit = strings.ToUpper(testCommit) }, func(x *Exchange) { x.OperationID = "wrong" },
	} {
		x := exchangeFixture(1)
		change(&x)
		decodeBad(t, wire(64, pendingJSON()), x, x.Session)
	}
}

func FuzzResponse(f *testing.F) {
	f.Add(wire(64, pendingJSON()))
	f.Add(wire(64, successJSON()))
	f.Add(wire(65, refusalJSON("busy", "later")))
	f.Add(wire(66, fetchJSON()))
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, op := range []byte{1, 2, 3} {
			x := exchangeFixture(op)
			before := append([]byte(nil), raw...)
			result, err := DecodeResponse(raw, x, x.Session)
			if !bytes.Equal(raw, before) {
				t.Fatal("input mutated")
			}
			if err != nil && (err != ErrResponse || result.Summary != nil || result.Refusal != nil || result.Fetch != nil) {
				t.Fatal("partial result")
			}
		}
	})
}
