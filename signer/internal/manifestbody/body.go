// Package manifestbody decodes only the complete opcode34 JSON BODY into owned,
// unqualified fields. It performs no framing, DATA, graph, filesystem, acquisition,
// build or signing operation. Shape and raw-digest equality confer no authority.
package manifestbody

import (
	"bytes"
)

// MaxOpcode34BodyBytes is the active, inclusive public BODY bound.
const MaxOpcode34BodyBytes = 1048576

// BodyShapeReason is a closed local classification, not a wire error code.
type BodyShapeReason string

const (
	ReasonBodyTooLarge              BodyShapeReason = "body_too_large"
	ReasonJSONEncoding              BodyShapeReason = "json_encoding"
	ReasonJSONSyntax                BodyShapeReason = "json_syntax"
	ReasonDecodedDuplicateName      BodyShapeReason = "decoded_duplicate_name"
	ReasonMemberSet                 BodyShapeReason = "member_set"
	ReasonValueType                 BodyShapeReason = "value_type"
	ReasonIntegerSpelling           BodyShapeReason = "integer_spelling"
	ReasonScalarBound               BodyShapeReason = "scalar_bound"
	ReasonIdentifierSyntax          BodyShapeReason = "identifier_syntax"
	ReasonEntryShape                BodyShapeReason = "entry_shape"
	ReasonPathShape                 BodyShapeReason = "path_shape"
	ReasonEntryOrderOrDuplicate     BodyShapeReason = "entry_order_or_duplicate"
	ReasonModuleOrderOrDuplicate    BodyShapeReason = "module_order_or_duplicate"
	ReasonReceiptShape              BodyShapeReason = "receipt_shape"
	ReasonDeclaredBytesInconsistent BodyShapeReason = "declared_bytes_inconsistent"
	ReasonRawDigestMismatch         BodyShapeReason = "raw_digest_mismatch"
	ReasonResultAbsent              BodyShapeReason = "result_absent"
)

// BodyShapeRefusal never includes input text, including a caller-made Reason.
type BodyShapeRefusal struct{ Reason BodyShapeReason }

func (e *BodyShapeRefusal) Error() string {
	if e != nil {
		switch e.Reason {
		case ReasonBodyTooLarge:
			return "body_too_large"
		case ReasonJSONEncoding:
			return "json_encoding"
		case ReasonJSONSyntax:
			return "json_syntax"
		case ReasonDecodedDuplicateName:
			return "decoded_duplicate_name"
		case ReasonMemberSet:
			return "member_set"
		case ReasonValueType:
			return "value_type"
		case ReasonIntegerSpelling:
			return "integer_spelling"
		case ReasonScalarBound:
			return "scalar_bound"
		case ReasonIdentifierSyntax:
			return "identifier_syntax"
		case ReasonEntryShape:
			return "entry_shape"
		case ReasonPathShape:
			return "path_shape"
		case ReasonEntryOrderOrDuplicate:
			return "entry_order_or_duplicate"
		case ReasonModuleOrderOrDuplicate:
			return "module_order_or_duplicate"
		case ReasonReceiptShape:
			return "receipt_shape"
		case ReasonDeclaredBytesInconsistent:
			return "declared_bytes_inconsistent"
		case ReasonRawDigestMismatch:
			return "raw_digest_mismatch"
		case ReasonResultAbsent:
			return "result_absent"
		}
	}
	return "input_invalid"
}

// UnqualifiedManifestFields is a mutable copy, never trusted input.
type UnqualifiedManifestFields struct {
	Version                                     uint64
	OperationID, TransferID, Commit, Tree       string
	PolicySHA256, RecipeSHA256, ToolchainSHA256 string
	Entries                                     []UnqualifiedEntryFields
	ModuleReceipt                               UnqualifiedReceiptFields
	DataBytes                                   uint64
}
type UnqualifiedEntryFields struct {
	Root, Path, Kind, Mode string
	Size                   uint64
	SHA256, LinkTarget     string
}
type UnqualifiedReceiptFields struct {
	SourceGoModSHA256, SourceGoSumSHA256 string
	Modules                              []UnqualifiedModuleFields
}
type UnqualifiedModuleFields struct {
	Path, Version, Directory, GoModH1, ModuleH1 string
}

type bodyState struct {
	raw      []byte
	digest   [32]byte
	manifest UnqualifiedManifestFields
}

// UnqualifiedOpcode34Body has private, eagerly computed immutable state. Its
// zero value is absent. Callers keep input stable during Decode; after return
// they may reuse it. Concurrent read-only access requires no lazy mutation.
type UnqualifiedOpcode34Body struct{ data *bodyState }

// DecodeOpcode34BodyShape binds the public API to the active constant. The
// private core's limit parameter exists only for labelled inactive white-box tests.
func DecodeOpcode34BodyShape(raw []byte) (*UnqualifiedOpcode34Body, error) {
	return decodeBody(raw, MaxOpcode34BodyBytes)
}
func (b *UnqualifiedOpcode34Body) RawBodyCopy() []byte {
	if b == nil || b.data == nil {
		return nil
	}
	return bytes.Clone(b.data.raw)
}
func (b *UnqualifiedOpcode34Body) ComputedRawSHA256() ([32]byte, bool) {
	if b == nil || b.data == nil {
		return [32]byte{}, false
	}
	return b.data.digest, true
}
func (b *UnqualifiedOpcode34Body) ManifestCopy() *UnqualifiedManifestFields {
	if b == nil || b.data == nil {
		return nil
	}
	m := b.data.manifest
	m.Entries = append([]UnqualifiedEntryFields(nil), m.Entries...)
	m.ModuleReceipt.Modules = append([]UnqualifiedModuleFields(nil), m.ModuleReceipt.Modules...)
	return &m
}
func (b *UnqualifiedOpcode34Body) CompareExpectedRawSHA256Only(expected [32]byte) error {
	if b == nil || b.data == nil {
		return &BodyShapeRefusal{ReasonResultAbsent}
	}
	if expected != b.data.digest {
		return &BodyShapeRefusal{ReasonRawDigestMismatch}
	}
	return nil
}
