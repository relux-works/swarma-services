package manifestbody

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

type object = map[string]any

const zeroH1 = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Test fixture derivation follows the specified domain independently of the
// shared helper; the helper itself is pinned by fixed literal directory rows.
func fixtureDirectory(p, v string) string { return "m/" + digest([]byte(p+"\x00"+v)) }
func entry(name string) object {
	return object{"root": "source", "path": name, "kind": "file", "mode": "100644", "size": uint64(0), "sha256": strings.Repeat("0", 64), "link_target": ""}
}
func record(p, v string) object {
	return object{"path": p, "version": v, "directory": fixtureDirectory(p, v), "go_mod_h1": zeroH1, "module_h1": ""}
}
func validManifest() object {
	return object{
		"version": uint64(1), "operation_id": strings.Repeat("a", 32), "transfer_id": strings.Repeat("b", 32),
		"commit": strings.Repeat("c", 40), "tree": strings.Repeat("d", 40), "policy_sha256": strings.Repeat("e", 64),
		"recipe_sha256": strings.Repeat("f", 64), "toolchain_sha256": strings.Repeat("0", 64),
		"entries": []any{entry("go.mod")}, "module_receipt": object{"source_go_mod_sha256": strings.Repeat("1", 64), "source_go_sum_sha256": strings.Repeat("2", 64), "modules": []any{}}, "data_bytes": uint64(0),
	}
}
func encoded(t *testing.T, m object) []byte {
	t.Helper()
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func entries(m object) []any  { return m["entries"].([]any) }
func first(m object) object   { return entries(m)[0].(object) }
func receipt(m object) object { return m["module_receipt"].(object) }
func withRecord(m object) object {
	r := record("example.com/alpha", "v1.0.0")
	receipt(m)["modules"] = []any{r}
	return r
}
func good(t *testing.T, b []byte) *UnqualifiedOpcode34Body {
	t.Helper()
	before := bytes.Clone(b)
	v, e := DecodeOpcode34BodyShape(b)
	if e != nil || v == nil {
		t.Fatalf("valid neighbor refused: %v", e)
	}
	if reflect.TypeOf(e) != nil {
		t.Fatal("success must return untyped nil error")
	}
	if !bytes.Equal(before, b) {
		t.Fatal("caller input modified")
	}
	return v
}
func bad(t *testing.T, b []byte, want BodyShapeReason) {
	t.Helper()
	before := bytes.Clone(b)
	v, e := DecodeOpcode34BodyShape(b)
	checkBad(t, v, e, want)
	if !bytes.Equal(before, b) {
		t.Fatal("refusal modified input")
	}
}
func checkBad(t *testing.T, v *UnqualifiedOpcode34Body, e error, want BodyShapeReason) {
	t.Helper()
	var r *BodyShapeRefusal
	if v != nil || !errors.As(e, &r) || r == nil || r.Reason != want {
		t.Fatalf("intended %s; body=%v error=%v", want, v != nil, e)
	}
}

// Each object shape requires every named member, rejects extras and refuses wrong value types.
func TestP03ExactSchema(t *testing.T) {
	for _, level := range []string{"manifest", "entry", "receipt", "record"} {
		build := func() (object, object) {
			m := validManifest()
			r := withRecord(m)
			o := m
			switch level {
			case "entry":
				o = first(m)
			case "receipt":
				o = receipt(m)
			case "record":
				o = r
			}
			return m, o
		}
		m, o := build()
		good(t, encoded(t, m))
		names := make([]string, 0, len(o))
		for k := range o {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			t.Run(level+"/"+name+"/missing", func(t *testing.T) { m, o := build(); delete(o, name); bad(t, encoded(t, m), ReasonMemberSet) })
			for _, wrong := range []any{nil, true, object{}, []any{}, "wrong", uint64(100644)} {
				t.Run(fmt.Sprintf("%s/%s/type_%T", level, name, wrong), func(t *testing.T) {
					m, o := build()
					original := o[name]
					// Same-kind domain mistakes belong to the separate semantic tables.
					if reflect.TypeOf(original) == reflect.TypeOf(wrong) {
						return
					}
					o[name] = wrong
					bad(t, encoded(t, m), ReasonValueType)
				})
			}
		}
		t.Run(level+"/extra", func(t *testing.T) { m, o := build(); o["extra"] = true; bad(t, encoded(t, m), ReasonMemberSet) })
	}
}

// Literal and escaped duplicate names refuse before their unwalked values at each object level.
func TestP04DecodedMemberDuplicate(t *testing.T) {
	m := validManifest()
	withRecord(m)
	b := string(encoded(t, m))
	good(t, []byte(b))
	for _, key := range []string{"operation_id", "root", "source_go_mod_sha256", "go_mod_h1"} {
		needle := `"` + key + `":`
		pos := strings.Index(b, needle)
		for _, alias := range []string{key, fmt.Sprintf(`\u%04x%s`, key[0], key[1:])} {
			duplicate := b[:pos] + `"` + alias + `":` + `"` + func() string {
				switch key {
				case "operation_id":
					return strings.Repeat("a", 32)
				case "root":
					return "source"
				case "source_go_mod_sha256":
					return strings.Repeat("1", 64)
				}
				return zeroH1
			}() + `",` + b[pos:]
			t.Run(key+alias, func(t *testing.T) { bad(t, []byte(duplicate), ReasonDecodedDuplicateName) })
		}
	}
	// Duplicates and unknown names win before an unwalked malformed value.
	bad(t, []byte(`{"version":1,"\u0076ersion":`), ReasonDecodedDuplicateName)
	for _, name := range []string{"Version", "ｖersion", "vérsion", "extra"} {
		bad(t, []byte(`{"`+name+`":`), ReasonMemberSet)
	}
}
func TestP05P06UnicodeAndEnvelope(t *testing.T) {
	base := string(encoded(t, validManifest()))
	pathBody := func(token string) []byte { return []byte(strings.Replace(base, `"path":"go.mod"`, `"path":`+token, 1)) }
	// Valid UTF-8 and escape spellings decode, while unpaired surrogates and broken escapes refuse.
	for _, token := range []string{`"café"`, `"caf\u00e9"`, `"\ud83d\ude00"`, `"�"`, `"\ufffd"`, `"x\ufeff"`, `"dir\/file"`} {
		good(t, pathBody(token))
	}
	for _, token := range []string{`"\ud800"`, `"\udc00"`, `"\udc00\ud800"`, `"\ud800\u0061"`} {
		bad(t, pathBody(token), ReasonJSONEncoding)
	}
	for _, token := range []string{`"\q"`, `"\u12x4"`, "\"raw\ncontrol\""} {
		bad(t, pathBody(token), ReasonJSONSyntax)
	}
	// Invalid raw UTF-8, BOMs, trailing bytes and broken envelopes retain their local reasons.
	for _, b := range [][]byte{{0xff}, {0xc0, 0xaf}, {0xe2, 0x82}} {
		bad(t, append([]byte(`{"unknown":0} `), b...), ReasonJSONEncoding)
	}
	for _, prefix := range []string{"\ufeff", " \t\r\n\ufeff"} {
		bad(t, []byte(prefix+base), ReasonJSONEncoding)
	}
	for _, suffix := range []string{"{}", "0", "garbage", "\x00"} {
		bad(t, []byte(base+suffix), ReasonJSONSyntax)
	}
	for _, b := range []string{"", " ", base[:len(base)-1], `{"version"`, `{"version":1,}`, `{version:1}`} {
		bad(t, []byte(b), ReasonJSONSyntax)
	}
	// Complete primitive or array bodies are wrong types; surrounding JSON whitespace is permitted.
	for _, b := range []string{`[]`, `[1]`, `null`, `true`, `"text"`, `1`, `1.0`, `-1`} {
		bad(t, []byte(b), ReasonValueType)
	}
	good(t, []byte(" \t\r\n"+base+" \n\r\t"))
	// Source NFC/NFD and case aliases intentionally remain shape-positive.
	m := validManifest()
	m["entries"] = []any{entry("A"), entry("a"), entry("é"), entry("é")}
	good(t, encoded(t, m))
}

// Integer fields distinguish canonical spelling, value type, overflow and field-specific bounds.
func TestP07IntegerTokens(t *testing.T) {
	base := string(encoded(t, validManifest()))
	for _, field := range []string{"version", "size", "data_bytes"} {
		old := `"` + field + `":0`
		if field == "version" {
			old = `"version":1`
		}
		for _, n := range []string{"-1", "-0", "+1", "01", "1.0", "1e0", "1x", "1e+"} {
			t.Run(field+"_"+n, func(t *testing.T) {
				bad(t, []byte(strings.Replace(base, old, `"`+field+`":`+n, 1)), ReasonIntegerSpelling)
			})
		}
		for _, n := range []string{`"1"`, `true`, `null`} {
			bad(t, []byte(strings.Replace(base, old, `"`+field+`":`+n, 1)), ReasonValueType)
		}
		for _, n := range []string{"9223372036854775808", strings.Repeat("9", 200)} {
			bad(t, []byte(strings.Replace(base, old, `"`+field+`":`+n, 1)), ReasonScalarBound)
		}
	}
	for _, n := range []string{"0", "2", "9223372036854775807"} {
		bad(t, []byte(strings.Replace(base, `"version":1`, `"version":`+n, 1)), ReasonScalarBound)
	}
	good(t, []byte(base))
}

// Every identifier requires its exact lowercase-hex byte width.
func TestP08Identifiers(t *testing.T) {
	for _, field := range []string{"operation_id", "transfer_id", "commit", "tree", "policy_sha256", "recipe_sha256", "toolchain_sha256", "sha256", "source_go_mod_sha256", "source_go_sum_sha256"} {
		for _, fault := range []string{"short", "long", "uppercase", "nonhex", "unicode"} {
			t.Run(field+"_"+fault, func(t *testing.T) {
				m := validManifest()
				o := m
				if field == "sha256" {
					o = first(m)
				}
				if strings.HasPrefix(field, "source_") {
					o = receipt(m)
				}
				good(t, encoded(t, m))
				s := o[field].(string)
				switch fault {
				case "short":
					s = s[1:]
				case "long":
					s += "a"
				case "uppercase":
					s = "A" + s[1:]
				case "nonhex":
					s = "g" + s[1:]
				case "unicode":
					s = "é" + s[2:]
				}
				o[field] = s
				bad(t, encoded(t, m), ReasonIdentifierSyntax)
			})
		}
	}
}

// Entry roots and kinds admit only the specified string mode pairs.
func TestP09ModePairs(t *testing.T) {
	for _, root := range []string{"source", "modules"} {
		for _, kind := range []string{"file", "symlink"} {
			for _, mode := range []any{"100644", "100755", "120000", "0644", "0100644", "0o100644", "104755", "100600", uint64(100644)} {
				t.Run(fmt.Sprint(root, kind, mode), func(t *testing.T) {
					m := validManifest()
					e := first(m)
					e["root"] = root
					e["kind"] = kind
					e["mode"] = mode
					if kind == "symlink" {
						e["link_target"] = "peer"
						e["size"] = uint64(4)
						e["sha256"] = digest([]byte("peer"))
					}
					valid := root == "source" && kind == "symlink" && mode == "120000" || kind == "file" && (mode == "100644" || root == "source" && mode == "100755")
					if valid {
						good(t, encoded(t, m))
					} else if _, ok := mode.(uint64); ok {
						bad(t, encoded(t, m), ReasonValueType)
					} else {
						bad(t, encoded(t, m), ReasonEntryShape)
					}
				})
			}
		}
	}
	for _, field := range []string{"root", "kind"} {
		for _, value := range []string{"", "device", "gitlink", "fifo", "unknown"} {
			m := validManifest()
			first(m)[field] = value
			bad(t, encoded(t, m), ReasonEntryShape)
		}
	}
}

// Decoded entry paths obey byte bounds and relative segment rules without normalization.
func TestP10EntryPaths(t *testing.T) {
	for _, path := range []string{"dir/file", "dir/C:peer", "dir/a:b", "1:peer", ":peer", "é:peer", "file:foo", "percent%2fpath", "quoted\"name", "line\nname", ".info", "asset.tar.gz", strings.Repeat("x", 1024), strings.Repeat("é", 512)} {
		m := validManifest()
		first(m)["path"] = path
		good(t, encoded(t, m))
	}
	for _, path := range []string{"", "/a", "C:peer", "c:/peer", "a\\b", "a\x00b", ".", "..", "a/./b", "a/../b", "a//b", "a/", "/"} {
		m := validManifest()
		first(m)["path"] = path
		bad(t, encoded(t, m), ReasonPathShape)
	}
	m := validManifest()
	first(m)["path"] = strings.Repeat("x", 1025)
	bad(t, encoded(t, m), ReasonScalarBound)
	base := string(encoded(t, validManifest()))
	for _, path := range []string{`\u002e\u002e/file`, `a/\u002e/b`, `a\u0000b`, `a\u005cb`, `\u0043:peer`} {
		bad(t, []byte(strings.Replace(base, `go.mod`, path, 1)), ReasonPathShape)
	}
	good(t, []byte(strings.Replace(base, `go.mod`, `dir\/\u0066ile`, 1)))
}

// Entries sort by decoded root/path bytes and reject duplicate paths, including escaped aliases.
func TestP11EntryOrder(t *testing.T) {
	m := validManifest()
	a, b := entry("a"), entry("a")
	a["root"] = "modules"
	m["entries"] = []any{a, b}
	good(t, encoded(t, m))
	m["entries"] = []any{b, a}
	bad(t, encoded(t, m), ReasonEntryOrderOrDuplicate)
	for _, paths := range [][]string{{"b", "a"}, {"a", "a"}} {
		m := validManifest()
		m["entries"] = []any{entry(paths[0]), entry(paths[1])}
		bad(t, encoded(t, m), ReasonEntryOrderOrDuplicate)
	}
	m = validManifest()
	m["entries"] = []any{entry("a"), entry("b")}
	raw := string(encoded(t, m))
	good(t, []byte(raw))
	bad(t, []byte(strings.Replace(raw, `"path":"b"`, `"path":"\u0061"`, 1)), ReasonEntryOrderOrDuplicate)
}
func TestP16P17P18BoundsAndSum(t *testing.T) {
	// A regular file admits exactly 64 MiB and refuses the next byte.
	m := validManifest()
	first(m)["size"] = uint64(67108864)
	m["data_bytes"] = uint64(67108864)
	good(t, encoded(t, m))
	first(m)["size"] = uint64(67108865)
	m["data_bytes"] = uint64(67108865)
	bad(t, encoded(t, m), ReasonScalarBound)
	// The checked running file sum admits 1 GiB and refuses overflow before later schema faults.
	m = validManifest()
	es := []any{}
	for i := 0; i < 16; i++ {
		e := entry(fmt.Sprintf("f%02d", i))
		e["size"] = uint64(67108864)
		es = append(es, e)
	}
	m["entries"] = es
	m["data_bytes"] = uint64(1073741824)
	good(t, encoded(t, m))
	e := entry("z")
	e["size"] = uint64(1)
	m["entries"] = append(es, e)
	// Declaration remains bounded: this isolates the in-parse running sum.
	bad(t, encoded(t, m), ReasonScalarBound)
	// An early sum failure wins over a later unknown top-level member.
	raw := string(encoded(t, m))
	raw = raw[:len(raw)-1] + `,"unknown":0}`
	bad(t, []byte(raw), ReasonScalarBound)
	// Declared DATA bytes have an independent bound and must equal the regular-file sum.
	m = validManifest()
	m["data_bytes"] = uint64(1073741825)
	bad(t, encoded(t, m), ReasonScalarBound)
	m = validManifest()
	m["data_bytes"] = uint64(1)
	bad(t, encoded(t, m), ReasonDeclaredBytesInconsistent)
	// Symlink target bytes do not contribute to the streamed regular-file sum.
	m = validManifest()
	e = first(m)
	e["kind"] = "symlink"
	e["mode"] = "120000"
	e["link_target"] = "peer"
	e["size"] = uint64(4)
	e["sha256"] = digest([]byte("peer"))
	good(t, encoded(t, m))
	m["data_bytes"] = uint64(4)
	bad(t, encoded(t, m), ReasonDeclaredBytesInconsistent)
}
func TestP19TargetShapeAndHash(t *testing.T) {
	link := func(target string) object {
		m := validManifest()
		e := first(m)
		e["path"] = "dir/link"
		e["kind"] = "symlink"
		e["mode"] = "120000"
		e["link_target"] = target
		e["size"] = uint64(len(target))
		e["sha256"] = digest([]byte(target))
		return m
	}
	// Target shape admits bounded relative text without claiming symlink graph containment.
	for _, target := range []string{"peer", "./peer", "../peer", "C:peer", "C:/peer", "a//b", "é", strings.Repeat("x", 1024)} {
		good(t, encoded(t, link(target)))
	}
	for _, target := range []string{"", "/peer", "a\x00b", "a\\b"} {
		bad(t, encoded(t, link(target)), ReasonPathShape)
	}
	bad(t, encoded(t, link(strings.Repeat("x", 1025))), ReasonScalarBound)
	// Only symlinks carry targets, with size and lowercase SHA bound to exact decoded target bytes.
	m := validManifest()
	first(m)["link_target"] = "peer"
	bad(t, encoded(t, m), ReasonEntryShape)
	m = link("peer")
	first(m)["size"] = uint64(3)
	bad(t, encoded(t, m), ReasonEntryShape)
	m = link("peer")
	first(m)["sha256"] = strings.Repeat("0", 64)
	bad(t, encoded(t, m), ReasonEntryShape)
	m = link("peer")
	first(m)["sha256"] = strings.Repeat("A", 64)
	bad(t, encoded(t, m), ReasonIdentifierSyntax)
	m = link("peer")
	raw := string(encoded(t, m))
	good(t, []byte(strings.Replace(raw, `"link_target":"peer"`, `"link_target":"\u0070eer"`, 1)))
}
func TestP20P21RawOwnershipAndNil(t *testing.T) {
	// Stored digests bind the exact raw encoding and reject a different permitted encoding's digest.
	m := validManifest()
	withRecord(m)
	raw := encoded(t, m)
	original := bytes.Clone(raw)
	v := good(t, raw)
	w := good(t, raw)
	h := sha256.Sum256(original)
	if got, ok := v.ComputedRawSHA256(); !ok || got != h {
		t.Fatal("actual raw digest")
	}
	if e := v.CompareExpectedRawSHA256Only(h); e != nil {
		t.Fatal(e)
	}
	varied := append([]byte(" \n"), original...)
	other := good(t, varied)
	otherHash, _ := other.ComputedRawSHA256()
	if h == otherHash {
		t.Fatal("encoding lost")
	}
	var r *BodyShapeRefusal
	if e := v.CompareExpectedRawSHA256Only(otherHash); !errors.As(e, &r) || r.Reason != ReasonRawDigestMismatch {
		t.Fatal("wrong digest accepted")
	}
	// Caller and accessor mutations cannot change retained raw bytes or manifest fields.
	raw[0] = 'x'
	copyRaw := v.RawBodyCopy()
	copyRaw[0] = 'x'
	snap := v.ManifestCopy()
	snap.Entries[0].Path = "changed"
	snap.ModuleReceipt.Modules[0].Path = "changed"
	if !bytes.Equal(v.RawBodyCopy(), original) || !reflect.DeepEqual(v.ManifestCopy(), w.ManifestCopy()) {
		t.Fatal("mutable alias")
	}
	// Concurrent copy and digest reads observe immutable stored state.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if !bytes.Equal(v.RawBodyCopy(), original) || v.ManifestCopy().Entries[0].Path != "go.mod" {
					t.Error("concurrent snapshot")
				}
				if e := v.CompareExpectedRawSHA256Only(h); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	wg.Wait()
	// Nil and zero bodies expose no content or digest and refuse digest comparison as absent.
	for _, absent := range []*UnqualifiedOpcode34Body{nil, {}} {
		if absent.RawBodyCopy() != nil || absent.ManifestCopy() != nil {
			t.Fatal("absent copy")
		}
		if got, ok := absent.ComputedRawSHA256(); ok || got != [32]byte{} {
			t.Fatal("absent digest")
		}
		e := absent.CompareExpectedRawSHA256Only(h)
		if !errors.As(e, &r) || r.Reason != ReasonResultAbsent {
			t.Fatal("absent comparison")
		}
	}
	// Invalid or caller-made refusal reasons never echo arbitrary diagnostic text.
	for _, e := range []*BodyShapeRefusal{nil, {}, {BodyShapeReason("private input text")}} {
		if e.Error() != "input_invalid" {
			t.Fatal("unsafe diagnostic")
		}
	}
	bad(t, []byte(`{"version":2}`), ReasonScalarBound)
}
