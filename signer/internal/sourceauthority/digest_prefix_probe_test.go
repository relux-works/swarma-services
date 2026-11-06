package sourceauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func reviewer373Call(t *testing.T, f *fixture, phase, expected string) {
	t.Helper()
	stored := f.s.observation.Lookup.Scopes[0].Events[0].Body
	platform := f.s.observation.Reviews.Records[0].Body
	h := sha256.Sum256([]byte(stored))
	digest := hex.EncodeToString(h[:])
	if !strings.Contains(platform, "sha256:"+digest) {
		t.Fatal("independent exact digest binding lost before call")
	}
	a := f.authority(t)
	boundary := a.BeforeBuild
	if phase == "presign" {
		boundary = a.BeforeSign
	}
	q, err := boundary(context.Background(), f.r)
	if f.s.observation.Lookup.Scopes[0].Events[0].Body != stored || f.s.observation.Reviews.Records[0].Body != platform {
		t.Fatal("boundary rewrote exact body bytes")
	}
	if len(f.s.queries) != 1 || string(f.s.queries[0].Phase) != phase {
		t.Fatal("actual requested boundary did not independently read source")
	}
	if expected == "" {
		if q == nil || err != nil {
			t.Fatalf("valid neighbor refused: %v", err)
		}
		summary, ok := q.Summary()
		if !ok || summary.VerdictBodySHA256 != digest {
			t.Fatal("qualification summary digest mismatch")
		}
	} else {
		var refusal *Refusal
		if q != nil || !errors.Is(err, ErrRejected) || !errors.As(err, &refusal) || refusal.Predicate() != expected {
			t.Fatalf("UNSAFE_CONTEXT expected=%s qualification=%v err=%v", expected, q != nil, err)
		}
	}
}

// Claim: Independent escape neighbors preserve literal same-line closers while refusing ambiguous outside runs and suffixes.
func TestIndependent373EscapeEdges(t *testing.T) {
	cases := []struct {
		name, note string
		reject     bool
	}{
		{"closer_after_literal_backslash", "Note: `a\\`.", false},
		{"long_closer_after_literal_backslash", "Note: ``a\\``.", false},
		{"mismatched_run_inside_code", "Note: ```a\\``b```.", false},
		{"multiple_spans_literal_backslash", "Note: `a\\` then ``b\\``.", false},
		{"even_four_backslashes", "Note: " + strings.Repeat("\\", 4) + "` `", true},
		{"odd_three_backslashes", "Note: " + strings.Repeat("\\", 3) + "` `", true},
		{"adjacent_escape_after_span", "Note: `closed`\\` `", true},
		{"unmatched_opener", "Note: `open", true},
		{"different_length_closer", "Note: ``open`", true},
		{"escaped_long_opener", "Note: \\``` ```", true},
		{"unicode_plain_backslash", "Note: café e\u0301 path\\name.", false},
	}
	for _, tc := range cases {
		for _, surface := range []string{"stored", "platform"} {
			for _, phase := range []string{"prebuild", "presign"} {
				t.Run(tc.name+"/"+surface+"/"+phase, func(t *testing.T) {
					f := validFixture(t)
					// Put the uncertain context after already-valid fields: whole-body refusal
					// must still apply, and no scanner-produced fixture supplies the oracle.
					if surface == "stored" {
						f.s.observation.Lookup.Scopes[0].Events[0].Body += "\n" + tc.note + "\n"
						f.rebindDigest()
					} else {
						f.s.observation.Reviews.Records[0].Body += "\n" + tc.note + "\n"
					}
					expected := ""
					if tc.reject {
						expected = "verdict_format"
						if surface == "platform" {
							expected = "platform_format"
						}
					}
					reviewer373Call(t, f, phase, expected)
				})
			}
		}
	}
}

// Claim: A digest-like note in the stored verdict cannot exempt multiline or escaped delimiters around its only PR/head bindings.
func TestIndependent373DigestPrefixContext(t *testing.T) {
	for _, variant := range []string{"plain_neighbor", "closed_neighbor", "ordinary_multiline", "escaped_multiline", "unclosed_suffix"} {
		for _, phase := range []string{"prebuild", "presign"} {
			t.Run(variant+"/"+phase, func(t *testing.T) {
				f := validFixture(t)
				body := f.s.observation.Lookup.Scopes[0].Events[0].Body
				first, rest, _ := strings.Cut(body, "\n")
				rest = strings.ReplaceAll(strings.TrimSpace(rest), "\n\n", "\n")
				expected := "verdict_format"
				switch variant {
				case "plain_neighbor":
					body = first + "\n\nVerdict record digest: historical note\n" + rest + "\n"
					expected = ""
				case "closed_neighbor":
					body = first + "\n\nVerdict record digest: `historical note`\n" + rest + "\n"
					expected = ""
				// The four ordinary/escaped leaves place the only PR/head inside one paragraph.
				case "ordinary_multiline":
					body = first + "\n\nVerdict record digest: `\n" + rest + "\nVerdict record digest: `\n"
				case "escaped_multiline":
					body = first + "\n\nVerdict record digest: \\` `\n" + rest + "\nVerdict record digest: \\` `\n"
				// These two suffix leaves assert whole-body refusal, not hiding earlier fields.
				case "unclosed_suffix":
					body += "\nVerdict record digest: `\n"
				}
				f.s.observation.Lookup.Scopes[0].Events[0].Body = body
				f.rebindDigest()
				if expected != "" {
					t.Logf("SYNTHETIC_STORED_BODY=%q", body)
					t.Logf("SYNTHETIC_PLATFORM_BODY=%q", f.s.observation.Reviews.Records[0].Body)
				}
				reviewer373Call(t, f, phase, expected)
			})
		}
	}
}
