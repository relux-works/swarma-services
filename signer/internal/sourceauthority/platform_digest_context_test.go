package sourceauthority

import (
	"strings"
	"testing"
)

// Claim: Only platform digest payloads use strict value validation, preserving exact grammar and refusal predicates at both boundaries.
func TestPlatformDigestContextSeparation(t *testing.T) {
	for _, phase := range []string{"prebuild", "presign"} {
		for _, name := range []string{"plain", "single_pair", "empty", "ordinary_tick", "escaped_ticks", "unclosed_suffix", "two_pairs", "uppercase", "no_space", "trailing_space", "html"} {
			t.Run(name+"/"+phase, func(t *testing.T) {
				f := validFixture(t)
				original := f.s.observation.Reviews.Records[0].Body
				first, rest, _ := strings.Cut(original, "\n")
				line := strings.TrimSpace(rest)
				prefix := "Verdict record digest: "
				value := strings.TrimPrefix(line, prefix)
				expected := "platform_digest"
				switch name {
				case "plain":
					expected = ""
				case "single_pair":
					value = "`" + value + "`"
					expected = ""
				case "empty":
					value = ""
				case "ordinary_tick":
					value = "`"
				case "escaped_ticks":
					value = "\\` `"
				case "unclosed_suffix":
					value += "`"
				case "two_pairs":
					value = "``" + value + "``"
				case "uppercase":
					value = "sha256:" + strings.ToUpper(strings.TrimPrefix(value, "sha256:"))
				case "no_space":
					prefix = "Verdict record digest:"
				case "trailing_space":
					value += " "
				case "html":
					value = "<!-- `"
					expected = "platform_format"
				}
				f.s.observation.Reviews.Records[0].Body = first + "\n\n" + prefix + value + "\n"
				// Actual platform digest fields, unlike stored notes carrying the same label.
				if expected == "" {
					reviewer373Call(t, f, phase, expected)
				} else {
					stored := f.s.observation.Lookup.Scopes[0].Events[0].Body
					platform := f.s.observation.Reviews.Records[0].Body
					qualifyContext(t, f, phase, expected)
					if f.s.observation.Lookup.Scopes[0].Events[0].Body != stored || f.s.observation.Reviews.Records[0].Body != platform {
						t.Fatal("boundary rewrote exact body bytes")
					}
					if len(f.s.queries) != 1 || string(f.s.queries[0].Phase) != phase {
						t.Fatal("boundary did not independently read source")
					}
				}
			})
		}
	}
}

// Claim: Platform digest-like notes with noncanonical indentation receive ordinary context validation, while real digest fields retain strict parsing.
func TestDigestPrefixIndentedPlatformNotes(t *testing.T) {
	for _, indent := range []int{1, 3} {
		for _, phase := range []string{"prebuild", "presign"} {
			for _, variant := range []string{"plain_neighbor", "closed_neighbor", "ordinary_multiline", "escaped_multiline", "unclosed_suffix"} {
				t.Run(strings.Repeat("space", indent)+"/"+variant+"/"+phase, func(t *testing.T) {
					f := validFixture(t)
					original := f.s.observation.Reviews.Records[0].Body
					first, rest, _ := strings.Cut(original, "\n")
					rest = strings.ReplaceAll(strings.TrimSpace(rest), "\n\n", "\n")
					prefix := strings.Repeat(" ", indent) + "Verdict record digest: "
					expected := "platform_format"
					body := ""
					switch variant {
					case "plain_neighbor":
						body = first + "\n\n" + prefix + "historical note\n" + rest + "\n"
						expected = ""
					case "closed_neighbor":
						body = first + "\n\n" + prefix + "`historical note`\n" + rest + "\n"
						expected = ""
					// These four pairs wrap the only actual digest line in one paragraph.
					case "ordinary_multiline":
						body = first + "\n\n" + prefix + "`\n" + rest + "\n" + prefix + "`\n"
					case "escaped_multiline":
						body = first + "\n\n" + prefix + "\\` `\n" + rest + "\n" + prefix + "\\` `\n"
					// A suffix asserts whole-body refusal, not hiding an earlier field.
					case "unclosed_suffix":
						body = original + "\n" + prefix + "`\n"
					}
					f.s.observation.Reviews.Records[0].Body = body
					if expected != "" {
						t.Logf("INDENTED_PLATFORM_BODY=%q", body)
					}
					reviewer373Call(t, f, phase, expected)
				})
			}
		}
	}
}
