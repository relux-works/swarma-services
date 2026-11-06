package sourceauthority

import (
	"strings"
	"testing"
)

// Claim: Escaped opener runs refuse on both surfaces/boundaries while same-line code and literal backslashes preserve exact bodies.
func TestReviewEscapedInlineContextNeighbors(t *testing.T) {
	for _, tc := range []struct {
		name, note string
		reject     bool
	}{
		{"single_escape", "Note: " + string(byte(92)) + "` `", true},
		{"even_backslashes", "Note: " + strings.Repeat(string(byte(92)), 2) + "` `", true},
		{"long_escaped_run", "Note: " + string(byte(92)) + "`` ``", true},
		{"escaped_run_after_closed_span", "Note: `closed` " + string(byte(92)) + "` `", true},
		{"plain_backslash", "Note: path\\name.", false},
		{"plain_inline", "Note: `closed`.", false},
		{"long_inline", "Note: ``a`b``.", false},
		{"backslash_inside_span", "Note: ``a\\`b``.", false},
	} {
		for _, surface := range []string{"stored", "platform"} {
			for _, phase := range []string{"prebuild", "presign"} {
				t.Run(tc.name+"/"+surface+"/"+phase, func(t *testing.T) {
					f := validFixture(t)
					contextBody(f, surface == "platform", func(body string) string {
						first, rest, _ := strings.Cut(body, "\n")
						return first + "\n\n" + tc.note + "\n" + strings.ReplaceAll(strings.TrimSpace(rest), "\n\n", "\n") + "\n" + tc.note + "\n"
					})
					body := f.s.observation.Lookup.Scopes[0].Events[0].Body
					platformBody := f.s.observation.Reviews.Records[0].Body
					digest := bodyHash(body)
					if !strings.Contains(platformBody, "sha256:"+digest) {
						t.Fatal("exact stored body digest changed")
					}
					predicate := ""
					if tc.reject {
						predicate = "verdict_format"
						if surface == "platform" {
							predicate = "platform_format"
						}
					}
					qualifyContext(t, f, phase, predicate)
					if f.s.observation.Lookup.Scopes[0].Events[0].Body != body || f.s.observation.Reviews.Records[0].Body != platformBody || bodyHash(body) != digest {
						t.Fatal("qualification changed exact body bytes")
					}
				})
			}
		}
	}
}
