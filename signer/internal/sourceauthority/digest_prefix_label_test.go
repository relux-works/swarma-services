package sourceauthority

import (
	"strings"
	"testing"
)

// Claim: Changing only a stored note's label must not bypass ambiguity refusal.
func TestIndependent373LabelOnlyControl(t *testing.T) {
	for _, variant := range []string{"ordinary_multiline", "escaped_multiline"} {
		for _, phase := range []string{"prebuild", "presign"} {
			t.Run(variant+"/"+phase, func(t *testing.T) {
				f := validFixture(t)
				original := f.s.observation.Lookup.Scopes[0].Events[0].Body
				first, rest, _ := strings.Cut(original, "\n")
				rest = strings.ReplaceAll(strings.TrimSpace(rest), "\n\n", "\n")
				ticks := "`"
				if variant == "escaped_multiline" {
					ticks = "\\` `"
				}
				ordinary := first + "\n\nNote: " + ticks + "\n" + rest + "\nNote: " + ticks + "\n"
				for _, label := range []string{"Note:", "Verdict record digest:"} {
					t.Run(label, func(t *testing.T) {
						body := strings.ReplaceAll(ordinary, "Note:", label)
						f.s.queries = nil
						f.s.observation.Lookup.Scopes[0].Events[0].Body = body
						f.rebindDigest()
						t.Logf("LABEL_ONLY_BODY=%q", body)
						reviewer373Call(t, f, phase, "verdict_format")
					})
				}
			})
		}
	}
}
