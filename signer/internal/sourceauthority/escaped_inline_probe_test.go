package sourceauthority

import (
	"context"
	"strings"
	"testing"
)

// Claim: Escape/backtick ambiguity must not expose multiline-code bindings at either boundary.
func TestReReviewEscapedInlineAmbiguity(t *testing.T) {
	for _, surface := range []string{"stored", "platform"} {
		for _, phase := range []string{"prebuild", "presign"} {
			for _, variant := range []string{"baseline", "closed_inline", "escaped_open"} {
				t.Run(surface+"/"+phase+"/"+variant, func(t *testing.T) {
					f := validFixture(t)
					transform := func(b string) string {
						first, rest, _ := strings.Cut(b, "\n")
						if variant == "baseline" {
							return b
						}
						if variant == "closed_inline" {
							return first + "\n\nNote: `closed`.\n" + rest
						}
						// The first tick is escaped in Markdown; the second starts a span
						// which crosses the only authority bindings before the later tick.
						return first + "\n\nNote: \\` `\n" + strings.ReplaceAll(strings.TrimSpace(rest), "\n\n", "\n") + "\nNote: \\` `\n"
					}
					if surface == "stored" {
						f.s.observation.Lookup.Scopes[0].Events[0].Body = transform(f.s.observation.Lookup.Scopes[0].Events[0].Body)
						f.rebindDigest()
					} else {
						f.s.observation.Reviews.Records[0].Body = transform(f.s.observation.Reviews.Records[0].Body)
					}
					a := f.authority(t)
					boundary := a.BeforeBuild
					if phase == "presign" {
						boundary = a.BeforeSign
					}
					q, err := boundary(context.Background(), f.r)
					if variant == "escaped_open" {
						if q != nil || err == nil {
							t.Fatalf("MULTILINE_INLINE_BINDING_AUTHORIZED surface=%s phase=%s q=%v err=%v", surface, phase, q != nil, err)
						}
					} else if q == nil || err != nil {
						t.Fatalf("valid neighbor refused: %v", err)
					}
				})
			}
		}
	}
}
