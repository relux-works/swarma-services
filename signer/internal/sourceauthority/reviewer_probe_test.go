package sourceauthority

import (
	"context"
	"strings"
	"testing"
)

// Claim: A valid exact-head fixture and quoted historical examples remain eligible at both boundaries.
func TestReviewerValidNeighbors(t *testing.T) {
	for _, name := range []string{"baseline", "quoted_historical", "long_fence_with_real_bindings_outside"} {
		t.Run(name, func(t *testing.T) {
			for _, sign := range []bool{false, true} {
				f := validFixture(t)
				body := &f.s.observation.Lookup.Scopes[0].Events[0].Body
				if name == "quoted_historical" {
					*body += "\n> Blocking: historical example\n\n```\nREJECT: historical code example\n```\n"
				}
				if name == "long_fence_with_real_bindings_outside" {
					*body += "\n````\nBlocking: historical code example\n```\nstill in code\n````\n"
				}
				f.rebindDigest()
				a := f.authority(t)
				var q *Qualification
				var err error
				if sign {
					q, err = a.BeforeSign(context.Background(), f.r)
				} else {
					q, err = a.BeforeBuild(context.Background(), f.r)
				}
				if err != nil || q == nil {
					t.Fatalf("valid neighbor refused sign=%v: %v", sign, err)
				}
			}
		})
	}
}

// Claim: Fields inside an unclosed four-character code fence cannot supply authoritative head/PR/digest bindings.
func TestReviewerFencedBindingsRefuse(t *testing.T) {
	for _, variant := range []string{"short_close", "close_with_info", "platform_digest"} {
		for _, phase := range []string{"prebuild", "presign"} {
			t.Run(variant+"/"+phase, func(t *testing.T) {
				f := validFixture(t)
				if variant == "platform_digest" {
					b := f.s.observation.Reviews.Records[0].Body
					first, rest, _ := strings.Cut(b, "\n")
					f.s.observation.Reviews.Records[0].Body = first + "\n\n````\nquoted example\n```\n" + rest
				} else {
					b := f.s.observation.Lookup.Scopes[0].Events[0].Body
					first, rest, _ := strings.Cut(b, "\n")
					close := "```"
					if variant == "close_with_info" {
						close = "````not-a-closing-fence"
					}
					f.s.observation.Lookup.Scopes[0].Events[0].Body = first + "\n\n````\nquoted example\n" + close + "\n" + rest
					f.rebindDigest()
				}
				a := f.authority(t)
				var q *Qualification
				var err error
				if phase == "presign" {
					q, err = a.BeforeSign(context.Background(), f.r)
				} else {
					q, err = a.BeforeBuild(context.Background(), f.r)
				}
				if q != nil || err == nil {
					t.Fatalf("FENCED_BINDING_AUTHORIZED phase=%s variant=%s qualification=%v error=%v", phase, variant, q != nil, err)
				}
			})
		}
	}
}

// Claim: An indented literal fence cannot hide a later unquoted Blocking line from either qualification boundary.
func TestReviewerIndentedFenceCannotHideBlocking(t *testing.T) {
	for _, phase := range []string{"prebuild", "presign"} {
		t.Run(phase, func(t *testing.T) {
			f := validFixture(t)
			f.s.observation.Lookup.Scopes[0].Events[0].Body += "\n    ```\nBlocking: unresolved exact-source finding\n"
			f.rebindDigest()
			a := f.authority(t)
			var q *Qualification
			var err error
			if phase == "presign" {
				q, err = a.BeforeSign(context.Background(), f.r)
			} else {
				q, err = a.BeforeBuild(context.Background(), f.r)
			}
			if q != nil || err == nil {
				t.Fatalf("BLOCKING_LINE_HIDDEN phase=%s qualification=%v error=%v", phase, q != nil, err)
			}
		})
	}
}
