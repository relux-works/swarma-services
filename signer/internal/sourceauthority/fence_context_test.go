package sourceauthority

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func contextBody(f *fixture, platform bool, transform func(string) string) {
	if platform {
		f.s.observation.Reviews.Records[0].Body = transform(f.s.observation.Reviews.Records[0].Body)
	} else {
		f.s.observation.Lookup.Scopes[0].Events[0].Body = transform(f.s.observation.Lookup.Scopes[0].Events[0].Body)
		f.rebindDigest()
	}
}

func qualifyContext(t *testing.T, f *fixture, phase string, predicate string) {
	t.Helper()
	a := f.authority(t)
	boundary := a.BeforeBuild
	if phase == "presign" {
		boundary = a.BeforeSign
	}
	q, err := boundary(context.Background(), f.r)
	if predicate == "" {
		if q == nil || err != nil {
			t.Fatalf("valid context refused at %s: %v", phase, err)
		}
		return
	}
	var refusal *Refusal
	if q != nil || !errors.Is(err, ErrRejected) || !errors.As(err, &refusal) || refusal.Predicate() != predicate {
		t.Fatalf("expected %s at %s without qualification; got qualification=%v error=%v", predicate, phase, q != nil, err)
	}
}

// Claim: Closed long fences, literal indentation and quoted history preserve real unquoted bindings at both boundaries.
func TestReviewContextPositiveNeighbors(t *testing.T) {
	for _, tc := range []struct{ name, prefix string }{
		{"ordinary", ""},
		{"backtick_info", "\n```go\nBlocking: historical code\n```\n"},
		{"tilde_info_with_backtick", "\n~~~~lang`example\nREJECT: historical code\n~~~~~ \t\n"},
		{"one_space", "\n ```\nBlocking: code\n ```\n"},
		{"two_spaces", "\n  ~~~~\nBlocking: code\n  ~~~~\n"},
		{"three_spaces_longer_close", "\n   ````\nBlocking: code\n``````\t \n"},
		{"long_run", "\n" + strings.Repeat("~", 32) + "\nBlocking: code\n" + strings.Repeat("~", 33) + "\n"},
		{"nonclosers_inside_long_fence", "\n````info\n```\nBlocking: still code\n````suffix\nREJECT: still code\n~~~~\n> ````\n    ````\n\t````\n````\n"},
		{"four_space_literal", "\n    ```\n"},
		{"tab_literal", "\n\t~~~\n"},
		{"mixed_literal_indent", "\n   \t````\n"},
		{"quoted_fence", "\n> ````\n> Blocking: historical example\n\n"},
		{"closed_inline_code", "\nNon-blocking note: `code` and ``a`b``.\n\n"},
	} {
		for _, surface := range []string{"stored", "platform"} {
			for _, phase := range []string{"prebuild", "presign"} {
				t.Run(tc.name+"/"+surface+"/"+phase, func(t *testing.T) {
					f := validFixture(t)
					contextBody(f, surface == "platform", func(body string) string {
						first, rest, _ := strings.Cut(body, "\n")
						return first + "\n" + tc.prefix + rest
					})
					qualifyContext(t, f, phase, "")
				})
			}
		}
	}
}

// Claim: Fenced/quoted/indented bindings and unsupported ambiguous contexts refuse with the intended format or missing-digest predicate.
func TestReviewContextNegativeNeighbors(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, suffix string
		missing              bool
	}{
		{"short_close", "\n````\nexample\n```\n", "", false},
		{"close_with_info", "\n````\nexample\n````not-a-closer\n", "", false},
		{"wrong_delimiter", "\n~~~~\nexample\n````\n", "", false},
		{"indented_closer", "\n````\nexample\n    ````\n", "", false},
		{"tab_closer", "\n~~~~\nexample\n\t~~~~\n", "", false},
		{"short_close_then_real_close", "\n````\n```\n", "````\n", true},
		{"info_close_then_real_close", "\n~~~~\n~~~~suffix\n", "~~~~\n", true},
		{"backtick_in_info", "\n```bad`info\n", "```\n", false},
		{"ambiguous_indent", "    ```\n", "", false},
		{"lazy_quote", "> historical example\n", "", false},
		{"html_container", "\n<!--\n", "-->\n", false},
		{"inline_html_comment", "Note <!--\n", "-->\n", false},
		{"list_container", "\n- historical example\n", "", false},
		{"ordered_list_container", "\n1. historical example\n", "", false},
		{"multiline_inline_code", "\n`historical\n", "`\n", false},
		{"unclosed_after_bindings", "", "\n~~~~\nBlocking: cannot establish context\n", false},
		{"cr_context", "\n````\r\n", "````\r\n", false},
	} {
		for _, surface := range []string{"stored", "platform"} {
			for _, phase := range []string{"prebuild", "presign"} {
				t.Run(tc.name+"/"+surface+"/"+phase, func(t *testing.T) {
					f := validFixture(t)
					contextBody(f, surface == "platform", func(body string) string {
						first, rest, _ := strings.Cut(body, "\n")
						if tc.name == "lazy_quote" {
							rest = strings.TrimPrefix(rest, "\n")
						}
						return first + "\n" + tc.prefix + rest + tc.suffix
					})
					predicate := "verdict_format"
					if surface == "platform" {
						predicate = "platform_format"
						if tc.missing {
							predicate = "platform_digest"
						}
					}
					qualifyContext(t, f, phase, predicate)
				})
			}
		}
	}
	for _, indent := range []string{"> ", "    ", "\t", "   \t"} {
		for _, surface := range []string{"stored", "platform"} {
			for _, phase := range []string{"prebuild", "presign"} {
				t.Run("non_authoritative_bindings/"+indent+"/"+surface+"/"+phase, func(t *testing.T) {
					f := validFixture(t)
					contextBody(f, surface == "platform", func(body string) string {
						first, rest, _ := strings.Cut(body, "\n")
						return first + "\n\n" + indent + strings.ReplaceAll(strings.TrimSuffix(rest, "\n"), "\n", "\n"+indent) + "\n"
					})
					predicate := "verdict_format"
					if surface == "platform" {
						predicate = "platform_digest"
					}
					qualifyContext(t, f, phase, predicate)
				})
			}
		}
	}
}

// Claim: Every explicit unquoted contradiction after a literal or closed fence refuses at both boundaries.
func TestReviewContextUnquotedBlockingRefuses(t *testing.T) {
	for _, marker := range []string{"REJECT:", "CHANGES_REQUESTED:", "Blocking findings:", "Blocking:"} {
		for _, prefix := range []string{"", "\n    ```\n", "\n\t~~~\n", "\n   \t````\n", "\n````\nquoted history\n`````\n"} {
			for _, surface := range []string{"stored", "platform"} {
				for _, phase := range []string{"prebuild", "presign"} {
					t.Run(marker+"/"+prefix+"/"+surface+"/"+phase, func(t *testing.T) {
						f := validFixture(t)
						contextBody(f, surface == "platform", func(body string) string {
							return body + "\n" + prefix + "  " + marker + " unresolved current finding\n"
						})
						qualifyContext(t, f, phase, "review_blocking")
					})
				}
			}
		}
	}
}
