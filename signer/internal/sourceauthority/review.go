package sourceauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

func bodyHash(body string) string { h := sha256.Sum256([]byte(body)); return hex.EncodeToString(h[:]) }

// visibleLines checks shared block context and the caller-specific line grammar.
// Returned lines still require complete format-specific value/binding validation.
// It never changes the exact bytes of the authoritative declaration/bindings.
func visibleLines(body string, unsupportedLine func(string) bool) ([]string, bool) {
	var lines []string
	var fence byte
	fenceLength := 0
	blank, indented, quoted := true, false, false
	for line := range strings.SplitSeq(body, "\n") {
		// Only LF separates lines in the configured body grammar.
		if strings.ContainsAny(line, "\r\v\f") {
			return nil, false
		}
		t := strings.TrimLeft(line, " ")
		indent := len(line) - len(t)
		if fence != 0 {
			// Closers use the same delimiter, at least the opening length,
			// at most three leading spaces and only a space/tab suffix.
			if indent <= 3 && len(t) > 0 && t[0] == fence {
				n := fenceRun(t)
				if n >= fenceLength && strings.Trim(t[n:], " \t") == "" {
					fence, fenceLength = 0, 0
				}
			}
			continue
		}
		if strings.Trim(line, " \t") == "" {
			blank, quoted = true, false
			continue
		}
		// A leading tab after zero to three spaces reaches column four.
		// Literal indentation cannot open or close a fence. Without a blank
		// separator it could continue a paragraph; refuse that ambiguity.
		if indent >= 4 || strings.HasPrefix(t, "\t") {
			if !blank && !indented {
				return nil, false
			}
			indented, blank = true, false
			continue
		}
		indented = false
		if strings.HasPrefix(t, ">") {
			quoted, blank = true, false
			continue
		}
		if (t[0] == 0x60 || t[0] == '~') && fenceRun(t) >= 3 {
			n := fenceRun(t)
			// Backtick info strings cannot contain backticks.
			if t[0] == 0x60 && strings.ContainsRune(t[n:], 0x60) {
				return nil, false
			}
			fence, fenceLength, quoted, blank = t[0], n, false, false
			continue
		}
		// An unprefixed paragraph may be a lazy quote continuation. The
		// supported subset ends quotes with a blank line or an actual fence.
		if quoted || unsupportedLine(line) {
			return nil, false
		}
		lines = append(lines, line)
		blank = false
	}
	if fence != 0 {
		return nil, false
	}
	return lines, true
}

// fenceRun counts the complete initial delimiter run, never just its prefix.
func fenceRun(line string) int {
	n := 0
	for n < len(line) && line[n] == line[0] {
		n++
	}
	return n
}

// Only raw platform digest fields defer to the strict value parser. Keep errors
// at platform_digest; HTML ambiguity still refuses at platform_format. Stored
// verdict notes never use this format-specific exemption.
func unsupportedPlatformReviewLine(line string) bool {
	if strings.HasPrefix(line, "Verdict record digest:") && !strings.ContainsRune(line, '<') {
		return false
	}
	return unsupportedReviewLine(line)
}

// Other Markdown containers and multiline inline code are outside this finite
// grammar; rejecting them prevents their contents from becoming authority.
func unsupportedReviewLine(line string) bool {
	line = strings.TrimLeft(line, " ")
	if strings.ContainsRune(line, '<') {
		return true // HTML can hide later lines, including inline comments.
	}
	if len(line) > 1 && strings.ContainsRune("-*+", rune(line[0])) && (line[1] == ' ' || line[1] == '\t') {
		return true
	}
	n := 0
	for n < len(line) && n < 9 && line[n] >= '0' && line[n] <= '9' {
		n++
	}
	if n > 0 && n+1 < len(line) && (line[n] == '.' || line[n] == ')') && (line[n+1] == ' ' || line[n+1] == '\t') {
		return true
	}
	// Code spans must close on the same line with an identical run length.
	// Unmatched runs and ambiguous escaped openers conservatively refuse.
	span := 0
	for i := 0; i < len(line); {
		if line[i] != 0x60 {
			i++
			continue
		}
		// Outside a span, backslash/backtick runs have unsupported escape
		// semantics. Refuse without guessing backslash parity or unescaping.
		if span == 0 && i > 0 && line[i-1] == '\\' {
			return true
		}
		n := fenceRun(line[i:])
		if span == 0 {
			span = n
		} else if span == n {
			span = 0
		}
		i += n
	}
	return span != 0
}

func contradiction(line string) bool {
	for _, prefix := range []string{"REJECT:", "CHANGES_REQUESTED:", "Blocking findings:", "Blocking:"} {
		if strings.HasPrefix(strings.TrimLeft(line, " "), prefix) {
			return true
		}
	}
	return false
}

// These finite text forms implement the r5 declarations, not a substring or
// natural-language classifier. Qualification against actual forward-form bodies
// remains a production freeze gate, documented with the source dependencies.
func platformDigest(r PlatformReview, head, base string) (string, error) {
	if !utf8.ValidString(r.Body) || strings.ContainsRune(r.Body, 0) {
		return "", rejected("platform_format")
	}
	first := strings.SplitN(r.Body, "\n", 2)[0]
	expected := "Independent source review: **ACCEPT** for exact head `" + head + "` (base `" + base + "`)."
	if first != expected {
		return "", rejected("platform_format")
	}
	var digest string
	count := 0
	lines, valid := visibleLines(r.Body, unsupportedPlatformReviewLine)
	if !valid {
		return "", rejected("platform_format")
	}
	for _, line := range lines {
		if contradiction(line) {
			return "", rejected("review_blocking")
		}
		if !strings.HasPrefix(line, "Verdict record digest:") {
			continue
		}
		count++
		value := strings.TrimPrefix(line, "Verdict record digest: ")
		if len(value) >= 2 && strings.HasPrefix(value, "`") && strings.HasSuffix(value, "`") {
			value = value[1 : len(value)-1]
		}
		if !strings.HasPrefix(value, "sha256:") || !lowerHex(strings.TrimPrefix(value, "sha256:"), 64) {
			return "", rejected("platform_digest")
		}
		digest = value[len("sha256:"):]
	}
	if count != 1 {
		return "", rejected("platform_digest")
	}
	return digest, nil
}

func verdictBody(body string, p Policy, pr PullRequest) error {
	if !utf8.ValidString(body) || strings.ContainsRune(body, 0) {
		return rejected("verdict_format")
	}
	declaration := fmt.Sprintf("ACCEPT: independent source review of %s PR #%d", p.RepositoryName, pr.Number)
	first := strings.SplitN(body, "\n", 2)[0]
	if first != declaration && first != declaration+"." {
		return rejected("verdict_format")
	}
	prLine := fmt.Sprintf("PR %s/pull/%d", p.CanonicalRepository, pr.Number)
	headLine := "Exact head " + pr.Head + ", base " + pr.Base + "."
	prCount, headCount, acceptCount := 0, 0, 0
	lines, valid := visibleLines(body, unsupportedReviewLine)
	if !valid {
		return rejected("verdict_format")
	}
	for _, line := range lines {
		if contradiction(line) {
			return rejected("review_blocking")
		}
		if strings.HasPrefix(line, "ACCEPT:") {
			acceptCount++
		}
		if strings.HasPrefix(line, "PR ") {
			prCount++
			if line != prLine {
				return rejected("verdict_binding")
			}
		}
		if strings.HasPrefix(line, "Exact head ") {
			headCount++
			if line != headLine {
				return rejected("verdict_binding")
			}
		}
	}
	if prCount != 1 || headCount != 1 || acceptCount != 1 {
		return rejected("verdict_format")
	}
	return nil
}

func selectedPlatformReview(o Observation, p Policy) (PlatformReview, error) {
	var selected PlatformReview
	if o.Reviews.Coverage != Complete {
		return selected, unavailable("review_coverage")
	}
	if !text(o.Reviews.SelectedID, 256) {
		return selected, rejected("review_missing")
	}
	found := 0
	seen := make(map[string]bool)
	for _, r := range o.Reviews.Records {
		if !text(r.ID, 256) || seen[r.ID] || r.Repository != p.CanonicalRepository || r.PR != o.PR.Number {
			return selected, unavailable("review_inventory")
		}
		seen[r.ID] = true
		if r.State == "active" && r.Kind == "CHANGES_REQUESTED" {
			return selected, rejected("review_withdrawal_or_blocking")
		}
		if r.ID == o.Reviews.SelectedID {
			selected = r
			found++
		}
	}
	if found != 1 {
		return selected, rejected("review_missing")
	}
	if selected.Head != o.PR.Head || selected.Base != o.PR.Base || selected.Kind != "COMMENT" || selected.State != "active" {
		return selected, rejected("review_withdrawal_or_binding")
	}
	if selected.SubmittedAt < 86400 || selected.SubmittedAt > o.ObservedAt || selected.SubmittedAt > 9223372036854775807-300 {
		return selected, unavailable("review_time")
	}
	return selected, nil
}

func verifyReview(o Observation, p Policy) (PlatformReview, string, error) {
	selected, err := selectedPlatformReview(o, p)
	if err != nil {
		return selected, "", err
	}
	digest, err := platformDigest(selected, o.PR.Head, o.PR.Base)
	if err != nil {
		return selected, "", err
	}
	match, err := lookupVerdict(o.Lookup, o, selected, digest, p)
	if err != nil {
		return selected, "", err
	}
	if match.State != "intact" || !contains(p.ReviewerSenders, match.Sender) || match.Sender == o.Producer.Sender {
		return selected, "", rejected("reviewer_identity_or_integrity")
	}
	if err := verdictBody(match.Body, p, o.PR); err != nil {
		return selected, "", err
	}
	return selected, digest, nil
}

func lookupVerdict(lookup Lookup, o Observation, review PlatformReview, digest string, p Policy) (Event, error) {
	var match Event
	if lookup.WindowStart != review.SubmittedAt-86400 || lookup.WindowEnd != review.SubmittedAt+300 || lookup.ObservedAt != o.ObservedAt {
		return match, rejected("lookup_window")
	}
	if len(lookup.Scopes) != len(p.Scopes) {
		return match, unavailable("lookup_scope_coverage")
	}
	scopes := make(map[string]bool)
	type identity struct{ scope, event string }
	seen := make(map[identity]Event)
	pages, events, bodyBytes, matches := 0, 0, 0, 0
	for _, scope := range lookup.Scopes {
		if scope.Origin != p.MatrixOrigin || !contains(p.Scopes, scope.Scope) || scopes[scope.Scope] {
			return match, rejected("lookup_scope_binding")
		}
		scopes[scope.Scope] = true
		if scope.Coverage != Complete || !lowerHex(scope.FrontierSHA256, 64) || scope.Pages < 1 {
			return match, unavailable("lookup_frontier_coverage")
		}
		if scope.Pages > MaxPages-pages || len(scope.Events) > MaxEvents-events {
			return match, unavailable("lookup_capacity")
		}
		pages += scope.Pages
		events += len(scope.Events)
		for _, event := range scope.Events {
			if len(event.Body) > MaxBodyBytes-bodyBytes {
				return match, unavailable("lookup_capacity")
			}
			bodyBytes += len(event.Body)
			if !text(event.ID, 512) || !text(event.Sender, 255) || !utf8.ValidString(event.Body) || event.ServerAt < lookup.WindowStart || event.ServerAt > lookup.WindowEnd || event.ServerAt > lookup.ObservedAt {
				return match, unavailable("lookup_event")
			}
			id := identity{scope.Scope, event.ID}
			if previous, exists := seen[id]; exists {
				if previous != event {
					return match, unavailable("lookup_event_integrity")
				}
				continue
			}
			seen[id] = event
			// Hash the exact JSON-decoded UTF-8 body, without trim, newline,
			// normalization or rendering. Count ALL digest matches before
			// deciding whether the unique event's sender is independent.
			if bodyHash(event.Body) == digest {
				matches++
				match = event
			}
		}
	}
	if matches != 1 {
		return match, rejected("lookup_uniqueness")
	}
	return match, nil
}
