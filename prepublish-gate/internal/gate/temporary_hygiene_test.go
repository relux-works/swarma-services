package gate

import "testing"

// Slash-delimited tmp segments match at any depth; adjacent spellings stay neutral.
func TestTemporarySegmentHygieneNeighbors(t *testing.T) {
	p := policy{exceptions: map[string]bool{}}
	for _, sample := range []struct {
		name, text string
		hits       int
	}{
		{"temporary-root", "/" + "tmp/build-2024/out", 1},
		{"relative-project", "./" + "tmp/run-2", 1},
		{"nested-project", "src/" + "tmp/cache-3/x", 1},
		{"absolute-project", "/srv/app/" + "tmp/out-9", 1},
		{"url-path", "https://example.test/" + "tmp/item-7/", 1},
		{"no-leading-slash", "tmp/build-2024", 0},
		{"no-separator", "/" + "tmp/build2024", 0},
		{"digit-suffix", "/" + "tmp/build-2024x", 0},
		{"uppercase", "/TMP/build-1", 0},
		{"different-segment", "/mytmp/build-1", 0},
		{"underscore", "/" + "tmp/build_2024", 0},
	} {
		t.Run(sample.name, func(t *testing.T) {
			r := Report{}
			if p.match("line", []byte(sample.text), &r) != nil ||
				r != (Report{HygieneHits: sample.hits}) {
				t.Fatal("temporary segment classification")
			}
		})
	}
}
