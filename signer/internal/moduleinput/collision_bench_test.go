package moduleinput

import (
	"fmt"
	"strings"
	"testing"
)

// BenchmarkCollisionSharedAncestors measures only collision indexing for a fixed
// in-bounds path set, including fresh operation state. It excludes snapshot and
// checksum work; timings are evidence, never an admission threshold.
func BenchmarkCollisionSharedAncestors(b *testing.B) {
	prefix := "m/" + strings.Repeat("0", 64) + "/" + strings.Repeat("a/", 256)
	paths := make([]string, MaxFiles)
	for i := range paths[:MaxFiles-1] {
		paths[i] = fmt.Sprintf("%sf%04d.txt", prefix, i)
	}
	paths[MaxFiles-1] = "m/" + strings.Repeat("0", 64) + "/go.mod"
	for _, p := range paths {
		if !validPath(p) {
			b.Fatal("invalid benchmark path")
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seen := collisionSet{folded: make(map[string]node), exact: make(map[string]bool)}
		for _, p := range paths {
			if !seen.check(p) {
				b.Fatal("valid shared ancestor refused")
			}
		}
	}
}
