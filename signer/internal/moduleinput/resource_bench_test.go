package moduleinput

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Explicit single-operation resource qualification, never an ordinary test or
// timing assertion. Generation and validation are outside measurement. The
// distinct case has 8192 paths, 476 components/path, and 3883010 actual ancestors.
// Every path is valid for the collision checker; absent root go.mod deliberately
// triggers Layout only after collision indexing. This is not a verified module.
// Run one heavy fixture at a time under an external RSS and wall-time guard.
func BenchmarkCollisionResource(b *testing.B) {
	for _, distinct := range []bool{false, true} {
		name := "shared"
		depth := 256
		if distinct {
			name, depth = "distinct", 472
		}
		b.Run(name, func(b *testing.B) {
			prefix := "m/" + strings.Repeat("0", 64) + "/"
			paths := make([]string, MaxFiles)
			files := make([]File, MaxFiles)
			pathBytes, components := 0, 0
			for i := range paths {
				rel := fmt.Sprintf("%sf%04d.txt", strings.Repeat("a/", depth), i)
				if distinct {
					rel = fmt.Sprintf("d%04d/%sf.txt", i, strings.Repeat("a/", depth))
				}
				paths[i] = prefix + rel
				files[i] = File{rel, "100644", nil}
				if !validPath(paths[i]) {
					b.Fatal("invalid resource fixture")
				}
				pathBytes += len(paths[i])
				components += strings.Count(paths[i], "/") + 1
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				seen := resourceChecker()
				for _, p := range paths {
					if !seen.check(p) {
						b.Fatal("valid deep path refused")
					}
				}
				indexElapsed := time.Since(start)
				nodes, segments := resourceCardinalities(&seen)
				var invalid *InvalidError
				if err := material(Record{}, files); !errors.As(err, &invalid) || invalid.Reason != Layout {
					b.Fatalf("wrong terminal refusal: %v", err)
				}
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc), "measured-allocated-B/op")
				b.ReportMetric(float64(after.Mallocs-before.Mallocs), "measured-mallocs/op")
				b.ReportMetric(float64(indexElapsed.Nanoseconds()), "index-ns/op")
				b.ReportMetric(float64(nodes), "ancestors/op")
				b.ReportMetric(float64(segments), "segments/op")
				b.ReportMetric(float64(pathBytes), "input-path-B/op")
				b.ReportMetric(float64(components), "components/op")
				b.ReportMetric(float64(len(paths)), "files/op")
			}
		})
	}
}

func resourceChecker() collisionSet                    { return collisionSet{} }
func resourceCardinalities(c *collisionSet) (int, int) { return len(c.edges), len(c.segments) }
