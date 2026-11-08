package gate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// All names and formats in this file are neutral synthetic policy examples.
func TestConfiguredPrivateProvenanceAndNeighbors(t *testing.T) {
	f := newFixture(t)
	write(t, f.patterns, []byte("R:^(crew_[a-z]+|machine-[a-z]+|ticket-[0-9]{4})$\n"))
	p, err := loadPolicy(f.patterns, "")
	if err != nil {
		t.Fatal("synthetic policy refused")
	}
	for _, kind := range []string{"line", "path", "message", "header"} {
		for _, value := range []string{"crew_example", "machine-example", "ticket-1234"} {
			var r Report
			if p.match(kind, []byte(value), &r) != nil || r.PrivateHits != 1 || r.HygieneHits != 0 {
				t.Fatal("configured private provenance missed or misclassified")
			}
			var generic Report
			if (policy{}).match(kind, []byte(value), &generic) != nil || generic.PrivateHits != 0 || generic.HygieneHits != 0 {
				t.Fatal("installation policy has a public fallback")
			}
		}
	}
	for _, value := range []string{"crew_Example", "machine-123", "ticket-12345", "ordinary text"} {
		var r Report
		if p.match("line", []byte(value), &r) != nil || r.PrivateHits != 0 || r.HygieneHits != 0 {
			t.Fatal("private policy benign neighbor misclassified")
		}
	}
}

func TestPrivatePolicyCLICountsOnly(t *testing.T) {
	f := newFixture(t)
	const marker = "crew_synthetic"
	const expression = "^crew_[a-z]+$"
	write(t, filepath.Join(f.repo, "data.txt"), []byte("base\n"+marker+"\n"))
	f.candidate = f.commit("synthetic provenance", true)
	for _, kind := range []string{"hit", "neighbor", "broad-false-positive", "missing", "omitted", "invalid", "empty", "mode", "symlink", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			write(t, f.patterns, []byte("R:"+expression+"\n"))
			if os.Chmod(f.patterns, 0600) != nil {
				t.Fatal("chmod")
			}
			c := f.config()
			wantCode, wantHits, wantScan, wantArgs, wantCompleted := 1, 0, 0, 0, 0
			switch kind {
			case "hit":
				wantHits, wantCompleted = 1, 1
			case "neighbor":
				write(t, f.patterns, []byte("R:^crew_[0-9]+$\n"))
				wantCode, wantCompleted = 0, 1
			case "broad-false-positive":
				// An overbroad operator policy remains a reported private hit, even when
				// the operator intended this ordinary synthetic content to be public.
				write(t, f.patterns, []byte("L:crew\n"))
				wantHits, wantCompleted = 1, 1
			case "missing":
				c.Patterns += "-missing"
				wantScan = 1
			case "omitted":
				c.Patterns = ""
				wantCode, wantArgs = 2, 1
			case "invalid":
				write(t, f.patterns, []byte("R:["+marker+"\n"))
				wantScan = 1
			case "empty":
				write(t, f.patterns, nil)
				wantScan = 1
			case "mode":
				if os.Chmod(f.patterns, 0644) != nil {
					t.Fatal("chmod")
				}
				wantScan = 1
			case "symlink":
				c.Patterns = filepath.Join(f.dir, "policy-link")
				if os.Symlink(f.patterns, c.Patterns) != nil {
					t.Fatal("symlink")
				}
				wantScan = 1
			case "oversize":
				write(t, f.patterns, []byte(strings.Repeat("L:synthetic\n", MaxControl)))
				wantScan = 1
			}
			var out bytes.Buffer
			code := Run([]string{"check", "--objects", c.Objects, "--base", c.Base, "--candidate", c.Candidate,
				"--patterns", c.Patterns, "--allowed-signers", c.Signers, "--principal", c.Principal}, &out)
			var r Report
			if json.Unmarshal(out.Bytes(), &r) != nil {
				t.Fatal("invalid JSON")
			}
			require(t, code == wantCode && r.PrivateHits == wantHits && r.HygieneHits == 0 &&
				r.ScanErrors == wantScan && r.ArgumentErrors == wantArgs && r.Completed == wantCompleted, r, code)
			var counts map[string]int
			if json.Unmarshal(out.Bytes(), &counts) != nil {
				t.Fatal("non-numeric diagnostic")
			}
			for _, forbidden := range []string{marker, expression, "crew", "synthetic", c.Objects, f.patterns, "policy-link"} {
				if strings.Contains(out.String(), forbidden) {
					t.Fatal("private diagnostic leaked")
				}
			}
		})
	}
}
