package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-services/signer/internal/nativedurability"
	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

func fixtureFactory(*os.File, uint64) (signingaudit.Durability, error) {
	return signingaudit.LocalFSync{}, nil
}

func TestRunnerControlMatrixWithLocalIO(t *testing.T) {
	for _, control := range controls {
		t.Run(control, func(t *testing.T) {
			root := t.TempDir()
			r := runCase(root, 1, control, fixtureFactory)
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(encoded))
			if !r.ControlVerified {
				t.Fatalf("control failed: %+v", r)
			}
			if r.Profile != (signingaudit.LocalFSync{}).Name() {
				t.Fatal("fixture mislabeled native")
			}
			if r.Fixture == "" || !strings.HasPrefix(r.Fixture, "durability-") {
				t.Fatal("missing retained fixture")
			}
			entries, err := os.ReadDir(filepath.Join(root, r.Fixture))
			if err != nil || len(entries) != 1 {
				t.Fatalf("audit pruned or cleanup failed: %v %v", entries, err)
			}
			// Closing after every control must release the actual journal lock.
			p := &observedProfile{base: signingaudit.LocalFSync{}, result: &result{}, stage: "open"}
			e := &syntheticEffects{profile: p, result: &result{}}
			a, err := signingaudit.Open(filepath.Join(root, r.Fixture), signingaudit.Options{Durability: p, MaxBytes: 1 << 20}, e, e, e)
			if err != nil {
				t.Fatalf("cleanup/replay: %v", err)
			}
			if err = a.Close(); err != nil {
				t.Fatal(err)
			}
			if control == "intent-error" || control == "intent-omit" || control == "outcome-error" || control == "outcome-omit" || strings.HasPrefix(control, "open-") || control == "directory-omit" || control == "unsupported" {
				found := false
				for _, event := range r.Events {
					if event.Error != "" {
						found = true
						if event.Attempted || event.Completed {
							t.Fatal("injected/omitted operation reported as completed native call")
						}
					}
				}
				if !found || r.Error == "" {
					t.Fatal("refusal erased")
				}
			}
		})
	}
}

func TestRunnerRefusesBeforeFixtureCreation(t *testing.T) {
	for _, refusal := range []error{nativedurability.ErrUnavailable, nativedurability.ErrVolume, os.ErrPermission} {
		root := t.TempDir()
		r := runCase(root, 1, "baseline", func(*os.File, uint64) (signingaudit.Durability, error) { return nil, refusal })
		if r.ControlVerified || r.Error == "" || r.Fixture != "" || r.Signs != 0 || r.Releases != 0 {
			t.Fatalf("bad refusal: %+v", r)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("refused profile changed target")
		}
	}
}

type failingProfile struct{ signingaudit.LocalFSync }

func (failingProfile) File(*os.File) error { return os.ErrPermission }

func TestNativeErrorAndOmissionCannotBeSuccess(t *testing.T) {
	r := runCase(t.TempDir(), 1, "baseline", func(*os.File, uint64) (signingaudit.Durability, error) { return failingProfile{}, nil })
	if r.ControlVerified || r.Signs != 0 || r.Releases != 0 || r.Error == "" {
		t.Fatalf("failure claimed success: %+v", r)
	}
	if len(r.Events) != 1 || !r.Events[0].Attempted || r.Events[0].Completed || r.Events[0].Error == "" {
		t.Fatal("lost actual failure event")
	}
	for _, bad := range []struct {
		root    string
		device  uint64
		control string
	}{{"relative", 1, "suite"}, {"/tmp/../tmp", 1, "suite"}, {"/tmp", 0, "baseline"}, {"/tmp", 1, ""}, {"/tmp", 1, "unknown"}} {
		if validConfig(bad.root, bad.device, bad.control) {
			t.Fatal("invalid explicit configuration accepted")
		}
	}
	if !errors.Is(expectedError("intent-error"), signingaudit.ErrAudit) {
		t.Fatal("bad test expectation")
	}
}

type closingOutcomeProfile struct {
	signingaudit.LocalFSync
	files int
}

func (p *closingOutcomeProfile) File(f *os.File) error {
	p.files++
	if p.files == 5 {
		return f.Close()
	}
	return f.Sync()
}

func TestInjectedCloseFailureCannotHideActualCloseFailure(t *testing.T) {
	r := runCase(t.TempDir(), 1, "close-error", func(*os.File, uint64) (signingaudit.Durability, error) { return &closingOutcomeProfile{}, nil })
	if r.ControlVerified || r.Error != "" || r.CleanupError == "" || len(r.Failures) != 2 {
		t.Fatalf("actual cleanup failure hidden: %+v", r)
	}
}
