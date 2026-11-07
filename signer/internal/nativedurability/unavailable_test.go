//go:build !darwin || !cgo

package nativedurability

import (
	"errors"
	"os"
	"testing"
)

func TestUnavailableNeverSubstitutesLocalFSync(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := New(f, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(nativeFullSync(f), ErrUnavailable) {
		t.Fatal("platform fallback")
	}
}
