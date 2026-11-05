// Package lifecycletest provides finite subprocess fixtures for lifecycle tests.
// It is imported only by tests.
package lifecycletest

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Limit bounds fixture setup and failure cleanup; it is not a command timeout.
const Limit = 5 * time.Second

// Child runs only in a selected subprocess of the calling test binary.
func Child() {
	for i, arg := range os.Args {
		if arg != "--lifecycle-child" || i+1 >= len(os.Args) {
			continue
		}
		root := os.Args[i+1]
		deadline := time.Now().Add(Limit)
		write := func(name, value string) {
			if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
				os.Exit(97)
			}
		}
		wait := func(name string) {
			for {
				if _, err := os.Stat(filepath.Join(root, name)); err == nil {
					return
				}
				if time.Now().After(deadline) {
					os.Exit(98)
				}
				time.Sleep(time.Millisecond)
			}
		}
		write("started", strconv.Itoa(os.Getpid()))
		wait("release")
		fmt.Print("before")
		write("ready", "ready")
		wait("finish")
		os.Exit(0)
	}
}

func Argv(t *testing.T, root string) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{exe, "-test.run=^TestLifecycleChild$", "--", "--lifecycle-child", root}
}

func Release(t *testing.T, root, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
		t.Fatal(err)
	}
}

func WaitFile(t *testing.T, root, name string) {
	t.Helper()
	deadline := time.Now().Add(Limit)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("child did not publish %s", name)
}

func Await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(Limit):
		t.Fatalf("did not observe %s", what)
	}
}

// Kill is a failure backstop for this fixture only. The fixture never changes
// the process group established by capture.Run and also expires on its own.
func Kill(root string) {
	b, err := os.ReadFile(filepath.Join(root, "started"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(string(b))
	if err == nil && pid > 1 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}
