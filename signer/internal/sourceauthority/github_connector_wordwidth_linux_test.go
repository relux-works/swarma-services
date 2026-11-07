//go:build linux

package sourceauthority

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Real nonblocking sockets exercise both word boundaries and the kernel fd_set
// capacity. No parallel tests or accept goroutine may consume the reserved fd.
func TestOwnedNumericFDSetBoundaries(t *testing.T) {
	listener, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(listener)
	if err = syscall.Bind(listener, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Listen(listener, 8); err != nil {
		t.Fatal(err)
	}
	address, err := syscall.Getsockname(listener)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(address.(*syscall.SockaddrInet4).Port)
	drain := func() {
		for {
			fd, _, e := syscall.Accept4(listener, syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
			if e != nil {
				return
			}
			syscall.Close(fd)
		}
	}
	dial := func(p uint16) error {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		c, e := ownedNumericDial(ctx, netip.MustParseAddr("127.0.0.1"), p)
		if c != nil {
			c.Close()
		}
		return e
	}
	if err = dial(port); err != nil {
		t.Fatal("paired low-fd control", err)
	}
	drain()
	// Obtain a closed local port for a real connection-refused neighbor.
	refused, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Bind(refused, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		syscall.Close(refused)
		t.Fatal(err)
	}
	closedAddress, err := syscall.Getsockname(refused)
	syscall.Close(refused)
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(closedAddress.(*syscall.SockaddrInet4).Port)
	count := func() int {
		e, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(e)
	}
	before := count()
	var set syscall.FdSet
	wordBits := int(8 * unsafe.Sizeof(set.Bits[0]))
	capacity := len(set.Bits) * wordBits
	t.Logf("GOARCH=%s wordBits=%d capacity=%d low-fd=PASS", runtime.GOARCH, wordBits, capacity)
	for _, fd := range []int{31, 32, 41, 63, 64, capacity - 1, capacity, capacity + 1} {
		t.Run(fmt.Sprintf("fd%d", fd), func(t *testing.T) {
			var fillers []int
			defer func() {
				for _, f := range fillers {
					syscall.Close(f)
				}
			}()
			for {
				f, e := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
				if e != nil {
					t.Fatal(e)
				}
				if f >= fd {
					syscall.Close(f)
					if f != fd {
						t.Fatalf("wanted fd %d, first free %d", fd, f)
					}
					break
				}
				fillers = append(fillers, f)
			}
			check := func(e error, want string) {
				t.Helper()
				if want == "" {
					if e != nil {
						t.Fatal(e)
					}
					return
				}
				r, ok := e.(*Refusal)
				if !ok || r.Predicate() != want {
					t.Fatalf("wanted %s, got %v", want, e)
				}
			}
			want := ""
			refusedWant := "acquisition_dial"
			if fd >= capacity {
				want = "acquisition_dial_capacity"
				refusedWant = want
			}
			check(dial(port), want)
			drain()
			check(dial(closedPort), refusedWant)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			cancel()
			c, e := ownedNumericDial(ctx, netip.MustParseAddr("127.0.0.1"), port)
			if c != nil {
				c.Close()
				t.Fatal("pre-canceled connection")
			}
			check(e, "acquisition_dial")
		})
	}
	drain()
	after := count()
	if before != after {
		t.Fatalf("descriptor cleanup %d -> %d", before, after)
	}
	t.Logf("descriptor cleanup %d -> %d", before, after)
}
