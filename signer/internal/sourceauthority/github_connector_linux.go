//go:build linux

package sourceauthority

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// ownedGitHubConnector dials one previously qualified numeric destination.
// No DNS, resolver singleflight, racing dial, retry or background worker runs.
// A custodian must issue a current canonical-address capability: there is no
// public numeric-pin constructor and no discovery/readiness claim here.
// TLS above this connector still authenticates api.github.com with public roots.
type ownedGitHubConnector struct{ address netip.Addr }

func (c ownedGitHubConnector) connect(ctx context.Context, host, port string) (net.Conn, error) {
	if host != "api.github.com" || port != "443" || !c.address.IsValid() || !c.address.IsGlobalUnicast() || c.address.IsPrivate() {
		return nil, unavailable("github_connector_pin")
	}
	return ownedNumericDial(ctx, c.address, 443)
}

// ownedNumericDial owns the nonblocking socket and checks cancellation in the
// calling goroutine. Select uses slices bounded by the ORIGINAL deadline. There
// is no context callback or Go DialContext worker to join, even on errors.
// FileConn only duplicates an already-connected descriptor into the Go poller;
// neither it nor this function starts resolution or connection work.
func ownedNumericDial(ctx context.Context, address netip.Addr, port uint16) (net.Conn, error) {
	if ctx == nil || acquisitionExpired(ctx) || !address.IsValid() || address.Zone() != "" || port == 0 {
		return nil, unavailable("acquisition_dial")
	}
	deadline, _ := ctx.Deadline()
	if time.Until(deadline) > AuthorityBudget {
		return nil, unavailable("authority_budget")
	}
	family := syscall.AF_INET
	var target syscall.Sockaddr
	if address.Is4() {
		target = &syscall.SockaddrInet4{Port: int(port), Addr: address.As4()}
	} else {
		family = syscall.AF_INET6
		target = &syscall.SockaddrInet6{Port: int(port), Addr: address.As16()}
	}
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, unavailable("acquisition_dial")
	}
	defer func() {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}()
	err = syscall.Connect(fd, target)
	if err != nil && err != syscall.EINPROGRESS {
		return nil, unavailable("acquisition_dial")
	}
	for err != nil {
		if acquisitionExpired(ctx) {
			return nil, unavailable("acquisition_canceled")
		}
		var ready syscall.FdSet
		// FdSet words are int32 on some Linux targets (including 386).
		// Bound and index the actual representation before shifting.
		const wordBits = int(8 * unsafe.Sizeof(ready.Bits[0]))
		if fd < 0 || fd >= len(ready.Bits)*wordBits {
			return nil, unavailable("acquisition_dial_capacity")
		}
		ready.Bits[fd/wordBits] |= 1 << uint(fd%wordBits)
		wait := min(5*time.Millisecond, time.Until(deadline))
		if wait <= 0 {
			return nil, unavailable("acquisition_canceled")
		}
		tv := syscall.NsecToTimeval(wait.Nanoseconds())
		n, e := syscall.Select(fd+1, nil, &ready, nil, &tv)
		if e == syscall.EINTR {
			continue
		}
		if e != nil {
			return nil, unavailable("acquisition_dial")
		}
		if n == 0 {
			continue
		}
		status, e := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if e != nil || status != 0 {
			return nil, unavailable("acquisition_dial")
		}
		err = nil
	}
	if acquisitionExpired(ctx) {
		return nil, unavailable("acquisition_canceled")
	}
	f := os.NewFile(uintptr(fd), "owned-connection")
	if f == nil {
		return nil, unavailable("acquisition_dial")
	}
	fd = -1
	conn, e := net.FileConn(f)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, unavailable("acquisition_dial")
	}
	if acquisitionExpired(ctx) {
		_ = conn.Close()
		return nil, unavailable("acquisition_canceled")
	}
	return conn, nil
}
