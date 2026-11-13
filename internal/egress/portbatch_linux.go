//go:build linux

package egress

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// issue admits the batches that begin their connects. connect(2) on a
// loopback address does the whole handshake in the caller, and the same
// work on every core at once costs several times the CPU of a few cores:
// the kernel's lock for the ports of a connect and the sockets' table are
// shared. A batch that has begun its connects waits for them without a slot.
var issue = make(chan struct{}, issueWidth)

// issueWidth is how many batches begin their connects at once: more did not
// shorten a full range of loopback and cost more CPU.
const issueWidth = 4

// errRefused is what each refused connect of a batch says; it holds no
// address, as the error each carried before held none.
var errRefused error = &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}

// CanBatch says TCPBatch can connect to ip: the scan's connects go direct
// (not through a proxy) and ip is a plain address.
func (d *PortDialer) CanBatch(ip string) bool {
	if d.via != nil || d.socks != "" {
		return false
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Zone() == ""
}

// TCPBatch connects to each of ports of ip at once, on non-blocking sockets
// that one poll waits on, instead of a goroutine and a netpoller entry for
// each: a full-range scan spends most of its CPU on that. Each connect passes
// what TCP asks (kill file, scope, one ledger line as it begins, a refund when it never did) and ends as TCP's would: done is
// called once for each port, from this goroutine, with the open connection or
// the error (a refusal wraps ECONNREFUSED, a timeout is a net.Error that says
// so) and how long the connect took.
func (d *PortDialer) TCPBatch(ctx context.Context, host, ip string, ports []int, done func(i int, c net.Conn, rtt time.Duration, err error)) {
	// What a connection is then written is listed in the ledger, probe by probe.
	opened := done
	done = func(i int, c net.Conn, rtt time.Duration, err error) {
		if err == nil && c != nil {
			c = ledger.WrapProbes(ctx, ledger.ClassTarget, host, net.JoinHostPort(ip, itoa(ports[i])), false, c)
		}
		opened(i, c, rtt, err)
	}
	ap, _ := netip.ParseAddr(ip)
	ap = ap.Unmap()
	family := syscall.AF_INET
	if ap.Is6() {
		family = syscall.AF_INET6
	}
	var local syscall.Sockaddr
	if d.src != nil {
		if t := net.IP(ap.AsSlice()); (t.To4() == nil) == (d.src.To4() == nil) {
			local = sockaddr(netip.AddrFrom16([16]byte(d.src.To16())).Unmap(), 0)
		}
	}
	type pending struct {
		i, fd int
		at    time.Time
	}
	var wait []pending
	var fds []unix.PollFd
	fail := func(i int, op string, err error) {
		if err == syscall.ECONNREFUSED && op == "connect" {
			done(i, nil, 0, errRefused) // the answer of nearly every port of a range
			return
		}
		done(i, nil, 0, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError(op, err)})
	}
	issue <- struct{}{} // few batches at once begin their connects
	issued := false
	endIssue := func() {
		if !issued {
			issued = true
			<-issue
		}
	}
	defer endIssue()
	addrs := make([]string, len(ports))
	for i, port := range ports {
		addrs[i] = net.JoinHostPort(ip, itoa(port))
	}
	var gotBuf [64]bool
	got := gotBuf[:0]
	if len(ports) <= len(gotBuf) {
		got = gotBuf[:len(ports)]
	} else {
		got = make([]bool, len(ports))
	}
	d.takeReservedMany(addrs, got)
	for i, port := range ports {
		addr, reserved := addrs[i], got[i]
		// As a dial of TCP's: Reserve wrote the line of a reserved connect, and a
		// stop since then waits until its connect has begun; any other connect is
		// held to the kill file, the scope and ctx, makes its line as it begins,
		// and one that never begun is given back to the budget the caller counted.
		if !reserved {
			if err := d.allowed(host, addr); err != nil {
				Refund()
				done(i, nil, 0, err)
				continue
			}
			if err := ctx.Err(); err != nil {
				Refund()
				done(i, nil, 0, err)
				continue
			}
		}
		fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			Refund()
			fail(i, "socket", err)
			continue
		}
		if local != nil {
			if err := syscall.Bind(fd, local); err != nil {
				syscall.Close(fd)
				Refund()
				fail(i, "bind", err)
				continue
			}
		}
		if !reserved {
			ledger.TCP(ctx, host, addr) // the socket is about to connect(2)
		}
		at := time.Now()
		switch err := syscall.Connect(fd, sockaddr(ap, port)); err {
		case nil:
			d.opened(fd, time.Since(at), i, done)
		case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
			wait = append(wait, pending{i, fd, at})
			fds = append(fds, unix.PollFd{Fd: int32(fd), Events: unix.POLLOUT})
		default:
			syscall.Close(fd)
			fail(i, "connect", err)
		}
	}
	endIssue()
	// ctx ending wakes the poll through an eventfd of this batch's own.
	var wake int = -1
	if len(wait) > 0 && ctx.Done() != nil {
		if fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC); err == nil {
			wake = fd
			defer syscall.Close(wake)
			stop := context.AfterFunc(ctx, func() {
				var one = [8]byte{1}
				_, _ = syscall.Write(wake, one[:])
			})
			defer stop()
			fds = append(fds, unix.PollFd{Fd: int32(wake), Events: unix.POLLIN})
		}
	}
	// Every connect of a batch is given the dialer's timeout from its own start.
	for len(wait) > 0 {
		ms := -1
		if d.timeout > 0 {
			rest := time.Until(wait[0].at.Add(d.timeout))
			ms = int((rest + time.Millisecond - 1) / time.Millisecond)
			ms = max(ms, 0)
		}
		n, err := unix.Poll(fds, ms)
		if err != nil && err != syscall.EINTR {
			for _, w := range wait {
				syscall.Close(w.fd)
				fail(w.i, "poll", err)
			}
			return
		}
		if wake >= 0 && fds[len(fds)-1].Revents != 0 {
			for _, w := range wait {
				syscall.Close(w.fd)
				done(w.i, nil, 0, ctx.Err())
			}
			return
		}
		keep := wait[:0]
		kfds := fds[:0]
		now := time.Now()
		for j, w := range wait {
			f := fds[j]
			switch {
			case n > 0 && f.Revents != 0:
				e, gerr := syscall.GetsockoptInt(w.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
				switch {
				case gerr != nil:
					syscall.Close(w.fd)
					fail(w.i, "getsockopt", gerr)
				case e != 0:
					syscall.Close(w.fd)
					fail(w.i, "connect", syscall.Errno(e))
				default:
					d.opened(w.fd, now.Sub(w.at), w.i, done)
				}
			case d.timeout > 0 && now.Sub(w.at) >= d.timeout:
				syscall.Close(w.fd)
				done(w.i, nil, 0, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded})
			default:
				keep = append(keep, w)
				kfds = append(kfds, unix.PollFd{Fd: int32(w.fd), Events: unix.POLLOUT})
			}
		}
		wait = keep
		if wake >= 0 {
			kfds = append(kfds, unix.PollFd{Fd: int32(wake), Events: unix.POLLIN})
		}
		fds = kfds
	}
}

// opened makes the net.Conn of a connected socket (FileConn dups it, so the
// socket is closed after).
func (d *PortDialer) opened(fd int, rtt time.Duration, i int, done func(int, net.Conn, time.Duration, error)) {
	f := os.NewFile(uintptr(fd), "tcp")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		done(i, nil, 0, err)
		return
	}
	done(i, c, rtt, nil)
}

func sockaddr(a netip.Addr, port int) syscall.Sockaddr {
	if a.Is4() {
		return &syscall.SockaddrInet4{Port: port, Addr: a.As4()}
	}
	return &syscall.SockaddrInet6{Port: port, Addr: a.As16()}
}

func itoa(n int) string {
	var b [8]byte
	i := len(b)
	for n >= 10 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	i--
	b[i] = byte('0' + n)
	return string(b[i:])
}
