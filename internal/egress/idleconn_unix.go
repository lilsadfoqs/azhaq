//go:build linux || darwin || freebsd || netbsd || openbsd

package egress

import (
	"crypto/tls"
	"net"
	"syscall"
)

// connDead says a connection waiting in the pool is one the other end has
// closed (or that sent something unasked, a TLS close_notify): a request
// written to it would never be read. The socket is peeked without reading
// from it, so the transport's own watch of it is not disturbed.
func connDead(c net.Conn) bool {
	if tc, ok := c.(*tls.Conn); ok {
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			return false // HTTP/2 reads its connection all the time
		}
		c = tc.NetConn()
	} else if lc, ok := c.(*legacyConn); ok {
		c = lc.NetConn()
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	dead := false
	_ = rc.Control(func(fd uintptr) {
		var b [1]byte
		_, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		dead = err != syscall.EAGAIN && err != syscall.EINTR
	})
	return dead
}
