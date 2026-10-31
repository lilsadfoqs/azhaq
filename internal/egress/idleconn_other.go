//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package egress

import "net"

// connDead is not known on this system: the transport's own watch is all
// there is.
func connDead(net.Conn) bool { return false }
