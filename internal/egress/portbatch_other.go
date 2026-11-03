//go:build !linux

package egress

import (
	"context"
	"net"
	"time"
)

// CanBatch is false off Linux: each connect is its own dial.
func (d *PortDialer) CanBatch(string) bool { return false }

// TCPBatch is never called when CanBatch is false.
func (d *PortDialer) TCPBatch(context.Context, string, string, []int, func(int, net.Conn, time.Duration, error)) {
}
