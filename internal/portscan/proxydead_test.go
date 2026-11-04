package portscan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// A proxy that cannot be reached ends the scan with its error, and its
// connects are not a host answering: no port is closed and no address is up.
func TestDeadProxyStopsTheScanAndCallsNothingUp(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	newScanner := func() *Scanner { return &Scanner{Proxy: dead, Detect: DetectBanner, Timeout: time.Second} }

	var pe *egress.ProxyError
	r, err := newScanner().ScanEach(context.Background(), "", "127.0.0.1", []int{22, 80, 443})
	if !errors.As(err, &pe) || len(r.Open) != 0 {
		t.Fatalf("scan: %v, %d open", err, len(r.Open))
	}
	up, err := newScanner().Up(context.Background(), "", "127.0.0.1")
	if up || !errors.As(err, &pe) {
		t.Fatalf("up: %v, %v", up, err)
	}
}
