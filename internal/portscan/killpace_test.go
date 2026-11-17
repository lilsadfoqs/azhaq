package portscan

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A kill file met while a connect waits for the pace ends the scan with the
// kill, as one met at the count of the connect does: a scan that returned
// nothing of the ports it never asked read as finished.
func TestKillFileWhileWaitingForThePaceStopsTheScan(t *testing.T) {
	egress.Reset()
	defer egress.Reset()
	egress.SetRate(1e6)
	kill := filepath.Join(t.TempDir(), "run.stop")
	defer egress.SetKill(kill)()
	var takes atomic.Int32
	s := &Scanner{Detect: DetectNone, Workers: 1, Take: func() error {
		if takes.Add(1) == 10 {
			_ = os.WriteFile(kill, nil, 0o644)
		}
		return nil
	}}
	ports := make([]int, 200)
	for i := range ports {
		ports[i] = 41000 + i
	}
	r, err := s.ScanEachFn(t.Context(), "", "127.0.0.1", ports, nil)
	if !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("the scan ended with %v, want the kill file", err)
	}
	if r.Asked >= len(ports) {
		t.Errorf("%d of %d ports asked after the kill file", r.Asked, len(ports))
	}
}

// The same for the UDP ports of an address: their stop is reported, with
// what was left to ask.
func TestKillFileWhileWaitingForThePaceStopsTheUDPScan(t *testing.T) {
	egress.Reset()
	defer egress.Reset()
	egress.SetRate(1e6)
	kill := filepath.Join(t.TempDir(), "run.stop")
	defer egress.SetKill(kill)()
	var takes atomic.Int32
	s := &Scanner{Workers: 1, Timeout: 50e6, Take: func() error {
		if takes.Add(1) == 5 {
			_ = os.WriteFile(kill, nil, 0o644)
		}
		return nil
	}}
	ports := make([]int, 50)
	for i := range ports {
		ports[i] = 41000 + i
	}
	r, err := s.ScanUDP(t.Context(), "", "127.0.0.1", ports)
	if !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("the UDP scan ended with %v, want the kill file", err)
	}
	if len(r.Stopped) == 0 {
		t.Error("the stopped scan names no port it left unasked")
	}
}
