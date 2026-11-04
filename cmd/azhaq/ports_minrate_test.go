package main

import (
	"testing"
	"time"
)

// -min-rate only raises the pace: 1,500 loopback ports at -min-rate 500 take as
// long as without it (well under the 3 s a pace of 500 would take).
func TestPortsMinRateNeverLowersThePace(t *testing.T) {
	t0 := time.Now()
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", "1-1500", "-detect", "none", "-min-rate", "500", "-allow", "127.0.0.1", "-json")
	if code != exitOK {
		t.Fatalf("exit %d:\n%s", code, errOut)
	}
	if took := time.Since(t0); took > 2*time.Second {
		t.Errorf("1500 loopback ports at -min-rate 500 took %v: the pace was set to 500, not raised from the default", took)
	}
}
