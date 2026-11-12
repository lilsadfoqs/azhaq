package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// plan says the ledger's expected size: the connects it counts times what a
// connect writes, which is a floor as the connect count is.
func TestPlanSaysTheLedgerSize(t *testing.T) {
	args := []string{"plan", "-cidr", "127.0.0.1/32", "-ports", "default", "-allow", "127.0.0.1/32", "-sources", "none"}
	out, _, _ := cli(t, args...)
	want := "ledger: about 22.9 MB for the 65,535 connects (about 350 bytes each; the requests, probes and queries add their own lines)"
	if !strings.Contains(out, want) {
		t.Errorf("plan does not say %q:\n%s", want, out)
	}
	js, _, _ := cli(t, append(args, "-json")...)
	var p struct {
		Estimate struct {
			LedgerBytes int64 `json:"ledger_bytes"`
		} `json:"estimate"`
	}
	if err := json.Unmarshal([]byte(js), &p); err != nil {
		t.Fatal(err)
	}
	if p.Estimate.LedgerBytes != 65535*ledger.BytesPerConnect {
		t.Errorf("ledger_bytes %d, want %d", p.Estimate.LedgerBytes, 65535*ledger.BytesPerConnect)
	}
	// The docs' example: a /24 on every port.
	var big struct {
		Estimate struct {
			LedgerBytes int64 `json:"ledger_bytes"`
		} `json:"estimate"`
	}
	bj, _, _ := cli(t, "plan", "-cidr", "127.0.0.0/24", "-ports", "1-65535", "-allow", "127.0.0.0/24", "-sources", "none", "-json")
	if err := json.Unmarshal([]byte(bj), &big); err != nil {
		t.Fatal(err)
	}
	if got := big.Estimate.LedgerBytes; got < 5_800_000_000 || got > 5_900_000_000 {
		t.Errorf("a /24 on every port is %d ledger bytes, the docs say about 5.9 GB", got)
	}
	// A plan with no connect has no ledger line of its own.
	none, _, _ := cli(t, "plan", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1", "-sources", "none")
	if strings.Contains(none, "ledger: about") {
		t.Errorf("a plan with no connects estimates the ledger:\n%s", none)
	}
}
