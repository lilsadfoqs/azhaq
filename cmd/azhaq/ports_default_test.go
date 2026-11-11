package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// The default scan asks the top 1000 and the usual ports of the services azhaq
// names and checks on every address, then every other port of each address that
// answered. The plan counts the first pass of each address, and the second of
// an address given alone; a service on a port of the catalog (here Redis, 6379)
// turns up in the first pass.
func TestPortsDefaultSetIsAskedAndCounted(t *testing.T) {
	first := portscan.DefaultPorts()
	plan := func(cidr string) map[string]any {
		return planCost(t, "-cidr", cidr, "-ports", "default", "-allow", cidr, "-sources", "none")["ports"]
	}
	if got := stageAmount(plan("127.0.0.0/30"), "estimate", "connects"); got != float64(4*len(first)) {
		t.Errorf("the plan counts %v connects for -ports default on 4 addresses, want %d", got, 4*len(first))
	}
	if got := stageAmount(plan("127.0.0.1/32"), "estimate", "connects"); got != 65535 {
		t.Errorf("the plan counts %v connects for -ports default on one address, want 65535: both passes", got)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:6379")
	if err != nil {
		t.Skipf("no 127.0.0.1:6379: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("-NOAUTH Authentication required.\r\n"))
			c.Close()
		}
	}()
	out, errOut, _ := cli(t, "ports", "-host", "127.0.0.1", "-json")
	if !strings.Contains(out, `"port":6379`) {
		t.Errorf("a default scan does not find the service on 6379:\n%s", out)
	}
	sum := sumMap(t, errOut)
	st := stagesOf(t, sum)["ports"]
	if got := stageAmount(st, "actual", "connects"); got < 65535 {
		t.Errorf("the scan made %v connects: an address that answered is asked every port", got)
	}
	if got := stageAmount(st, "estimate", "connects"); got != 65535 {
		t.Errorf("the scan estimated %v connects, want 65535 for one address given alone", got)
	}
	// The docs say how many ports the first pass is.
	doc, err := os.ReadFile("../../docs/commands/ports.md")
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.Itoa(len(first)) + " ports"; !strings.Contains(string(doc), want) {
		t.Errorf("docs/commands/ports.md does not say the first pass is %s", want)
	}
}
