package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// The default set of ports is the top 100 and the usual ports of the services
// azhaq names and checks: ports with no -p asks all of it, and the plan counts
// them; a service on a port of the catalog (here Redis, 6379) turns up with no
// wider scan.
func TestPortsDefaultSetIsAskedAndCounted(t *testing.T) {
	def := portscan.DefaultPorts()
	if st := planCost(t, "-cidr", "127.0.0.1/32", "-ports", "default", "-allow", "127.0.0.1", "-sources", "none")["ports"]; stageAmount(st, "estimate", "connects") != float64(len(def)) {
		t.Errorf("the plan counts %v connects for -ports default, want %d", st, len(def))
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
	if got := stageAmount(st, "actual", "connects"); got < float64(len(def)) {
		t.Errorf("the scan made %v connects, the default set has %d ports", got, len(def))
	}
	if got := stageAmount(st, "estimate", "connects"); got != float64(len(def)) {
		t.Errorf("the scan estimated %v connects, the default set has %d ports", got, len(def))
	}
	// The docs say how many ports it is.
	doc, err := os.ReadFile("../../docs/commands/ports.md")
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.Itoa(len(def)) + " ports"; !strings.Contains(string(doc), want) {
		t.Errorf("docs/commands/ports.md does not say the default set is %s", want)
	}
}
