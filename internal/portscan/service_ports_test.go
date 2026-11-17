package portscan_test

import (
	"slices"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
	_ "github.com/lilsadfoqs/azhaq/internal/verify" // registers the catalogs' ports
)

// The size of the first pass: the top 1000, the protocols and names the scan
// knows, and the ports of the verify catalogs. A change here is a change to
// docs/commands (ports, run, plan) and docs/claims.tsv.
func TestDefaultSizeWithTheCatalogs(t *testing.T) {
	if got, want := len(portscan.DefaultPorts()), 1075; got != want {
		t.Errorf("the first pass has %d ports, want %d", got, want)
	}
	if got, want := len(portscan.UsualPorts()), 205; got != want {
		t.Errorf("the usual set has %d ports, want %d", got, want)
	}
}

// A broker's console and wire port, a queue manager's console and a graph
// database's HTTP API: the ports a default scan once left out (#608).
func TestDefaultAsksTheConsolePortsOfTheLoginCatalog(t *testing.T) {
	def := portscan.DefaultPorts()
	for q, name := range map[int]string{8161: "activemq", 61616: "activemq", 15672: "rabbitmq", 7474: "neo4j"} {
		if !slices.Contains(def, q) {
			t.Errorf("default lacks %d (%s)", q, name)
		}
		if got := portscan.ServiceName(q); got == "" {
			t.Errorf("%d has no name", q)
		}
	}
}
