package main

import "testing"

// With -allow naming one host, no row of the run names the host's parent
// domain: it is outside the scope.
func TestAllowOfAHostStoresNoRowForItsParentDomain(t *testing.T) {
	port := portsServer(t)
	zone := serveZone(t, fakeZone{a: map[string]string{"www.example.test": "127.0.0.1"}})
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, "run", "-list", hostsFile(t, "www.example.test"), "-ports", port,
		"-resolvers", zone, "-allow", "www.example.test", "-allow", "127.0.0.1", "-sources", "none", "-skip", "http,tls,paths", "-db", "d.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	for _, r := range jsonRows(t, out) {
		if r["type"] == "Domain" {
			t.Errorf("a Domain row outside the scope: %v", r)
		}
	}
	q, _, _ := runContract(t, "query", "-db", "d.db", "-type", "Domain", "-fields", "key")
	if n := len(lines(q)); n != 0 {
		t.Errorf("the workspace holds %d Domain rows:\n%s", n, q)
	}
}

// A scope that holds the domain (-allow example.test: the domain and its
// subdomains) keeps its row.
func TestAllowOfTheDomainKeepsItsRow(t *testing.T) {
	port := portsServer(t)
	zone := serveZone(t, fakeZone{a: map[string]string{"www.example.test": "127.0.0.1"}})
	t.Chdir(t.TempDir())
	if _, rep, code := runContract(t, "run", "-list", hostsFile(t, "www.example.test"), "-ports", port,
		"-resolvers", zone, "-allow", "example.test", "-allow", "127.0.0.1", "-sources", "none", "-skip", "http,tls,paths", "-db", "d.db"); code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	q, _, _ := runContract(t, "query", "-db", "d.db", "-type", "Domain", "-fields", "key")
	if got := lines(q); len(got) != 1 || got[0] != `{"key":"example.test"}` {
		t.Errorf("Domain rows: %v", got)
	}
}
