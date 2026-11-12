package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/types"
)

func certPortsObs(t *testing.T, host string, services string) types.StoredObservation {
	t.Helper()
	raw := `{"host":"` + host + `","ip":"127.0.0.1","services":` + services + `}`
	return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: json.RawMessage(raw), ObservedAt: time.Now()}}
}

// A TLS service whose certificate is expired, self-signed or not for the
// name asked is a lead with the command that shows the certificate again; a
// service whose certificate has none of these is not listed.
func TestCertificateLeads(t *testing.T) {
	obs := []types.StoredObservation{certPortsObs(t, "a.test", `[
	  {"port":443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_before":"2020-01-01T00:00:00Z","not_after":"2021-01-01T00:00:00Z","expired":true}},
	  {"port":8443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=a","not_before":"2026-01-01T00:00:00Z","not_after":"2030-01-01T00:00:00Z","self_signed":true,"name_mismatch":true,"asked":"a.test","sans":["b.test"]}},
	  {"port":993,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_before":"2026-01-01T00:00:00Z","not_after":"2030-01-01T00:00:00Z","asked":"a.test"}},
	  {"port":22,"service":"ssh"}]`)}
	set := buildFindings(&graphView{obs: obs})
	if len(set.Leads) != 2 || len(set.Findings) != 0 || len(set.Identifications) != 0 {
		t.Fatalf("%d findings, %d identifications, %d leads: %+v", len(set.Findings), len(set.Identifications), len(set.Leads), set.Leads)
	}
	byPort := map[int]findingRecord{}
	for _, l := range set.Leads {
		byPort[l.Port] = l
	}
	if l := byPort[443]; l.Tier != "lead" || l.Kind != "tls-certificate" || l.Host != "a.test" || !strings.Contains(l.Evidence, "expired (not after 2021-01-01T00:00:00Z)") ||
		strings.Contains(l.Evidence, "self-signed") || !strings.Contains(l.Check, "openssl s_client -connect a.test:443 -servername a.test") {
		t.Errorf("443: %+v", l)
	}
	if l := byPort[8443]; !strings.Contains(l.Evidence, "self-signed") || !strings.Contains(l.Evidence, "not for the name asked, a.test (names: b.test") || strings.Contains(l.Evidence, "expired") {
		t.Errorf("8443: %+v", l)
	}
}

// Of a service scanned twice, the newest scan stands: a certificate renewed
// since is no lead.
func TestCertificateLeadOfTheNewestScan(t *testing.T) {
	old := certPortsObs(t, "a.test", `[{"port":443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_after":"2021-01-01T00:00:00Z","expired":true}}]`)
	old.ObservedAt = time.Now().Add(-time.Hour)
	renewed := certPortsObs(t, "a.test", `[{"port":443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_after":"2030-01-01T00:00:00Z"}}]`)
	if got := certLeads([]types.StoredObservation{renewed, old}, ""); len(got) != 0 {
		t.Errorf("a renewed certificate is a lead: %+v", got)
	}
	if got := certLeads([]types.StoredObservation{old, renewed}, ""); len(got) != 0 {
		t.Errorf("a renewed certificate is a lead: %+v", got)
	}
}

// ports gives each TLS service the facts of its certificate in the row, from
// the handshake it made, and report -findings lists the lead.
func TestPortsReadsTheCertificateAndReportsALead(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	db := filepath.Join(t.TempDir(), "w.db")
	// localhost is not a name of httptest's certificate, which is self-signed.
	out, _, _ := cli(t, "ports", "-host", "localhost", "-p", port, "-db", db, "-json", "-ledger", "off")
	var row struct {
		TLS         bool `json:"tls"`
		Certificate struct {
			Subject, Issuer string
			NotBefore       string   `json:"not_before"`
			NotAfter        string   `json:"not_after"`
			SANs            []string `json:"sans"`
			SelfSigned      bool     `json:"self_signed"`
			Expired         bool     `json:"expired"`
			Mismatch        bool     `json:"name_mismatch"`
			Asked           string   `json:"asked"`
		} `json:"certificate"`
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"port":`+port) {
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := row.Certificate
	if !row.TLS || c.Subject == "" || c.NotAfter == "" || len(c.SANs) == 0 || c.NotBefore == "" || !c.SelfSigned || c.Expired || !c.Mismatch || c.Asked != "localhost" {
		t.Fatalf("row: %s\n%+v", out, row)
	}
	csv, _, _ := cli(t, "ports", "-host", "localhost", "-p", port, "-csv", "-ledger", "off")
	if head, _, _ := strings.Cut(csv, "\n"); !strings.Contains(head, "subject_cn") || strings.Contains(head, "certificate") {
		t.Errorf("the CSV header has a column for the certificate object: %s", head)
	}
	rep, _, _ := cli(t, "report", "-db", db, "-findings", "-format", "jsonl")
	_, _, leads := parseTiers(t, []byte(rep))
	found := false
	for _, l := range leads {
		found = found || l["kind"] == "tls-certificate" && strings.Contains(l["evidence"].(string), "not for the name asked, localhost")
	}
	if !found {
		t.Errorf("no tls-certificate lead in:\n%s", rep)
	}
}

// run gives a TLS service of its port scan the same facts and the same lead.
func TestRunReadsTheCertificateOfAPortItScans(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	db := filepath.Join(t.TempDir(), "n.db")
	cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", "off", "-db", db, "-ports", port, "-quiet", "-json")
	rep, _, _ := cli(t, "report", "-db", db, "-findings", "-format", "jsonl")
	_, _, leads := parseTiers(t, []byte(rep))
	found := false
	for _, l := range leads {
		found = found || l["kind"] == "tls-certificate" && strings.Contains(l["evidence"].(string), "self-signed") && l["port"] == float64(srv.Listener.Addr().(*net.TCPAddr).Port)
	}
	if !found {
		t.Errorf("no tls-certificate lead for port %s in:\n%s", port, rep)
	}
}
