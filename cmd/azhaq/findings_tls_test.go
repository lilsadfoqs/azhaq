package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/tlstest"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

func certPortsObs(t *testing.T, host string, services string) types.StoredObservation {
	t.Helper()
	raw := `{"host":"` + host + `","ip":"127.0.0.1","services":` + services + `}`
	return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: json.RawMessage(raw), ObservedAt: time.Now()}}
}

func certHTTPObs(url, cert string) types.StoredObservation {
	return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-http", Kind: "application",
		Payload: json.RawMessage(`{"url":"` + url + `","status":200,"certificate":` + cert + `}`), ObservedAt: time.Now()}}
}

// A TLS service whose certificate is expired, self-signed or not for the
// name asked is a measured finding, from a port row and from an HTTP row;
// a certificate with none of these is not listed.
func TestCertificateFindingsOfRows(t *testing.T) {
	obs := []types.StoredObservation{certPortsObs(t, "a.test", `[
	  {"port":443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_before":"2020-01-01T00:00:00Z","not_after":"2021-01-01T00:00:00Z","expired":true,"asked":"a.test"}},
	  {"port":8443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=a","not_before":"2026-01-01T00:00:00Z","not_after":"2030-01-01T00:00:00Z","self_signed":true,"name_mismatch":true,"asked":"a.test","sans":["b.test"]}},
	  {"port":993,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_before":"2026-01-01T00:00:00Z","not_after":"2030-01-01T00:00:00Z","asked":"a.test"}},
	  {"port":22,"service":"ssh"}]`),
		certHTTPObs("https://panel.test:10000/login", `{"subject":"CN=p","issuer":"CN=p","not_before":"2026-01-01T00:00:00Z","not_after":"2030-01-01T00:00:00Z","self_signed":true,"asked":"panel.test"}`),
		certHTTPObs("http://plain.test/", `{"subject":"CN=p","issuer":"CN=p","not_after":"2020-01-01T00:00:00Z","expired":true}`),
	}
	set := buildFindings(&graphView{obs: obs})
	if len(set.Findings) != 3 || len(set.Leads) != 0 || len(set.Identifications) != 0 {
		t.Fatalf("%d findings, %d identifications, %d leads: %+v", len(set.Findings), len(set.Identifications), len(set.Leads), set.Findings)
	}
	by := map[string]findingRecord{}
	for _, f := range set.Findings {
		by[f.Host+":"+strconv.Itoa(f.Port)] = f
	}
	f := by["a.test:443"]
	if f.Tier != "finding" || f.Kind != "tls-certificate" || f.Label != "observed-certificate" || f.Severity != "low" || f.Collector != "azhaq-ports" ||
		!strings.Contains(f.Evidence, "expired (not after 2021-01-01T00:00:00Z)") || strings.Contains(f.Evidence, "self-signed") ||
		!f.Proof.Complete() || f.Proof.ExcerptPart != "certificate" ||
		f.Proof.Reproduce != "openssl s_client -connect a.test:443 -servername 'a.test' </dev/null | openssl x509 -noout -subject -issuer -dates" {
		t.Errorf("443: %+v %+v", f, f.Proof)
	}
	if f := by["a.test:8443"]; !strings.Contains(f.Evidence, "self-signed") || !strings.Contains(f.Evidence, "not for the name asked, a.test (names: b.test") || strings.Contains(f.Evidence, "expired") {
		t.Errorf("8443: %+v", f)
	}
	if f := by["panel.test:10000"]; f.Collector != "azhaq-http" || !strings.Contains(f.Evidence, "self-signed") || f.Proof.How != "azhaq-http" {
		t.Errorf("an https URL's own handshake: %+v", f)
	}
	if _, ok := by["a.test:993"]; ok {
		t.Error("a certificate with no fact to state is listed")
	}
}

// Of a service seen twice, the newest row stands: a certificate renewed
// since is no finding.
func TestCertificateFindingOfTheNewestRow(t *testing.T) {
	old := certPortsObs(t, "a.test", `[{"port":443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_after":"2021-01-01T00:00:00Z","expired":true}}]`)
	old.ObservedAt = time.Now().Add(-time.Hour)
	renewed := certPortsObs(t, "a.test", `[{"port":443,"tls":true,"certificate":{"subject":"CN=a","issuer":"CN=CA","not_after":"2030-01-01T00:00:00Z"}}]`)
	if got := certRecords([]types.StoredObservation{renewed, old}, ""); len(got) != 0 {
		t.Errorf("a renewed certificate is a finding: %+v", got)
	}
	if got := certRecords([]types.StoredObservation{old, renewed}, ""); len(got) != 0 {
		t.Errorf("a renewed certificate is a finding: %+v", got)
	}
}

// certServer serves 200 over TLS with cert, counting the requests it reads.
func certServer(t *testing.T, cert tls.Certificate) (port string, requests *atomic.Int32) {
	t.Helper()
	requests = new(atomic.Int32)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port), requests
}

// certFindings are the tls-certificate findings of a workspace, by port, from
// report -findings, and the hunt rows of the same kind.
func certFindings(t *testing.T, db string) (map[string]map[string]any, map[string]map[string]any) {
	t.Helper()
	rep, _, _ := cli(t, "report", "-db", db, "-findings", "-format", "jsonl")
	f, _, leads := parseTiers(t, []byte(rep))
	for _, l := range leads {
		if l["kind"] == "tls-certificate" {
			t.Errorf("a certificate is a lead: %v", l)
		}
	}
	found := map[string]map[string]any{}
	for _, r := range f {
		if r["kind"] == "tls-certificate" {
			found[strconv.Itoa(int(r["port"].(float64)))] = r
		}
	}
	hout, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json", "-limit", "1000"}) })
	if err != nil {
		t.Fatal(err)
	}
	hunted := map[string]map[string]any{}
	for _, r := range jsonLines(t, hout) {
		if rs, _ := r["reasons"].([]any); len(rs) > 0 && rs[0].(map[string]any)["signal"] == "tls-certificate" {
			hunted[r["key"].(string)] = r
		}
	}
	return found, hunted
}

// ports gives each TLS service the facts of its certificate in the row, from
// the handshake it made; report -findings lists a finding for an expired
// self-signed certificate and for one not for the name asked, none for a
// valid one, with the openssl line that shows it, and hunt lists the same.
func TestPortsCertificateFacts(t *testing.T) {
	now := time.Now()
	expired, _ := certServer(t, tlstest.SelfSigned(t, now.Add(-72*time.Hour), now.Add(-24*time.Hour), "localhost")) // expired yesterday
	mismatch, _ := certServer(t, tlstest.CASigned(t, now.Add(-time.Hour), now.Add(24*time.Hour), "other.test"))
	valid, _ := certServer(t, tlstest.CASigned(t, now.Add(-time.Hour), now.Add(24*time.Hour), "localhost"))
	db := filepath.Join(t.TempDir(), "w.db")
	rows := map[string]struct {
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
	}{}
	out, _, _ := cli(t, "ports", "-host", "localhost", "-p", expired+","+mismatch+","+valid, "-db", db, "-json", "-ledger", "off")
	for _, line := range strings.Split(out, "\n") {
		var row struct {
			Port int `json:"port"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || row.Port == 0 {
			continue
		}
		r := rows[strconv.Itoa(row.Port)]
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows[strconv.Itoa(row.Port)] = r
	}
	if c := rows[expired].Certificate; !c.Expired || !c.SelfSigned || c.Mismatch || c.Subject != "CN=self" || c.Issuer != "CN=self" || c.NotBefore == "" || c.NotAfter == "" || c.Asked != "localhost" || len(c.SANs) != 1 {
		t.Errorf("expired: %+v", c)
	}
	if c := rows[mismatch].Certificate; c.Expired || c.SelfSigned || !c.Mismatch || c.Issuer != "CN=Test CA" || c.SANs[0] != "other.test" {
		t.Errorf("mismatch: %+v", c)
	}
	if c := rows[valid].Certificate; c.Expired || c.SelfSigned || c.Mismatch || c.Subject != "CN=leaf" || c.Issuer != "CN=Test CA" {
		t.Errorf("valid: %+v", c)
	}
	found, hunted := certFindings(t, db)
	if len(found) != 2 || found[valid] != nil || len(hunted) != 2 {
		t.Fatalf("findings %v, hunt rows %v: want the expired and the mismatched one only", found, hunted)
	}
	f := found[expired]
	if f["tier"] != "finding" || f["severity"] != "low" || f["label"] != "observed-certificate" || f["excerpt_part"] != "certificate" || f["host"] != "localhost" ||
		!strings.Contains(f["evidence"].(string), "expired (not after ") || !strings.Contains(f["evidence"].(string), "self-signed") ||
		f["reproduce"] != "openssl s_client -connect localhost:"+expired+" -servername 'localhost' </dev/null | openssl x509 -noout -subject -issuer -dates" {
		t.Errorf("expired finding: %v", f)
	}
	if ev := found[mismatch]["evidence"].(string); !strings.Contains(ev, "not for the name asked, localhost (names: other.test") || strings.Contains(ev, "expired") || strings.Contains(ev, "self-signed") {
		t.Errorf("mismatch finding: %s", ev)
	}
	// hunt and report agree: the same services, the same evidence, the same line.
	for p, r := range found {
		h := hunted["localhost:"+p]
		if h == nil || h["tier"] != "finding" || h["next"] != r["reproduce"] || h["reasons"].([]any)[0].(map[string]any)["detail"] != r["evidence"] {
			t.Errorf("hunt row of %s: %v, report: %v", p, h, r)
		}
	}
}

// run reads the certificate from the HTTP answer's own handshake: the row
// has its facts and the findings hold the record, with no request of the
// run's besides those its ledger records.
func TestRunHTTPRowHasTheCertificate(t *testing.T) {
	now := time.Now()
	port, requests := certServer(t, tlstest.SelfSigned(t, now.Add(-72*time.Hour), now.Add(-24*time.Hour), "localhost"))
	dir := t.TempDir()
	db, led := filepath.Join(dir, "r.db"), filepath.Join(dir, "r.jsonl")
	cli(t, "run", "-url", "https://localhost:"+port+"/", "-allow", "localhost", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-quiet", "-json", "-db", db, "-ledger", led)
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	var row struct {
		Certificate struct {
			Subject, Issuer string
			Expired         bool   `json:"expired"`
			SelfSigned      bool   `json:"self_signed"`
			Mismatch        bool   `json:"name_mismatch"`
			Asked           string `json:"asked"`
		} `json:"certificate"`
	}
	have := false
	for _, o := range obs {
		if o.Collector == "azhaq-http" && strings.Contains(string(o.Payload), `"certificate"`) {
			have = true
			_ = json.Unmarshal(o.Payload, &row)
		}
	}
	if c := row.Certificate; !have || !c.Expired || !c.SelfSigned || c.Mismatch || c.Asked != "localhost" || c.Subject != "CN=self" {
		t.Fatalf("the http row's certificate: %+v (found %v)", row, have)
	}
	sent := 0
	if err := ledger.Read(led, func(e ledger.Entry) error {
		if e.Kind == "http" && strings.Contains(e.Target, ":"+port+"/") {
			sent++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := int(requests.Load()); got != sent || got == 0 {
		t.Errorf("the server read %d requests, the ledger holds %d: reading the certificate added none", got, sent)
	}
	found, hunted := certFindings(t, db)
	if f := found[port]; f == nil || f["collector"] != "azhaq-http" || len(hunted) != 1 {
		t.Errorf("findings %v, hunt rows %v", found, hunted)
	}
}

// run gives a TLS service of its port scan the same facts and the same finding.
func TestRunReadsTheCertificateOfAPortItScans(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	db := filepath.Join(t.TempDir(), "n.db")
	cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", "off", "-db", db, "-ports", port, "-quiet", "-json")
	found, _ := certFindings(t, db)
	if f := found[port]; f == nil || !strings.Contains(f["evidence"].(string), "self-signed") {
		t.Errorf("no tls-certificate finding for port %s: %v", port, found)
	}
}
