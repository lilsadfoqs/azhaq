package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ingestFixture loads one fixture into db and returns the summary's counts.
func ingestFixture(t *testing.T, db, fixture string) map[string]int {
	t.Helper()
	_, errOut, err := captureBoth(t, func() error {
		return cmdIngest([]string{filepath.Join("..", "..", "fixtures", fixture), "-db", db, "-json"})
	})
	if err != nil {
		t.Fatalf("ingest %s: %v", fixture, err)
	}
	rep := lastReport(t, errOut)
	if len(rep.Notes) > 0 {
		t.Errorf("ingest %s noted %v", fixture, rep.Notes)
	}
	return rep.Counts
}

func rowsOf(t *testing.T, db string, args ...string) map[string]map[string]any {
	t.Helper()
	out, _, code := runContract(t, append([]string{"query", "-db", db}, args...)...)
	if code != exitOK {
		t.Fatalf("query %v exit %d", args, code)
	}
	rows := map[string]map[string]any{}
	for _, r := range jsonRows(t, out) {
		rows[r["key"].(string)] = r
	}
	return rows
}

func from(r map[string]any) []string {
	var out []string
	for _, v := range r["evidence_from"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

// arjun's JSON: the names it found on each page, as a params run's are, from
// arjun and never visited.
func TestIngestReadsArjun(t *testing.T) {
	db := filepath.Join(t.TempDir(), "a.db")
	if c := ingestFixture(t, db, "arjun.json"); c["arjun"] != 2 {
		t.Errorf("counts %v", c)
	}
	rows := rowsOf(t, db, "-type", "URL")
	search, login := rows["http://app.test/search"], rows["http://app.test/api/login"]
	if search == nil || login == nil {
		t.Fatalf("rows %v", rows)
	}
	if got := search["params"]; strings.Join(strs(got), ",") != "debug,q" && strings.Join(strs(got), ",") != "q,debug" {
		t.Errorf("GET names: %v", got)
	}
	if got := strings.Join(strs(login["body"]), ","); got != "pass,user" && got != "user,pass" {
		t.Errorf("JSON names are body fields: %v", login)
	}
	if !slices.Contains(strs(login["methods"]), "POST") {
		t.Errorf("a JSON body is a POST: %v", login)
	}
	for u, r := range rows {
		if r["coverage"] == "visited" {
			t.Errorf("%s is visited: azhaq asked nothing", u)
		}
		if !slices.Contains(from(r), "arjun") || !strings.Contains(r["proof"].(string), "via=arjun") {
			t.Errorf("%s does not say it came from arjun: %v", u, r)
		}
	}
}

// gowitness's JSON lines: the page it loaded and what it saw, a hint of the
// URL with the tool named.
func TestIngestReadsGowitness(t *testing.T) {
	db := filepath.Join(t.TempDir(), "g.db")
	if c := ingestFixture(t, db, "gowitness.jsonl"); c["gowitness"] != 2 {
		t.Errorf("counts %v", c)
	}
	rows := rowsOf(t, db, "-type", "URL")
	if len(rows) != 2 {
		t.Fatalf("rows %v", rows)
	}
	for u, r := range rows {
		if r["coverage"] != "hint" {
			t.Errorf("%s coverage %v, want hint: gowitness asked, azhaq did not", u, r["coverage"])
		}
		if !slices.Contains(from(r), "gowitness") || !strings.Contains(r["proof"].(string), "via=gowitness") {
			t.Errorf("%s does not say it came from gowitness: %v", u, r)
		}
	}
	if p := rows["http://app.test/"]["proof"].(string); !strings.Contains(p, "status=200") || !strings.Contains(p, "title=Shop") {
		t.Errorf("what gowitness saw is not kept on the row: %s", p)
	}
	if p := rows["http://down.test/"]["proof"].(string); !strings.Contains(p, "ERR_CONNECTION_REFUSED") {
		t.Errorf("the failure is not kept: %s", p)
	}
}

// asnmap's JSON: the AS and its prefixes, not a request of azhaq's.
func TestIngestReadsAsnmap(t *testing.T) {
	db := filepath.Join(t.TempDir(), "s.db")
	if c := ingestFixture(t, db, "asnmap.jsonl"); c["asnmap"] != 1 {
		t.Errorf("counts %v", c)
	}
	rows := rowsOf(t, db)
	as := rows["AS13335"]
	if as == nil || !strings.Contains(as["proof"].(string), "via=asnmap") || !strings.Contains(as["proof"].(string), "count=2") {
		t.Errorf("AS row: %v", as)
	}
	for _, p := range []string{"104.16.0.0/13", "1.0.0.0/24"} {
		if rows[p] == nil || rows[p]["type"] != "Prefix" {
			t.Errorf("no Prefix row %s in %v", p, rows)
		}
	}
}

// nmap's XML: the open ports with the service, product and version nmap read,
// the script output kept on the port, and the tool named; a closed or filtered
// port is no service.
func TestIngestReadsNmap(t *testing.T) {
	db := filepath.Join(t.TempDir(), "n.db")
	if c := ingestFixture(t, db, "nmap.xml"); c["nmap"] != 3 {
		t.Errorf("counts %v, want the 3 ports that answered open (22, 443, udp 161)", c)
	}
	rows := rowsOf(t, db, "-type", "Port")
	if len(rows) != 3 {
		t.Fatalf("port rows %v", rows)
	}
	ssh := rows["192.0.2.7:22/tcp"]
	if ssh == nil || ssh["service"] != "ssh" || ssh["product"] != "OpenSSH" || ssh["version"] != "8.9p1" || ssh["state"] != "open" {
		t.Errorf("ssh row: %v", ssh)
	}
	web := rows["192.0.2.7:443/tcp"]
	if web == nil || web["product"] != "nginx" {
		t.Fatalf("https row: %v", web)
	}
	proof := web["proof"].(string)
	for _, want := range []string{"via=nmap", `script:http-title="Shop - Home"`, `script:ssl-cert="Subject: commonName=web.app.test"`, "tls=true"} {
		if !strings.Contains(proof, want) {
			t.Errorf("https proof lacks %q: %s", want, proof)
		}
	}
	if snmp := rows["192.0.2.7:161/udp"]; snmp == nil || snmp["state"] != "open|filtered" || !strings.Contains(snmp["proof"].(string), "via=nmap") {
		t.Errorf("udp row: %v", snmp)
	}
	if strings.Contains(proof, "claim") || strings.Contains(proof, "proven") || strings.Contains(proof, "verified") {
		t.Errorf("an nmap line claims proof: %s", proof)
	}
	names := rowsOf(t, db, "-type", "Hostname")
	if names["web.app.test"] == nil || names["ptr.app.test"] == nil {
		t.Errorf("the host's names are not kept: %v", names)
	}
	if ports := rows["192.0.2.7:443/tcp"]["names"]; !slices.Equal(strs(ports), []string{"ptr.app.test", "web.app.test"}) {
		t.Errorf("names on the port row: %v", ports)
	}
	// Evidence, not a finding.
	var found strings.Builder
	if err := exportAs(db, "findings", "", &found); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(found.String(), `"findings":0`) {
		t.Errorf("nmap's output made findings: %s", found.String())
	}
	// A host nmap found down gives no row.
	if all := rowsOf(t, db); all["192.0.2.8"] != nil {
		t.Errorf("a host that was down is a row: %v", all["192.0.2.8"])
	}
}

// A file that is XML and not nmap's, or a JSON document of no tool, is said so
// rather than read as something else.
func TestIngestRefusesWhatItDoesNotRead(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"x.xml": "<?xml version=\"1.0\"?><nessus/>", "x.json": "{\n \"a\": 1\n}"} {
		in := writeFile(t, dir, name, body)
		if err := run([]string{"ingest", in, "-db", filepath.Join(dir, "d.db")}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
