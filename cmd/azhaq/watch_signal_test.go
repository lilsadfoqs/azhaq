package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// seenRow is one stored observation of an entity in a run.
type seenRow struct{ key, collector, payload string }

func webPage(url string) seenRow { return seenRow{url, "azhaq-http", `{"status":200,"title":"t"}`} }

// watchRuns stores each list as one run of a workspace and returns the
// change set of the last two, as watch computes it.
func watchRuns(t *testing.T, runs ...[]seenRow) changes {
	t.Helper()
	db := filepath.Join(t.TempDir(), "ws.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	for i, run := range runs {
		if err := st.BeginRun(fmt.Sprintf("run%d", i), 0, 0); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		for _, r := range run {
			typ := types.TypeHostname
			if strings.Contains(r.key, "://") {
				typ = types.TypeURL
			}
			e, err := st.UpsertEntity(typ, r.key, now)
			if err != nil {
				t.Fatal(err)
			}
			collector, kind, _ := strings.Cut(r.collector, "/") // "azhaq-paths/detected": a collector and the row's kind
			if kind == "" {
				kind = "x"
			}
			if _, err := st.AddObservation(e.ID, types.Observation{Collector: collector, Kind: kind, Payload: json.RawMessage(r.payload), ObservedAt: now}); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(2 * time.Millisecond) // runs are ordered by start time
	}
	st.Close()
	ch, err := diffRuns(db)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestWatchURLIdentity(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"http://h/js/m.php?lang=en&token=006be6", "http://h/js/m.php?token=ffee01&lang=de", true},
		{"http://h/list.php?sort=a&sortorder=ASC", "http://h/list.php?sort=b&sortorder=DESC", true},
		{"http://h/list.php?sort=a", "http://h/list.php?sort=a&page=2", false},
		{"http://h/static/384de1e8/images", "http://h/static/81869691/images", true},
		{"http://h/u/12/edit", "http://h/u/99/edit", true},
		{"http://h/o/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "http://h/o/6ba7b810-9dad-11d1-80b4-00c04fd430c8", true},
		{"http://h/api/orders/{id}", "http://h/api/orders/{orderId}", true},
		{"http://h/static/deadbeef/x", "http://h/static/cafebabe/x", false}, // hex with no digit is a word
		{"http://h/static/abc123/x", "http://h/static/def456/x", false},     // under 8 characters
		{"http://h/a", "http://h/b", false},
		{"http://h/a", "https://h/a", false},
		{"http://h:8080/a", "http://h:9090/a", false},
		{"http://h:80/a", "http://H/a", true},
		{"http://h/a#x", "http://h/a#y", true},
	} {
		if got := foldURL(c.a) == foldURL(c.b); got != c.same {
			t.Errorf("%s vs %s: same identity %v, want %v (%s | %s)", c.a, c.b, got, c.same, foldURL(c.a), foldURL(c.b))
		}
	}
}

// Static files with no stored role, a token or sort value, a build id in
// the path: a run with only these churn classes reports no change.
func TestWatchChurnIsNoChange(t *testing.T) {
	old := []seenRow{
		webPage("http://h:8080/"),
		webPage("http://h:8080/adjuncts/7490ae30/lib/form/link/link.js"),
		webPage("http://h:8080/adjuncts/7490ae30/style.css"),
		webPage("http://h:8080/adjuncts/7490ae30/logo.png"),
		webPage("http://h:8080/js/messages.php?lang=en&token=006be6aa"),
		webPage("http://h:8080/hostinventories.php?sort=pr_tag&sortorder=ASC"),
		webPage("http://h:8080/static/384de1e8/images"),
	}
	neu := []seenRow{
		webPage("http://h:8080/"),
		webPage("http://h:8080/adjuncts/c0ffee11/lib/form/link/link.js"),
		webPage("http://h:8080/adjuncts/c0ffee11/style.css"),
		webPage("http://h:8080/adjuncts/c0ffee11/logo.png"),
		webPage("http://h:8080/adjuncts/c0ffee11/font.woff2"),
		webPage("http://h:8080/js/messages.php?lang=en&token=99aa77bb"),
		webPage("http://h:8080/hostinventories.php?sort=pr_macaddress_a&sortorder=DESC"),
		webPage("http://h:8080/static/81869691/images"),
	}
	if ch := watchRuns(t, old, neu); ch.any() {
		t.Fatalf("churn reported: %+v", ch)
	}
	// And the other way: nothing is gone.
	if ch := watchRuns(t, neu, old); ch.any() {
		t.Fatalf("churn reported gone: %+v", ch)
	}
}

func TestWatchStaticFilesAreLeftOutByClassNotOnlyByRole(t *testing.T) {
	base := []seenRow{webPage("http://h/")}
	neu := append([]seenRow{}, base...)
	for _, f := range []string{"a.js", "b.mjs", "c.css", "d.png", "e.woff2", "f.js.map", "g.svg"} {
		neu = append(neu, webPage("http://h/assets/"+f))
	}
	if ch := watchRuns(t, base, neu); ch.any() {
		t.Fatalf("static files reported new: %+v", ch)
	}
	if ch := watchRuns(t, neu, base); ch.any() {
		t.Fatalf("static files reported gone: %+v", ch)
	}
}

func TestWatchNewQueryNameIsNewSurfaceAndOneLinePerIdentity(t *testing.T) {
	old := []seenRow{webPage("http://h/"), webPage("http://h/p?a=1")}
	neu := []seenRow{webPage("http://h/"), webPage("http://h/p?a=2"), webPage("http://h/p?a=2&b=3"), webPage("http://h/q?sort=x"), webPage("http://h/q?sort=y")}
	ch := watchRuns(t, old, neu)
	want := []string{"http://h/p?a=2&b=3", "http://h/q?sort=x"}
	if strings.Join(ch.URLs, "|") != strings.Join(want, "|") || len(ch.GoneURLs) != 0 {
		t.Fatalf("urls %q gone %q, want %q", ch.URLs, ch.GoneURLs, want)
	}
	// A path that disappears is gone, once per identity.
	ch = watchRuns(t, neu, old)
	if len(ch.URLs) != 0 || strings.Join(ch.GoneURLs, "|") != "http://h/p?a=2&b=3|http://h/q?sort=x" {
		t.Fatalf("urls %q gone %q", ch.URLs, ch.GoneURLs)
	}
}

func TestWatchNamesWhatAServiceIs(t *testing.T) {
	jup := seenRow{"http://h:8888/", "azhaq-http", `{"status":302,"title":"Home","tech":["Jupyter Notebook:6.0","Tornado"]}`}
	ch := watchRuns(t, []seenRow{webPage("http://h/")}, []seenRow{webPage("http://h/"), jup})
	if len(ch.Services) != 1 || ch.Services[0] != "http://h:8888/ [302] Home (Jupyter Notebook 6.0, Tornado)" {
		t.Fatalf("services %q", ch.Services)
	}
	// Nothing the run did not state: no tech, no suffix.
	plain := seenRow{"http://h:8889/", "azhaq-http", `{"status":200,"title":"Home"}`}
	if ch := watchRuns(t, []seenRow{webPage("http://h/")}, []seenRow{webPage("http://h/"), plain}); len(ch.Services) != 1 || ch.Services[0] != "http://h:8889/ [200] Home" {
		t.Fatalf("services %q", ch.Services)
	}
}

func resolvesTo(host, ips string) seenRow {
	return seenRow{host, "azhaq-dns", `{"fqdn":"` + host + `","ips":["` + ips + `"]}`}
}

func openPorts(host, open, services string) seenRow {
	return seenRow{host, "azhaq-ports", `{"host":"` + host + `","ip":"10.0.0.5","scanned":100,"open":[` + open + `],"services":[` + services + `]}`}
}

func TestWatchNewHostNamesItsServices(t *testing.T) {
	neu := []seenRow{
		resolvesTo("dns.example", "10.0.0.5"),
		openPorts("dns.example", "22,53,9999", `{"port":22,"service":"ssh"},{"port":53,"service":"domain","product":"BIND","version":"9.11"},{"port":9999}`),
	}
	ch := watchRuns(t, []seenRow{webPage("http://h/")}, neu)
	want := "dns.example (10.0.0.5): 22/tcp ssh, 53/tcp BIND 9.11, 9999/tcp"
	if len(ch.Hosts) != 1 || ch.Hosts[0] != want {
		t.Fatalf("hosts %q, want %q", ch.Hosts, want)
	}
	// A host with no scan says no more than before.
	ch = watchRuns(t, []seenRow{webPage("http://h/")}, []seenRow{resolvesTo("a.example", "10.0.0.6")})
	if len(ch.Hosts) != 1 || ch.Hosts[0] != "a.example (10.0.0.6)" {
		t.Fatalf("hosts %q", ch.Hosts)
	}
}

func TestWatchPortsNameWhatWasAddedAndRemoved(t *testing.T) {
	old := []seenRow{resolvesTo("soap.example", "10.0.0.5"), openPorts("soap.example", "22,8080", `{"port":22,"service":"ssh","product":"OpenSSH","version":"8.9"},{"port":8080,"service":"http","product":"nginx"}`)}
	neu := []seenRow{resolvesTo("soap.example", "10.0.0.5"), openPorts("soap.example", "22,9000,9100", `{"port":22,"service":"ssh","product":"OpenSSH","version":"8.9"},{"port":9000,"service":"fastcgi","product":"php-fpm"},{"port":9100}`)}
	ch := watchRuns(t, old, neu)
	want := "soap.example (10.0.0.5): +9000/tcp php-fpm, +9100/tcp, -8080/tcp (open: 22,9000,9100)"
	if len(ch.Ports) != 1 || ch.Ports[0] != want || len(ch.Changed) != 0 {
		t.Fatalf("ports %q changed %q, want %q", ch.Ports, ch.Changed, want)
	}
	// The same set in another order of services is no change.
	same := []seenRow{resolvesTo("soap.example", "10.0.0.5"), openPorts("soap.example", "8080,22", `{"port":8080,"service":"http","product":"nginx"},{"port":22,"service":"ssh","product":"OpenSSH","version":"8.9"}`)}
	if ch := watchRuns(t, old, same); ch.any() {
		t.Fatalf("%+v", ch)
	}
}

func TestWatchProductChangeNamesBeforeAndAfter(t *testing.T) {
	front := func(tech string) seenRow {
		return seenRow{"http://h/", "azhaq-http", `{"status":200,"title":"Home","url":"http://h/","tech":[` + tech + `]}`}
	}
	ch := watchRuns(t, []seenRow{front(`"nginx:1.18","jQuery:3.6"`)}, []seenRow{front(`"nginx:1.24","jQuery:3.6"`)})
	want := "http://h/: [200] Home (product: nginx 1.18 → nginx 1.24)"
	if len(ch.Changed) != 1 || ch.Changed[0] != want {
		t.Fatalf("changed %q, want %q", ch.Changed, want)
	}
	// Alongside a title change the product is named too.
	moved := seenRow{"http://h/", "azhaq-http", `{"status":403,"title":"Denied","url":"http://h/","tech":["nginx:1.24","jQuery:3.6"]}`}
	ch = watchRuns(t, []seenRow{front(`"nginx:1.18","jQuery:3.6"`)}, []seenRow{moved})
	if len(ch.Changed) != 1 || ch.Changed[0] != "http://h/: [200] Home → [403] Denied (product: nginx 1.18 → nginx 1.24)" {
		t.Fatalf("changed %q", ch.Changed)
	}
	// A run that read no technologies says nothing about them.
	if ch := watchRuns(t, []seenRow{front(`"nginx:1.18"`)}, []seenRow{front(``)}); ch.any() {
		t.Fatalf("%+v", ch)
	}
	if ch := watchRuns(t, []seenRow{front(`"nginx:1.18"`)}, []seenRow{front(`"nginx:1.18"`)}); ch.any() {
		t.Fatalf("%+v", ch)
	}
	// A port that stayed open with another product.
	old := []seenRow{resolvesTo("s.example", "10.0.0.5"), openPorts("s.example", "22", `{"port":22,"service":"ssh","product":"OpenSSH","version":"8.9"}`)}
	neu := []seenRow{resolvesTo("s.example", "10.0.0.5"), openPorts("s.example", "22", `{"port":22,"service":"ssh","product":"OpenSSH","version":"9.6"}`)}
	ch = watchRuns(t, old, neu)
	if len(ch.Changed) != 1 || ch.Changed[0] != "s.example (10.0.0.5): 22/tcp OpenSSH 8.9 → OpenSSH 9.6" || len(ch.Ports) != 0 {
		t.Fatalf("changed %q ports %q", ch.Changed, ch.Ports)
	}
}

func rangeRow(prefix string) seenRow {
	return seenRow{prefix, "azhaq-ports", `{"range":true,"prefix":"` + prefix + `","scanned":1000,"open":[]}`}
}

// addrRow is a ports row of one address as a range scan stores it: under the
// range, with the address for host.
func addrRow(prefix, ip, open, services string, partial bool) seenRow {
	return seenRow{prefix, "azhaq-ports", fmt.Sprintf(`{"host":%q,"ip":%q,"prefix":%q,"scanned":1000,"partial":%t,"open":[%s],"services":[%s]}`, ip, ip, prefix, partial, open, services)}
}

// Ports are compared per address, whichever seed scanned it (#493): the rows
// a range stores under itself are not merged into one line, an address the
// range finished with no row had nothing open, and a name's scan in one run
// meets the range's scan of its address in the other.
func TestWatchComparesPortsPerAddress(t *testing.T) {
	const pf = "10.0.0.0/29"
	httpd := `{"port":8080,"service":"http","product":"Apache httpd","version":"2.4.54"}`
	base := func() []seenRow {
		return []seenRow{rangeRow(pf), addrRow(pf, "10.0.0.2", "8080", httpd, false),
			addrRow(pf, "10.0.0.4", "8080", `{"port":8080,"service":"http","product":"BaseHTTP","version":"0.6"}`, false)}
	}
	// Two addresses with one port and two products: the same in another order is no change.
	rev := base()
	rev[1], rev[2] = rev[2], rev[1]
	if ch := watchRuns(t, base(), rev); ch.any() {
		t.Fatalf("%+v", ch)
	}
	// A new address of the range, named by a name that resolves to it.
	neu := append(base(), resolvesTo("files.example", "10.0.0.3"),
		addrRow(pf, "10.0.0.3", "445,6699", `{"port":445,"service":"smb","product":"Samba smbd"},{"port":6699,"service":"tcpwrapped"}`, false))
	ch := watchRuns(t, base(), neu)
	want := "files.example (10.0.0.3): +445/tcp Samba smbd, +6699/tcp tcpwrapped (open: 445,6699)"
	if len(ch.Ports) != 1 || ch.Ports[0] != want || len(ch.Changed) != 0 {
		t.Fatalf("ports %q changed %q, want %q", ch.Ports, ch.Changed, want)
	}
	// Scanned under its name in one run and by the range in the next: one address.
	byName := []seenRow{resolvesTo("app.example", "10.0.0.2"), openPorts2("app.example", "10.0.0.2", "8080", httpd)}
	moved := append(base()[:1], addrRow(pf, "10.0.0.2", "8080,9000", httpd+`,{"port":9000,"service":"fastcgi","product":"php-fpm"}`, false))
	ch = watchRuns(t, byName, moved)
	if len(ch.Ports) != 1 || ch.Ports[0] != "app.example (10.0.0.2): +9000/tcp php-fpm (open: 8080,9000)" {
		t.Fatalf("ports %q", ch.Ports)
	}
	// An address the new run finished the range without: its ports are gone.
	gone := []seenRow{rangeRow(pf), addrRow(pf, "10.0.0.2", "8080", httpd, false)}
	ch = watchRuns(t, base(), gone)
	if len(ch.Ports) != 1 || ch.Ports[0] != "10.0.0.4: -8080/tcp (open: none)" {
		t.Fatalf("ports %q", ch.Ports)
	}
}

// A scan a limit stopped saw part of the ports: what it did not reach is not
// gone, and what a stopped scan of the old run did not reach is not new.
func TestWatchStoppedScanSaysOnlyWhatItSaw(t *testing.T) {
	const pf = "10.0.0.0/29"
	full := []seenRow{rangeRow(pf), addrRow(pf, "10.0.0.2", "22,8080", "", false)}
	part := []seenRow{rangeRow(pf), addrRow(pf, "10.0.0.2", "22", "", true)}
	if ch := watchRuns(t, full, part); ch.any() {
		t.Fatalf("a stopped scan made ports gone: %+v", ch)
	}
	if ch := watchRuns(t, part, full); ch.any() {
		t.Fatalf("a stopped scan before made ports new: %+v", ch)
	}
	more := []seenRow{rangeRow(pf), addrRow(pf, "10.0.0.2", "22,8080,9000", "", true)}
	if ch := watchRuns(t, full, more); len(ch.Ports) != 1 || ch.Ports[0] != "10.0.0.2: +9000/tcp (open: 22,8080,9000)" {
		t.Fatalf("ports %q", ch.Ports)
	}
}

func openPorts2(host, ip, open, services string) seenRow {
	return seenRow{host, "azhaq-ports", `{"host":"` + host + `","ip":"` + ip + `","scanned":100,"open":[` + open + `],"services":[` + services + `]}`}
}

func pointsNowhere(host, target, extra string) seenRow {
	return seenRow{host, "azhaq-dns", `{"fqdn":"` + host + `","cname":"` + target + `","dangling":{"chain":["` + target + `"],"target":"` + target + `","rcode":"NXDOMAIN"}` + extra + `}`}
}

func TestWatchDanglingNamesAreReportedWhenNew(t *testing.T) {
	ok := []seenRow{webPage("http://h/")}
	// New name that points nowhere; one that already did is not repeated.
	old := append([]seenRow{pointsNowhere("old.example", "gone.cloudhost.example", "")}, ok...)
	neu := append([]seenRow{
		pointsNowhere("old.example", "gone.cloudhost.example", ""),
		pointsNowhere("cdn.example", "old-bucket.cloudhost.example", ""),
		pointsNowhere("pages.example", "x.pages.example", `,"takeover":{"service":"Example Pages","status":"candidate"}`),
		pointsNowhere("wild.example", "w.cloudhost.example", `,"wildcard":true`),
	}, ok...)
	ch := watchRuns(t, old, neu)
	want := []string{
		"cdn.example → old-bucket.cloudhost.example (NXDOMAIN)",
		"pages.example → x.pages.example (NXDOMAIN; takeover candidate: Example Pages)",
	}
	if strings.Join(ch.Dangling, "|") != strings.Join(want, "|") || len(ch.Hosts) != 0 {
		t.Fatalf("dangling %q hosts %q, want %q", ch.Dangling, ch.Hosts, want)
	}
	if text := ch.text(); !strings.Contains(text, "! 2 names that point nowhere\n    cdn.example → old-bucket.cloudhost.example (NXDOMAIN)\n") {
		t.Fatalf("%s", text)
	}
	raw, _ := json.Marshal(ch)
	if !strings.Contains(string(raw), `"dangling":["cdn.example → `) {
		t.Fatalf("%s", raw)
	}
	// Unchanged: no change. A name that stopped pointing nowhere and one whose
	// previous lookup failed are not new.
	if ch := watchRuns(t, neu, neu); ch.any() {
		t.Fatalf("%+v", ch)
	}
	failed := append([]seenRow{{"cdn.example", "azhaq-dns", `{"fqdn":"cdn.example","degraded":true,"error":"timeout"}`}}, ok...)
	if ch := watchRuns(t, failed, []seenRow{pointsNowhere("cdn.example", "old-bucket.cloudhost.example", ""), ok[0]}); len(ch.Dangling) != 0 {
		t.Fatalf("a failed lookup is not an answer: %q", ch.Dangling)
	}
	healed := append([]seenRow{resolvesTo("cdn.example", "10.0.0.9")}, ok...)
	if ch := watchRuns(t, neu, healed); len(ch.Dangling) != 0 {
		t.Fatalf("%q", ch.Dangling)
	}
	// The baseline names every one.
	if ch := watchRuns(t, neu); !ch.Baseline || len(ch.Dangling) != 3 {
		t.Fatalf("baseline %v %q", ch.Baseline, ch.Dangling)
	}
}

// A product a detection template named, on the answer or by a product check
// of the sweep, is said on the service's line like a technology (#498).
func TestWatchNamesWhatADetectionTemplateNamed(t *testing.T) {
	front := seenRow{"http://g:3000/", "azhaq-http", `{"status":302,"title":"Grafana","url":"http://g:3000/","detected":[{"product":"Grafana","version":"8.2.6","template":"grafana-detect"}]}`}
	ch := watchRuns(t, []seenRow{webPage("http://h/")}, []seenRow{webPage("http://h/"), front})
	if len(ch.Services) != 1 || ch.Services[0] != "http://g:3000/ [302] Grafana (Grafana 8.2.6)" {
		t.Fatalf("services %q", ch.Services)
	}
	// A product check's row is the sweep's (azhaq-paths, kind detected), on the same service.
	plain := seenRow{"http://o:8080/", "azhaq-http", `{"status":200,"title":"Files","url":"http://o:8080/"}`}
	check := seenRow{"http://o:8080/", "azhaq-paths/detected", `{"url":"http://o:8080/","path":"/status.php","detected":[{"product":"Owncloud StatusPage","template":"owncloud-status-page"}]}`}
	ch = watchRuns(t, []seenRow{webPage("http://h/")}, []seenRow{webPage("http://h/"), plain, check})
	if len(ch.Services) != 1 || ch.Services[0] != "http://o:8080/ [200] Files (Owncloud StatusPage)" {
		t.Fatalf("services %q", ch.Services)
	}
}
