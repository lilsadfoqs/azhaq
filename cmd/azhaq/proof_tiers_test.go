package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// shell runs a reproduce command the way a reader pastes it, and returns what it printed.
func shell(t *testing.T, command string) string {
	t.Helper()
	for _, tool := range []string{"curl", "nc"} {
		if strings.Contains(command, tool+" ") {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s is not installed", tool)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	return string(out)
}

// shownBy says what an excerpt holds that the reproduce command's output must hold too: the
// excerpt's printable text, up to its first escape.
func shownBy(excerpt string) string {
	if i := strings.Index(excerpt, `\`); i > 0 {
		excerpt = excerpt[:i]
	}
	if len(excerpt) > 24 {
		excerpt = excerpt[:24]
	}
	return excerpt
}

// pathFixture is a host with a catch-all index, a login redirect for what is guarded,
// a soft 404 page, a real /.env and a real actuator.
func pathFixture(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=production\nDB_PASSWORD=hunter2hunter2\n")
		case "/actuator":
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			fmt.Fprint(w, `{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"}}}`)
		case "/admin", "/dashboard":
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Sign in</title><form><input type="password" name="p"></form></html>`)
		case "/swagger-ui.html":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Page not found</title><body>Sorry, nothing here.</body></html>`)
		case "/backup":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Backups - Acme</title><body>Manage your backups.</body></html>`)
		case "/.git/HEAD":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Acme</title><body>.git is not served here</body></html>`)
		default: // the app's index answers every other path, /config included
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Acme</title><body><div id="app"></div><script src="/app.js"></script></body></html>`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

var pathWords = []string{".env", "config", "backup", "admin", "dashboard", "actuator", "swagger-ui.html", ".git/HEAD"}

func runPathFixture(t *testing.T) (db string, srv *httptest.Server) {
	t.Helper()
	srv = pathFixture(t)
	db = filepath.Join(t.TempDir(), "p.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", db, "-json", "-depth", "1", "-paths", wlist(t, pathWords...), "-no-tech", "-no-favicon", "-ledger", "off"})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	return db, srv
}

// A host with a soft-404 page, a login redirect and a real /.env: the path checks give one
// finding for the file and one for the actuator; the guesses that only look like something
// are leads, or dropped when their answer is one of the host's baselines.
func TestPathChecksOnAHostWithBaselines(t *testing.T) {
	db, srv := runPathFixture(t)
	g, err := readGraph(db)
	if err != nil {
		t.Fatal(err)
	}
	set := buildFindings(g)
	byURL := func(rs []findingRecord) map[string]findingRecord {
		m := map[string]findingRecord{}
		for _, r := range rs {
			m[r.URL] = r
		}
		return m
	}
	finds, leads := byURL(set.Findings), byURL(set.Leads)
	env, ok := finds[srv.URL+"/.env"]
	if !ok || env.Kind != "exposed-file" || env.Tier != "finding" {
		t.Fatalf("/.env is not a finding: %+v\nfindings %v", env, finds)
	}
	if env.Proof == nil || !env.Proof.Complete() || env.Status != 200 || env.ExcerptOffset == nil || !strings.Contains(env.Excerpt, "APP_ENV=production") {
		t.Errorf("/.env proof %+v", env.Proof)
	}
	if act, ok := finds[srv.URL+"/actuator"]; !ok || act.Kind != "exposed-panel" {
		t.Errorf("/actuator is no finding: %v", finds)
	}
	if len(set.Findings) != 2 {
		t.Errorf("%d findings, want 2 (the file and the actuator): %v", len(set.Findings), finds)
	}
	// What looks like something and shows nothing is a lead, with its check.
	for _, p := range []string{"/backup", "/.git/HEAD"} {
		l, ok := leads[srv.URL+p]
		if !ok || l.Tier != "lead" || l.Check == "" || l.Proof != nil {
			t.Errorf("%s: want a lead with a check and no proof, got %+v", p, l)
		}
	}
	// Equal to a baseline of the host, they are dropped: no finding and no lead.
	for _, p := range []string{"/config", "/admin", "/dashboard", "/swagger-ui.html", "/login"} {
		if _, f := finds[srv.URL+p]; f {
			t.Errorf("%s is a finding", p)
		}
		if _, l := leads[srv.URL+p]; l && p != "/login" {
			t.Errorf("%s is a lead: its answer equals a baseline", p)
		}
	}
	// Run the command a reader would: it shows the excerpt without azhaq.
	if out := shell(t, env.Reproduce); !strings.Contains(out, "APP_ENV=production") {
		t.Errorf("%s printed %q, want the excerpt", env.Reproduce, out)
	}
}

// Findings, identifications and leads are counted apart, and the counts are the rows.
func TestTierCountsPartitionTheRows(t *testing.T) {
	db, _ := runPathFixture(t)
	g, err := readGraph(db)
	if err != nil {
		t.Fatal(err)
	}
	set := buildFindings(g)
	var buf strings.Builder
	buf.Write(findingsJSONL(set))
	n := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var row struct{ Type, Tier string }
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		n[row.Type]++
		if row.Type != "folded" && row.Type != row.Tier {
			t.Errorf("line of type %s has tier %q: %s", row.Type, row.Tier, line)
		}
	}
	c := set.counts()
	if n["finding"] != c.Findings || n["identification"] != c.Identifications || n["lead"] != c.Leads {
		t.Errorf("lines %v, counts %+v", n, c)
	}
	if c.Findings+c.Identifications+c.Leads != n["finding"]+n["identification"]+n["lead"] || c.Findings == 0 || c.Leads == 0 {
		t.Errorf("the tiers do not partition the rows: %+v / %v", c, n)
	}
	// The same counts in the run's summary, in report and in export.
	_, errOut, err := captureBoth(t, func() error {
		return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl", "-o", filepath.Join(t.TempDir(), "f.jsonl")})
	})
	if err != nil || !strings.Contains(errOut, c.String()) {
		t.Errorf("report says %q, want %q (%v)", errOut, c, err)
	}
	var ex strings.Builder
	_, errOut, err = captureBoth(t, func() error { return exportAs(db, "findings", "", &ex) })
	if err != nil || !strings.Contains(errOut, c.String()) {
		t.Errorf("export says %q, want %q (%v)", errOut, c, err)
	}
	_, errOut, err = captureBoth(t, func() error {
		return cmdRun([]string{"-url", "http://127.0.0.1:1/", "-db", filepath.Join(t.TempDir(), "x.db"), "-json", "-no-paths", "-ledger", "off"})
	})
	var sum struct{ Tiers *tierCounts }
	if i := strings.LastIndex(errOut, `{"type":"summary"`); i >= 0 {
		_ = json.Unmarshal([]byte(strings.TrimSpace(errOut[i:])), &sum)
	}
	if sum.Tiers == nil {
		t.Errorf("the run's summary has no tiers: %s", errOut)
	}
}

// hunt lists the findings first and the leads apart, each lead with the check that would prove it.
func TestHuntListsTheTiersApart(t *testing.T) {
	db, srv := runPathFixture(t)
	out, errOut, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	seenLead := false
	var findings, leads int
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct {
			Key, Tier, Check string
			Proof            *proof.Proof
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		switch r.Tier {
		case "finding":
			findings++
			if seenLead {
				t.Errorf("a finding after a lead: %s", line)
			}
			if strings.HasSuffix(r.Key, "/.env") && !r.Proof.Complete() {
				t.Errorf("the /.env finding has no proof: %s", line)
			}
		case "lead":
			leads++
			seenLead = true
			if r.Check == "" {
				t.Errorf("a lead with no check: %s", line)
			}
		default:
			t.Errorf("row with no tier: %s", line)
		}
		if strings.HasSuffix(r.Key, "/config") || strings.HasSuffix(r.Key, "/swagger-ui.html") || strings.HasSuffix(r.Key, "/dashboard") {
			t.Errorf("%s ranks: its answer equals a baseline of the host", r.Key)
		}
	}
	if findings < 2 {
		t.Errorf("%d findings, want the /.env and the actuator (%s)", findings, srv.URL)
	}
	if !strings.Contains(errOut, fmt.Sprintf(`"tiers":{"findings":%d,"identifications":0,"leads":%d}`, findings, leads)) {
		t.Errorf("hunt's summary does not count the tiers apart: %s", errOut)
	}
	text, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db}) })
	if err != nil {
		t.Fatal(err)
	}
	fi, li := strings.Index(text, "findings ("), strings.Index(text, "leads (")
	if fi < 0 || li < 0 || fi > li || !strings.Contains(text[li:], "→ check: ") {
		t.Errorf("hunt's text does not list findings first and the leads apart with their checks:\n%s", text)
	}
}

// Every kind of finding and identification row carries a complete proof and a command that shows
// its excerpt without azhaq, run here against local fixtures.
func TestEveryFindingKindHasAProofThatReproduces(t *testing.T) {
	// A memcached-like data store on a local port: the read with no credential (unauthenticated-read).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _ := c.Read(buf)
				if strings.HasPrefix(string(buf[:n]), "version") {
					c.Write([]byte("VERSION 1.6.9\r\n"))
				}
			}(c)
		}
	}()
	// A service that greets: an SSH banner (an identification with no advisory).
	greet, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer greet.Close()
	go func() {
		for {
			c, err := greet.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	gport := greet.Addr().(*net.TCPAddr).Port
	svc := advisory.Service{Host: "127.0.0.1", IP: "127.0.0.1", Port: port, Proto: "tcp", Service: "memcached", Product: "Memcached"}
	check, ok := verify.ForService(svc)
	if !ok {
		t.Fatal("no memcached check")
	}
	res, err := check.Execute(context.Background(), svc, func(ctx context.Context, host, ip string, p int) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
	})
	if err != nil || res.Label != verify.Proved || res.Proof == nil {
		t.Fatalf("verify: %+v %v", res, err)
	}
	vraw, _ := json.Marshal(res)
	ports, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "ip": "127.0.0.1", "services": []map[string]any{
		{"port": gport, "service": "ssh", "product": "OpenSSH", "version": "8.2p1", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu"}}})

	// A web server with a stack trace in an answer, a script with a key and a real file.
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Acme</title><script src="/app.js"></script><a href="/boom">b</a></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `var cfg = {mailer: "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789abcdefg"};`)
		case "/boom":
			w.WriteHeader(500)
			fmt.Fprint(w, "java.lang.IllegalStateException: boom\n\tat com.acme.A.run(A.java:1)\n\tat com.acme.B.run(B.java:2)\n\tat com.acme.C.run(C.java:3)\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer web.Close()
	db := filepath.Join(t.TempDir(), "k.db")
	if _, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", web.URL + "/", "-db", db, "-json", "-depth", "2", "-paths", wlist(t, "boom"), "-no-favicon", "-ledger", "off"})
	}); err != nil && exitCode(err) != exitPartial {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	g, err := readGraph(db)
	if err != nil {
		t.Fatal(err)
	}
	g.obs = append(g.obs,
		types.StoredObservation{Observation: types.Observation{Collector: "azhaq-verify", Kind: "verify", Payload: vraw, ObservedAt: time.Now()}},
		types.StoredObservation{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: ports, ObservedAt: time.Now()}},
		types.StoredObservation{Observation: types.Observation{Collector: "azhaq-http", Kind: "application", ObservedAt: time.Now(), Payload: []byte(
			`{"url":"http://gone.test/","fqdn":"gone.test","takeover":{"service":"GitHub Pages","target":"x.github.io","strength":"strong","status":"verified","evidence":"CNAME to x.github.io; page says \"There isn't a GitHub Pages site here\""}}`)}},
	)
	set := buildFindings(g)
	kinds := map[string]bool{}
	for _, r := range append(append([]findingRecord{}, set.Findings...), set.Identifications...) {
		kinds[r.Tier+"/"+r.Kind] = true
		if !r.Proof.Complete() {
			t.Errorf("%s %s on %s has an incomplete proof: %+v", r.Tier, r.Kind, r.URL+r.Host, r.Proof)
			continue
		}
		if r.Kind == "takeover" {
			continue // dig and the page of a name that does not exist cannot run here
		}
		out := shell(t, r.Reproduce)
		want := shownBy(r.Excerpt)
		if r.Kind == "secret" {
			want = "SG.abc" // the command greps the start of the value, which the excerpt redacts after
		}
		if !strings.Contains(out, want) {
			t.Errorf("%s %s: %s printed %q, want the excerpt %q", r.Tier, r.Kind, r.Reproduce, out, r.Excerpt)
		}
	}
	for _, want := range []string{"finding/unauthenticated-read", "finding/error-disclosure", "finding/secret", "finding/takeover", "identification/software-version"} {
		if !kinds[want] {
			t.Errorf("no %s record: %v", want, kinds)
		}
	}
	if strings.Contains(string(findingsJSONL(set)), "abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789abcdefg") {
		t.Errorf("a secret's value is in the findings output")
	}
	if os.Getenv("AZHAQ_TEST_SHOW") != "" {
		t.Logf("%s", findingsJSONL(set))
	}
}

// A read stored without the request and the answer that prove it is a lead: no proof, no finding.
func TestAVerifyReadWithoutItsAnswerIsALead(t *testing.T) {
	raw, _ := json.Marshal(verify.Result{Kind: verify.KindUnauthenticatedRead, Label: verify.Proved, Severity: "high",
		Host: "10.0.0.5", Port: 6379, Target: "10.0.0.5:6379", Product: "Redis", Request: "INFO server", Evidence: "# Server"})
	g := &graphView{obs: []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-verify", Kind: "verify", Payload: raw}}}}
	set := buildFindings(g)
	if len(set.Findings) != 0 || len(set.Leads) != 1 || set.Leads[0].Check == "" {
		t.Errorf("%+v, want one lead and no finding", set)
	}
}
