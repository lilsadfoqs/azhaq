package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/store"
)

const logProxyServer = "BaseHTTP/0.6 Python/3.14.4"

// The advisories a run could match to what the proxy's header says (Python
// 3.14.4, BaseHTTP 0.6) and to a real nginx.
const proxyAdvFixture = `[
  {"id":"CVE-TEST-PY","summary":"python issue",
   "affected":[{"package":{"name":"python","ecosystem":"test"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0.0"},{"fixed":"3.15.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-PY"}]},
  {"id":"CVE-TEST-BH","summary":"basehttp issue",
   "affected":[{"package":{"name":"basehttp","ecosystem":"test"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0.1"},{"fixed":"0.9"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-BH"}]},
  {"id":"CVE-TEST-NGINX","summary":"nginx issue",
   "affected":[{"package":{"name":"nginx","ecosystem":"test"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.26.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-NGINX"}]}
]`

// logProxy is a forward proxy for plain HTTP, as a logging one is. A request
// addressed to it gets its own page, which says Server: logProxyServer (or is
// hung up on, with refuse). With add, every answer it forwards gets that
// header too; without, the target's headers pass through.
type logProxy struct {
	*httptest.Server
	mu     sync.Mutex
	direct int
}

func newLogProxy(t *testing.T, add, refuse bool) *logProxy {
	t.Helper()
	p := &logProxy{}
	tr := &http.Transport{Proxy: nil}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "" {
			p.mu.Lock()
			p.direct++
			p.mu.Unlock()
			if refuse {
				c, _, _ := w.(http.Hijacker).Hijack()
				c.Close()
				return
			}
			w.Header().Set("Server", logProxyServer)
			io.WriteString(w, "proxy page")
			return
		}
		out, _ := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		out.Header = r.Header.Clone()
		resp, err := tr.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		if add {
			w.Header().Set("Server", logProxyServer)
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *logProxy) asked() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.direct
}

// headerTarget answers every path, with the Server header given ("" for none).
func headerTarget(t *testing.T, server string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
		io.WriteString(w, "<html><head><title>app</title></head><body>hello</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

type proxiedRun struct {
	rep     report
	rows    []httprow.Row
	ledger  []ledger.Entry
	notes   string
	leads   int
	proxyOf string
}

// runBehind runs `run` on target through proxy, with advisories matched against
// proxyAdvFixture, and gathers what the tests look at.
func runBehind(t *testing.T, proxy, target string) proxiedRun {
	t.Helper()
	egress.Reset()
	dir := t.TempDir()
	db, led := filepath.Join(dir, "w.db"), filepath.Join(dir, "l.jsonl")
	out, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", target + "/", "-db", db, "-ledger", led, "-json", "-depth", "0", "-no-paths", "-no-favicon",
			"-proxy", proxy, "-advisories", "-advisory-source", writeAdvFixture(t, proxyAdvFixture)})
	})
	if err != nil {
		t.Fatalf("run: %v\n%s\n%s", err, out, errOut)
	}
	r := proxiedRun{rep: withStoredAdvisories(t, db, lastReport(t, errOut)), proxyOf: proxy}
	r.notes = strings.Join(r.rep.Notes, "\n")
	r.leads = len(r.rep.Advisories)
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Collector == "azhaq-http" && o.Kind == "application" {
			row, err := httprow.ParseRow(o.Payload)
			if err != nil {
				t.Fatal(err)
			}
			r.rows = append(r.rows, row)
		}
	}
	_ = ledger.Read(led, func(e ledger.Entry) error {
		if e.Kind != ledger.KindSeal {
			r.ledger = append(r.ledger, e)
		}
		return nil
	})
	return r
}

// A Server header the proxy adds to every answer is not the target's: no
// product or version is named from it, no advisory is matched, and the notes
// say how many answers carried it.
func TestRunBehindAProxyThatAddsServerNamesNoProduct(t *testing.T) {
	px := newLogProxy(t, true, false)
	srv := headerTarget(t, "")
	r := runBehind(t, px.URL, srv.URL)
	if len(r.rows) == 0 {
		t.Fatal("the run stored no answer")
	}
	for _, row := range r.rows {
		if row.Server != "" || slices.ContainsFunc(row.Tech, func(s string) bool { return strings.Contains(strings.ToLower(s), "python") }) {
			t.Errorf("the target is named from the proxy's header: server %q tech %v", row.Server, row.Tech)
		}
		for _, d := range row.Detected {
			if strings.Contains(strings.ToLower(d.Product), "python") || strings.Contains(strings.ToLower(d.Product), "basehttp") {
				t.Errorf("a template named %+v from the proxy's header", d)
			}
		}
	}
	if r.leads != 0 {
		t.Errorf("%d advisory leads matched to the proxy's software: %+v", r.leads, r.rep.Advisories)
	}
	if !strings.Contains(r.notes, "carried a Server header equal to the proxy's own") || !strings.Contains(r.notes, logProxyServer) {
		t.Errorf("notes %q", r.notes)
	}
	if px.asked() != 1 {
		t.Errorf("the proxy was asked %d times for its own answer, want once", px.asked())
	}
}

// The target's own Server header, which this proxy passes through, is still
// the target's: nginx is named and its advisory matched.
func TestRunBehindAProxyThatPassesServerThroughNamesTheTarget(t *testing.T) {
	px := newLogProxy(t, false, false)
	srv := headerTarget(t, "nginx/1.25.3")
	r := runBehind(t, px.URL, srv.URL)
	if len(r.rows) == 0 || r.rows[0].Server != "nginx/1.25.3" {
		t.Fatalf("rows %+v, want the target's nginx/1.25.3", r.rows)
	}
	if r.leads != 1 || r.rep.Advisories[0].AdvisoryID != "CVE-TEST-NGINX" {
		t.Errorf("advisories %+v, want the nginx one", r.rep.Advisories)
	}
	if strings.Contains(r.notes, "equal to the proxy's own") || strings.Contains(r.notes, "could not be asked") {
		t.Errorf("notes %q for a proxy whose header the target does not share", r.notes)
	}
	if px.asked() != 1 {
		t.Errorf("the proxy was asked %d times for its own answer, want once", px.asked())
	}
}

// A proxy that refuses a request addressed to it cannot be asked: the run
// says so, marks what only a header named as read through it, and matches no
// advisory to a version only a header gave. The header is not dropped.
func TestRunBehindAProxyThatRefusesMarksTheHeaderReads(t *testing.T) {
	px := newLogProxy(t, true, true)
	srv := headerTarget(t, "")
	r := runBehind(t, px.URL, srv.URL)
	if !strings.Contains(r.notes, "could not be asked for its own answer") || !strings.Contains(r.notes, "marked as read through the proxy") {
		t.Errorf("notes %q", r.notes)
	}
	var marked bool
	for _, row := range r.rows {
		if row.Server == logProxyServer && slices.Contains(row.ViaProxy, "Server") {
			marked = true
		}
	}
	if !marked {
		t.Errorf("the Server header read is not marked as read through the proxy: %+v", r.rows)
	}
	if r.leads != 0 {
		t.Errorf("%d advisory leads matched to a version only a header gave through an unasked proxy: %+v", r.leads, r.rep.Advisories)
	}
}

// The request to the proxy is in the ledger as the proxy's, once, and is not
// a line to a target: the summary's requests are the lines to targets and it.
func TestTheRequestToTheProxyIsInTheLedger(t *testing.T) {
	px := newLogProxy(t, true, false)
	srv := headerTarget(t, "")
	r := runBehind(t, px.URL, srv.URL)
	var proxyLines, targetLines int
	for _, e := range r.ledger {
		switch {
		case e.Class == ledger.ClassProxy:
			proxyLines++
			if e.Kind != "http" || e.Method != "GET" || e.Target != px.URL+"/" || e.Collector != "proxy" {
				t.Errorf("proxy line %+v", e)
			}
		case e.IsTarget():
			targetLines++
			if strings.HasPrefix(e.Target, px.URL) {
				t.Errorf("a target line addressed to the proxy: %+v", e)
			}
		}
	}
	if proxyLines != 1 {
		t.Errorf("%d proxy lines in the ledger, want 1: %+v", proxyLines, r.ledger)
	}
	if int(r.rep.Requests) != targetLines+proxyLines {
		t.Errorf("requests %d, lines to targets %d and to the proxy %d: the proxy's own request is counted as a target's", r.rep.Requests, targetLines, proxyLines)
	}
}

// crawl reads the same answers: the proxy's header is not the target's there
// either, and the note counts it.
func TestCrawlBehindAProxyThatAddsServerNamesNoProduct(t *testing.T) {
	egress.Reset()
	px := newLogProxy(t, true, false)
	srv := headerTarget(t, "")
	db := filepath.Join(t.TempDir(), "c.db")
	out, errOut, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/", "-d", "0", "-proxy", px.URL, "-db", db, "-json"})
	})
	if err != nil {
		t.Fatalf("crawl: %v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "carried a Server header equal to the proxy's own") {
		t.Errorf("notes %q", rep.Notes)
	}
	if strings.Contains(strings.ToLower(out), "python") {
		t.Errorf("the crawl names the proxy's software: %s", out)
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, _ := st.Observations()
	for _, o := range obs {
		if strings.Contains(strings.ToLower(string(o.Payload)), "python") {
			t.Errorf("a row names the proxy's software: %s", o.Payload)
		}
	}
}
