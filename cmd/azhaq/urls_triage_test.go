package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// testdataDir is found before a test changes directory.
var testdataDir, _ = filepath.Abs("testdata")

// recordedArchives serves the archives of azhaq urls for example.org from
// recorded answers (testdata/urls). wayback says how the Wayback Machine
// answers: "" the recorded page, then none; "504" a gateway timeout at once;
// "504-later" the recorded page, then a 504 for the next.
func recordedArchives(t *testing.T, wayback string) []string {
	t.Helper()
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(testdataDir, "urls", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/wayback" && wayback == "504", r.URL.Path == "/wayback" && wayback == "504-later" && q.Get("page") != "0":
			http.Error(w, "Gateway Time-out", http.StatusGatewayTimeout)
		case r.URL.Path == "/wayback" && q.Get("page") == "0":
			fmt.Fprint(w, read("wayback-cdx-page0.json"))
		case r.URL.Path == "/wayback":
			w.WriteHeader(http.StatusBadRequest) // past the last page
		case r.URL.Path == "/cc/collinfo.json":
			fmt.Fprintf(w, `[{"cdx-api":"http://%s/cc/idx"}]`, r.Host)
		case r.URL.Path == "/cc/idx" && q.Get("showNumPages") != "":
			fmt.Fprint(w, `{"pages":1}`)
		case r.URL.Path == "/cc/idx":
			fmt.Fprint(w, read("commoncrawl-index.jsonl"))
		case strings.HasPrefix(r.URL.Path, "/otx/"):
			fmt.Fprint(w, read("otx-url-list.json"))
		case r.URL.Path == "/urlscan":
			fmt.Fprint(w, read("urlscan-search.json"))
		case r.URL.Path == "/arquivo":
			fmt.Fprint(w, read("arquivo-cdx.jsonl"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	var flags []string
	for name, path := range map[string]string{"wayback": "/wayback", "commoncrawl": "/cc/collinfo.json", "otx": "/otx", "urlscan": "/urlscan", "arquivo": "/arquivo"} {
		flags = append(flags, "-archive", name+"="+srv.URL+path)
	}
	return flags
}

type triageRow struct {
	URL        string `json:"url"`
	Normalized string `json:"normalized"`
	RawURL     string `json:"raw_url"`
	Source     string `json:"source"`
	Archived   string `json:"archived"`
	Junk       string `json:"junk"`
	Reason     string `json:"junk_reason"`
	Verified   *bool  `json:"verified"`
	Status     int    `json:"verified_status"`
	VerifyErr  string `json:"verified_error"`
}

func triageRows(t *testing.T, out string) map[string]triageRow {
	t.Helper()
	rows := map[string]triageRow{}
	for _, l := range lines(out) {
		var r triageRow
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		rows[r.URL] = r
	}
	return rows
}

// A row says which archive gave the URL, when it was captured, its
// normalised form, and why it looks like junk; and a Wayback Machine that
// answers 504 leaves a partial set that the summary names, with the other
// archives' URLs delivered and exit 0 (the run did its job; -strict-exit says 3).
func TestURLsRowsCarryTriageFieldsAndAFailedArchiveIsNamed(t *testing.T) {
	t.Chdir(t.TempDir())
	flags := recordedArchives(t, "504")
	args := append([]string{"urls", "-d", "example.org", "-json", "-sort", "-keep-junk", "-urls-pause", "0"}, flags...)
	out, errOut, err := captureBoth(t, func() error { return run(args) })
	if code := exitCode(err); code != exitOK || lastReport(t, errOut).Failures == 0 {
		t.Fatalf("exit %d, want %d with the failure counted: %v\n%s", code, exitOK, err, errOut)
	}
	rows := triageRows(t, out)
	for u, want := range map[string]triageRow{
		"http://example.org/cc/page": {Source: "commoncrawl", Archived: "2024-01-05T11:22:33Z"},
		"http://example.org/otx":     {Source: "otx", Archived: "2023-05-02T10:11:12Z"},
		"http://example.org/us":      {Source: "urlscan", Archived: "2024-03-04T05:06:07Z"},
		"http://example.org/arq":     {Source: "arquivo", Archived: "2012-09-10T10:10:10Z"},
	} {
		got, ok := rows[u]
		if !ok || got.Source != want.Source || got.Archived != want.Archived || got.Normalized != u || got.Junk != "" {
			t.Errorf("%s: %+v, want source %s archived %s", u, got, want.Source, want.Archived)
		}
	}
	for u, r := range rows {
		if r.Source == "wayback" {
			t.Errorf("%s came from the wayback that answered 504", u)
		}
	}
	// A scanner's payload is kept only with -keep-junk, with its class and reason.
	var payload triageRow
	for u, r := range rows {
		if strings.Contains(u, "union") {
			payload = r
		}
	}
	if payload.Junk != "scanner-payload" || payload.Reason != "scanner payload" || payload.Source != "commoncrawl" {
		t.Errorf("payload row %+v", payload)
	}
	rep := lastReport(t, errOut)
	if rep.Sources == nil || rep.Sources.FailedSources["wayback"] == "" || !strings.Contains(rep.Sources.FailedSources["wayback"], "504") {
		t.Fatalf("the summary does not name the wayback failure: %+v", rep.Sources)
	}
	if rep.Sources.Queries["wayback"] != "example.org/*" || rep.Sources.URLs["commoncrawl"] != 2 {
		t.Errorf("asked and got: %+v", rep.Sources)
	}
	var partial bool
	for _, n := range rep.Notes {
		partial = partial || strings.Contains(n, "wayback failed and gave nothing")
	}
	if !rep.Degraded && rep.Failures == 0 || !partial {
		t.Errorf("summary %+v", rep)
	}
}

// Without -keep-junk the same payload is left out and counted, as before,
// and a static file is listed and labelled.
func TestURLsJunkIsCountedAndAssetsAreLabelled(t *testing.T) {
	t.Chdir(t.TempDir())
	flags := recordedArchives(t, "")
	out, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"urls", "-d", "example.org", "-json", "-sort", "-urls-pause", "0"}, flags...))
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows := triageRows(t, out)
	for u := range rows {
		if strings.Contains(u, "union") {
			t.Errorf("a payload is listed without -keep-junk: %s", u)
		}
	}
	if r := rows["http://example.org/img/logo.png"]; r.Junk != "asset" || r.Reason == "" || r.Source != "wayback" || r.Archived != "2021-01-01T00:00:00Z" {
		t.Errorf("asset row %+v", r)
	}
	// Two archives give this URL: the one that gave it first is its source,
	// and the date is that archive's.
	if r := rows["http://example.org/a?x=1"]; !(r.Source == "wayback" && r.Archived == "2019-03-12T08:30:15Z") && !(r.Source == "commoncrawl" && r.Archived == "2024-01-06T01:02:03Z") {
		t.Errorf("a URL's source and date go together: %+v", r)
	}
	if rep := lastReport(t, errOut); rep.Counts["dropped as junk"] != 1 {
		t.Errorf("counts %v", rep.Counts)
	}
}

// An archive that fails after giving URLs is a partial source: what it gave
// is in the set, and the summary says it stopped.
func TestURLsArchiveThatFailsMidwayIsPartial(t *testing.T) {
	t.Chdir(t.TempDir())
	flags := recordedArchives(t, "504-later")
	out, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"urls", "-d", "example.org", "-json", "-sort", "-urls-pause", "0", "-retries", "0"}, flags...))
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit %d, want %d\n%s", code, exitOK, errOut)
	}
	if rows := triageRows(t, out); rows["http://www.example.org/w"].Source != "wayback" {
		t.Errorf("what wayback gave before it failed is lost: %v", rows)
	}
	rep := lastReport(t, errOut)
	if !slices.Equal(rep.Sources.PartialSources, []string{"wayback"}) {
		t.Errorf("partial sources %v", rep.Sources.PartialSources)
	}
}

// -live asks the live site for each URL once and marks the rows: a page that
// answers is verified, a 404 is gone, a host that does not answer is said,
// and a URL that looks like junk is never sent.
func TestURLsLiveVerifiesAtAStatedRate(t *testing.T) {
	t.Chdir(t.TempDir())
	flags := recordedArchives(t, "")
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/b"):
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/otx"):
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close() // no answer
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(proxy.Close)
	args := append([]string{"urls", "-d", "example.org", "-json", "-keep-junk", "-urls-pause", "0", "-live", "-live-rate", "50", "-live-proxy", proxy.URL, "-db", filepath.Join(t.TempDir(), "u.db")}, flags...)
	out, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows := triageRows(t, out)
	ok := func(u string, verified bool, status int) {
		t.Helper()
		r, found := rows[u]
		if !found || r.Verified == nil || *r.Verified != verified || r.Status != status {
			t.Errorf("%s: %+v, want verified %v status %d", u, r, verified, status)
		}
	}
	ok("http://example.org/cc/page", true, 200)
	ok("http://example.org/b", false, 404)
	if r := rows["http://example.org/otx"]; r.Verified == nil || *r.Verified || r.VerifyErr == "" {
		t.Errorf("a host with no answer: %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, u := range seen {
		if strings.Contains(u, "union") {
			t.Errorf("a junk URL was sent: %s", u)
		}
	}
	for u, r := range rows {
		if r.Junk != "" && r.Junk != "asset" && r.Verified != nil {
			t.Errorf("%s is junk and was verified", u)
		}
	}
	rep := lastReport(t, errOut)
	var said bool
	for _, n := range rep.Notes {
		said = said || strings.HasPrefix(n, "-live: ") && strings.Contains(n, "at 50 requests a second")
	}
	if rep.Requests != 9 {
		t.Errorf("the summary counts %d requests to the targets, the check sent 9", rep.Requests)
	}
	if !said || rep.Counts["verified live"] == 0 || rep.Counts["gone (404, 410)"] != 1 || rep.Counts["no answer"] != 1 {
		t.Errorf("counts %v notes %q", rep.Counts, rep.Notes)
	}
}
