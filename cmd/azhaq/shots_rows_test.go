package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// shotRowsOf reads the rows of a -json shots run: those with a url, the
// summary and the notes left out.
func shotRowsOf(t *testing.T, out string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(l), &r) == nil && r["type"] == nil && r["url"] != nil {
			rows = append(rows, r)
		}
	}
	return rows
}

// A target with no picture ends as a row that says why, whatever it is: a
// URL that timed out, a name that does not resolve, a bare name with no web
// service. A target with a picture is not listed. No Chrome is needed: the
// run's records are a fixture.
func TestShotMissesGiveEveryTargetItsRow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	add := func(typ types.SeedType, key, collector, kind, payload string) {
		t.Helper()
		e, err := st.UpsertEntity(typ, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.AddObservation(e.ID, types.Observation{Collector: collector, Kind: kind, Payload: json.RawMessage(payload), ObservedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	add(types.TypeURL, "http://slow.test/", "azhaq-http", "error", `{"error":"timeout","url":"http://slow.test/"}`)
	add(types.TypeHostname, "nx.test", "azhaq-dns", "dns", `{"fqdn":"nx.test","error":"nxdomain"}`)
	add(types.TypeHostname, "quiet.test", "azhaq-http", "noweb", `{"host":"quiet.test","ports":"443 or 80"}`)

	given := []string{"http://ok.test/", "http://slow.test/", "nx.test", "quiet.test", "http://ok.test/", "198.51.100.7:8080"}
	rep := &report{}
	got := shotMisses(rep, st, given, []string{"http://ok.test/"}, map[string]bool{"198.51.100.7:8080": true})
	want := []shotMiss{
		{target: "http://slow.test/", why: "timeout", failed: true},
		{target: "nx.test", why: "no such host", failed: true, by: "azhaq-dns"},
		{target: "quiet.test", why: "no web service on 443 or 80 (connection refused)"},
	}
	if len(got) != len(want) {
		t.Fatalf("misses %+v, want %+v (the target that has a picture and the scan's guessed port are no rows)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("miss %d is %+v, want %+v", i, got[i], want[i])
		}
	}
	// A stopped run leaves the targets it did not reach for resume.
	rep = &report{Stopped: "budget"}
	if got := shotMisses(rep, st, []string{"http://later.test/"}, nil, nil); len(got) != 0 {
		t.Errorf("a target the run never reached has a row: %+v", got)
	}
}

// A name or host:port is answered by a picture of any scheme of that host;
// a URL only by a picture of that URL: a redirect's destination is not
// another target.
func TestShotTargetMatchesItsOwnPage(t *testing.T) {
	for _, c := range []struct {
		target, page string
		want         bool
	}{
		{"http://h.test/", "http://h.test/", true},
		{"http://h.test/", "https://h.test/", false},
		{"h.test", "https://h.test/", true},
		{"h.test:8443", "https://h.test:8443/", true},
		{"h.test:8443", "https://h.test/", false},
		{"[2001:db8::1]:8080", "http://[2001:db8::1]:8080/", true},
		{"h.test", "https://other.test/", false},
	} {
		if got := shotTargetMatches(c.target, c.page); got != c.want {
			t.Errorf("%s answered by %s: %v, want %v", c.target, c.page, got, c.want)
		}
	}
}

// -u http://host/ whose server redirects to https is one target: one row
// and one file, with where Chrome ended in final_url.
func TestShotsRedirectIsOneRowWithTheDestinationInFinalURL(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var addr string
	addr = bothSchemes(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Redirect(w, r, "https://"+r.Host+"/", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>secure</title></head><body><h1>hi</h1></body></html>`)
	}))
	_, port, _ := net.SplitHostPort(addr)
	dir := filepath.Join(t.TempDir(), "s")
	js, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", "http://localhost:" + port + "/", "-dir", dir, "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if err != nil {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, errOut)
	}
	rows := shotRowsOf(t, js)
	if len(rows) != 1 || rows[0]["url"] != "http://localhost:"+port+"/" || rows[0]["final_url"] != "https://localhost:"+port+"/" {
		t.Fatalf("rows %v, want one: the URL given, ending at the https page", rows)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*.png")); len(files) != 1 {
		t.Errorf("files %v, want one for the one target", files)
	}
	if rep := lastReport(t, errOut); rep.Results != 1 {
		t.Errorf("results %d, want 1", rep.Results)
	}
}

// A batch: each target ends as one row, a target that timed out, was
// refused, or whose name does not resolve with its error, and the summary's
// counts add up to the rows.
func TestShotsBatchGivesEveryTargetARow(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	ok := bothSchemes(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>fine</title></head><body><h1>hi</h1></body></html>`)
	}))
	hung, err := net.Listen("tcp", "127.0.0.1:0") // accepts, never answers
	if err != nil {
		t.Fatal(err)
	}
	defer hung.Close()
	go func() {
		for {
			c, err := hung.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()

	_, okPort, _ := net.SplitHostPort(ok)
	given := []string{"http://localhost:" + okPort + "/", "http://" + hung.Addr().String() + "/", "http://" + closedAddr + "/", "nonexistent.invalid"}
	dir := filepath.Join(t.TempDir(), "s")
	csvPath := filepath.Join(t.TempDir(), "o.csv")
	args := []string{"-dir", dir, "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-csv", csvPath}
	for _, g := range given {
		args = append(args, "-u", g)
	}
	js, errOut, err := captureBoth(t, func() error { return cmdShots(args) })
	if exitCode(err) != exitOK {
		t.Fatalf("exit %d (%v), want 0: one target answered and the summary names the rest\n%s", exitCode(err), err, errOut)
	}
	rows := shotRowsOf(t, js)
	byURL := map[string]map[string]any{}
	for _, r := range rows {
		u := fmt.Sprint(r["url"])
		if byURL[u] != nil {
			t.Errorf("two rows for %s", u)
		}
		byURL[u] = r
	}
	if len(rows) != len(given) {
		t.Fatalf("%d rows for %d targets: %v", len(rows), len(given), rows)
	}
	for i, g := range given {
		r := byURL[g]
		if r == nil {
			t.Fatalf("no row for %s: %v", g, rows)
		}
		if i == 0 {
			if r["file"] == nil || r["failed"] != nil {
				t.Errorf("the page that answered has no picture: %v", r)
			}
			continue
		}
		if r["failed"] != true || fmt.Sprint(r["error"]) == "" || r["file"] != nil {
			t.Errorf("%s: want a failed row with its error, got %v", g, r)
		}
	}
	if e := fmt.Sprint(byURL[given[1]]["error"]); !strings.Contains(e, "timeout") {
		t.Errorf("the hung server's error %q does not say timeout", e)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*.png")); len(files) != 1 {
		t.Errorf("files %v, want one: only the page that answered has a picture", files)
	}
	rep := lastReport(t, errOut)
	if rep.Results != 1 || rep.Counts["without a screenshot"] != 3 || rep.Failures != 3 {
		t.Errorf("summary: %d results, counts %v, %d failures; want 1, 3 without a screenshot, 3", rep.Results, rep.Counts, rep.Failures)
	}
	raw, _ := os.ReadFile(csvPath)
	if lines := strings.Split(strings.TrimSpace(string(raw)), "\n"); len(lines) != 1+len(given) || !strings.HasSuffix(lines[0], ",error") {
		t.Errorf("csv has %d lines, want a header and one for each target:\n%s", len(lines), raw)
	}
}

// When no target answers the run did not do its job: exit 3, a row each.
func TestShotsEveryTargetFailedExits3WithRows(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.Addr().String()
	closed.Close()
	js, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", "http://" + addr + "/", "-u", "nonexistent.invalid", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if exitCode(err) != exitPartial {
		t.Fatalf("exit %d, want 3: nothing answered\n%s", exitCode(err), errOut)
	}
	if rows := shotRowsOf(t, js); len(rows) != 2 {
		t.Errorf("rows %v, want one for each target", rows)
	}
}
