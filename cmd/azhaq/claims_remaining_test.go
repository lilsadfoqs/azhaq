package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fuzz"
)

// The docs name the encoders -enc takes: the list is the code's, and
// ffuf's htmlescape and htmlunescape are not among them.
func TestFuzzEncodersAreTheListTheDocsName(t *testing.T) {
	raw, err := os.ReadFile("../../docs/commands/fuzz.md")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.Contains(l, "The encoders are") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("the page does not list the encoders")
	}
	list, _, _ := strings.Cut(line, "run in process")
	var named []string
	for _, m := range regexp.MustCompile("`([a-z0-9]+)`").FindAllStringSubmatch(list, -1) {
		named = append(named, m[1])
	}
	slices.Sort(named)
	if have := fuzz.EncoderNames(); !slices.Equal(named, have) {
		t.Errorf("the page names %v, -enc takes %v", named, have)
	}
	for _, name := range []string{"htmlescape", "htmlunescape"} {
		_, errOut, code := cli(t, "fuzz", "-u", "http://127.0.0.1:9/FUZZ", "-w", wlist(t, "a"), "-enc", "FUZZ:"+name)
		if code != exitUsage || !strings.Contains(errOut, fmt.Sprintf("encoder %q is not one of", name)) {
			t.Errorf("%s: exit %d\n%s", name, code, errOut)
		}
	}
}

// -min-rate paces a loopback scan as -rate does (1,500 ports at 500 a
// second take about 3 s), and keeps every core; with GOMAXPROCS in the
// environment -rate leaves the number alone, without it -rate sizes it.
func TestPortsMinRatePacesTheLoopbackAndGOMAXPROCSIsYours(t *testing.T) {
	t.Chdir(t.TempDir())
	args := []string{"ports", "-host", "127.0.0.1", "-p", "1-1500", "-detect", "none", "-silent", "-ledger", "off"}
	was := runtime.GOMAXPROCS(0)
	gc := debug.SetGCPercent(100)
	t.Cleanup(func() { runtime.GOMAXPROCS(was); debug.SetGCPercent(gc) })
	t0 := time.Now()
	cli(t, append(slices.Clone(args), "-min-rate", "500")...)
	if d := time.Since(t0); d < 2500*time.Millisecond {
		t.Errorf("-min-rate 500 took %v for 1,500 ports on the loopback: it paces them over about 3 s", d)
	}
	runtime.GOMAXPROCS(3)
	t.Setenv("GOMAXPROCS", "3")
	cli(t, append(slices.Clone(args), "-rate", "5000")...)
	if got := runtime.GOMAXPROCS(0); got != 3 {
		t.Errorf("with GOMAXPROCS=3 in the environment -rate 5000 set %d cores", got)
	}
	t.Setenv("GOMAXPROCS", "")
	cli(t, append(slices.Clone(args), "-rate", "5000")...)
	if got := runtime.GOMAXPROCS(0); got != 1 {
		t.Errorf("without GOMAXPROCS in the environment -rate 5000 left %d cores: one core is what 5,000 a second needs", got)
	}
}

// A route that streams for ever is cut by probe and crawl (status and the
// first part of the body, then closed); dirs, params and fuzz read an
// answer to its end, so the stream of 3 s runs out under them.
func TestOnlyProbeAndCrawlCutAStreamTheOthersReadToItsEnd(t *testing.T) {
	for _, c := range []struct {
		name string
		cuts bool
		run  func(t *testing.T, url string)
	}{
		{"probe", true, func(t *testing.T, url string) {
			runContract(t, "probe", "-u", url+"/events", "-req-timeout", "30s")
		}},
		{"crawl", true, func(t *testing.T, url string) {
			runContract(t, "crawl", "-u", url+"/events", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db"))
		}},
		{"dirs", false, func(t *testing.T, url string) {
			runContract(t, "dirs", "-u", url+"/", "-w", wlist(t, "events"), "-ac=false", "-ledger", "off", "-allow", "127.0.0.1")
		}},
		{"params", false, func(t *testing.T, url string) {
			runContract(t, "params", "-u", url+"/events", "-w", wlist(t, "q"), "-rate", "10000", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db"))
		}},
		{"fuzz", false, func(t *testing.T, url string) {
			runContract(t, "fuzz", "-u", url+"/FUZZ", "-w", wlist(t, "events"), "-ac=false", "-mc", "all")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			var first atomic.Bool
			var whole, cut atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if first.Swap(true) {
					fmt.Fprint(w, "ok") // only the first request is the stream
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				for i := 0; i < 8; i++ { // 8 x 400 ms: past the 2 s a stream is given
					if _, err := fmt.Fprint(w, "data: tick\n\n"); err != nil || r.Context().Err() != nil {
						cut.Add(1)
						return
					}
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						cut.Add(1)
						return
					case <-time.After(400 * time.Millisecond):
					}
				}
				whole.Add(1)
			}))
			defer srv.Close()
			c.run(t, srv.URL)
			for i := 0; i < 50 && cut.Load()+whole.Load() == 0; i++ {
				time.Sleep(50 * time.Millisecond) // the handler sees the close a moment later
			}
			if c.cuts && (cut.Load() != 1 || whole.Load() != 0) {
				t.Errorf("%s: the stream was read to its end (cut %d, whole %d): it is cut after 2 s", c.name, cut.Load(), whole.Load())
			}
			if !c.cuts && (cut.Load() != 0 || whole.Load() != 1) {
				t.Errorf("%s: cut %d, whole %d: it reads the stream to its end", c.name, cut.Load(), whole.Load())
			}
		})
	}
}

// -replay-max limits the history reads over all roles, and the replay that
// follows gets the whole count again: four reads of the owners' own pages
// and four cross reads are sent under -replay-max 4, and the run is not
// stopped by it.
func TestRolesReplayMaxIsSpentByTheHistoryReadsAndTheReplayEachInFull(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	defer site.Close()
	browse := func(file, user string) string {
		var es []map[string]any
		for i := 1; i <= 2; i++ {
			es = append(es, harEntry(fmt.Sprintf("2026-10-29T10:00:0%d.000Z", i), "GET", fmt.Sprintf("%s/%s/%d", site.URL, user, i), "", 200, "Authorization", "Bearer "+user))
		}
		return writeHAR(t, file, es...)
	}
	_, rep, err := rolesRows(t, site.URL, "-no-anon", "-replay-max", "4", "-har", "alice="+browse("a.har", "alice"), "-har", "bob="+browse("b.har", "bob"))
	own, cross := 0, 0
	for _, r := range log.all() {
		switch {
		case r.path == "/alice/1" || r.path == "/alice/2":
			if r.auth == "Bearer alice" {
				own++
			} else if r.auth == "Bearer bob" {
				cross++
			}
		case r.path == "/bob/1" || r.path == "/bob/2":
			if r.auth == "Bearer bob" {
				own++
			} else if r.auth == "Bearer alice" {
				cross++
			}
		}
	}
	if own != 4 || cross != 4 || rep.Requests != 8 || exitCode(err) != exitOK || rep.Stopped != "" {
		t.Errorf("own reads %d, cross reads %d, requests %d, exit %d, stopped %q: want 4 and 4 under -replay-max 4, 8 in all, not stopped", own, cross, rep.Requests, exitCode(err), rep.Stopped)
	}
}

// A write's verdict `only its owner writes it` is given when no other
// role's write was accepted (2xx) and none was answered 5xx: each answer is a
// 4xx, a redirect or a 2xx that says it was denied. A 5xx among them is not
// that verdict.
func TestRolesOnlyItsOwnerWritesItAlsoWhenTheOthersAreRedirectedOrDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"x"}`)
			return
		}
		switch r.Header.Get("A") {
		case "1": // the owner
			w.WriteHeader(200)
		case "2":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "3":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"error":"access denied"}`)
		case "4":
			w.WriteHeader(500)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	session := func(v string) http.Header { return http.Header{"A": {v}} }
	owner := role{name: "alice", headers: []string{"A: 1"}, session: session("1")}
	bob := role{name: "bob", headers: []string{"A: 2"}, session: session("2")}
	carol := role{name: "carol", headers: []string{"A: 3"}, session: session("3")}
	dave := role{name: "dave", headers: []string{"A: 4"}, session: session("4")}
	req := []writeReq{{owner: "alice", method: "PUT", url: srv.URL + "/api/items/3", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"name":"y"}`), from: "alice.har", status: 200}}
	run := func(roles ...role) roleRow {
		rows, _, err := replayWrites(append([]role{{name: "anon"}, owner}, roles...), req, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%v %+v", err, rows)
		}
		return rows[0]
	}
	row := run(bob, carol)
	if row.Verdict != verdictWriteOwner || row.Answers["bob"].Status != 302 || row.Answers["anon"].Status != 404 || !(row.Answers["carol"].Error || row.Answers["carol"].Refusal) {
		t.Errorf("verdict %q, answers %+v: want %q with a 302, a 404 and a denied 2xx", row.Verdict, row.Answers, verdictWriteOwner)
	}
	if row := run(bob, dave); row.Verdict == verdictWriteOwner || row.Verdict != verdictWriteMixed {
		t.Errorf("a 5xx among the answers: verdict %q, want %q", row.Verdict, verdictWriteMixed)
	}
}
