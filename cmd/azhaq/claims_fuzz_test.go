package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/store"
)

// resetServer closes the connection of every request it gets, and counts them.
func resetServer(t *testing.T, failFirstOnly bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		mu.Lock()
		first := !seen[r.URL.Path]
		seen[r.URL.Path] = true
		mu.Unlock()
		if !failFirstOnly || first {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func numberedWords(t *testing.T, n int) string {
	t.Helper()
	var ws []string
	for i := 0; i < n; i++ {
		ws = append(ws, fmt.Sprintf("w%d", i))
	}
	return wlist(t, ws...)
}

// With -input-cmd the position of the input is shown, not what the command
// printed; several keywords print one block each.
func TestFuzzInputCmdShowsThePositionAndKeywordsPrintBlocks(t *testing.T) {
	srv := fuzzServer(t)
	out, errOut, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-input-cmd", "printf cmdword$FFUF_NUM", "-input-num", "3", "-ac=false", "-mc", "all"})
	})
	if err != nil {
		t.Fatalf("%v: %q", err, errOut)
	}
	if strings.Contains(out, "cmdword") {
		t.Errorf("the command's output is shown: %q", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines, want one for each of the 3 inputs: %q", len(lines), out)
	}
	seen := map[string]bool{}
	for _, l := range lines {
		seen[strings.Fields(l)[0]] = true
	}
	if len(seen) != 3 {
		t.Errorf("the lines do not show 3 different positions: %q", out)
	}
	// Several keywords: one block each, a line of numbers then a line for each keyword.
	out, _, err = captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ?x=BAR", "-w", wlist(t, "admin", "docs") + ":FUZZ", "-w", wlist(t, "p", "q") + ":BAR", "-ac=false", "-mc", "all"})
	})
	if err != nil {
		t.Fatal(err)
	}
	blocks := strings.Count(out, "[Status: ")
	if blocks != 4 || strings.Count(out, "    * FUZZ: ") != 4 || strings.Count(out, "    * BAR: ") != 4 {
		t.Errorf("want 4 blocks, each with a line for FUZZ and one for BAR: %q", out)
	}
}

// A target that does not answer: five unanswered requests in a row stop the
// run, exit 3, and the summary lists the origin under "did not answer".
func TestFuzzFiveUnansweredRequestsStopTheRun(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens here now: the connection is refused
	words := numberedWords(t, 40)
	args := []string{"-u", "http://" + addr + "/FUZZ", "-w", words, "-ac=false", "-mc", "all", "-t", "1"}
	_, rep, err := fuzzRows(t, args...)
	if exitCode(err) != exitPartial || rep.Exit != exitPartial {
		t.Errorf("exit %d (summary %d), want %d", exitCode(err), rep.Exit, exitPartial)
	}
	if len(rep.Unreachable) != 1 || !strings.Contains(rep.Unreachable[0], addr) {
		t.Errorf("unreachable %v, want the origin %s", rep.Unreachable, addr)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "stopped answering after 5 requests in a row without an answer") {
		t.Errorf("notes %q", rep.Notes)
	}
	if rep.Requests >= 40 {
		t.Errorf("%d requests: the run did not stop", rep.Requests)
	}
	_, errOut, _ := captureBoth(t, func() error { return cmdFuzz(args) })
	if !strings.Contains(errOut, "! did not answer: "+rep.Unreachable[0]) {
		t.Errorf("the summary does not list the origin under did not answer: %q", errOut)
	}
}

// -se stops after twice -t failures of any kind in a row, -se-after N after
// N; without them a reset connection (an answer that is a failure but not a
// silence) stops nothing; a request that is answered ends the row.
func TestFuzzSEStopsAfterFailuresInARow(t *testing.T) {
	srv, _ := resetServer(t, false)
	base := []string{"-u", srv.URL + "/FUZZ", "-w", numberedWords(t, 40), "-ac=false", "-mc", "all"}
	_, rep, _ := fuzzRows(t, append(base, "-t", "2")...)
	if len(rep.Unreachable) != 0 || rep.Stopped != "" || len(rep.Notes) > 1 {
		t.Errorf("without -se: unreachable %v, stopped %q, notes %q", rep.Unreachable, rep.Stopped, rep.Notes)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-t", "2", "-se"}, "after 4 requests in a row failing"},
		{[]string{"-t", "3", "-se"}, "after 6 requests in a row failing"},
		{[]string{"-t", "2", "-se", "-se-after", "3"}, "after 3 requests in a row failing"},
		{[]string{"-t", "2", "-sa"}, "after 4 requests in a row failing"},
	} {
		_, rep, err := fuzzRows(t, append(append([]string(nil), base...), c.args...)...)
		if len(rep.Unreachable) != 1 || !strings.Contains(strings.Join(rep.Notes, "\n"), c.want) || exitCode(err) != exitPartial {
			t.Errorf("%v: exit %d, unreachable %v, notes %q, want %q", c.args, exitCode(err), rep.Unreachable, rep.Notes, c.want)
		}
	}
	// Every first try fails and its retry is answered: no row of failures.
	srv2, _ := resetServer(t, true)
	rows, rep, err := fuzzRows(t, "-u", srv2.URL+"/FUZZ", "-w", numberedWords(t, 20), "-ac=false", "-mc", "all", "-t", "1", "-se", "-se-after", "2")
	if err != nil || len(rep.Unreachable) != 0 || len(rows) != 20 {
		t.Errorf("failures with an answer between them: %d rows, unreachable %v, err %v", len(rows), rep.Unreachable, err)
	}
}

// -sf and -sa end the run with exit 4 and say why; -maxtime-job adds a note.
func TestFuzzStopFlagsSayWhatTheyDid(t *testing.T) {
	status := atomic.Int64{}
	status.Store(403)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)
	base := []string{"-u", srv.URL + "/FUZZ", "-w", numberedWords(t, 200), "-ac=false", "-mc", "all", "-t", "1"}
	for _, flag := range []string{"-sf", "-sa"} {
		_, rep, err := fuzzRows(t, append(append([]string(nil), base...), flag)...)
		if exitCode(err) != exitLimit || !regexp.MustCompile(`^over 95% of the first (5[1-9]|[6-9]\d|\d{3,}) answers were 403`).MatchString(rep.Stopped) || !strings.Contains(rep.Stopped, " answers were 403 (-sf/-sa): the target is refusing, or the run is blocked") {
			t.Errorf("%s: exit %d, stopped %q", flag, exitCode(err), rep.Stopped)
		}
		if !strings.Contains(rep.Resume, "-start ") || rep.Requests >= 200 || rep.Requests < 51 {
			t.Errorf("%s: %d requests, resume %q: want a stop after the first 50 or more, with the -start that goes on", flag, rep.Requests, rep.Resume)
		}
	}
	// -sf alone does not look at 429; -sa does.
	status.Store(429)
	// 200 matches with their evidence overfill the pipe the test reads
	// stdout from, so -quiet keeps them off it; the summary counts them.
	_, rep, err := fuzzRows(t, append(append([]string(nil), base...), "-sf", "-quiet")...)
	if err != nil || rep.Stopped != "" || rep.Requests != 200 {
		t.Errorf("-sf on 429: exit %d, stopped %q, %d requests", exitCode(err), rep.Stopped, rep.Requests)
	}
	_, rep, err = fuzzRows(t, append(append([]string(nil), base...), "-sa")...)
	if exitCode(err) != exitLimit || !strings.Contains(rep.Stopped, "over 20% of the first ") || !strings.Contains(rep.Stopped, "were 429 (-sa): the target is rate limiting; lower -rate or -t") {
		t.Errorf("-sa on 429: exit %d, stopped %q", exitCode(err), rep.Stopped)
	}
	// -maxtime-job gives up the job and notes it.
	status.Store(200)
	_, rep, err = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", numberedWords(t, 100), "-ac=false", "-mc", "all", "-t", "1", "-p", "0.05", "-maxtime-job", "0.3")
	if err != nil || rep.Stopped != "" || rep.Requests >= 100 || !strings.Contains(strings.Join(rep.Notes, "\n"), "-maxtime-job ended "+srv.URL+"/FUZZ after ") {
		t.Errorf("-maxtime-job: exit %d, stopped %q, %d requests, notes %q", exitCode(err), rep.Stopped, rep.Requests, rep.Notes)
	}
}

// A report that cannot be written is a failed entry and exit 3; the place is
// tested before the first request.
func TestFuzzReportThatCannotBeWrittenIsAFailure(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "r.json")
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		os.Mkdir(report, 0o755) // the place was free when the run began
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a", "b"), "-ac=false", "-o", report, "-t", "1")
	if exitCode(err) != exitPartial || rep.Exit != exitPartial {
		t.Errorf("exit %d (summary %d), want %d", exitCode(err), rep.Exit, exitPartial)
	}
	found := false
	for _, f := range rep.Failed {
		found = found || strings.Contains(f.Error, "the report "+report+" was not written")
	}
	if !found || rep.Complete {
		t.Errorf("failed %+v, complete %v: want an entry that says the report was not written", rep.Failed, rep.Complete)
	}
	// A place that cannot take the file is found before the first request.
	n.Store(0)
	_, _, err = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a"), "-ac=false", "-o", filepath.Join(dir, "nodir", "r.json"))
	if exitCode(err) != exitUsage || n.Load() != 0 {
		t.Errorf("a missing directory: exit %d, %d requests, want a usage error and none sent", exitCode(err), n.Load())
	}
}

// A name ending .csv, .ecsv, .html, .md or .ejson takes that format without
// -of; -of all writes one file of each of the six; -or says it wrote nothing.
func TestFuzzReportFormatComesFromTheName(t *testing.T) {
	srv := fuzzServer(t)
	dir := t.TempDir()
	words := wlist(t, "admin")
	for name, want := range map[string]string{
		"r.csv":   "url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile,Ffufhash",
		"r.ecsv":  "url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile,Ffufhash",
		"r.html":  "<html",
		"r.md":    "| FUZZ |",
		"r.ejson": `"results"`,
	} {
		p := filepath.Join(dir, name)
		if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words, "-ac=false", "-o", p); err != nil {
			t.Fatal(name, err)
		}
		raw, _ := os.ReadFile(p)
		got := string(raw)
		if !strings.Contains(got, want) {
			t.Errorf("%s does not hold %q:\n%.300s", name, want, got)
		}
		switch name {
		case "r.ecsv":
			if !strings.Contains(got, "YWRtaW4=") {
				t.Errorf("%s: input values are not in base64: %.200s", name, got)
			}
		case "r.ejson":
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil || doc["config"] != nil || !strings.Contains(got, "YWRtaW4=") {
				t.Errorf("%s: want no config and base64 inputs (%v): %.400s", name, err, got)
			}
		case "r.csv":
			if !strings.Contains(got, ",admin") && !strings.Contains(got, "admin,") {
				t.Errorf("%s: input values are not plain: %.200s", name, got)
			}
		}
	}
	// A suffix of none of them is json, and -of wins over any suffix.
	p := filepath.Join(dir, "r.out")
	fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words, "-ac=false", "-o", p)
	if raw, _ := os.ReadFile(p); !strings.Contains(string(raw), `"config"`) {
		t.Errorf("r.out is not json: %.100s", raw)
	}
	p = filepath.Join(dir, "r.csv")
	fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words, "-ac=false", "-o", p, "-of", "md")
	if raw, _ := os.ReadFile(p); !strings.Contains(string(raw), "| FUZZ |") {
		t.Errorf("-of md on r.csv: %.100s", raw)
	}
	// -of all: one file of each of the six.
	base := filepath.Join(dir, "all")
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words, "-ac=false", "-o", base, "-of", "all"); err != nil {
		t.Fatal(err)
	}
	for _, suf := range []string{"json", "ejson", "html", "md", "csv", "ecsv"} {
		if st, err := os.Stat(base + "." + suf); err != nil || st.Size() == 0 {
			t.Errorf("-of all wrote no %s.%s: %v", base, suf, err)
		}
	}
	// -or: nothing written for no matches, and the summary says so.
	none := filepath.Join(dir, "none.json")
	_, rep, _ := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "zzz"), "-ac=false", "-fc", "200", "-o", none, "-or")
	if _, err := os.Stat(none); err == nil || !strings.Contains(strings.Join(rep.Notes, "\n"), "no matches and -or: "+none+" was not written") {
		t.Errorf("-or: file written %v, notes %q", err == nil, rep.Notes)
	}
}

// Calibration needs its keyword in the request: without it a note says
// nothing was calibrated. Its guesses are counted by -max-requests.
func TestFuzzCalibrationKeywordAndBudget(t *testing.T) {
	t.Cleanup(egress.Reset)
	srv := fuzzServer(t)
	words := wlist(t, "admin", "x")
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words, "-ac", "-ack", "USER")
	if err != nil || rep.Requests != 2 || !strings.Contains(strings.Join(rep.Notes, "\n"), "the keyword USER in the request (-ack names another): nothing was calibrated") {
		t.Errorf("-ack USER: %d requests, notes %q, err %v", rep.Requests, rep.Notes, err)
	}
	// 6 guesses of the default strategy, then the words; a budget of 7 leaves one word.
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "docs", "x", "y"), "-ac", "-max-requests", "7", "-t", "1")
	if exitCode(err) != exitLimit || rep.Requests != 7 || len(rows) > 1 {
		t.Errorf("-ac -max-requests 7: exit %d, %d requests, rows %q: the calibration guesses are not counted", exitCode(err), rep.Requests, rows)
	}
	_, rep, err = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "docs", "x", "y"), "-ac", "-max-requests", "10", "-t", "1")
	if err != nil || rep.Requests != 10 {
		t.Errorf("-ac -max-requests 10: exit %d, %d requests: the 6 guesses and the 4 words are 10", exitCode(err), rep.Requests)
	}
}

// -quiet prints no matches and no progress, only the summary; the matches
// are still counted and kept by -db and -o.
func TestFuzzQuietPrintsOnlyTheSummary(t *testing.T) {
	srv := fuzzServer(t)
	dir := t.TempDir()
	db, report := filepath.Join(dir, "q.db"), filepath.Join(dir, "q.json")
	out, errOut, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, "admin", "docs", "x"), "-ac=false", "-quiet", "-db", db, "-o", report, "-ledger", "off"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Errorf("stdout %q, want nothing", out)
	}
	if !strings.Contains(errOut, "azhaq fuzz: 3 matches") || strings.Contains(errOut, "[Status:") {
		t.Errorf("stderr %q: want the summary with the 3 matches counted, and no match", errOut)
	}
	raw, _ := os.ReadFile(report)
	if strings.Count(string(raw), `"position":`) != 3 {
		t.Errorf("the report does not keep the 3 matches: %.300s", raw)
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	keys := 0
	ents, _ := st.Entities()
	for _, e := range ents {
		if strings.HasPrefix(e.Key, srv.URL+"/") {
			keys++
		}
	}
	if keys != 3 {
		t.Errorf("-db keeps %d of the 3 matches: %v", keys, ents)
	}
}

// A run stopped by -max-requests at one thread leaves -start N: the inputs asked, in a row.
func TestFuzzStartIsTheFirstInputNotAskedInARow(t *testing.T) {
	t.Cleanup(egress.Reset)
	srv := fuzzServer(t)
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", numberedWords(t, 10), "-ac=false", "-max-requests", "4", "-t", "1")
	if exitCode(err) != exitLimit || !strings.Contains(rep.Resume, " -start 4") || strings.Count(rep.Resume, "-start") != 1 {
		t.Errorf("exit %d, resume %q: want -start 4 once", exitCode(err), rep.Resume)
	}
	// Run by hand, from there, it asks the others.
	_, rep, err = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", numberedWords(t, 10), "-ac=false", "-start", "4", "-t", "1")
	if err != nil || rep.Requests != 6 {
		t.Errorf("-start 4: %d requests, err %v, want the 6 others", rep.Requests, err)
	}
}

// -kill-file: every request stops at it, exit 4.
func TestFuzzStopsAtTheKillFile(t *testing.T) {
	t.Cleanup(egress.Reset)
	kill := filepath.Join(t.TempDir(), "stop")
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 3 {
			os.WriteFile(kill, nil, 0o644)
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", numberedWords(t, 200), "-ac=false", "-t", "1", "-kill-file", kill, "-rate", "200")
	if exitCode(err) != exitLimit || !strings.Contains(rep.Stopped, "kill file "+kill+" exists") {
		t.Errorf("exit %d, stopped %q", exitCode(err), rep.Stopped)
	}
	if n.Load() < 3 || n.Load() > 10 || rep.Requests != n.Load() {
		t.Errorf("the server saw %d requests, the summary says %d: want a stop soon after the file appeared", n.Load(), rep.Requests)
	}
}

// socksProxy is a SOCKS5 proxy with no authentication that relays CONNECT:
// it notes the address each connection asks for and whether it was a name.
func socksProxy(t *testing.T, upstream string) (addr string, asked func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 262)
				if _, err := io.ReadFull(c, b[:2]); err != nil {
					return
				}
				io.ReadFull(c, b[:int(b[1])]) // the methods
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, b[:4]); err != nil {
					return
				}
				var host string
				switch b[3] {
				case 1:
					io.ReadFull(c, b[:4])
					host = net.IP(b[:4]).String()
				case 3:
					io.ReadFull(c, b[:1])
					n := int(b[0])
					io.ReadFull(c, b[:n])
					host = "name:" + string(b[:n])
				default:
					return
				}
				io.ReadFull(c, b[:2])
				port := int(b[0])<<8 | int(b[1])
				mu.Lock()
				got = append(got, fmt.Sprintf("%s:%d", host, port))
				mu.Unlock()
				up, err := net.Dial("tcp", upstream) // every connection goes where the test says
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return "127.0.0.1:" + fmt.Sprint(l.Addr().(*net.TCPAddr).Port), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

// -x sends every request through an http, https, socks5 or socks5h proxy.
// The proxies here deliver to a stand-in, so a request that went round one
// would show: the target never sees it.
func TestFuzzSendsEveryRequestThroughAnyKindOfProxy(t *testing.T) {
	var direct, delivered atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1) }))
	t.Cleanup(target.Close)
	stand := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		fmt.Fprint(w, "from the stand-in")
	}))
	t.Cleanup(stand.Close)
	standAddr := strings.TrimPrefix(stand.URL, "http://")
	port := strings.Split(target.URL, ":")[2]
	words := wlist(t, "admin", "docs", "x")
	check := func(kind, proxyURL, targetURL string, extra ...string) {
		t.Helper()
		delivered.Store(0)
		args := append([]string{"-u", targetURL + "/FUZZ", "-w", words, "-ac=false", "-mc", "all", "-x", proxyURL}, extra...)
		rows, rep, err := fuzzRows(t, args...)
		if err != nil || len(rows) != 3 || rep.Requests != 3 {
			t.Errorf("%s: %d rows, %d requests, err %v", kind, len(rows), rep.Requests, err)
		}
		if delivered.Load() != 3 || direct.Load() != 0 {
			t.Errorf("%s: the stand-in behind the proxy got %d requests and the target %d: want 3 and 0", kind, delivered.Load(), direct.Load())
		}
	}
	// An http and an https proxy, as a forward proxy that relays to the stand-in.
	for _, tls := range []bool{false, true} {
		var mu sync.Mutex
		var seen []string
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.URL.Host)
			mu.Unlock()
			resp, err := http.Get(stand.URL + r.URL.Path)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			defer resp.Body.Close()
			io.Copy(w, resp.Body)
		})
		var px *httptest.Server
		if tls {
			px = httptest.NewTLSServer(h)
		} else {
			px = httptest.NewServer(h)
		}
		t.Cleanup(px.Close)
		check(map[bool]string{false: "http", true: "https"}[tls], px.URL, target.URL)
		mu.Lock()
		if len(seen) != 3 {
			t.Errorf("tls %v: the proxy was asked %d times, want 3", tls, len(seen))
		}
		mu.Unlock()
	}
	addr, asked := socksProxy(t, standAddr)
	check("socks5", "socks5://"+addr, target.URL)
	for _, got := range asked() {
		if got != "127.0.0.1:"+port {
			t.Errorf("socks5: the proxy was asked for %v", asked())
			break
		}
	}
	addrH, askedH := socksProxy(t, standAddr)
	check("socks5h", "socks5h://"+addrH, "http://app.test:"+port, "-allow", "app.test")
	if got := askedH(); len(got) == 0 || got[0] != "name:app.test:"+port {
		t.Errorf("socks5h: the proxy was asked for %v: want the name app.test handed to it", got)
	}
}

// fuzzKilledWith is fuzzKilled with more flags: it starts fuzz with -db,
// kills it with SIGKILL once the server has seen after requests, and says
// what the server saw by method and path.
func fuzzKilledWith(t *testing.T, method string, words, after int, extra ...string) (db string, seen func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.Method+" "+r.URL.Path]++
		mu.Unlock()
	}))
	t.Cleanup(s.Close)
	var lines []string
	for i := 1; i <= words; i++ {
		lines = append(lines, fmt.Sprintf("w%d", i))
	}
	dir := t.TempDir()
	db = filepath.Join(dir, "f.db")
	args := []string{"fuzz", "-u", s.URL + "/FUZZ", "-w", wlist(t, lines...), "-ac=false", "-mc", "all", "-rate", "25", "-t", "2", "-db", db, "-json"}
	if method != "" {
		args = append(args, "-X", method, "-d", "a=b")
	}
	cmd := exec.Command(os.Args[0], append(args, extra...)...)
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	total := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, c := range counts {
			n += c
		}
		return n
	}
	for i := 0; i < 400 && total() < after; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if total() < after || total() >= words {
		_ = cmd.Process.Kill()
		t.Fatalf("the server saw %d requests of %d before the kill, want %d or more and not all", total(), words, after)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	dataDirs.Store(t.Name(), dir)
	ledgerHoldsAKilledRun(t)
	return db, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range counts {
			out[k] = v
		}
		return out
	}
}

// A run killed with SIGKILL is continued from the last second kept: with
// -ledger off nothing says what was sent after it, so a write goes out
// twice; with the ledger it does not.
func TestFuzzKilledWithoutALedgerMaySendAWriteTwice(t *testing.T) {
	const words = 60
	twice := func(seen map[string]int) (n int) {
		for k, c := range seen {
			if strings.HasPrefix(k, "POST ") && c > 1 {
				n++
			}
		}
		return n
	}
	// Killed in the first second, before anything was kept: the resume asks from the first input.
	db, seen := fuzzKilledWith(t, "POST", words, 3, "-ledger", "off")
	if _, _, code := runContract(t, "resume", "-db", db, "-ledger", "off"); code != exitOK {
		t.Fatalf("resume: exit %d", code)
	}
	if n := twice(seen()); n < 3 {
		t.Errorf("-ledger off: %d writes went out twice, want the 3 the first run sent", n)
	}
	db, seen = fuzzKilledWith(t, "POST", words, 3)
	if _, _, code := runContract(t, "resume", "-db", db); code != exitOK {
		t.Fatalf("resume: exit %d", code)
	}
	if n := twice(seen()); n != 0 {
		t.Errorf("with the ledger: %d writes went out twice", n)
	}
}

// A run with -recursion or -control goes on from its first input, since the
// directories found and the filters changed are not in what is kept; it too
// holds back the writes already sent.
func TestFuzzKilledRecursionOrControlRunGoesOnFromItsFirstInput(t *testing.T) {
	const words, after = 60, 35 // the kill comes after the first second kept
	ctl := filepath.Join(t.TempDir(), "ctl")
	os.WriteFile(ctl, nil, 0o644)
	for _, extra := range [][]string{{"-recursion"}, {"-control", ctl}} {
		db, seen := fuzzKilledWith(t, "", words, after, extra...)
		before := seen()
		if _, _, code := runContract(t, "resume", "-db", db); code != exitOK {
			t.Fatalf("%v: resume: exit %d", extra, code)
		}
		again := 0
		for k, c := range seen() {
			if c > 1 && before[k] > 0 {
				again++
			}
		}
		if again < after-2 { // every input asked before the kill is asked again (a few may not have been answered)
			t.Errorf("%v: %d inputs asked again after the kill, want the %d it had asked: it goes on from the first input", extra, again, after)
		}
		db, seen = fuzzKilledWith(t, "POST", words, after, extra...)
		if _, _, code := runContract(t, "resume", "-db", db); code != exitOK {
			t.Fatalf("%v: resume of writes: exit %d", extra, code)
		}
		for i := 1; i <= words; i++ {
			if k := fmt.Sprintf("POST /w%d", i); seen()[k] != 1 {
				t.Errorf("%v: %s reached the server %d times, want 1", extra, k, seen()[k])
			}
		}
	}
}

// Without -x, HTTP_PROXY applies by Go's rule: a loopback target stays
// direct, a name goes through it; -replay-proxy is not read from the
// environment. Go reads the environment once, so the run is a process of its own.
func TestFuzzEnvironmentProxyFollowsGosRule(t *testing.T) {
	srv := fuzzServer(t)
	px, seen := countingProxy(srv, false, 0)
	defer px.Close()
	port := strings.Split(srv.URL, ":")[2]
	words := wlist(t, "admin", "x")
	runIt := func(target string, extra ...string) (rows int, summary string) {
		args := append([]string{"fuzz", "-u", target + "/FUZZ", "-w", words, "-ac=false", "-mc", "all", "-json"}, extra...)
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+t.TempDir(), "HTTP_PROXY="+px.URL, "http_proxy="+px.URL, "NO_PROXY=", "no_proxy=")
		var out, errOut strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errOut
		cmd.Run()
		return strings.Count(out.String(), `"position"`), errOut.String()
	}
	rows, sum := runIt(srv.URL)
	if rows != 2 || len(seen()) != 0 || strings.Contains(sum, "replay proxy") {
		t.Errorf("a loopback target: %d rows, proxy saw %v, summary %s: want direct", rows, seen(), sum)
	}
	// A name that is not loopback goes through the proxy the environment names.
	rows, sum = runIt("http://app.test:"+port, "-allow", "app.test")
	if got := seen(); rows != 2 || len(got) != 2 {
		t.Errorf("a name: %d rows, proxy saw %v, summary %s: want through the proxy", rows, got, sum)
	}
	// -x sends everything, loopback included, whatever the environment says.
	before := len(seen())
	rows, _ = runIt(srv.URL, "-x", px.URL)
	if got := seen(); rows != 2 || len(got)-before != 2 {
		t.Errorf("-x: %d rows, proxy saw %v", rows, got)
	}
}

// The copies -replay-proxy sends are the proxy's own: they are not in the
// ledger, the budget or the pace, and the summary says how many went.
func TestFuzzReplayCopiesAreNotRequestsToTheTarget(t *testing.T) {
	t.Cleanup(egress.Reset)
	srv := fuzzServer(t)
	px, copies := countingProxy(srv, false, 0)
	defer px.Close()
	led := filepath.Join(t.TempDir(), "l.jsonl")
	// A budget of exactly the 3 inputs: a copy counted in it would be refused.
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "admin", "docs", "x"), "-ac=false", "-mc", "all", "-t", "1",
		"-replay-proxy", px.URL, "-max-requests", "3", "-ledger", led)
	if err != nil || rep.Requests != 3 || rep.Stopped != "" {
		t.Errorf("exit %d, %d requests, stopped %q: the copies were counted in the budget", exitCode(err), rep.Requests, rep.Stopped)
	}
	if got := copies(); len(got) != 3 {
		t.Errorf("the replay proxy got %v, want one copy of each of the 3 matches", got)
	}
	if n := ledgerHTTP(t, led); n != 3 {
		t.Errorf("the ledger holds %d requests, want the 3 to the target and no copy", n)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "3 matches were sent through the replay proxy "+px.URL) {
		t.Errorf("the summary does not say how many were sent: %q", rep.Notes)
	}
}

// -od DIR writes each match's request and answer as one file, named by the
// md5 of its text, shown as | RES | in the text output and as resultfile in
// the reports.
func TestFuzzODKeepsEachMatchAsAFileNamedByItsHash(t *testing.T) {
	srv := fuzzServer(t)
	dir := t.TempDir()
	od := filepath.Join(dir, "od")
	out, _, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, "admin"), "-ac=false", "-od", od, "-o", filepath.Join(dir, "r.json"), "-of", "json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(od)
	if len(files) != 1 {
		t.Fatalf("%d files in -od, want 1", len(files))
	}
	name := files[0].Name()
	text, _ := os.ReadFile(filepath.Join(od, name))
	if fmt.Sprintf("%x", md5.Sum(text)) != name || !strings.Contains(string(text), "GET /admin") || !strings.Contains(string(text), "the admin page") {
		t.Errorf("the file %s is not the request and answer named by the md5 of its text: %.200s", name, text)
	}
	if !strings.Contains(out, "| RES | "+name) {
		t.Errorf("the text output does not show the file: %q", out)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "r.json"))
	if !strings.Contains(string(raw), `"resultfile":"`+name+`"`) {
		t.Errorf("the report does not name the file: %.300s", raw)
	}
}

// A Host from a -request file is not typed by you: one that differs from -u
// is refused unless -allow names it.
func TestFuzzRequestFileHostIsHeldToTheScope(t *testing.T) {
	var host atomic.Value
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		host.Store(r.Host)
	}))
	t.Cleanup(srv.Close)
	req := filepath.Join(t.TempDir(), "r.req")
	os.WriteFile(req, []byte("GET /FUZZ HTTP/1.1\r\nHost: other.lab\r\n\r\n"), 0o644)
	base := []string{"-u", srv.URL + "/FUZZ", "-request", req, "-w", wlist(t, "a"), "-ac=false", "-mc", "all"}
	_, _, err := fuzzRows(t, base...)
	if exitCode(err) != exitUsage || n.Load() != 0 {
		t.Errorf("exit %d, %d requests: a Host that differs from -u must be refused before anything is sent", exitCode(err), n.Load())
	}
	rows, _, err := fuzzRows(t, append(base, "-allow", "127.0.0.1", "-allow", "other.lab")...)
	if err != nil || len(rows) != 1 || host.Load() != "other.lab" {
		t.Errorf("with -allow: exit %d, %d rows, Host %v", exitCode(err), len(rows), host.Load())
	}
	// The same file with a Host that is -u's own needs no -allow.
	os.WriteFile(req, []byte("GET /FUZZ HTTP/1.1\r\nHost: "+strings.TrimPrefix(srv.URL, "http://")+"\r\n\r\n"), 0o644)
	if rows, _, err := fuzzRows(t, base...); err != nil || len(rows) != 1 {
		t.Errorf("the host of -u: exit %d, %d rows", exitCode(err), len(rows))
	}
}

// With -db the workspace holds the command from the first request on, and
// the inputs asked and the matches so far are kept every second.
func TestFuzzKilledRunLeavesItsCommandItsInputsAndItsMatches(t *testing.T) {
	db, _ := fuzzKilledWith(t, "", 60, 35)
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if cmd := st.GetMeta(fuzzResumeKey); !strings.Contains(cmd, "-u=") && !strings.Contains(cmd, "FUZZ") {
		t.Errorf("the workspace holds no command to resume: %q", cmd)
	}
	var asked fuzzAsked
	if err := json.Unmarshal([]byte(st.GetMeta(fuzzAskedKey)), &asked); err != nil || asked.Total != 60 || len(asked.Spans) == 0 {
		t.Errorf("the inputs asked are not kept: %q (%v)", st.GetMeta(fuzzAskedKey), err)
	}
	asks := 0
	for _, sp := range asked.Spans {
		asks += sp[1] - sp[0]
	}
	ents, _ := st.Entities()
	if asks < 10 || len(ents) != asks { // every input matches (-mc all): one match kept for each input kept
		t.Errorf("%d inputs asked are kept but %d matches: the matches so far are not kept with them", asks, len(ents))
	}
}

// A value read from an answer can never change the scheme, host or port of a
// request: the run is refused with the reason and exit 3.
func TestFuzzFlightValueCannotMoveARequest(t *testing.T) {
	var decoyHits, otherPath atomic.Int64
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { decoyHits.Add(1) }))
	t.Cleanup(decoy.Close)
	var val atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/form" {
			fmt.Fprintf(w, "val=%s", val.Load())
			return
		}
		otherPath.Add(1)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	file := func(name, text string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(text), 0o644)
		return p
	}
	pre1 := file("pre1.req", "GET /form HTTP/1.1\n\n")
	for _, c := range []struct{ what, value, second string }{
		{"host in the path", decoy.URL + "/x", "GET V HTTP/1.1\n\n"},
		{"scheme in the path", "https://" + host + "/x", "GET V HTTP/1.1\n\n"},
		{"port in the path", "http://127.0.0.1:1/x", "GET V HTTP/1.1\n\n"},
		{"Host header", "other.test", "GET /x HTTP/1.1\nHost: V\n\n"},
		{"a value in the query", "abc", "GET /x?q=V HTTP/1.1\n\n"}, // it moves nothing: no refusal
	} {
		val.Store(c.value)
		otherPath.Store(0)
		decoyHits.Store(0)
		_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a"), "-ac=false", "-mc", "all",
			"-preflight", pre1, "-preflight-var", `V:val=(\S+)`, "-preflight", file("pre2.req", c.second))
		refused := strings.Contains(fmt.Sprint(rep.Failed), "cannot choose where requests go")
		if c.what == "a value in the query" {
			if refused || exitCode(err) != exitOK {
				t.Errorf("%s: a value that moves nothing was refused: exit %d, %+v", c.what, exitCode(err), rep.Failed)
			}
			continue
		}
		if !refused || exitCode(err) != exitPartial || decoyHits.Load() != 0 || otherPath.Load() != 0 {
			t.Errorf("%s: exit %d, failed %+v, decoy %d, main requests %d: want a refusal, exit 3 and nothing sent", c.what, exitCode(err), rep.Failed, decoyHits.Load(), otherPath.Load())
		}
	}
	// ffuf's -preflight-anyhost does not exist here.
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a"), "-preflight", pre1, "-preflight-anyhost"); exitCode(err) != exitUsage {
		t.Errorf("-preflight-anyhost: exit %d, want a usage error", exitCode(err))
	}
	// The same for the request the words go into.
	val.Store("other.test")
	otherPath.Store(0)
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a"), "-ac=false", "-mc", "all", "-H", "Host: V",
		"-preflight", pre1, "-preflight-var", `V:val=(\S+)`)
	if !strings.Contains(fmt.Sprint(rep.Failed), "cannot choose where requests go") || exitCode(err) != exitPartial || otherPath.Load() != 0 {
		t.Errorf("-H Host: exit %d, failed %+v, %d requests", exitCode(err), rep.Failed, otherPath.Load())
	}
}

// A flight file that names a host the run may not touch is refused as
// outside the scope, and goes once -allow names the host (next to the one of -u).
func TestFuzzFlightFileOutsideTheScope(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 is not a loopback address here")
	}
	var hits atomic.Int64
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	other.Listener.Close()
	other.Listener = l
	other.Start()
	t.Cleanup(other.Close)
	srv := fuzzServer(t)
	pre := filepath.Join(t.TempDir(), "pre.req")
	os.WriteFile(pre, []byte("GET "+other.URL+"/x HTTP/1.1\n\n"), 0o644)
	base := []string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, "a"), "-ac=false", "-mc", "all", "-preflight", pre}
	_, rep, err := fuzzRows(t, base...)
	if exitCode(err) != exitPartial || !strings.Contains(fmt.Sprint(rep.Failed), "127.0.0.2 is outside the scope: not sent (-allow adds it)") || hits.Load() != 0 {
		t.Errorf("exit %d, failed %+v, %d requests to the other host", exitCode(err), rep.Failed, hits.Load())
	}
	_, rep, err = fuzzRows(t, append(base, "-allow", "127.0.0.1", "-allow", "127.0.0.2")...)
	if err != nil || hits.Load() != 1 || len(rep.Failed) != 0 {
		t.Errorf("with -allow: exit %d, failed %+v, %d requests to the other host", exitCode(err), rep.Failed, hits.Load())
	}
	// -allow with the other host alone leaves out the host of -u: it is the default only without -allow.
	_, _, err = fuzzRows(t, append(base, "-allow", "127.0.0.2")...)
	if exitCode(err) != exitUsage {
		t.Errorf("-allow 127.0.0.2 alone: exit %d, want a usage error: -u's host is outside it", exitCode(err))
	}
}

// Without -ac the run asks for no name that cannot exist: it sends one request
// for each word, and no match has a control. With -ac the guesses are sent
// besides.
func TestFuzzWithoutACAsksNoNameThatCannotExistAndNoMatchHasAControl(t *testing.T) {
	t.Cleanup(egress.Reset)
	var seen atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.URL.Path == "/real" {
			fmt.Fprint(w, "a real page of its own")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "no such item: %s", strings.TrimPrefix(r.URL.Path, "/"))
	}))
	t.Cleanup(srv.Close)
	words := wlist(t, "real", "foo", "bar")
	_, rows := fuzzWords(t, "-u", srv.URL+"/FUZZ", "-w", words, "-mc", "all")
	if got := seen.Load(); got != 3 {
		t.Errorf("without -ac the server saw %d requests, want the 3 words", got)
	}
	for w, row := range rows {
		if row["control"] != nil {
			t.Errorf("%s has a control and no calibration was asked: %v", w, row["control"])
		}
	}
	if len(rows) != 3 {
		t.Errorf("%d matches, want 3", len(rows))
	}
	seen.Store(0)
	fuzzWords(t, "-u", srv.URL+"/FUZZ", "-w", words, "-mc", "all", "-ac")
	if got := seen.Load(); got <= 3 {
		t.Errorf("with -ac the server saw %d requests: the calibration guesses were not asked", got)
	}
}

// Several matchers join with -mmode or (any one holds) or and (every one
// holds), and several filters with -fmode or (any one drops the answer) or
// and (every one must). The stand-in has four 302 answers, one of them with
// Location: index.php.
func TestFuzzFilterModesOrDropsOnAnyFilterAndAndOnEveryFilter(t *testing.T) {
	srv := matcherServer(t)
	words := wlist(t, "a", "b", "c", "d", "ok", "plain", "zzz")
	for _, c := range []struct {
		name  string
		flags []string
		want  string
	}{
		{"-fmode or by default: -fc 302 drops four, -fr index.php the same one", []string{"-mc", "all", "-fc", "302", "-fr", "index.php"}, "ok plain zzz"},
		{"-fmode or named", []string{"-mc", "all", "-fc", "302", "-fr", "index.php", "-fmode", "or"}, "ok plain zzz"},
		{"-fmode and: only what both filters hold for is dropped", []string{"-mc", "all", "-fc", "302", "-fr", "index.php", "-fmode", "and"}, "b c d ok plain zzz"},
		{"-fmode or: -fc 404 or -fr needle", []string{"-mc", "all", "-fc", "404", "-fr", "needle"}, "a b c d plain"},
		{"-fmode and: -fc 404 and -fr needle drops nothing", []string{"-mc", "all", "-fc", "404", "-fr", "needle", "-fmode", "and"}, "a b c d ok plain zzz"},
		{"-mmode or by default", []string{"-mc", "200", "-mr", "Location: index.php"}, "a ok plain"},
		{"-mmode and", []string{"-mc", "200", "-mr", "needle", "-mmode", "and"}, "ok"},
	} {
		got, _ := fuzzWords(t, append([]string{"-u", srv.URL + "/FUZZ", "-w", words}, c.flags...)...)
		if g := strings.Join(got, " "); g != c.want {
			t.Errorf("%s: %v listed %q, want %q", c.name, c.flags, g, c.want)
		}
	}
}
