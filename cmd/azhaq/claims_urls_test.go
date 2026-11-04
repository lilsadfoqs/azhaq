package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// archivesOf serves the five archives of azhaq urls with the URLs given for
// each (by provider name), and gives the -archive flags. wayback may be
// slowed: its page 1 waits for release.
func archivesOf(t *testing.T, urls map[string][]string) []string {
	t.Helper()
	jsonl := func(us []string, key string) string {
		var b strings.Builder
		for _, u := range us {
			fmt.Fprintf(&b, "{%q:%q}\n", key, u)
		}
		return b.String()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/wayback" && q.Get("page") == "0":
			rows := []string{`["original"]`}
			for _, u := range urls["wayback"] {
				rows = append(rows, fmt.Sprintf("[%q]", u))
			}
			fmt.Fprintf(w, "[%s]", strings.Join(rows, ","))
		case r.URL.Path == "/wayback":
			w.WriteHeader(http.StatusBadRequest)
		case r.URL.Path == "/cc/collinfo.json":
			fmt.Fprintf(w, `[{"cdx-api":"http://%s/cc/idx"}]`, r.Host)
		case r.URL.Path == "/cc/idx" && q.Get("showNumPages") != "":
			fmt.Fprint(w, `{"pages":1}`)
		case r.URL.Path == "/cc/idx":
			fmt.Fprint(w, jsonl(urls["commoncrawl"], "url"))
		case strings.HasPrefix(r.URL.Path, "/otx/"):
			var rows []string
			for _, u := range urls["otx"] {
				rows = append(rows, fmt.Sprintf(`{"url":%q,"httpcode":200}`, u))
			}
			fmt.Fprintf(w, `{"has_next":false,"url_list":[%s]}`, strings.Join(rows, ","))
		case r.URL.Path == "/urlscan":
			var rows []string
			for i, u := range urls["urlscan"] {
				rows = append(rows, fmt.Sprintf(`{"page":{"url":%q,"status":"200","mimeType":"text/html"},"task":{"url":%q},"sort":[%d,"a"]}`, u, u, i))
			}
			fmt.Fprintf(w, `{"has_more":false,"results":[%s]}`, strings.Join(rows, ","))
		case r.URL.Path == "/arquivo":
			fmt.Fprint(w, jsonl(urls["arquivo"], "url"))
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

// Into a pipe the URLs are printed as each archive page arrives, in the
// order the archive gave them, not sorted: the first one is on stdout while
// the next page is still being asked. -sort holds them until the archives
// have answered and sorts them.
func TestURLsPrintsEachURLAsItsPageArrivesAndUnsorted(t *testing.T) {
	printed := make(chan struct{})
	var once sync.Once
	var page1Waited atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "0":
			fmt.Fprint(w, `[["original"],["http://example.org/z"],["http://example.org/m"],["http://example.org/a"]]`)
		case "1":
			select { // the next page is not answered until the first URL has been printed
			case <-printed:
				page1Waited.Store(true)
			case <-time.After(5 * time.Second):
			}
			fmt.Fprint(w, `[["original"],["http://example.org/b"]]`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	args := []string{"urls", "-d", "example.org", "-providers", "wayback", "-urls-pause", "0", "-archive", "wayback=" + srv.URL, "-silent"}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	var got strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			got.Write(buf[:n])
			if n > 0 {
				once.Do(func() { close(printed) })
			}
			if err != nil {
				return
			}
		}
	}()
	runErr := run(args)
	os.Stdout = old
	w.Close()
	<-done
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !page1Waited.Load() {
		t.Error("nothing was printed before the second page was answered: the URLs are held until the end")
	}
	if want := []string{"http://example.org/z", "http://example.org/m", "http://example.org/a", "http://example.org/b"}; !slices.Equal(strings.Fields(got.String()), want) {
		t.Errorf("printed %v, want the archive's order %v", strings.Fields(got.String()), want)
	}
	sorted, _, err := urlsRun(t, append(args[1:], "-sort")...)
	if err != nil || !slices.IsSorted(sorted) || len(sorted) != 4 {
		t.Errorf("-sort printed %v (%v)", sorted, err)
	}
}

// With -db the list beside the workspace has one JSON object a line (run,
// url, source), written as the pages arrive: a run stopped by its time limit
// keeps what it read, and the resume adds to the list. A run with no -db
// keeps no list.
func TestURLsListBesideTheWorkspaceKeepsWhatWasRead(t *testing.T) {
	var release atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "0":
			fmt.Fprint(w, `[["original"],["http://example.org/one"],["http://example.org/two"]]`)
		case "1":
			for i := 0; i < 100 && !release.Load(); i++ {
				time.Sleep(50 * time.Millisecond)
			}
			if !release.Load() {
				return
			}
			fmt.Fprint(w, `[["original"],["http://example.org/three"]]`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	db := filepath.Join(dir, "u.db")
	list := db + ".urls.jsonl"
	args := []string{"urls", "-d", "example.org", "-providers", "wayback", "-urls-pause", "0", "-archive", "wayback=" + srv.URL, "-silent", "-db", db}
	_, _, err := urlsRun(t, append(args[1:], "-timeout", "1500ms")...)
	if exitCode(err) != exitLimit {
		t.Fatalf("the stopped run: exit %d, %v", exitCode(err), err)
	}
	read := func() (urls []string, runs map[string]bool) {
		raw, err := os.ReadFile(list)
		if err != nil {
			t.Fatalf("no list beside the workspace: %v", err)
		}
		runs = map[string]bool{}
		for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var o map[string]string
			if err := json.Unmarshal([]byte(l), &o); err != nil || len(o) != 3 || o["run"] == "" || o["source"] != "wayback" {
				t.Fatalf("a line of the list is not {run, url, source}: %q", l)
			}
			urls = append(urls, o["url"])
			runs[o["run"]] = true
		}
		return urls, runs
	}
	before, runs := read()
	if !slices.Equal(before, []string{"http://example.org/one", "http://example.org/two"}) || len(runs) != 1 {
		t.Fatalf("the stopped run kept %v", before)
	}
	release.Store(true)
	if _, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-timeout", "0", "-json"}) }); err != nil {
		t.Fatalf("resume: %v\n%s", err, errOut)
	}
	after, runs := read()
	if len(runs) != 1 || !slices.Equal(after[:2], before) || !slices.Contains(after[2:], "http://example.org/three") {
		t.Errorf("the resume did not add to the list: %v (runs %v)", after, runs)
	}

	// No -db: the workspace is temporary and no list is kept.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if _, _, err := urlsRun(t, "-d", "example.org", "-providers", "wayback", "-urls-pause", "0", "-archive", "wayback="+srv.URL, "-silent"); err != nil {
		t.Fatal(err)
	}
	var found []string
	_ = filepath.Walk(tmp, func(p string, _ os.FileInfo, _ error) error {
		if strings.Contains(p, ".urls.jsonl") {
			found = append(found, p)
		}
		return nil
	})
	if len(found) != 0 {
		t.Errorf("a run with no -db kept a list: %v", found)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.urls.jsonl")); len(left) != 1 {
		t.Errorf("lists in the working directory: %v", left)
	}
}

// Every archive's URLs go through the junk rules, each URL counted once,
// and none is printed or asked of the live site; with -keep-junk each is
// listed with its class and reason and stays counted in "dropped as junk".
func TestURLsEveryArchivesURLsGoThroughTheJunkRules(t *testing.T) {
	junk := map[string]string{
		"wayback":     "http://example.org/s?q=<script>alert(1)</script>",
		"commoncrawl": "http://example.org/t?id=1union select 1,2 from information_schema.tables",
		"otx":         "http://example.org/rest/basket/NaN",
		"urlscan":     "http://example.org/FUZZ/x",
		"arquivo":     "http://example.org/t/fit.txt?%00",
	}
	good := map[string][]string{}
	all := map[string][]string{}
	for name, j := range junk {
		good[name] = []string{"http://example.org/ok-" + name}
		all[name] = []string{j, "http://example.org/ok-" + name}
	}
	flags := archivesOf(t, all)
	base := append([]string{"-d", "example.org", "-urls-pause", "0", "-json"}, flags...)
	text, errOut, err := captureBoth(t, func() error { return run(append([]string{"urls"}, append(base, "-sort")...)) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if out := lines(text); len(out) != 5 {
		t.Errorf("printed %d rows %v, want the 5 good URLs", len(out), out)
	}
	if rep := lastReport(t, errOut); rep.Counts["dropped as junk"] != 5 {
		t.Errorf("counts %v, want 5 dropped as junk, one from each archive", rep.Counts)
	}
	// -keep-junk lists them with class and reason, and the count stays.
	text, errOut, err = captureBoth(t, func() error { return run(append([]string{"urls"}, append(base, "-sort", "-keep-junk")...)) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows := map[string]triageRow{}
	for _, l := range lines(text) {
		var r triageRow
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		rows[r.URL] = r
	}
	classes := map[string]string{}
	for _, r := range rows {
		if r.Junk != "" {
			classes[r.Junk] = r.Reason
		}
	}
	if len(rows) != 10 || classes["scanner-payload"] != "scanner payload" || classes["placeholder"] == "" || classes["scanner-probe"] == "" || classes["fuzzing"] == "" {
		t.Errorf("-keep-junk listed %d rows, classes %v", len(rows), classes)
	}
	if rep := lastReport(t, errOut); rep.Counts["dropped as junk"] != 5 {
		t.Errorf("with -keep-junk the count is %v, want 5 still", rep.Counts)
	}
}

// -live asks the live site once after every archive has answered: a GET that
// is not followed, so a redirect is its own answer; at 10 a second unless
// -live-rate says otherwise, and a note states it. -live-max N asks N URLs
// spread evenly over the sorted list, lists the others without verified and
// counts them. A URL that looks like junk is never sent, even with -keep-junk,
// and the counts say so.
func TestURLsLiveAsksOnceAfterTheArchivesAndSaysWhatItDid(t *testing.T) {
	var archiveDone, firstLive atomic.Int64
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, `{"has_next":false,"url_list":[{"url":"http://example.org/p9"},{"url":"http://example.org/redirect"}]}`)
		archiveDone.Store(time.Now().UnixNano())
	}))
	defer slow.Close()
	var all []string
	for i := 0; i < 9; i++ {
		all = append(all, fmt.Sprintf("http://example.org/p%d", i))
	}
	all = append(all, "http://example.org/x?q=<script>alert(1)</script>")
	flags := archivesOf(t, map[string][]string{"wayback": all})
	var mu sync.Mutex
	live := map[string]int{}
	snapshot := func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(live)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstLive.CompareAndSwap(0, time.Now().UnixNano())
		mu.Lock()
		live[r.URL.String()]++
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/redirect") {
			http.Redirect(w, r, "http://example.org/p0", http.StatusMovedPermanently)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer proxy.Close()
	args := append([]string{"urls", "-d", "example.org", "-providers", "wayback,otx", "-urls-pause", "0", "-json", "-keep-junk", "-live", "-live-proxy", proxy.URL}, flags...)
	args = append(args, "-archive", "otx="+slow.URL)
	t.Chdir(t.TempDir())
	out, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if d, l := archiveDone.Load(), firstLive.Load(); d == 0 || l == 0 || l < d {
		t.Errorf("the live site was asked (%d) before the slow archive had answered (%d)", l, d)
	}
	rows := triageRows(t, out)
	asked := snapshot()
	for u, n := range asked {
		if n != 1 {
			t.Errorf("%s was asked %d times", u, n)
		}
		if strings.Contains(u, "script") {
			t.Errorf("a junk URL was sent: %s", u)
		}
	}
	if r := rows["http://example.org/redirect"]; r.Verified == nil || !*r.Verified || r.Status != 301 || asked["http://example.org/p0"] != 1 {
		t.Errorf("a redirect is its own answer, not followed: %+v (p0 asked %d times)", r, asked["http://example.org/p0"])
	}
	rep := lastReport(t, errOut)
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "at 10 requests a second (-live-rate)") || rep.Counts["not asked (junk)"] != 1 {
		t.Errorf("counts %v, notes %q: want the default 10 a second said and 1 junk not asked", rep.Counts, rep.Notes)
	}
	if n := rep.Counts["verified live"] + rep.Counts["gone (404, 410)"] + rep.Counts["no answer"]; n != len(asked) || int(rep.Requests) != len(asked) {
		t.Errorf("counts %v add up to %d, the live site was asked %d times, summary requests %d", rep.Counts, n, len(asked), rep.Requests)
	}

	// -live-max 4: four of the URLs, evenly spread over the sorted list.
	t.Chdir(t.TempDir())
	mu.Lock()
	clear(live)
	mu.Unlock()
	out, errOut, err = captureBoth(t, func() error { return run(append(args, "-live-max", "4")) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	asked = snapshot()
	rows = triageRows(t, out)
	rep = lastReport(t, errOut)
	var verified, unverified []string
	for u, r := range rows {
		if r.Junk != "" && r.Junk != "asset" {
			continue
		}
		if r.Verified != nil {
			verified = append(verified, u)
		} else {
			unverified = append(unverified, u)
		}
	}
	if len(verified) != 4 || len(asked) != 4 || rep.Counts["not asked (-live-max)"] != len(unverified) || len(unverified) != 7 {
		t.Errorf("verified %d, asked %d, listed without verified %d, counts %v", len(verified), len(asked), len(unverified), rep.Counts)
	}
	slices.Sort(verified)
	var sortedAll []string
	for u := range rows {
		if r := rows[u]; r.Junk == "" || r.Junk == "asset" {
			sortedAll = append(sortedAll, u)
		}
	}
	slices.Sort(sortedAll)
	var want []string
	for i := 0; i < 4; i++ {
		want = append(want, sortedAll[i*len(sortedAll)/4])
	}
	if !slices.Equal(verified, want) || len(sortedAll) != 11 {
		t.Errorf("verified %v, want %v: 4 spread evenly over the %d sorted URLs", verified, want, len(sortedAll))
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "7 not asked (-live-max)") {
		t.Errorf("notes %q", rep.Notes)
	}
}

// Without -live nothing is sent to the live site; a failed archive leaves
// the others' URLs and a partial-set note, exit 0 while another archive
// answered; -strict-exit makes it 3, and so does every archive failing.
func TestURLsExitCodeOfAFailedArchive(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusGatewayTimeout) }))
	defer bad.Close()
	flags := archivesOf(t, map[string][]string{"otx": {"http://example.org/otx"}})
	base := append([]string{"urls", "-d", "example.org", "-providers", "wayback,otx", "-urls-pause", "0", "-json"}, flags...)
	base = append(base, "-archive", "wayback="+bad.URL)
	run1 := func(extra ...string) (int, report, string) {
		out, errOut, err := captureBoth(t, func() error { return run(append(slices.Clone(base), extra...)) })
		return exitCode(err), lastReport(t, errOut), out
	}
	code, rep, out := run1()
	if code != exitOK || rep.Failures != 1 || rep.Requests != 0 || !strings.Contains(out, "http://example.org/otx") ||
		!strings.Contains(strings.Join(rep.Notes, "\n"), "the set is partial: wayback failed, so the URLs only they hold are missing and those of the others are listed") {
		t.Errorf("one archive failed: exit %d, %d failures, %d requests, notes %q", code, rep.Failures, rep.Requests, rep.Notes)
	}
	if code, _, _ := run1("-strict-exit"); code != exitPartial {
		t.Errorf("-strict-exit with a failed archive: exit %d, want 3", code)
	}
	all := []string{"urls", "-d", "example.org", "-providers", "wayback", "-urls-pause", "0", "-json", "-archive", "wayback=" + bad.URL}
	_, errOut, err := captureBoth(t, func() error { return run(all) })
	if exitCode(err) != exitPartial || lastReport(t, errOut).Failures == 0 {
		t.Errorf("no archive answered: exit %d", exitCode(err))
	}
}

// The plain output is one URL a row; -json carries the fields of the page and
// no others, and a row of an archive that records no type has none.
func TestURLsRowsAreURLsAndTheDocumentedFields(t *testing.T) {
	flags := archivesOf(t, map[string][]string{"otx": {"http://example.org/a", "http://example.org/b.png"}})
	base := append([]string{"-d", "example.org", "-providers", "otx", "-urls-pause", "0", "-mt", "text/html", "-sort"}, flags...)
	plain, _, err := urlsRun(t, append(base, "-silent")...)
	if err != nil || !slices.Equal(plain, []string{"http://example.org/a", "http://example.org/b.png"}) {
		t.Errorf("plain rows %v (%v)", plain, err)
	}
	out, errOut, err := captureBoth(t, func() error { return run(append([]string{"urls"}, append(base, "-json")...)) })
	if err != nil {
		t.Fatal(err)
	}
	documented := []string{"url", "normalized", "raw_url", "source", "archived", "junk", "junk_reason", "verified", "verified_status", "verified_error"}
	for _, l := range lines(out) {
		var row map[string]any
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatal(err)
		}
		for k := range row {
			if !slices.Contains(documented, k) {
				t.Errorf("a field the page does not document: %s in %s", k, l)
			}
		}
		if row["url"] == nil || row["normalized"] == nil || row["source"] != "otx" {
			t.Errorf("row %s", l)
		}
	}
	if rep := lastReport(t, errOut); !strings.Contains(strings.Join(rep.Notes, "\n"), "otx has no type of its captures: its 2 URLs are not filtered by -mt") || rep.Results != 2 {
		t.Errorf("notes %q results %d: OTX is asked all the same and its URLs are kept", rep.Notes, rep.Results)
	}
}

// -raw prints every row of the domain as the archive gave it (a duplicate, a
// junk URL, the case it was written in), while -blacklist and -fp still apply.
func TestURLsRawPrintsTheRowsAsGivenAndStillAppliesTheBlacklist(t *testing.T) {
	flags := archivesOf(t, map[string][]string{"otx": {"HTTP://Example.ORG/A#frag", "http://example.org/a.txt", "http://example.org/a.txt", "http://example.org/x/..", "http://example.org/b.png", "http://other.test/z"}})
	base := append([]string{"-d", "example.org", "-providers", "otx", "-urls-pause", "0", "-silent", "-raw"}, flags...)
	got, _, err := urlsRun(t, base...)
	want := []string{"HTTP://Example.ORG/A#frag", "http://example.org/a.txt", "http://example.org/a.txt", "http://example.org/x/..", "http://example.org/b.png"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("-raw printed %v (%v), want %v", got, err, want)
	}
	got, _, err = urlsRun(t, append(base, "-blacklist", "png", "-fp")...)
	if err != nil || !slices.Equal(got, []string{"HTTP://Example.ORG/A#frag", "http://example.org/a.txt", "http://example.org/x/.."}) {
		t.Errorf("-raw -blacklist png -fp printed %v (%v)", got, err)
	}
}
