package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/store"
)

// resumeFlags make a run send only the seeds' own requests.
var resumeFlags = []string{"-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths", "-no-favicon", "-no-tech", "-json", "-depth", "0"}

// closedPort is an address nothing listens on: a request to it is refused,
// which no later try fixes.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

// rateLimited answers 429 until healed, and counts what it was asked.
func rateLimited(t *testing.T) (srv *httptest.Server, asked *atomic.Int32, heal func()) {
	t.Helper()
	var healed atomic.Bool
	asked = new(atomic.Int32)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if !healed.Load() {
			w.WriteHeader(429)
		}
		fmt.Fprint(w, "<title>home</title>")
	}))
	t.Cleanup(srv.Close)
	return srv, asked, func() { healed.Store(true) }
}

// A run whose every request ended is finished: resume says so and exits 1.
// With only failed targets a later try may fix, it says that instead, names
// -retry-failed, and still exits 1. A request that failed is a finished
// task, so a plain resume does not ask it again.
func TestResumeOfAFinishedRunExitsOneAndNamesWhatIsRetryable(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<title>ok</title>") }))
	defer good.Close()
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "f.db")
	if _, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"run", "-url", good.URL + "/", "-db", db, "-ledger", "off"}, resumeFlags...))
	}); err != nil {
		t.Fatalf("the run: %v\n%s", err, errOut)
	}
	_, _, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-json"}) })
	if err == nil || exitCode(err) != exitError || !strings.Contains(err.Error(), "nothing to resume in "+db+": every run finished") {
		t.Errorf("resume of a finished run: exit %d, %v", exitCode(err), err)
	}

	srv, asked, _ := rateLimited(t)
	db2 := filepath.Join(t.TempDir(), "g.db")
	if _, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"run", "-url", srv.URL + "/", "-db", db2, "-ledger", "off"}, resumeFlags...))
	}); err != nil {
		t.Fatalf("the run: %v\n%s", err, errOut)
	}
	before := asked.Load()
	_, _, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db2, "-json"}) })
	if err == nil || exitCode(err) != exitError ||
		!strings.Contains(err.Error(), "no task left in "+db2+", but 1 failed targets are retryable") || !strings.Contains(err.Error(), "-retry-failed") {
		t.Errorf("resume with only a retryable failure: exit %d, %v", exitCode(err), err)
	}
	if asked.Load() != before {
		t.Errorf("a plain resume asked the failed target again: %d requests", asked.Load()-before)
	}
}

// -retry-failed asks again only the failed targets the summary marks
// retryable (once each), leaves what a retry cannot fix in failed as it was
// and unasked, puts the retried request in the ledger and the summary's count,
// and exits 1 with nothing to retry when none is left.
func TestResumeRetryFailedAsksOnlyWhatIsRetryable(t *testing.T) {
	srv, asked, heal := rateLimited(t)
	dead := closedPort(t)
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "r.db")
	l := filepath.Join(t.TempDir(), "r.jsonl")
	_, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"run", "-url", srv.URL + "/", "-url", "http://" + dead + "/", "-db", db, "-ledger", l}, resumeFlags...))
	})
	rep := lastReport(t, errOut)
	if exitCode(err) != exitOK || len(rep.Failed) != 2 {
		t.Fatalf("first run: exit %d, failed %+v", exitCode(err), rep.Failed)
	}
	var retryable, final []string
	for _, f := range rep.Failed {
		if f.Retryable {
			retryable = append(retryable, f.Targets...)
		} else {
			final = append(final, f.Targets...)
		}
	}
	if len(retryable) != 1 || len(final) != 1 || !strings.Contains(final[0], dead) {
		t.Fatalf("retryable %v, final %v", retryable, final)
	}
	sent := func(target string) (n int) {
		_ = ledger.Read(l, func(e ledger.Entry) error {
			if e.Kind == "http" && e.IsTarget() && e.Target == target {
				n++
			}
			return nil
		})
		return n
	}
	deadSent, srvSent := sent("http://"+dead+"/"), sent(retryable[0])
	heal()
	before := asked.Load()
	out, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	rep = lastReport(t, errOut)
	if exitCode(err) != exitOK || !strings.Contains(strings.Join(rep.Notes, "\n"), "-retry-failed: 1 failed targets of run "+rep.RunID+" asked again, 0 still fail") {
		t.Fatalf("the retry: exit %d, notes %v\n%s", exitCode(err), rep.Notes, errOut)
	}
	if n := asked.Load() - before; n != 1 {
		t.Errorf("the 429 target was asked %d times: a stored 429 was read back, or more than the failed target was asked", n)
	}
	if !strings.Contains(out, `"key":"`+srv.URL+`/"`) {
		t.Errorf("the retried target has no row:\n%s", out)
	}
	if status := newestStatus(t, db, srv.URL+"/"); status != 200 {
		t.Errorf("the newest answer stored for the retried target has status %d, want the retry's 200", status)
	}
	if len(rep.Failed) != 1 || rep.Failed[0].Retryable || !slices.Equal(rep.Failed[0].Targets, final) || rep.Failed[0].Error != "connection refused" {
		t.Errorf("what a retry cannot fix did not stay in failed as it was: %+v", rep.Failed)
	}
	// The retried request is in the ledger like any other, and the one a
	// retry cannot fix was not asked.
	if n := sent(retryable[0]) - srvSent; n != 1 || rep.Requests != 1 {
		t.Errorf("the retry put %d requests in the ledger, the summary says %d: want 1 and 1", n, rep.Requests)
	}
	if n := sent("http://"+dead+"/") - deadSent; n != 0 {
		t.Errorf("a refused connection was asked again: %d requests", n)
	}
	// Nothing is retryable now.
	_, _, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	if exitCode(err) != exitError || err == nil || !strings.Contains(err.Error(), "nothing to retry") {
		t.Errorf("a second -retry-failed: exit %d, %v", exitCode(err), err)
	}
}

// The requests a retry sends count against -max-requests: with a cap of one
// and two failed targets, one is asked and the run stops with work left.
func TestResumeRetryFailedCountsAgainstMaxRequests(t *testing.T) {
	a, askedA, healA := rateLimited(t)
	b, askedB, healB := rateLimited(t)
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "m.db")
	if _, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"run", "-url", a.URL + "/", "-url", b.URL + "/", "-db", db, "-ledger", "off"}, resumeFlags...))
	}); err != nil {
		t.Fatalf("first run: %v\n%s", err, errOut)
	}
	healA()
	healB()
	beforeA, beforeB := askedA.Load(), askedB.Load()
	_, errOut, err := captureBoth(t, func() error {
		return cmdResume([]string{"-db", db, "-retry-failed", "-max-requests", "1", "-json"})
	})
	rep := lastReport(t, errOut)
	if exitCode(err) != exitLimit || rep.Requests != 1 || !strings.Contains(rep.Stopped, "request budget of 1") {
		t.Errorf("the retry under -max-requests 1: exit %d, %d requests, stopped %q", exitCode(err), rep.Requests, rep.Stopped)
	}
	if n := (askedA.Load() - beforeA) + (askedB.Load() - beforeB); n != 1 {
		t.Errorf("the two targets were asked %d times in all, want 1", n)
	}
}

// What still fails after a retry is in failed again, and the exit code is the
// shared rule's: 3 when nothing the run was given answered, 0 when something did.
func TestResumeRetryFailedExitCodeFollowsTheSharedRule(t *testing.T) {
	var closed atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		closed.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer bad.Close()
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "x.db")
	_, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"run", "-url", bad.URL + "/", "-db", db, "-ledger", "off"}, resumeFlags...))
	})
	if rep := lastReport(t, errOut); exitCode(err) != exitPartial || len(rep.Failed) != 1 || !rep.Failed[0].Retryable {
		t.Fatalf("first run: exit %d, failed %+v", exitCode(err), rep.Failed)
	}
	before := closed.Load()
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	rep := lastReport(t, errOut)
	if exitCode(err) != exitPartial || closed.Load() == before || len(rep.Failed) != 1 || rep.Failed[0].Targets[0] != bad.URL+"/" ||
		!strings.Contains(strings.Join(rep.Notes, "\n"), "-retry-failed: 1 failed targets of run "+rep.RunID+" asked again, 1 still fail") {
		t.Errorf("a retry that fails again with nothing answered: exit %d, failed %+v, notes %v", exitCode(err), rep.Failed, rep.Notes)
	}
	// One that answered is a run that did its job: the failure is listed, the exit is 0.
	srv, _, _ := rateLimited(t)
	db2 := filepath.Join(t.TempDir(), "y.db")
	if _, _, err = captureBoth(t, func() error {
		return run(append([]string{"run", "-url", srv.URL + "/", "-db", db2, "-ledger", "off"}, resumeFlags...))
	}); err != nil {
		t.Fatal(err)
	}
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db2, "-retry-failed", "-json"}) })
	if rep := lastReport(t, errOut); exitCode(err) != exitOK || len(rep.Failed) != 1 || !strings.Contains(strings.Join(rep.Notes, "\n"), "asked again, 1 still fail") {
		t.Errorf("a retry that fails again with a target that answered: exit %d, failed %+v", exitCode(err), rep.Failed)
	}
}

// When the newest run has nothing retryable and an earlier one has, the error
// names that run and the command that asks it.
func TestResumeRetryFailedNamesTheEarlierRunWithRetryableFailures(t *testing.T) {
	srv, _, _ := rateLimited(t)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<title>ok</title>") }))
	defer good.Close()
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "e.db")
	_, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"run", "-url", srv.URL + "/", "-url", good.URL + "/", "-db", db, "-ledger", "off"}, resumeFlags...))
	})
	first := lastReport(t, errOut)
	if exitCode(err) != exitOK || len(first.Failed) != 1 {
		t.Fatalf("first run: exit %d, failed %+v", exitCode(err), first.Failed)
	}
	if _, errOut, err = captureBoth(t, func() error {
		return run([]string{"probe", "-u", good.URL + "/", "-allow", "127.0.0.1", "-db", db, "-ledger", "off", "-json"})
	}); err != nil {
		t.Fatalf("probe: %v\n%s", err, errOut)
	}
	_, _, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	want := "run " + first.RunID + " has 1 retryable failed target: azhaq resume -db " + db + " -retry-failed -retry-run " + first.RunID
	if exitCode(err) != exitError || err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("exit %d, error %v\nwant it to say %q", exitCode(err), err, want)
	}
}

// A resume says on stderr which run it continues and how many tasks are known
// and not done (the number the stopped run's summary gave), and -json leaves
// the line out.
func TestResumeSaysOnStderrWhatItContinues(t *testing.T) {
	srv, _ := spaStandIn(t)
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "s.db")
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-db", db, "-ledger", "off", "-max-requests", "8", "-json"})
	})
	first := lastReport(t, errOut)
	m := regexp.MustCompile(`(\d+) tasks known and not done`).FindStringSubmatch(first.Stopped)
	if exitCode(err) != exitLimit || m == nil {
		t.Fatalf("first run: exit %d, stopped %q", exitCode(err), first.Stopped)
	}
	tasksLeft := func() int {
		t.Helper()
		st, err := store.OpenExisting(db)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		_, _, left, ok, err := st.Resumable()
		if err != nil || !ok {
			t.Fatalf("resumable: %v %v", ok, err)
		}
		return left
	}
	if n := tasksLeft(); strconv.Itoa(n) != m[1] {
		t.Fatalf("the stopped run's summary says %s tasks not done, its workspace holds %d", m[1], n)
	}
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-max-requests", "8", "-json"}) })
	if exitCode(err) != exitLimit || strings.Contains(errOut, "resuming run") {
		t.Errorf("-json: exit %d, the line is in stderr:\n%s", exitCode(err), errOut)
	}
	left := tasksLeft()
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-max-requests", "0"}) })
	if err != nil || !strings.Contains(errOut, "azhaq: resuming run "+first.RunID+" of "+db+", "+strconv.Itoa(left)+" tasks known and not done\n") {
		t.Errorf("exit %d; stderr lacks the line for %d tasks:\n%s", exitCode(err), left, errOut)
	}
}

// A word of a dirs sweep the stopped run stored is answered from the
// workspace: the resume sends a request for only the words not yet asked, so
// a cap of that many is enough and the replay is not paced.
func TestResumeOfDirsSendsOnlyTheWordsNotYetAsked(t *testing.T) {
	srv := dirsServer(t, nil)
	var words []string
	for i := range 40 {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	wl := wlist(t, words...)
	db := filepath.Join(t.TempDir(), "d.db")
	base := []string{"-u", srv.URL + "/", "-w", wl, "-ac=false", "-json", "-ledger", "off", "-db", db}
	_, errOut, err := captureBoth(t, func() error { return cmdDirs(append(slices.Clone(base), "-max-requests", "25")) })
	first := lastReport(t, errOut)
	if exitCode(err) != exitLimit || first.Requests != 25 {
		t.Fatalf("first: exit %d, %d requests", exitCode(err), first.Requests)
	}
	t0 := time.Now()
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-max-requests", "15", "-rate", "10", "-json"}) })
	rep := lastReport(t, errOut)
	if exitCode(err) != exitOK || rep.Requests != 15 {
		t.Fatalf("resume under a cap of the 15 words left: exit %d, %d requests, stopped %q: the 25 stored words took budget", exitCode(err), rep.Requests, rep.Stopped)
	}
	// 40 words paced at 10 a second take 4 s; 15 take about 1.5 s.
	if d := time.Since(t0); d > 3500*time.Millisecond {
		t.Errorf("the resume at -rate 10 took %s: the stored words were paced", d)
	}
}

// Every secret named on the page is left out of the run's stored flags, and a
// header is kept unless its name holds one of the words.
func TestKeptArgsLeaveOutEverySecretTheResumePageNames(t *testing.T) {
	in := []string{"-url", "http://t/", "-cookie", "a=SECRET-1", "-login-pass", "SECRET-2", "-worker-token", "SECRET-3",
		"-proxy", "http://u:SECRET-4@p:1", "-source-proxy", "http://u:SECRET-5@p:1", "-chrome-proxy=http://u:SECRET-6@p:1",
		"-urls-proxy", "http://u:SECRET-7@p:1", "-port-proxy", "u:SECRET-8@p:1080"}
	secretNames := []string{"Authorization", "X-Cookie-Jar", "X-Api-Token", "X-Api-Key", "X-Session-Id", "X-Client-Secret", "X-Csrf-Value", "X-Xsrf-Value", "PROXY-AUTHORIZATION"}
	for i, n := range secretNames {
		in = append(in, "-header", n+": SECRET-h"+strconv.Itoa(i))
	}
	in = append(in, "-header", "X-Trace: kept")
	got := strings.Join(keptArgs(in), " ")
	if strings.Contains(got, "SECRET") {
		t.Errorf("a secret is kept: %s", got)
	}
	for _, want := range []string{"-url http://t/", "-proxy=http://p:1", "-source-proxy=http://p:1", "-chrome-proxy=http://p:1", "-urls-proxy=http://p:1", "-port-proxy=p:1080", "-header=X-Trace: kept"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is not kept in %s", want, got)
		}
	}
}

// What a resume is given for itself (-quiet, -max-requests) is not kept for
// the next one, on a fuzz workspace: the stored command is the run's own, so
// the resume after it has the run's cap and prints its matches, and a -quiet
// resume writes no progress line.
func TestFuzzResumeDoesNotKeepWhatItWasGivenForItself(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	defer func(d time.Duration) { stderrProgressEvery = d }(stderrProgressEvery)
	stderrProgressEvery = 20 * time.Millisecond
	db := filepath.Join(t.TempDir(), "k.db")
	words := wlist(t, "a", "b", "c", "d", "e", "f", "g", "h")
	if _, _, code := runContract(t, "fuzz", "-u", srv.URL+"/FUZZ", "-w", words, "-ac=false", "-mc", "all", "-t", "1", "-max-requests", "2", "-db", db); code != exitLimit {
		t.Fatalf("first: exit %d", code)
	}
	dataDirs.Store(t.Name(), t.TempDir())
	out, errOut, err := captureBoth(t, func() error {
		return run([]string{"resume", "-db", db, "-quiet", "-max-requests", "3", "-json"})
	})
	rep := lastReport(t, errOut)
	if exitCode(err) != exitLimit || out != "" || rep.Requests != 3 || strings.Contains(errOut, `"type":"progress"`) {
		t.Fatalf("resume -quiet -max-requests 3: exit %d, stdout %q, %d requests, stderr has progress: %v", exitCode(err), out, rep.Requests, strings.Contains(errOut, `"type":"progress"`))
	}
	out, errOut, err = captureBoth(t, func() error { return run([]string{"resume", "-db", db, "-json"}) })
	rep = lastReport(t, errOut)
	if exitCode(err) != exitLimit || rep.Requests != 2 || len(lines(out)) != 2 || !strings.Contains(errOut, `"type":"progress"`) {
		t.Errorf("the next resume: exit %d, %d requests, %d rows printed; want the run's own cap of 2, its matches printed and its progress said", exitCode(err), rep.Requests, len(lines(out)))
	}
}

// resume gives run's -timeout to fuzz as -maxtime, in seconds.
func TestFuzzSpellingTurnsRunsTimeoutIntoMaxtime(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"-timeout", "1m", "-quiet"}, []string{"-maxtime", "60", "-quiet"}},
		{[]string{"-timeout=90s"}, []string{"-maxtime=90"}},
	} {
		if got := fuzzSpelling(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("%v became %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A run an older azhaq stored with -all-gets or -get-words goes on without
// them, and the resume says on stderr that every GET found in scope is
// requested now (-json leaves the line out).
func TestResumeDropsTheFlagsAnOlderAzhaqStored(t *testing.T) {
	srv, _ := spaStandIn(t)
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "o.db")
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-db", db, "-ledger", "off", "-max-requests", "8", "-json"})
	})
	first := lastReport(t, errOut)
	if exitCode(err) != exitLimit {
		t.Fatalf("first run: exit %d", exitCode(err))
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	st.UseRun(first.RunID)
	if err := st.SetRunArgs(append(st.RunArgs(), "-all-gets", "-get-words", "exec,import")); err != nil {
		t.Fatal(err)
	}
	st.Close()
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-max-requests", "0"}) })
	if err != nil || !strings.Contains(errOut, "the run was started with -all-gets, -get-words, which azhaq no longer has: every GET found in scope is requested, whatever its name says; ignored") {
		t.Errorf("exit %d; stderr:\n%s", exitCode(err), errOut)
	}
}

// newestStatus is the status of the newest answer a workspace stores for a URL.
func newestStatus(t *testing.T, db, url string) int {
	t.Helper()
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	var at time.Time
	status := 0
	for _, o := range obs {
		var p struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		}
		if o.Kind == "application" && json.Unmarshal(o.Payload, &p) == nil && p.URL == url && o.ObservedAt.After(at) {
			at, status = o.ObservedAt, p.Status
		}
	}
	return status
}

// A resumed run of a command other than run, ports, dirs and fuzz names that
// command in its summary, prints the rows of the map as run does, says so in
// a note, and -quiet leaves only the summary.
func TestResumeOfCrawlAndSubsPrintsTheMapAndSaysSo(t *testing.T) {
	srv, _ := spaStandIn(t)
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "c.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", db, "-ledger", "off", "-max-requests", "4", "-json"})
	})
	if exitCode(err) != exitLimit {
		t.Fatalf("crawl: exit %d\n%s", exitCode(err), errOut)
	}
	out, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-max-requests", "0", "-json"}) })
	rep := lastReport(t, errOut)
	if err != nil || rep.Command != "crawl" || rep.Results != len(lines(out)) || rep.Results == 0 {
		t.Fatalf("resumed crawl: %v, command %q, %d results, %d rows", err, rep.Command, rep.Results, len(lines(out)))
	}
	for _, r := range jsonRows(t, out) {
		if r["type"] == nil || r["key"] == nil {
			t.Errorf("a row of the crawl's own, not the map's: %v", r)
		}
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "a resumed crawl run prints the rows of the map, as run does, not crawl's own rows: azhaq query -db "+db+" lists what the run found") {
		t.Errorf("notes %v", rep.Notes)
	}

	// subs: the run stopped by -timeout, then resumed with -quiet.
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "fast", Default: true, Names: []string{"a.example.org"}},
		subcol.TestSource{Name: "slow", Default: true, Names: []string{"b.example.org"}, Delay: 2 * time.Second},
	)()
	db2 := filepath.Join(t.TempDir(), "s.db")
	dataDirs.Store(t.Name(), t.TempDir())
	if _, rep, code := runContract(t, "subs", "-d", "example.org", "-timeout", "800ms", "-db", db2); code != exitLimit {
		t.Fatalf("subs: exit %d, %+v", code, rep)
	}
	out, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db2, "-quiet", "-timeout", "0", "-json"}) })
	rep = lastReport(t, errOut)
	if err != nil || out != "" || rep.Command != "subs" || rep.Results != 2 {
		t.Errorf("resumed subs -quiet: exit %d, stdout %q, command %q, %d results, notes %v, stopped %q failed %+v", exitCode(err), out, rep.Command, rep.Results, rep.Notes, rep.Stopped, rep.Failed)
	}
}
