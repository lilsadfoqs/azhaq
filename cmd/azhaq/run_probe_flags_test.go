package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/store"
)

// -probe turns off what a flag does not ask for. A collector the command line
// asks for by name -dirs, -params, -ports runs, and the run says it did.
func TestRunProbeRunsTheCollectorsFlagsAskFor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/":
			if r.URL.Query().Has("secret") {
				fmt.Fprint(w, "<html><title>home</title>"+strings.Repeat("a long answer when secret is given ", 30)+"</html>")
				return
			}
			fmt.Fprint(w, "<html><title>home</title></html>")
		case r.URL.Path == "/admin":
			fmt.Fprint(w, "<html><title>admin</title>found</html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port := fmt.Sprint(srv.Listener.Addr().(*net.TCPAddr).Port)
	dir := t.TempDir()
	t.Chdir(dir)
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-probe", "-no-paths", "-no-favicon",
		"-dirs", wlist(t, "admin", "nothere"), "-dirs-ac=false", "-dirs-mc", "all", "-params", wlist(t, "x1", "x2", "secret"),
		"-ports", port, "-db", "p.db", "-timeout", "30s")
	if code != exitOK {
		t.Fatalf("exit %d, notes %q", code, rep.Notes)
	}
	st, err := store.OpenExisting("p.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, _ := st.Observations()
	ran := map[string]bool{}
	for _, o := range obs {
		ran[o.Collector] = true
	}
	for _, c := range []string{"azhaq-http", "azhaq-dirs", "azhaq-params", "azhaq-ports"} {
		if !ran[c] {
			t.Errorf("%s was asked for by a flag and did not run (ran: %v)", c, ran)
		}
	}
	for _, c := range []string{"azhaq-crawl", "azhaq-js", "azhaq-tls"} {
		if ran[c] {
			t.Errorf("%s ran under -probe, which turns it off", c)
		}
	}
}

// A collector -probe leaves out and a flag asks for in the plan too.
func TestPlanProbeListsTheCollectorsFlagsAskFor(t *testing.T) {
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, "plan", "-url", "http://127.0.0.1:1/", "-probe", "-dirs", wlist(t, "a"), "-ports", "1")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, want := range []string{"azhaq-dirs", "azhaq-ports", "azhaq-http"} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "azhaq-crawl") {
		t.Errorf("the plan has the crawl under -probe:\n%s", out)
	}
}

// -screenshots under -probe takes the screenshot: the picture is in the
// directory and the run says so.
func TestRunProbeTakesTheScreenshotsAskedFor(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>home</title><body>hello</body></html>")
	}))
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-probe", "-no-paths", "-no-favicon", "-screenshots", "shots", "-db", "p.db", "-timeout", "60s")
	if code != exitOK {
		t.Fatalf("exit %d, notes %q", code, rep.Notes)
	}
	pics, _ := filepath.Glob(filepath.Join(dir, "shots", "*"))
	if len(pics) == 0 {
		t.Errorf("-screenshots was given with -probe and no picture was taken (notes %q)", rep.Notes)
	}
	for _, p := range pics {
		if !slices.Contains(rep.Wrote, filepath.Join("shots", filepath.Base(p))) {
			t.Errorf("wrote %q does not name the screenshot %s", rep.Wrote, p)
		}
	}
}

// A flag that only a collector -probe turns off reads cannot work with it: a
// usage error naming both, not a flag that is dropped.
func TestRunProbeRefusesFlagsOfWhatItTurnsOff(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, flag := range []string{"-fill-forms", "-submit-forms", "-path-climb"} {
		_, errOut, code := cli(t, "run", "-url", "http://127.0.0.1:1/", "-probe", flag, "-ledger", "off", "-db", "p.db")
		if code != exitUsage || !strings.Contains(errOut, "-probe") || !strings.Contains(errOut, flag) {
			t.Errorf("%s: exit %d\n%s", flag, code, errOut)
		}
	}
	_, errOut, code := cli(t, "run", "-url", "http://127.0.0.1:1/", "-probe", "-known-files", "all", "-ledger", "off", "-db", "p.db")
	if code != exitUsage || !strings.Contains(errOut, "-known-files") {
		t.Errorf("-known-files: exit %d\n%s", code, errOut)
	}
}

// Every request Chrome makes for a screenshot spends the run's budget: the
// page's images stop at the cap, the run exits 4 with work left, and the
// summary counts what the server saw.
func TestRunScreenshotsHoldsMaxRequests(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>home</title><body>")
			for i := 0; i < 60; i++ {
				fmt.Fprintf(w, `<img src="/i/%d.png">`, i)
			}
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-probe", "-no-paths", "-no-favicon", "-screenshots", "shots", "-max-requests", "20", "-db", "p.db", "-timeout", "60s")
	if code != exitLimit {
		t.Errorf("exit %d, want %d (notes %q)", code, exitLimit, rep.Notes)
	}
	if got := hits.Load(); got > 20 || rep.Requests != got {
		t.Errorf("the server saw %d requests, the summary says %d, the cap is 20", got, rep.Requests)
	}
}
