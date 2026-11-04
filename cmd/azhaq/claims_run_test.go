package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/types"
)

// seenServer answers like a small app and records "METHOD /path?query" for
// every request it gets.
type seenServer struct {
	*httptest.Server
	mu    sync.Mutex
	seen  []string
	delay time.Duration
}

func (s *seenServer) asked(method, uri string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.seen {
		if r == method+" "+uri {
			n++
		}
	}
	return n
}

func (s *seenServer) any(prefix string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.seen {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func newSeenServer(t *testing.T) *seenServer {
	t.Helper()
	s := &seenServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Method+" "+r.URL.RequestURI())
		delay := s.delay
		s.mu.Unlock()
		time.Sleep(delay)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>app</title><script src="/app.js"></script></head><body>
<a href="/createdb">set up</a><a href="/logout">out</a><a href="/flush">flush</a>
<form method="get" action="/search"><input name="q" type="text"></form>
<form method="post" action="/contact"><input name="msg" type="text"></form>
</body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/from-script")`)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/api/described":{"get":{"summary":"lists","responses":{"200":{"description":"ok"}}}}}}`)
		case "/createdb", "/logout", "/flush", "/search", "/api/from-script", "/api/described", "/robots.txt":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// run asks every GET URL it finds in scope under any name that declares no
// state change: a link (/flush), a script's call, an API description's route
// and a GET form (filled with -fill-forms) are all requested; a POST form is
// not sent. A link whose own name declares a state change (/createdb,
// /logout) is held back: not sent, listed as skipped with the flag that sends
// it.
func TestRunRequestsEveryGETFoundInALinkAScriptADescriptionAndAForm(t *testing.T) {
	srv := newSeenServer(t)
	t.Chdir(t.TempDir())
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-fill-forms", "-db", "g.db", "-ledger", "off", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	for _, path := range []string{"/flush", "/api/from-script", "/api/described"} {
		if srv.asked("GET", path) == 0 {
			t.Errorf("GET %s declares no state change and was not requested", path)
		}
	}
	if !srv.any("GET /search?") {
		t.Errorf("the GET form was not filled and requested: %v", srv.seen)
	}
	if srv.any("POST ") {
		t.Errorf("a POST was sent without -submit-forms: %v", srv.seen)
	}
	rep := lastReport(t, errOut)
	for _, path := range []string{"/createdb", "/logout"} {
		if srv.asked("GET", path) != 0 {
			t.Errorf("GET %s declares a state change and was requested", path)
		}
	}
	if len(rep.Skipped) != 2 {
		t.Errorf("only the two held links are kept out, with no -deny-path rule: %+v", rep.Skipped)
	}
	for _, s := range rep.Skipped {
		if !strings.Contains(s.Reason, "-send-state-changing") {
			t.Errorf("%s is skipped for %q, want the flag that sends it", s.Target, s.Reason)
		}
	}
}

// The built-in paths are asked of each web service unless -no-paths says not
// to.
func TestRunNoPathsTurnsTheBuiltInPathsOff(t *testing.T) {
	for _, off := range []bool{false, true} {
		srv := newSeenServer(t)
		t.Chdir(t.TempDir())
		args := []string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-depth", "0", "-no-favicon", "-no-tech", "-db", "p.db", "-ledger", "off", "-json"}
		if off {
			args = append(args, "-no-paths")
		}
		if _, errOut, err := captureBoth(t, func() error { return run(args) }); err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		if asked := srv.asked("GET", "/robots.txt") + srv.asked("GET", "/openapi.json"); (asked > 0) == off {
			t.Errorf("-no-paths %v: the built-in paths /robots.txt and /openapi.json were asked %d times", off, asked)
		}
	}
}

// -quiet prints no map and no progress lines, only the summary.
func TestRunQuietPrintsOnlyTheSummary(t *testing.T) {
	srv := newSeenServer(t)
	srv.delay = 40 * time.Millisecond
	defer func(d time.Duration) { stderrProgressEvery = d }(stderrProgressEvery)
	stderrProgressEvery = 30 * time.Millisecond
	t.Chdir(t.TempDir())
	base := []string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-depth", "0", "-ledger", "off"}
	progress := func(errOut string) int {
		n := 0
		for _, l := range lines(errOut) {
			if strings.HasPrefix(l, "azhaq: ") && strings.Contains(l, "requests sent") {
				n++
			}
		}
		return n
	}
	out, errOut, err := captureBoth(t, func() error { return run(append(slices.Clone(base), "-db", "n.db")) })
	if err != nil || out == "" || progress(errOut) == 0 {
		t.Fatalf("without -quiet: %v, %d bytes of map, %d progress lines (the check below needs both)\n%s", err, len(out), progress(errOut), errOut)
	}
	out, errOut, err = captureBoth(t, func() error { return run(append(slices.Clone(base), "-quiet", "-db", "q.db")) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if out != "" || progress(errOut) != 0 || !strings.HasPrefix(strings.TrimSpace(errOut), "azhaq run: ") {
		t.Errorf("-quiet: map on stdout %q, %d progress lines, stderr:\n%s", out, progress(errOut), errOut)
	}
}

// A resumed run has no estimate, only what it sent: its cost has no estimate,
// at the total or on any stage, and its stages' actual add up to its requests.
func TestAResumedRunHasNoEstimateOnlyWhatItSent(t *testing.T) {
	srv, _ := spaStandIn(t)
	t.Chdir(t.TempDir())
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-db", "e.db", "-ledger", "off", "-max-requests", "10", "-json"})
	})
	first := lastReport(t, errOut)
	if exitCode(err) != exitLimit || first.Cost == nil || first.Cost.Estimate == nil {
		t.Fatalf("the first run: exit %d, cost %+v: it has an estimate", exitCode(err), first.Cost)
	}
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", "e.db", "-max-requests", "0", "-json"}) })
	rep := lastReport(t, errOut)
	if err != nil || rep.Cost == nil || rep.Cost.Estimate != nil {
		t.Fatalf("the resume: %v, cost %+v: it has an estimate", err, rep.Cost)
	}
	var sent int64
	for _, st := range rep.Cost.Stages {
		if st.Estimate != nil {
			t.Errorf("stage %s of a resumed run has an estimate", st.Stage)
		}
		sent += st.Actual.Requests
	}
	if sent != rep.Requests || sent == 0 {
		t.Errorf("the stages sent %d, the summary says %d", sent, rep.Requests)
	}
}

// -stream says a name only when it resolves, and its address with it: a name
// that does not resolve (no address, or a wildcard answer) is not streamed.
func TestStreamSaysNamesThatResolveNotThoseThatDoNot(t *testing.T) {
	out, _, err := captureBoth(t, func() error {
		see := streamFound(false)
		for _, p := range []string{
			`{"fqdn":"live.a.test","ips":["192.0.2.7"]}`,
			`{"fqdn":"dead.a.test","ips":[]}`,
			`{"fqdn":"nx.a.test","rcode":"NXDOMAIN"}`,
			`{"fqdn":"wild.a.test","ips":["192.0.2.9"],"wildcard":true}`,
		} {
			see(types.Entity{}, types.Observation{Kind: "dns", Payload: []byte(p)})
		}
		return nil
	})
	for _, dead := range []string{"dead.a.test", "nx.a.test", "wild.a.test"} {
		if strings.Contains(out, dead) {
			t.Errorf("%s was streamed:\n%s", dead, out)
		}
	}
	if err != nil || !strings.Contains(out, "found  name    live.a.test") {
		t.Errorf("the name that resolves was not streamed (%v):\n%s", err, out)
	}
}
