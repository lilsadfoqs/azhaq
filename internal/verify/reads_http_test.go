package verify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// showDoc stands in for the sign-in of a documentation app as its server's
// UserController::login answers it: no password is an error, a wrong pair is
// an error, the published pair gets a user_token and a cookie. Logout is the
// POST its logout takes. gated false makes it answer a token to anyone.
type showDoc struct {
	mu      sync.Mutex
	pass    string // the password it accepts for "showdoc"
	gated   bool
	logouts []string // cookie and body of each logout it was sent
}

func (s *showDoc) handler(n int, w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.RequestURI() == "/server/index.php?s=/api/user/login":
		_ = r.ParseForm()
		user, pass := r.PostForm.Get("username"), r.PostForm.Get("password")
		switch {
		case s.gated && pass == "":
			fmt.Fprint(w, `{"error_code":10206,"error_message":"no empty password"}`)
		case !s.gated || (user == "showdoc" && pass == s.pass):
			http.SetCookie(w, &http.Cookie{Name: "cookie_token", Value: "tok123"})
			fmt.Fprint(w, `{"error_code":0,"data":{"uid":"1","username":"showdoc","user_token":"tok123"}}`)
		default:
			fmt.Fprint(w, `{"error_code":10210,"error_message":"username or password incorrect"}`)
		}
	case r.Method == http.MethodPost && r.URL.RequestURI() == "/server/index.php?s=/api/user/logout":
		_ = r.ParseForm()
		s.mu.Lock()
		s.logouts = append(s.logouts, r.Header.Get("Cookie")+" "+r.PostForm.Get("confirm"))
		s.mu.Unlock()
		fmt.Fprint(w, `{"error_code":0}`)
	default:
		w.WriteHeader(404)
	}
}

// The published default account of the documentation app signs in, after
// the two controls (no credential, a random wrong one) were refused; the
// proof shows the three answers and a command that sends them without azhaq,
// the password written nowhere, and the session ended with the product's own
// logout.
func TestShowDocPublishedDefaultIsProvedAgainstItsControls(t *testing.T) {
	sd := &showDoc{pass: "123456", gated: true}
	origin, _ := newFixture(t, sd.handler)
	d, count := noFollowDoer()
	lg := catalogEntry(t, "showdoc-default-account")
	if lg.User != "showdoc" || lg.Pass != "123456" || !strings.Contains(lg.Source, "star7th/showdoc") || len(lg.Ports) != 1 || lg.Ports[0] != 4999 {
		t.Fatalf("the entry is not the published account of its source: %+v", lg)
	}
	if got := LoginsForProduct("ShowDoc"); len(got) != 1 || got[0].ID != lg.ID {
		t.Fatalf("catalog for ShowDoc: %+v", got)
	}
	_, out, tried, err := AttemptLogins(context.Background(), d, origin, []DefaultLogin{lg})
	if err != nil || !out.Success || tried != 1 {
		t.Fatalf("out %+v tried %d err %v", out, tried, err)
	}
	if count() != 3 {
		t.Errorf("%d requests, want the two controls and the pair", count())
	}
	const want = "no credential: 200, marker absent; wrong pair: 200, marker absent; the published pair (showdoc): 200 + marker"
	if out.Controls != want || !strings.Contains(out.Proof.Excerpt, want) {
		t.Errorf("controls %q / proof %q", out.Controls, out.Proof.Excerpt)
	}
	cmd := out.Proof.Reproduce
	if strings.Count(cmd, "curl ") != 3 || !strings.Contains(cmd, "read -rs PASS") || !strings.Contains(cmd, "username=showdoc") || !strings.Contains(cmd, `password=$PASS`) {
		t.Errorf("reproduce %q", cmd)
	}
	for _, s := range []string{out.Request, out.Excerpt, out.Proof.Excerpt, cmd} {
		if strings.Contains(s, "123456") {
			t.Errorf("the password is in %q", s)
		}
	}
	lg.Logout(context.Background(), d, origin, out.Cookie, out.Body)
	if len(sd.logouts) != 1 || sd.logouts[0] != "cookie_token=tok123 1" {
		t.Errorf("logout sent %q, want the session cookie and confirm=1", sd.logouts)
	}
}

// A changed password proves nothing, and a page that hands a token to anyone
// is not gated: no pair is sent to it and it is not proved.
func TestShowDocNotProvedWhenThePasswordChangedOrNothingIsGated(t *testing.T) {
	lg := catalogEntry(t, "showdoc-default-account")
	d, _ := noFollowDoer()
	changed := &showDoc{pass: "S3cr3t-changed", gated: true}
	origin, _ := newFixture(t, changed.handler)
	_, out, _, err := AttemptLogins(context.Background(), d, origin, []DefaultLogin{lg})
	if err != nil || out.Success || out.Proof != nil {
		t.Fatalf("a changed password was proved: %+v err %v", out, err)
	}
	open := &showDoc{gated: false}
	origin, h := newFixture(t, open.handler)
	_, out, _, err = AttemptLogins(context.Background(), d, origin, []DefaultLogin{lg})
	if err != nil || out.Success || out.Proof != nil || !strings.Contains(out.Note, "was not proved") {
		t.Fatalf("an ungated answer was proved: %+v err %v", out, err)
	}
	if h.count() != 1 {
		t.Errorf("%d requests, want only the no-credential control", h.count())
	}
	// A marker alone on another path proves nothing either.
	origin, _ = newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>user_token</html>`)
	})
	_, out, _, err = AttemptLogins(context.Background(), d, origin, []DefaultLogin{lg})
	if err != nil || out.Success {
		t.Fatalf("a page that names user_token was proved: %+v err %v", out, err)
	}
}

// openTSDB serves the two reads of a time-series database. open false makes
// it answer what a gated one answers.
func openTSDB(open bool) func(n int, w http.ResponseWriter, r *http.Request) {
	return func(n int, w http.ResponseWriter, r *http.Request) {
		if !open {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":{"code":401,"message":"Authentication required"}}`)
			return
		}
		switch r.URL.Path {
		case "/api/config":
			fmt.Fprint(w, `{"tsd.network.port":"4242","tsd.network.bind":"0.0.0.0","tsd.core.auto_create_metrics":"true"}`)
		case "/api/stats":
			fmt.Fprint(w, `[{"metric":"tsd.connectionmgr.connections","timestamp":1369350222,"value":"1","tags":{"host":"tsdb-1"}}]`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":{"code":404,"message":"Endpoint not found"}}`)
		}
	}
}

// The two read-only GETs of the time-series database find its configuration
// and statistics when its answer shows their keys, each read sent with no
// credential and again with a wrong one.
func TestOpenTSDBConfigAndStatsAreReadWithNoCredential(t *testing.T) {
	reads := ReadsForProduct("OpenTSDB")
	if len(reads) != 2 || reads[0].Path != "/api/config" || reads[1].Path != "/api/stats" {
		t.Fatalf("catalog for OpenTSDB: %+v", reads)
	}
	for _, u := range reads {
		if !strings.HasPrefix(u.Source, "https://opentsdb.net/docs/") || len(u.Ports) != 1 || u.Ports[0] != 4242 {
			t.Errorf("%s: source %q ports %v", u.ID, u.Source, u.Ports)
		}
	}
	var methods []string
	origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		openTSDB(true)(n, w, r)
	})
	want := map[string]string{"/api/config": `"tsd.network.port":"4242"`, "/api/stats": `"metric":"tsd.connectionmgr.connections"`}
	for _, u := range reads {
		found, req, ev, err := u.Check(context.Background(), testDoer(), origin)
		if err != nil || !found {
			t.Fatalf("%s: found %v err %v", u.ID, found, err)
		}
		if !strings.Contains(ev, want[u.Path]) || !strings.Contains(req, "GET "+u.Path+" with no credential") {
			t.Errorf("%s: request %q evidence %q", u.ID, req, ev)
		}
	}
	if h.count() != 4 {
		t.Errorf("%d requests, want two for each read", h.count())
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("a %s was sent: the reads are GETs", m)
		}
	}
}

// An answer that does not hold the keys proves nothing: a refusal, another
// body on the path, keys in a page that is not a 200, and a 404 of the API.
func TestOpenTSDBAnswerWithoutItsKeysIsNoFinding(t *testing.T) {
	for name, serve := range map[string]func(n int, w http.ResponseWriter, r *http.Request){
		"a refusal":    openTSDB(false),
		"a not found":  openTSDB(true),
		"another body": func(n int, w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `<html>Welcome</html>`) },
		"keys in a 403": func(n int, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"tsd.network.port":"4242","metric":"tsd.connectionmgr.x"}`)
		},
		"text, not keys": func(n int, w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `tsd.network.port tsd.connectionmgr.connections`)
		},
	} {
		origin, _ := newFixture(t, serve)
		for _, u := range ReadsForProduct("OpenTSDB") {
			if name == "a not found" {
				u.Path = "/api/other" // a path the stand-in does not serve
			}
			if found, _, ev, err := u.Check(context.Background(), testDoer(), origin); err != nil || found {
				t.Errorf("%s: %s found %v err %v: %q", name, u.ID, found, err, ev)
			}
		}
	}
}

// The evidence of a read keeps the key it matched, never the secrets that sit
// beside it: a configuration body that names a password, a token or a key
// shows none of their values, wherever they fall, however the excerpt is cut.
func TestUnauthReadEvidenceNeverHoldsASecretValue(t *testing.T) {
	filler := strings.Repeat(`"tsd.core.padding.x":"y",`, 12)
	config := `{"tsd.rabbitmq.password":"hunter2",` + filler + `"tsd.network.port":"4242","tsd.http.api_key":"k-777","auth.token":12345,` +
		`"cred":{"credential":"c-888"},"tsd.rtpublisher.rabbitmq.pass":"guest","secret_note": "s-999"}`
	serve := func(n int, w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, config) }
	origin, _ := newFixture(t, serve)
	secrets := []string{"hunter2", "k-777", "12345", "c-888", "guest", "s-999"}
	for _, u := range ReadsForProduct("OpenTSDB") {
		_, _, ev, err := u.Check(context.Background(), testDoer(), origin)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if strings.Contains(ev, s) {
				t.Errorf("%s: evidence holds %q: %s", u.ID, s, ev)
			}
		}
	}
	u := ReadsForProduct("OpenTSDB")[0]
	if _, _, ev, _ := u.Check(context.Background(), testDoer(), origin); !strings.Contains(ev, `unauthenticated: 200 "tsd.network.port":"4242"; with a wrong credential: 200 "tsd.network.port":"4242"`) {
		t.Errorf("evidence is not the matched key and its value: %s", ev)
	}
	// An entry with no window keeps the start of the body, masked before the cut.
	plain := UnauthRead{ID: "p", Product: "x", Path: "/c", Shown: func(int, []byte) bool { return true }}
	long := `{"a":"` + strings.Repeat("z", 150) + `","db_password":"` + strings.Repeat("hunter2", 20) + `"}`
	origin, _ = newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, long) })
	if _, _, ev, _ := plain.Check(context.Background(), testDoer(), origin); strings.Contains(ev, "hunter") || !strings.Contains(ev, "[redacted]") {
		t.Errorf("a cut inside a secret value left it: %s", ev)
	}
	// A body cut inside a value (the read is bounded) is masked too.
	if got := redactSecrets(`{"x":1,"api_key":"abc def, ghi`); strings.Contains(got, "abc") || strings.Contains(got, "ghi") {
		t.Errorf("a cut value stays: %s", got)
	}
}
