package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// -replay-max is one count for the history reads and the replay together,
// over all roles, as its help says: what the history reads sent is not
// given to the replay again.
func TestReplayMaxIsSharedByHistoryReadsAndReplay(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q,"as":%q}`, r.URL.Path, r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	browse := func(file, user string) string {
		var es []map[string]any
		for i := 1; i <= 6; i++ {
			es = append(es, harEntry(fmt.Sprintf("2026-10-29T10:00:%02d.000Z", i), "GET", fmt.Sprintf("%s/api/%s/%d", srv.URL, user, i), "", 200, "Authorization", "Bearer t-"+user))
		}
		return writeHAR(t, file, es...)
	}
	alice, bob := browse("alice.har", "alice"), browse("bob.har", "bob")
	// Twelve pages are read from the histories; the replay needs more than the
	// two requests the cap leaves it.
	_, errOut, code := cli(t, "roles", "-har", "alice="+alice, "-har", "bob="+bob, "-json", "-dir", t.TempDir(), "-replay-max", "14")
	if n := hits.Load(); n > 14 {
		t.Errorf("-replay-max 14: the target saw %d requests", n)
	}
	sum := sumMap(t, errOut)
	stopped, _ := sum["stopped"].(string)
	if code != exitLimit || !strings.Contains(stopped, "-replay-max 14") {
		t.Errorf("exit %d, stopped %q: the cap that ended the replay is not named", code, stopped)
	}
}

// A write another role sent that the server answered with a redirect (not
// followed) was not refused: the verdict says what happened.
func TestWriteRedirectIsNotARefusal(t *testing.T) {
	answer := map[string]int{} // role's A header → status
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch st := answer[r.Header.Get("A")]; {
		case st >= 300 && st < 400:
			http.Redirect(w, r, "/login", st)
		default:
			w.WriteHeader(st)
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon", session: h("anon")}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	del := writeReq{owner: "alice", method: "DELETE", url: srv.URL + "/api/items/3", header: http.Header{}}
	for _, c := range []struct {
		anon, bob int
		want      string
	}{
		{403, 403, verdictWriteRefused},
		{302, 302, verdictWriteRedirected},
		{401, 302, verdictWriteMixedRedirect},
		{500, 302, verdictWriteMixedRedirect},
		{401, 500, verdictWriteMixed},
		{500, 500, verdictWriteFailed},
	} {
		answer["anon"], answer["bob"] = c.anon, c.bob
		rows, _, _ := replayWrites(roles, []writeReq{del}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		if len(rows) != 1 || rows[0].Verdict != c.want {
			t.Errorf("anon %d, bob %d: %+v, want %q", c.anon, c.bob, rows, c.want)
		}
	}
}

var atLeastMore = regexp.MustCompile(`at least (\d+) requests? more`)

// The next pass for the writes a history holds says it is a floor, and the
// run it suggests sends at least that many requests more, whatever the
// server answers: it counts each write once for each other role, not the
// reads that depend on the answers.
func TestWritesNextPassIsAFloor(t *testing.T) {
	var hits atomic.Int64
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "GET" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Books":[{"book_title":"b1"}]}`)
	}))
	defer refusing.Close()
	open := vampiShaped(&hits)
	defer open.Close()
	for _, c := range []struct{ name, url, method, path string }{
		{"refused PUT", refusing.URL, "PUT", "/books/v1/b1"},
		{"refused POST", refusing.URL, "POST", "/books/v1"},
		{"open POST", open.URL, "POST", "/books/v1"},
	} {
		alice := writeHAR(t, "alice.har",
			harEntry("2026-10-29T10:00:00.000Z", "GET", c.url+"/books/v1", "", 200, "Authorization", "Bearer t-alice"),
			harEntry("2026-10-29T10:00:01.000Z", c.method, c.url+c.path, `{"book_title":"x"}`, 200, "Authorization", "Bearer t-alice", "Content-Type", "application/json"))
		bob := writeHAR(t, "bob.har", harEntry("2026-10-29T10:00:00.000Z", "GET", c.url+"/books/v1", "", 200, "Authorization", "Bearer t-bob"))
		flags := []string{"roles", "-har", "alice=" + alice, "-har", "bob=" + bob, "-json"}
		hits.Store(0)
		_, errOut, _ := cli(t, append(flags, "-dir", t.TempDir())...)
		first := hits.Load()
		line := fmt.Sprint(sumMap(t, errOut)["next"])
		m := atLeastMore.FindStringSubmatch(line)
		if m == nil || !strings.Contains(line, "a floor") {
			t.Fatalf("%s: the next pass does not say it is a floor: %s", c.name, line)
		}
		floor, _ := strconv.ParseInt(m[1], 10, 64)
		hits.Store(0)
		cli(t, append(flags, "-dir", t.TempDir(), "-replay-writes", "post,put,patch")...)
		if more := hits.Load() - first; more < floor {
			t.Errorf("%s: the next pass says at least %d requests more; the run sent %d more", c.name, floor, more)
		}
	}
}

// The plan caps the replay by what -replay-max leaves after the history
// reads, as the run does.
func TestRolesPlanSharesReplayMax(t *testing.T) {
	var hits atomic.Int64
	srv := vampiShaped(&hits)
	defer srv.Close()
	alice := writeHAR(t, "alice.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/books/v1", "", 200, "Authorization", "Bearer t-alice"),
		harEntry("2026-10-29T10:00:01.000Z", "GET", srv.URL+"/books/v1/b1", "", 200, "Authorization", "Bearer t-alice"),
		harEntry("2026-10-29T10:00:02.000Z", "GET", srv.URL+"/me", "", 200, "Authorization", "Bearer t-alice"))
	bob := writeHAR(t, "bob.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/books/v1", "", 200, "Authorization", "Bearer t-bob"),
		harEntry("2026-10-29T10:00:01.000Z", "GET", srv.URL+"/books/v1/b2", "", 200, "Authorization", "Bearer t-bob"),
		harEntry("2026-10-29T10:00:02.000Z", "GET", srv.URL+"/me", "", 200, "Authorization", "Bearer t-bob"))
	out, _, _ := cli(t, "roles", "-plan", "-json", "-har", "alice="+alice, "-har", "bob="+bob, "-replay-max", "8")
	var p struct {
		Estimate struct {
			Stages []struct {
				Stage    string `json:"stage"`
				Estimate struct {
					Requests int64 `json:"requests"`
				} `json:"estimate"`
			} `json:"stages"`
		} `json:"estimate"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := map[string]int64{}
	for _, s := range p.Estimate.Stages {
		got[s.Stage] = s.Estimate.Requests
	}
	// Six history reads leave two of the eight for the replay, which needs six.
	if got["history reads"] != 6 || got["replay"] != 2 {
		t.Errorf("-replay-max 8: history reads %d, replay %d, want 6 and 2", got["history reads"], got["replay"])
	}
}
