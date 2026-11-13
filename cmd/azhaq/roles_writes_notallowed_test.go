package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A 405 or 501 says the route does not take the method: not a refusal of the
// role. The verdict says so, and says nothing about who may write.
func TestReplayWriteMethodNotAllowedIsNotARefusal(t *testing.T) {
	answer := map[string]int{} // role's A header → status
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(answer[r.Header.Get("A")])
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon", session: h("anon")}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	del := writeReq{owner: "alice", method: "DELETE", url: srv.URL + "/api/items/3", header: http.Header{}, from: "alice.har", status: 200}
	for _, c := range []struct {
		anon, bob int
		want      string
	}{
		{405, 405, verdictWriteNotAllowed},
		{501, 501, verdictWriteNotAllowed},
		{405, 501, verdictWriteNotAllowed},
		{401, 405, verdictWriteMixedNotAllowed},
		{500, 405, verdictWriteMixedNotAllowed},
		{302, 405, verdictWriteMixedNotAllowed},
		{403, 403, verdictWriteOwner},
		{500, 500, verdictWriteFailed},
	} {
		answer["anon"], answer["bob"] = c.anon, c.bob
		rows, _, _ := replayWrites(roles, []writeReq{del}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		if len(rows) != 1 || rows[0].Verdict != c.want {
			t.Errorf("anon %d, bob %d: %+v, want %q", c.anon, c.bob, rows, c.want)
			continue
		}
		if notAllowedVerdict(c.want) != listed(rows[0].Verdict) && c.want != verdictWriteOwner && c.want != verdictWriteFailed {
			t.Errorf("%q: listed() is %v", c.want, listed(rows[0].Verdict))
		}
	}
	// The row says each role's status and where the owner's came from.
	answer["anon"], answer["bob"] = 405, 405
	rows, _, _ := replayWrites(roles, []writeReq{del}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	ev := rows[0].Evidence
	for _, want := range []string{"anon got 405", "bob got 405", "alice (the owner) got 200", "as recorded in alice.har", "not replayed"} {
		if !strings.Contains(ev, want) {
			t.Errorf("the evidence lacks %q: %q", want, ev)
		}
	}
	if strings.Contains(rows[0].Verdict, "owner") || strings.Contains(rows[0].Verdict, "refused") {
		t.Errorf("the verdict says something about who may write: %q", rows[0].Verdict)
	}
}

// A DELETE the route does not take (405 for everyone) is listed without -all,
// its rows carry each role's status, the summary counts it among the listed
// rows, and a note names the writes with their statuses.
func TestRolesADeleteAnswered405IsListedByDefaultAndSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"username":"` + strings.TrimPrefix(r.URL.Path, "/users/v1/") + `"}`))
		default:
			w.WriteHeader(405)
		}
	}))
	defer srv.Close()
	args := []string{"-no-anon", "-replay-writes", "delete"}
	for _, u := range []string{"alice", "bob"} {
		h := writeHAR(t, u+".har",
			harEntry("2026-11-13T10:00:00.000Z", "GET", srv.URL+"/users/v1/"+u, "", 200, "Authorization", "Bearer tok-"+u),
			harEntry("2026-11-13T10:00:01.000Z", "DELETE", srv.URL+"/users/v1/"+u, "", 200, "Authorization", "Bearer tok-"+u))
		args = append(args, "-har", u+"="+h, "-role", u+"=Authorization: Bearer tok-"+u)
	}
	_, rows, rep, err := rolesJSONReport(t, srv.URL, args...)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		row, ok := rows["/users/v1/"+u]
		if !ok || row.Method != "DELETE" {
			t.Fatalf("no DELETE row for %s listed without -all: %+v", u, rows)
		}
		other := map[string]string{"alice": "bob", "bob": "alice"}[u]
		if row.Verdict != verdictWriteNotAllowed || row.Status[other] != 405 || row.Status[u] != 200 {
			t.Errorf("%s: verdict %q, status %v", u, row.Verdict, row.Status)
		}
		if !strings.Contains(row.Evidence, "as recorded in "+u+".har") {
			t.Errorf("%s: the evidence does not say the owner's status is from the history: %q", u, row.Evidence)
		}
	}
	if rep.Counts[verdictWriteNotAllowed] != 2 || rep.Counts[verdictWriteOwner] != 0 {
		t.Errorf("the summary counts %v", rep.Counts)
	}
	n := 0
	for _, c := range rep.Counts {
		n += c
	}
	if n != rep.Results {
		t.Errorf("the counts add up to %d, the summary lists %d", n, rep.Results)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "2 writes answered 405 or 501") || !strings.Contains(notes, "bob got 405") || strings.Contains(notes, "not listed ("+verdictWriteNotAllowed) {
		t.Errorf("the notes: %s", notes)
	}
}
