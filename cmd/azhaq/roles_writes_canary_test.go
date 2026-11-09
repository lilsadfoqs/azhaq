package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"encoding/json"
	"regexp"
)

// A canary keeps the shape of the value it replaces: an email keeps its
// domain, digits stay digits of the same length, anything else is the token.
func TestCanaryKeepsTheShapeOfTheRecordedValue(t *testing.T) {
	if got := canaryLike("alice@x.test", "azhaq-1"); got != "azhaq-1@x.test" {
		t.Errorf("an email: %q", got)
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		got := canaryLike("0123456789", "azhaq-1")
		if !regexp.MustCompile(`^[0-9]{10}$`).MatchString(got) || got == "0123456789" {
			t.Fatalf("digits: %q", got)
		}
		seen[got] = true
	}
	if len(seen) < 15 {
		t.Errorf("digits are not unique: %d of 20 differ", len(seen))
	}
	if got := canaryLike("7", "azhaq-1"); got == "7" || len(got) != 1 {
		t.Errorf("one digit: %q", got)
	}
	for _, v := range []string{"hello", "a@b@c", "@x.test", "me@", "12ab", ""} {
		if got := canaryLike(v, "azhaq-1"); got != "azhaq-1" {
			t.Errorf("%q: %q", v, got)
		}
	}
	out, f, ok := withCanary([]byte(`{"phone":"55512"}`), "azhaq-1")
	var m map[string]string
	if err := json.Unmarshal(out, &m); !ok || f != "phone" || err != nil || !regexp.MustCompile(`^[0-9]{5}$`).MatchString(m["phone"]) || m["phone"] == "55512" {
		t.Errorf("a digits field: %s %q %v", out, f, ok)
	}
}

// VAmPI's PUT /users/v1/{username}/email refuses a value that is not an
// email (400): the canary an email field carries is an email, so the write
// is accepted, read back at the debug listing, and proved.
func TestReplayWriteCanaryOfAnEmailFieldIsAnEmail(t *testing.T) {
	var mu sync.Mutex
	emails := map[string]string{"alice": "alice@x.test", "bob": "bob@x.test"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/users/v1/_debug":
			fmt.Fprintf(w, `{"users":[{"username":"alice","email":%q},{"username":"bob","email":%q}]}`, emails["alice"], emails["bob"])
		case r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"username":%q}`, strings.TrimPrefix(r.URL.Path, "/users/v1/"))
		default:
			var m map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &m)
			if !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[a-z]+$`).MatchString(m["email"]) {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"status":"fail","message":"Please Provide a valid email address."}`)
				return
			}
			emails[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/users/v1/"), "/email")] = m["email"]
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	ownAnswer, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
	debugAnswer, _ := readAnswer(200, []byte(`{"users":[{"username":"alice","email":"alice@x.test"},{"username":"bob","email":"bob@x.test"}]}`), "application/json")
	answers := map[string]map[string]answer{"alice": {srv.URL + "/users/v1/alice": ownAnswer, srv.URL + "/users/v1/_debug": debugAnswer}}
	put := writeReq{owner: "alice", method: "PUT", url: srv.URL + "/users/v1/alice/email",
		header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"email":"alice@x.test"}`), status: 204, from: "alice.har"}
	rows, _, err := replayWritesPaused(nil, roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, true, nil, nil, "email")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if r.Verdict != verdictWriteCross || r.WriteVerification != verifyProved || r.Status["bob"] != 204 {
		t.Fatalf("the write was not accepted and proved: %+v", r)
	}
	if got := emails["alice"]; !regexp.MustCompile(`^azhaq-[0-9a-f]{16}@x\.test$`).MatchString(got) {
		t.Errorf("alice's email after the canary: %q", got)
	}
}

// A canary the server answers 400 or 422 did not reach the write path: the
// row says so with the status and what the server said, it is neither a
// refusal nor a negative, and the summary says the write path was not
// exercised.
func TestReplayWriteCanaryRejectedIsNotARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			w.WriteHeader(422)
			fmt.Fprint(w, `{"error":"note must be one of the saved notes"}`)
			return
		}
		fmt.Fprint(w, `{"id":3,"owner":"alice","note":"hello"}`)
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	u := srv.URL + "/api/notes/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"owner":"alice","note":"hello"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {u: before}}
	put := writeReq{owner: "alice", method: "PUT", url: u, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"hello"}`), status: 204, from: "alice.har"}
	rows, _, err := replayWrites(roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, true)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if r.Verdict != verdictWriteCanaryRejected || !listed(r.Verdict) {
		t.Fatalf("verdict %q", r.Verdict)
	}
	for _, want := range []string{"bob", "note", "422", "note must be one of the saved notes"} {
		if !strings.Contains(r.Evidence, want) {
			t.Errorf("the evidence lacks %q: %q", want, r.Evidence)
		}
	}
	if r.Status["bob"] != 422 || len(r.Readers) != 0 {
		t.Errorf("row %+v", r)
	}
	notes := canaryRejections(rows)
	if len(notes) != 1 || !strings.Contains(notes[0], "write path was not exercised") || !strings.Contains(notes[0], "PUT /api/notes/3") {
		t.Errorf("notes %q", notes)
	}
	// Without the canary the same 422 is the server's answer to the write
	// as recorded: no canary, so no rejection.
	rows, _, _ = replayWrites(roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict == verdictWriteCanaryRejected {
		t.Errorf("a recorded write answered 422 is not a rejected canary: %+v", rows)
	}
}

// The summary of a run says, in its notes, that a rejected canary left the
// write path unexercised, and the row is listed with what the server said.
func TestRolesSummaryNamesARejectedCanary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		if user == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"message":"Please Provide a valid label"}`)
			return
		}
		fmt.Fprint(w, `{"id":3,"label":"first"}`)
	}))
	defer srv.Close()
	browse := func(file, user string) string {
		return writeHAR(t, file,
			harEntry("2026-10-29T10:00:00.000Z", "PUT", srv.URL+"/api/items/3", `{"label":"first"}`, 204, "Authorization", "Bearer tok-"+user, "Content-Type", "application/json"))
	}
	alice, bob := browse("alice.har", "alice"), browse("bob.har", "bob")
	args := []string{"-json", "-dir", t.TempDir(), "-har", "alice=" + alice, "-har", "bob=" + bob, "-replay-writes", "put", "-replay-writes-canary"}
	_, errOut, err := captureBoth(t, func() error { return cmdRoles(args) })
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, want := range []string{"the write path was not exercised", "PUT /api/items/3", `"canary rejected`, "2 writes answered 400 or 422"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the summary lacks %q:\n%s", want, errOut)
		}
	}
}
