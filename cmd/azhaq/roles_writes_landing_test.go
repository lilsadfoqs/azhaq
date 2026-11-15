package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// landingServer is a service whose PUT /users/v1/{name}/email takes a bearer
// token. byToken: it writes the email of the token's user and ignores the name
// in the path; else it writes the email of the user the path names.
func landingServer(byToken bool) (*httptest.Server, func(string) string) {
	var mu sync.Mutex
	emails := map[string]string{"alice": "alice@x.test", "bob": "bob@x.test"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		if user == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/users/v1/"), "/")
		if _, ok := emails[name]; !ok {
			w.WriteHeader(404)
			return
		}
		switch {
		case r.Method == http.MethodGet && rest == "":
			fmt.Fprintf(w, `{"username":%q,"email":%q}`, name, emails[name])
		case r.Method == http.MethodPut && rest == "email":
			var in map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			if byToken {
				name = user
			}
			emails[name] = in["email"]
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	return srv, func(n string) string { mu.Lock(); defer mu.Unlock(); return emails[n] }
}

func landingHARs(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	var args []string
	for _, u := range []string{"alice", "bob"} {
		h := writeHAR(t, u+".har",
			harEntry("2026-11-13T10:00:00.000Z", "GET", srv.URL+"/users/v1/"+u, "", 200, "Authorization", "Bearer tok-"+u),
			harEntry("2026-11-13T10:00:01.000Z", "PUT", srv.URL+"/users/v1/"+u+"/email", `{"email":"`+u+`.old@x.test"}`, 204, "Authorization", "Bearer tok-"+u, "Content-Type", "application/json"))
		args = append(args, "-har", u+"="+h)
	}
	return append(args, "-role", "alice=Authorization: Bearer tok-alice", "-role", "bob=Authorization: Bearer tok-bob", "-no-anon",
		"-replay-writes", "put", "-replay-writes-canary", "-replay-writes-field", "email", "-all")
}

var canaryEmail = regexp.MustCompile(`^azhaq-[0-9a-f]{16}@x\.test$`)

// A service that writes the bearer's own record whatever name the path has:
// the owner's object is unchanged, so the verdict stays "changed nothing of
// the owner's", and the row says, as a measured fact, that the canary was
// read back in the sender's own object, with the one extra read it cost.
func TestRolesAWriteThatLandsOnTheSendersOwnObjectSaysSo(t *testing.T) {
	srv, email := landingServer(true)
	defer srv.Close()
	_, rows, rep, err := rolesJSONReport(t, srv.URL, landingHARs(t, srv)...)
	if err != nil {
		t.Fatal(err)
	}
	for owner, sender := range map[string]string{"alice": "bob", "bob": "alice"} {
		row := rows["/users/v1/"+owner+"/email"]
		if row.Verdict != verdictWriteNoChange {
			t.Fatalf("%s's row: verdict %q, want it kept as %q", owner, row.Verdict, verdictWriteNoChange)
		}
		if row.LandedOn != "sender" || len(row.LandedBy) != 1 || row.LandedBy[0] != sender {
			t.Errorf("%s's row: landed_on %q by %v, want sender by [%s]", owner, row.LandedOn, row.LandedBy, sender)
		}
		for _, want := range []string{sender + "'s write landed on " + sender + "'s own object", "the route does not use the name in the path", "not restored", "now holds the canary value"} {
			if !strings.Contains(row.Evidence, want) {
				t.Errorf("%s's row: the evidence lacks %q: %q", owner, want, row.Evidence)
			}
		}
		if !strings.Contains(row.OwnerBy, sender+"'s own object, read at /users/v1/"+sender) {
			t.Errorf("%s's row: owner_by does not say where the sender's object was read: %q", owner, row.OwnerBy)
		}
		if !canaryEmail.MatchString(email(sender)) {
			t.Errorf("%s's email after the run: %q", sender, email(sender))
		}
	}
	// The sender's read is a verification read, in the ledger's stage.
	var verify int64
	for _, st := range rep.Cost.Stages {
		if st.Stage == stageVerify {
			verify = st.Actual.Requests
		}
	}
	if verify < 4 {
		t.Errorf("the verification stage sent %d requests: each write reads the owner's object and then the sender's, so at least 4", verify)
	}
	// The text table carries it too.
	out, _, err := captureBoth(t, func() error {
		return cmdRoles(append([]string{"-dir", t.TempDir()}, landingHARs(t, srv)...))
	})
	if err != nil || !strings.Contains(out, "landed on bob's own object") || !strings.Contains(out, "is not restored") {
		t.Errorf("the text table does not say where the write landed (%v):\n%s", err, out)
	}
}

// A path that names the owner and a service that honours it is a cross write:
// proved, and nothing says it landed on the sender.
func TestRolesAProvedCrossWriteDoesNotLandOnTheSender(t *testing.T) {
	srv, email := landingServer(false)
	defer srv.Close()
	_, rows, _, err := rolesJSONReport(t, srv.URL, landingHARs(t, srv)...)
	if err != nil {
		t.Fatal(err)
	}
	row := rows["/users/v1/alice/email"]
	if row.Verdict != verdictWriteCross || row.WriteVerification != verifyProved || row.LandedOn != "" || len(row.LandedBy) != 0 || strings.Contains(row.Evidence, "landed") {
		t.Errorf("a cross write: %+v", row)
	}
	if !canaryEmail.MatchString(email("alice")) {
		t.Errorf("alice's email after bob's write: %q", email("alice"))
	}
}

// When the sender's own object cannot be read, the row says it was not read:
// no object of its own known on the route, or an answer that is not 2xx. It
// never says where the write landed.
func TestRolesASendersObjectThatCannotBeReadIsSaidNotRead(t *testing.T) {
	srv, _ := landingServer(true)
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("Authorization", "Bearer tok-"+v); return x }
	roles := []role{{name: "alice", headers: []string{"Authorization: Bearer tok-alice"}, session: h("alice")}, {name: "bob", headers: []string{"Authorization: Bearer tok-bob"}, session: h("bob")}}
	ownAnswer, _ := readAnswer(200, []byte(`{"username":"alice","email":"alice@x.test"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {srv.URL + "/users/v1/alice": ownAnswer}}
	put := func(ownRead func(string, string) string) writeReq {
		return writeReq{owner: "alice", method: "PUT", url: srv.URL + "/users/v1/alice/email", header: http.Header{"Content-Type": {"application/json"}},
			body: []byte(`{"email":"alice.old@x.test"}`), status: 204, from: "alice.har", ownRead: ownRead}
	}
	for name, c := range map[string]struct {
		own  func(string, string) string
		want string
	}{
		"no route for the sender":   {nil, "no object of bob's own is known"},
		"an answer that is not 2xx": {func(string, string) string { return srv.URL + "/users/v1/nobody" }, "answered 404"},
	} {
		rows, _, err := replayWrites(roles, []writeReq{put(c.own)}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, true, "email")
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: rows %+v err %v", name, rows, err)
		}
		r := rows[0]
		if r.Verdict != verdictWriteNoChange || r.LandedOn != "" {
			t.Errorf("%s: %+v", name, r)
		}
		if !strings.Contains(r.OwnerBy, "bob's own object was not read to see where the write landed") || !strings.Contains(r.OwnerBy, c.want) {
			t.Errorf("%s: owner_by does not say it was not read (%q): %q", name, c.want, r.OwnerBy)
		}
	}
}
