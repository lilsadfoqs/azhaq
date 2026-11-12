package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

func TestParseVerifyWrites(t *testing.T) {
	got, err := parseVerifyWrites([]string{"login:https://app/users/login", "read:https://app/users/{owner};field=email=new@x.test", "read:https://app/x;field=email"})
	if err != nil || len(got) != 3 || got[0].kind != "login" || got[0].url != "https://app/users/login" ||
		got[1].field != "email" || got[1].value != "new@x.test" || got[2].field != "email" || got[2].value != "" {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"https://app/x", "login:", "read:https://app/x;expect=1", "login:https://app/x;field=email"} {
		if _, err := parseVerifyWrites([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A session that dies mid-replay and cannot be renewed pauses the role:
// the rest is not attempted (and the budget is not spent on it), while
// what was asked since the last good check is suspect.
func TestReplayPausesOnSessionLoss(t *testing.T) {
	fetch.Reset()
	var mu sync.Mutex
	var asked []string
	n := 0
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		tok := r.Header.Get("Authorization")
		if r.URL.Path != "/me" {
			asked = append(asked, r.URL.Path)
			if tok == "t1" {
				n++
			}
		}
		if tok != "t1" || n > 4 && r.URL.Path == "/me" || tok == "t1" && n > 4 && r.URL.Path != "/me" {
			// The token dies after four object requests.
			if tok != "t2" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"expired"}`)
				return
			}
		}
		if r.URL.Path == "/me" {
			if tok != "t1" || n > 4 {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"expired"}`)
				return
			}
			fmt.Fprint(w, `{"name":"alice"}`)
			return
		}
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	defer site.Close()
	me, _ := readAnswer(200, []byte(`{"name":"alice"}`), "application/json")
	roles := []role{{name: "alice", headers: []string{"Authorization: t1"}, session: http.Header{"Authorization": {"t1"}}}}
	answers := map[string]map[string]answer{"alice": {}}
	found := map[string][]string{}
	for i := 1; i <= 9; i++ {
		found[fmt.Sprintf("%s/o/%d", site.URL, i)] = []string{"bob"}
	}
	w := &replayWatch{every: 3, canaries: map[string]*canary{"alice": {url: site.URL + "/me", want: me}}, renew: func(i int) error {
		return fmt.Errorf("its session was given with -role, and roles cannot renew it")
	}}
	sent, err := replayAll(roles, answers, found, nil, map[string]bool{"127.0.0.1": true}, 0, 100, w)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/o/7", "/o/8", "/o/9"} {
		if strings.Contains(strings.Join(asked, " "), p) {
			t.Errorf("%s was asked after the session was lost and could not be renewed: %v (sent %d)", p, asked, sent)
		}
		if _, ok := answers["alice"][site.URL+p]; ok {
			t.Errorf("%s has an answer though it was not attempted", p)
		}
	}
	all := strings.Join(w.notes, "\n")
	if !strings.Contains(all, "paused on session loss") || !strings.Contains(all, "not attempted") || !strings.Contains(all, "proved") || !strings.Contains(all, "suspect") {
		t.Errorf("notes do not separate proved, suspect and not-attempted:\n%s", all)
	}
	if !w.failed {
		t.Errorf("a paused role should mark the comparison failed (exit 3)")
	}
}

// passwordApp is a VAmPI-shaped user store: a password change answers
// 204 and no GET shows the password; only a sign-in proves it took.
func passwordApp(t *testing.T, callerOnly bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	passwords := map[string]string{"alice": "old", "bob": "bobpw"}
	emails := map[string]string{"alice": "alice@x.test", "bob": "bob@x.test"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get("A")
		if caller == "" && r.URL.Path != "/users/login" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/users/login":
			var in map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			if passwords[in["username"]] == in["password"] && in["password"] != "" {
				fmt.Fprint(w, `{"ok":true}`)
			} else {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"bad credentials"}`)
			}
		case r.Method == http.MethodPut:
			target := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/users/"), "/password")
			target = strings.TrimSuffix(target, "/email")
			if callerOnly {
				target = caller
			}
			var in map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			if strings.HasSuffix(r.URL.Path, "/password") {
				passwords[target] = in["password"]
			} else {
				emails[target] = in["email"]
			}
			w.WriteHeader(204)
		case strings.HasPrefix(r.URL.Path, "/profile/"):
			name := strings.TrimPrefix(r.URL.Path, "/profile/")
			fmt.Fprintf(w, `{"username":%q,"email":%q}`, name, emails[name])
		default:
			name := strings.TrimPrefix(r.URL.Path, "/users/")
			fmt.Fprintf(w, `{"username":%q}`, name)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A password change a read-back cannot show is proved by the sign-in
// step the user gave, and refuted when the sign-in fails: the two are
// not both "accepted".
func TestVerifyWriteBySignIn(t *testing.T) {
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	run := func(callerOnly bool) roleRow {
		srv := passwordApp(t, callerOnly)
		steps, err := parseVerifyWrites([]string{"login:" + srv.URL + "/users/login"})
		if err != nil {
			t.Fatal(err)
		}
		obj := srv.URL + "/users/alice"
		before, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
		answers := map[string]map[string]answer{"alice": {obj: before}}
		put := writeReq{owner: "alice", method: "PUT", url: srv.URL + "/users/alice/password", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"password":"n3w"}`), status: 204, from: "alice.har"}
		// The run learned that role alice is the user alice: a failed sign-in
		// as a user it observed is a refusal.
		id := newIdentity()
		id.keep("username", "alice")
		rows, _, err := replayWritesVerify(map[string]identity{"alice": id}, roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, false, steps)
		if err != nil || len(rows) != 1 {
			t.Fatalf("rows %+v err %v", rows, err)
		}
		return rows[0]
	}
	if r := run(false); r.Verdict != verdictWriteCross || r.WriteVerification != verifyProved {
		t.Errorf("a sign-in with the new password proves the change: verdict %q verification %q", r.Verdict, r.WriteVerification)
	}
	if r := run(true); r.Verdict == verdictWriteCross || r.WriteVerification != verifyRefuted {
		t.Errorf("a failed sign-in refutes it: verdict %q verification %q", r.Verdict, r.WriteVerification)
	}
}

// A read of a named field the user gave proves a write the object's own
// GET cannot show.
func TestVerifyWriteByReadingAField(t *testing.T) {
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	srv := passwordApp(t, false)
	steps, err := parseVerifyWrites([]string{"read:" + srv.URL + "/profile/{owner};field=email"})
	if err != nil {
		t.Fatal(err)
	}
	obj := srv.URL + "/users/alice"
	before, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {obj: before}}
	put := writeReq{owner: "alice", method: "PUT", url: srv.URL + "/users/alice/email", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"email":"new@x.test"}`), status: 204, from: "alice.har"}
	rows, _, err := replayWritesVerify(nil, roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, false, steps)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if r := rows[0]; r.Verdict != verdictWriteCross || r.WriteVerification != verifyProved {
		t.Errorf("reading the field proves the change: verdict %q verification %q owner_by %q", r.Verdict, r.WriteVerification, r.OwnerBy)
	}
}

// Roles are labels: ra is the user alice and rb is bob. The sign-in goes
// out as the application user, never as the role's name, and a name that was
// only read off the URL cannot refute a write.
func TestVerifyWriteSignsInAsTheOwnersUserNotTheRoleName(t *testing.T) {
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "ra", headers: []string{"A: ra"}, session: h("ra")}, {name: "rb", headers: []string{"A: rb"}, session: h("rb")}}
	run := func(callerOnly bool, steps []string, who map[string]identity) roleRow {
		srv := passwordApp(t, callerOnly)
		vs := make([]string, len(steps))
		for i, s := range steps {
			vs[i] = strings.Replace(s, "SRV", srv.URL, 1)
		}
		parsed, err := parseVerifyWrites(vs)
		if err != nil {
			t.Fatal(err)
		}
		obj := srv.URL + "/users/alice"
		before, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
		answers := map[string]map[string]answer{"ra": {obj: before}}
		put := writeReq{owner: "ra", method: "PUT", url: srv.URL + "/users/alice/password", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"password":"n3w"}`), status: 204, from: "ra.har"}
		rows, _, err := replayWritesVerify(who, roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, false, parsed)
		if err != nil || len(rows) != 1 {
			t.Fatalf("rows %+v err %v", rows, err)
		}
		return rows[0]
	}
	login := []string{"login:SRV/users/login"}
	// Nothing learned of ra: the user is read off the path, and the change took.
	if r := run(false, login, nil); r.WriteVerification != verifyProved {
		t.Errorf("a sign-in as alice proves the change though the role is called ra: %q, %q", r.WriteVerification, r.OwnerBy)
	}
	// The same, with the user the run observed for ra.
	id := newIdentity()
	id.keep("username", "alice")
	if r := run(false, login, map[string]identity{"ra": id}); r.WriteVerification != verifyProved {
		t.Errorf("observed user: %q, %q", r.WriteVerification, r.OwnerBy)
	}
	// The user given on the step wins over the path.
	if r := run(false, []string{"login:SRV/users/login;user=alice"}, nil); r.WriteVerification != verifyProved {
		t.Errorf("user= on the step: %q, %q", r.WriteVerification, r.OwnerBy)
	}
	// The app applied the write to its caller: alice's sign-in fails. With a
	// user read off the path that decides nothing and names who was tried.
	r := run(true, login, nil)
	if r.WriteVerification != verifyAccepted || !strings.Contains(r.OwnerBy, `"alice"`) || !strings.Contains(r.OwnerBy, "decides nothing") {
		t.Errorf("a failed sign-in as a name read off the URL is not a refutation: %q, %q", r.WriteVerification, r.OwnerBy)
	}
	// With the user observed it is a refutation.
	if r := run(true, login, map[string]identity{"ra": id}); r.WriteVerification != verifyRefuted {
		t.Errorf("a failed sign-in as the observed user refutes: %q, %q", r.WriteVerification, r.OwnerBy)
	}
}

// When no application user is known for the owner role, the sign-in is not
// sent as the role's name: the row is accepted-not-verified and says which
// name was not tried.
func TestVerifyWriteWithNoKnownUserIsNotSentAsTheRoleName(t *testing.T) {
	var logins atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			logins.Add(1)
			w.WriteHeader(401)
		case r.Header.Get("A") == "":
			w.WriteHeader(401)
		case r.Method == http.MethodPut:
			w.WriteHeader(204)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":7}`)
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "ra", headers: []string{"A: ra"}, session: h("ra")}, {name: "rb", headers: []string{"A: rb"}, session: h("rb")}}
	steps, _ := parseVerifyWrites([]string{"login:" + srv.URL + "/login"})
	before, _ := readAnswer(200, []byte(`{"id":7}`), "application/json")
	put := writeReq{owner: "ra", method: "PUT", url: srv.URL + "/acct/7/password", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"password":"n3w"}`), status: 204, from: "ra.har"}
	rows, _, err := replayWritesVerify(nil, roles, []writeReq{put}, map[string]map[string]answer{"ra": {srv.URL + "/acct/7": before}}, map[string]bool{"127.0.0.1": true}, 0, 100, false, steps)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
	if r := rows[0]; r.WriteVerification != verifyAccepted || !strings.Contains(r.OwnerBy, `"ra" was not tried`) || logins.Load() != 0 {
		t.Errorf("no known user: %q, %q, %d sign-ins", r.WriteVerification, r.OwnerBy, logins.Load())
	}
}

// ownerUser reads the owner's application user: the step's, then what the run
// learned, then the route's {username} or the segment after a user noun (a
// version segment is no user). Only the last two are readings of a URL.
func TestOwnerUserOfAWrite(t *testing.T) {
	id := newIdentity()
	id.keep("username", "alice")
	who := map[string]identity{"ra": id}
	put := func(u, route string) writeReq { return writeReq{owner: "ra", method: "PUT", url: u, route: route} }
	for _, c := range []struct {
		name  string
		step  verifyWrite
		who   map[string]identity
		w     writeReq
		want  string
		firm  bool
		owner string
	}{
		{"the step names it", verifyWrite{user: "zed"}, who, put("http://h/users/v1/alice/password", ""), "zed", true, "ra"},
		{"the run learned it", verifyWrite{}, who, put("http://h/users/v1/alice/password", ""), "alice", true, "ra"},
		{"the route's {username}", verifyWrite{}, nil, put("http://h/a/b/zed/password", "http://h/a/b/{username}/password"), "zed", false, "ra"},
		{"after a user noun, past a version", verifyWrite{}, nil, put("http://h/users/v1/zed/password", ""), "zed", false, "ra"},
		{"nothing says", verifyWrite{}, nil, put("http://h/acct/7/password", ""), "", false, "ra"},
		{"a role name is not a user", verifyWrite{}, nil, put("http://h/x/ra", ""), "", false, "ra"},
	} {
		got, firm, how := ownerUser(c.step, c.owner, c.w, c.who)
		if got != c.want || firm != c.firm || (got != "" && how == "") {
			t.Errorf("%s: %q firm %v (%s), want %q firm %v", c.name, got, firm, how, c.want, c.firm)
		}
	}
}
