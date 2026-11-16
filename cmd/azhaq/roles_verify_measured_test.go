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

// callerApp is a VAmPI-shaped user store whose writes change the account of
// the token, whatever name the path holds; reads are public. showEmail false
// leaves the email out of GET /users/v1/{name}, as VAmPI does.
type callerApp struct {
	mu        sync.Mutex
	email, pw map[string]string
	showEmail bool
	logins    int
}

func newCallerApp(t *testing.T, showEmail bool) (*httptest.Server, *callerApp) {
	t.Helper()
	app := &callerApp{showEmail: showEmail,
		email: map[string]string{"alice": "alice@x.test", "bob": "bob@x.test"},
		pw:    map[string]string{"alice": "a", "bob": "b"}}
	var userPath = regexp.MustCompile(`^/users/v1/([^/]+)$`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		defer app.mu.Unlock()
		caller := r.Header.Get("A")
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/users/v1/login":
			app.logins++
			if app.pw[in["username"]] == in["password"] && in["password"] != "" {
				fmt.Fprint(w, `{"auth_token":"t"}`)
			} else {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"message":"Password is not correct for the given username."}`)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/users/v1/register":
			app.email[in["username"]], app.pw[in["username"]] = in["email"], in["password"]
			fmt.Fprint(w, `{"status":"success","message":"Successfully registered."}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/debug/users/"):
			n := strings.TrimPrefix(r.URL.Path, "/debug/users/")
			fmt.Fprintf(w, `{"username":%q,"email":%q}`, n, app.email[n])
		case caller == "":
			w.WriteHeader(401)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/email"):
			app.email[caller] = in["email"] // the token decides, never the path
			w.WriteHeader(204)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/password"):
			app.pw[caller] = in["password"]
			w.WriteHeader(204)
		case r.Method == http.MethodGet && userPath.MatchString(r.URL.Path):
			n := userPath.FindStringSubmatch(r.URL.Path)[1]
			e, ok := app.email[n]
			if !ok {
				w.WriteHeader(404)
				return
			}
			if app.showEmail {
				fmt.Fprintf(w, `{"username":%q,"email":%q}`, n, e)
			} else {
				fmt.Fprintf(w, `{"username":%q}`, n)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, app
}

func putOf(srv *httptest.Server, owner, path, body string) writeReq {
	return writeReq{owner: owner, method: "PUT", url: srv.URL + path, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(body), status: 204, from: owner + ".har"}
}

func nameOf(_ string) map[string]identity {
	who := map[string]identity{}
	for _, r := range []string{"alice", "bob"} {
		id := newIdentity()
		id.keep("username", r)
		who[r] = id
	}
	return who
}

// replayOne replays one write of alice's, asked with bob (the app takes the
// token's account), over the object alice's run read.
func replayOne(t *testing.T, srv *httptest.Server, w writeReq, canary bool, steps []string, allow ...string) roleRow {
	t.Helper()
	parsed, err := parseVerifyWrites(steps)
	if err != nil {
		t.Fatal(err)
	}
	roles := bookRoles()
	roles = []role{roles[1], roles[2]}
	obj := srv.URL + "/users/v1/alice"
	ans := readAs0(t, obj, "alice")
	answers := map[string]map[string]answer{"alice": {obj: ans}}
	rows, _, err := replayWritesVerify(nameOf(""), roles, []writeReq{w}, answers, map[string]bool{"127.0.0.1": true}, 0, 200, canary, parsed, allow...)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	return rows[0]
}

func readAs0(t *testing.T, u, who string) answer {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("A", who)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	a, _ := readAnswer(resp.StatusCode, b, "application/json")
	return a
}

// #517: the owner's email already equals the recorded value and the app wrote
// the sender's own account. The owner's object was read before and after and
// did not change, so no verification step may call the write proved, and the
// canary that landed on the sender's object is said so.
func TestRolesAVerifyStepCannotOverruleAnOwnerReadbackThatShowsNoChange(t *testing.T) {
	for _, steps := range [][]string{
		{"read:SRV/users/v1/{owner};field=email"},
		{"read:SRV/users/v1/{owner}"},
		{"login:SRV/users/v1/login;user=alice"},
	} {
		for _, canary := range []bool{true, false} {
			srv, app := newCallerApp(t, true)
			spec := make([]string, len(steps))
			for i, s := range steps {
				spec[i] = strings.Replace(s, "SRV", srv.URL, 1)
			}
			put := putOf(srv, "alice", "/users/v1/alice/email", `{"email":"alice@x.test"}`)
			row := replayOne(t, srv, put, canary, spec, "email")
			if row.Verdict == verdictWriteCross || row.WriteVerification == verifyProved {
				t.Errorf("%v canary %v: proved though alice's email did not change: verdict %q verification %q owner_by %q", steps, canary, row.Verdict, row.WriteVerification, row.OwnerBy)
			}
			if row.Verdict != verdictWriteNoChange || !strings.Contains(row.OwnerBy, "was not applied") {
				t.Errorf("%v canary %v: want changed-nothing with the step not applied: verdict %q owner_by %q", steps, canary, row.Verdict, row.OwnerBy)
			}
			if canary && strings.HasPrefix(steps[0], "read:") && (row.LandedOn != "sender" || len(row.LandedBy) != 1 || row.LandedBy[0] != "bob") {
				t.Errorf("%v: the canary is on bob's own object: landed_on %q by %v owner_by %q evidence %q", steps, row.LandedOn, row.LandedBy, row.OwnerBy, row.Evidence)
			}
			if !canary && row.LandedOn != "" {
				t.Errorf("%v: no canary was sent, so no landing is claimed: %q", steps, row.LandedOn)
			}
			if got := app.email["alice"]; got != "alice@x.test" {
				t.Errorf("stub: alice's email %q", got)
			}
		}
	}
}

// With a different stored value the same run is a plain "changed nothing".
func TestRolesAnOwnerValueThatDiffersIsStillNotAWriteOnTheOwner(t *testing.T) {
	srv, app := newCallerApp(t, true)
	app.email["alice"] = "other@x.test"
	put := putOf(srv, "alice", "/users/v1/alice/email", `{"email":"alice@x.test"}`)
	row := replayOne(t, srv, put, true, []string{"read:" + srv.URL + "/users/v1/{owner};field=email"}, "email")
	if row.Verdict != verdictWriteNoChange || row.WriteVerification == verifyProved {
		t.Errorf("verdict %q verification %q", row.Verdict, row.WriteVerification)
	}
}

// The owner's GET shows no email, so a step is the only reading. A read
// without ;field= shows the object is readable, which proves nothing.
func TestRolesAReadStepWithoutAFieldProvesNothing(t *testing.T) {
	srv, _ := newCallerApp(t, false)
	put := putOf(srv, "alice", "/users/v1/alice/email", `{"email":"new@x.test"}`)
	row := replayOne(t, srv, put, false, []string{"read:" + srv.URL + "/users/v1/{owner}"})
	if row.Verdict == verdictWriteCross || row.WriteVerification == verifyProved || !strings.Contains(row.OwnerBy, "proves nothing") {
		t.Errorf("verdict %q verification %q owner_by %q", row.Verdict, row.WriteVerification, row.OwnerBy)
	}
}

// A step that reads a field is read before the write as well: a value that
// was already there is not the write's, a value that is not there after it
// refutes it, and one that changed proves it. The owner's own GET shows no
// email here, so the step (a debug listing) is the only reading.
func TestRolesAReadStepProvesOnlyAValueThatChanged(t *testing.T) {
	step := func(srv *httptest.Server) []string {
		return []string{"read:" + srv.URL + "/debug/users/{owner};field=email"}
	}
	srv, app := newCallerApp(t, false)
	put := putOf(srv, "alice", "/users/v1/alice/email", `{"email":"alice@x.test"}`)
	row := replayOne(t, srv, put, false, step(srv))
	if row.Verdict == verdictWriteCross || row.WriteVerification == verifyProved || !strings.Contains(row.OwnerBy, "already held the written value") {
		t.Errorf("a value held before the write proves nothing: verdict %q verification %q owner_by %q", row.Verdict, row.WriteVerification, row.OwnerBy)
	}
	// The app writes bob's account, alice's holds another value: refuted.
	app.email["alice"] = "old@x.test"
	if row := replayOne(t, srv, put, false, step(srv)); row.WriteVerification != verifyRefuted || row.Verdict == verdictWriteCross {
		t.Errorf("alice's email is still old: verdict %q verification %q", row.Verdict, row.WriteVerification)
	}
	// A sender whose token is alice's: the app does write alice's account.
	h := http.Header{"A": {"alice"}}
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h}, {name: "eve", headers: []string{"A: alice"}, session: h}}
	steps, _ := parseVerifyWrites(step(srv))
	app.email["alice"] = "old@x.test"
	obj := srv.URL + "/users/v1/alice"
	rows, _, err := replayWritesVerify(nameOf(""), roles, []writeReq{put}, map[string]map[string]answer{"alice": {obj: readAs0(t, obj, "alice")}}, map[string]bool{"127.0.0.1": true}, 0, 200, false, steps)
	if err != nil || len(rows) != 1 || rows[0].WriteVerification != verifyProved || rows[0].Verdict != verdictWriteCross {
		t.Errorf("a value that changed to the written one proves: %+v %v", rows, err)
	}
}

// A password route: the sign-in with the password the write set already
// worked before the write, so it shows nothing; when it was refused before
// and works after, it proves the change. The row says a password was set.
func TestRolesALoginStepProvesOnlyWhatWasRefusedBefore(t *testing.T) {
	// The recorded password is alice's own current one: signed in before.
	srv, app := newCallerApp(t, false)
	put := putOf(srv, "alice", "/users/v1/alice/password", `{"password":"a"}`)
	row := replayOne(t, srv, put, false, []string{"login:" + srv.URL + "/users/v1/login;user=alice"})
	if row.Verdict == verdictWriteCross || row.WriteVerification == verifyProved || !strings.Contains(row.OwnerBy, "already worked before") {
		t.Errorf("verdict %q verification %q owner_by %q", row.Verdict, row.WriteVerification, row.OwnerBy)
	}
	if !strings.Contains(row.OwnerBy, "does not restore it") {
		t.Errorf("the row must say the password is not restored: %q", row.OwnerBy)
	}
	if app.pw["bob"] != "a" {
		t.Errorf("stub: bob's password %q", app.pw["bob"])
	}
	// A new password the app does set on alice's account: refused before, accepted after.
	srv2, _ := newCallerApp(t, false)
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: alice"}, session: h("alice")}}
	steps, _ := parseVerifyWrites([]string{"login:" + srv2.URL + "/users/v1/login;user=alice"})
	put2 := putOf(srv2, "alice", "/users/v1/alice/password", `{"password":"n3w"}`)
	obj := srv2.URL + "/users/v1/alice"
	rows, _, err := replayWritesVerify(nameOf(""), roles, []writeReq{put2}, map[string]map[string]answer{"alice": {obj: readAs0(t, obj, "alice")}}, map[string]bool{"127.0.0.1": true}, 0, 200, false, steps)
	if err != nil || len(rows) != 1 || rows[0].WriteVerification != verifyProved || rows[0].Verdict != verdictWriteCross {
		t.Errorf("refused before and accepted after proves: %+v %v", rows, err)
	}
}

// A login step that was not tried before the write cannot be told from one
// that worked all along: not proved.
func TestVerifyOutcomeWithNoReadingBeforeIsNotProved(t *testing.T) {
	read := func(role, string) (answer, bool) {
		a, _ := readAnswer(200, []byte(`{"email":"x@y.test"}`), "application/json")
		return a, true
	}
	send := func(role, writeReq) (answer, error) { return answer{Status: 200, Hash: "h"}, nil }
	put := writeReq{owner: "alice", method: "PUT", url: "http://h/users/v1/alice/email", body: []byte(`{"email":"x@y.test"}`)}
	for _, spec := range []string{"read:http://h/u/{owner};field=email;user=alice", "login:http://h/login;user=alice"} {
		steps, _ := parseVerifyWrites([]string{spec})
		w := put
		if strings.HasPrefix(spec, "login") {
			w.body = []byte(`{"password":"p"}`)
		}
		out, notes := verifyOutcome(steps, w, role{name: "bob"}, "alice", nil, "", make([]stepPre, 1), read, send)
		if out != "" || !strings.Contains(strings.Join(notes, " "), "effect not measured") {
			t.Errorf("%s: out %q notes %v", spec, out, notes)
		}
	}
}

// #523: a create's object is located where the user's read step says, with
// the identifier from the body; a step that cannot apply to a POST says so.
func TestRolesACreatedObjectIsLocatedByTheUsersReadStep(t *testing.T) {
	run := func(spec string, route bool) roleRow {
		srv, _ := newCallerApp(t, true)
		w := writeReq{owner: "alice", method: "POST", url: srv.URL + "/users/v1/register", header: http.Header{"Content-Type": {"application/json"}},
			body: []byte(`{"username":"alice_new1","password":"pw","email":"alice_new1@x.test"}`), status: 200, from: "alice.har"}
		if route {
			w.route = srv.URL + "/users/v1/{username}"
		}
		var steps []verifyWrite
		if spec != "" {
			var err error
			if steps, err = parseVerifyWrites([]string{strings.ReplaceAll(spec, "SRV", srv.URL)}); err != nil {
				t.Fatal(err)
			}
		}
		roles := []role{bookRoles()[1], bookRoles()[2]}
		rows, _, err := replayWritesVerify(nameOf(""), roles, []writeReq{w}, map[string]map[string]answer{}, map[string]bool{"127.0.0.1": true}, 0, 200, false, steps)
		if err != nil || len(rows) != 1 {
			t.Fatal(rows, err)
		}
		return rows[0]
	}
	// Today's default: the guess is <collection>/<value>, which is not it.
	if r := run("", false); r.WriteVerification != verifyUnlocated || !strings.Contains(r.OwnerBy, "could not be located") {
		t.Errorf("nothing says where it is: %q %q", r.WriteVerification, r.OwnerBy)
	}
	if r := run("read:SRV/users/v1/{username}", false); r.WriteVerification == verifyUnlocated || !strings.Contains(r.OwnerBy, "readable back at /users/v1/alice_new1 (the verification step read:") {
		t.Errorf("the step's {username} is the body's: %q %q", r.WriteVerification, r.OwnerBy)
	}
	// A route the maps found: /users/v1/{username} filled with the body's username.
	if r := run("", true); r.WriteVerification == verifyUnlocated || !strings.Contains(r.OwnerBy, "readable back at /users/v1/alice_new1 (the route /users/v1/{username} the maps found") {
		t.Errorf("by the route: %q %q", r.WriteVerification, r.OwnerBy)
	}
	// Steps that cannot apply say so, and the row keeps its reason.
	for spec, want := range map[string]string{
		"login:SRV/users/v1/login;user=alice":      "does not apply to a POST",
		"read:SRV/users/v1/{nosuch}":               "holds a nosuch",
		"read:SRV/users/v1/{owner}":                "{owner} names no created object",
		"read:SRV/users/v1/{username};field=email": ";field= is not used for a POST",
	} {
		r := run(spec, false)
		if !strings.Contains(r.OwnerBy, want) {
			t.Errorf("%s: want %q in %q", spec, want, r.OwnerBy)
		}
		if want != ";field= is not used for a POST" && r.WriteVerification != verifyUnlocated {
			t.Errorf("%s: %q", spec, r.WriteVerification)
		}
	}
}

// A canary in the password field cannot have signed in before the write: the
// step proves it from one sign-in after, and asks none before.
func TestRolesACanaryPasswordNeedsNoSignInBefore(t *testing.T) {
	srv, app := newCallerApp(t, false)
	h := http.Header{"A": {"alice"}}
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h}, {name: "eve", headers: []string{"A: alice"}, session: h}}
	steps, _ := parseVerifyWrites([]string{"login:" + srv.URL + "/users/v1/login;user=alice"})
	put := putOf(srv, "alice", "/users/v1/alice/password", `{"password":"n3w"}`)
	obj := srv.URL + "/users/v1/alice"
	rows, _, err := replayWritesVerify(nameOf(""), roles, []writeReq{put}, map[string]map[string]answer{"alice": {obj: readAs0(t, obj, "alice")}}, map[string]bool{"127.0.0.1": true}, 0, 200, true, steps, "password")
	if err != nil || len(rows) != 1 || rows[0].WriteVerification != verifyProved || app.logins != 1 {
		t.Errorf("one sign-in, after the write: %d sign-ins, %+v %v", app.logins, rows, err)
	}
}

// A step whose user is the sender's own account (a ;user= fixed for every
// write) would sign in as the sender with the password it just set: that is
// where the write landed, not a change of the owner's.
func TestRolesAStepOnTheSendersOwnAccountProvesNothingOfTheOwner(t *testing.T) {
	srv, _ := newCallerApp(t, false)
	put := putOf(srv, "bob", "/users/v1/bob/password", `{"password":"bobpw-new"}`)
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: http.Header{"A": {"alice"}}}, {name: "bob", headers: []string{"A: bob"}, session: http.Header{"A": {"bob"}}}}
	steps, _ := parseVerifyWrites([]string{"login:" + srv.URL + "/users/v1/login;user=alice"})
	obj := srv.URL + "/users/v1/bob"
	rows, _, err := replayWritesVerify(nameOf(""), roles, []writeReq{put}, map[string]map[string]answer{"bob": {obj: readAs0(t, obj, "bob")}}, map[string]bool{"127.0.0.1": true}, 0, 200, false, steps)
	if err != nil || len(rows) != 1 || rows[0].WriteVerification == verifyProved || !strings.Contains(rows[0].OwnerBy, "alice's own account") {
		t.Errorf("%+v %v", rows, err)
	}
}
