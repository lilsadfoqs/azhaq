package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

func TestWriteMethods(t *testing.T) {
	m, err := writeMethods("post, PUT,patch")
	if err != nil || !m["POST"] || !m["PUT"] || !m["PATCH"] || m["DELETE"] {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"get", "", "put,trace"} {
		if _, err := writeMethods(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A HAR gives the owner's writes on the run's hosts, without the session
// that sent them (cookies, tokens, a CSRF token). The method decides what
// is replayed, not the name of the URL: a POST to /logout is one of them.
func TestHARWrites(t *testing.T) {
	h := map[string]any{"log": map[string]any{"entries": []any{
		entry("POST", "http://app.test/api/items", `{"basketId":7}`, 201, "Authorization", "Bearer secret", "X-CSRF-Token", "c", "Cookie", "s=1", "Content-Type", "application/json"),
		entry("POST", "http://app.test/api/items", `{"basketId":7}`, 201),
		entry("POST", "http://app.test/logout", "", 302),
		entry("GET", "http://app.test/api/items", "", 200),
		entry("PUT", "http://elsewhere.test/api/x", "{}", 200),
		entry("DELETE", "http://app.test/api/items/3", "", 204),
	}}}
	raw, _ := json.Marshal(h)
	path := filepath.Join(t.TempDir(), "alice.har")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := harWrites("alice", path, map[string]bool{"POST": true, "PUT": true}, map[string]bool{"app.test": true})
	if err != nil || len(ws) != 2 || ws[1].method != "POST" || ws[1].url != "http://app.test/logout" {
		t.Fatalf("%+v %v", ws, err)
	}
	w := ws[0]
	if w.owner != "alice" || w.method != "POST" || string(w.body) != `{"basketId":7}` || w.status != 201 || w.from != "alice.har" {
		t.Errorf("write %+v", w)
	}
	if w.header.Get("Authorization") != "" || w.header.Get("Cookie") != "" || w.header.Get("X-Csrf-Token") != "" || w.header.Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", w.header)
	}
}

func entry(method, u, body string, status int, headers ...string) map[string]any {
	var hs []any
	for i := 0; i+1 < len(headers); i += 2 {
		hs = append(hs, map[string]any{"name": headers[i], "value": headers[i+1]})
	}
	req := map[string]any{"method": method, "url": u, "headers": hs}
	if body != "" {
		req["postData"] = map[string]any{"mimeType": "application/json", "text": body}
	}
	return map[string]any{"request": req, "response": map[string]any{"status": status}}
}

// The routes' writes on each role's own objects: PUT and PATCH with an
// empty JSON object, DELETE when asked; a form's write and a POST to an
// object are left to the HAR.
func TestMapWrites(t *testing.T) {
	made := map[string]instance{
		"http://app.test/api/items/3": {template: "http://app.test/api/items/{id}", owner: "alice", value: "3"},
		"http://app.test/api/items/9": {template: "http://app.test/api/items/{id}"}, // nobody's
		"http://app.test/forms/4":     {template: "http://app.test/forms/{id}", owner: "bob"},
	}
	writes := map[string][]writeOp{
		"http://app.test/api/items/{id}": {{method: "PUT", bodyType: "json"}, {method: "DELETE"}, {method: "POST"}},
		"http://app.test/forms/{id}":     {{method: "PUT", bodyType: "application/x-www-form-urlencoded"}},
	}
	got := mapWrites(made, writes, map[string]bool{"PUT": true, "POST": true})
	if len(got) != 1 || got[0].method != "PUT" || string(got[0].body) != "{}" || !got[0].empty || got[0].owner != "alice" || got[0].from != "PUT /api/items/{id} with an empty body" {
		t.Fatalf("%+v", got)
	}
	if got := mapWrites(made, writes, map[string]bool{"DELETE": true}); len(got) != 1 || got[0].method != "DELETE" || got[0].body != nil {
		t.Fatalf("delete %+v", got)
	}
}

// An app where any signed-in user really writes anyone's object: bob's PUT
// changes alice's object, so the cross write is proved; the anonymous
// visitor is refused.
func TestReplayWritesProved(t *testing.T) {
	var mu sync.Mutex
	note := "hi"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet {
			var m map[string]any
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &m) == nil {
				if s, ok := m["note"].(string); ok {
					note = s
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":3,"owner":"alice","note":"` + note + `","updatedAt":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h("1")}, {name: "bob", headers: []string{"A: 2"}, session: h("2")}}
	u := srv.URL + "/api/items/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"owner":"alice","note":"hi","updatedAt":"2026-10-27T09:00:00Z"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {u: before}}
	own := map[string]bool{"127.0.0.1": true}
	// A HAR write with a body of alice's: bob's session changes alice's note.
	put := writeReq{owner: "alice", method: "PUT", url: u, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"pwned"}`), status: 200, from: "alice.har"}
	rows, _, err := replayWrites(roles, []writeReq{put}, answers, own, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if r := rows[0]; r.Verdict != verdictWriteCross || strings.Join(r.Readers, ",") != "bob" || r.Status["anon"] != 401 || r.label() != "bob writes alice's object" {
		t.Errorf("put row %+v", r)
	}
	if !strings.Contains(rows[0].OwnerBy, "after bob's PUT the owner's object changed") {
		t.Errorf("owner_by %q", rows[0].OwnerBy)
	}
}

// A real cross DELETE: bob's DELETE removes alice's object, so the owner's
// read afterwards is gone and the write is proved.
func TestReplayWriteDeleteProved(t *testing.T) {
	var mu sync.Mutex
	deleted := false
	var log []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		log = append(log, r.Method+" "+r.Header.Get("A"))
		g := deleted
		if r.Method == http.MethodDelete && r.Header.Get("A") != "" {
			deleted = true
		}
		mu.Unlock()
		switch {
		case r.Header.Get("A") == "":
			w.WriteHeader(401)
		case r.Method == http.MethodGet && g:
			w.WriteHeader(404)
		case r.Method == http.MethodDelete:
			w.WriteHeader(204)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":3,"owner":"alice"}`))
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h("1")}, {name: "bob", headers: []string{"A: 2"}, session: h("2")}}
	u := srv.URL + "/api/items/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"owner":"alice"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {u: before}}
	del := writeReq{owner: "alice", method: "DELETE", url: u, header: http.Header{}}
	rows, _, _ := replayWrites(roles, []writeReq{del}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if r := rows[0]; r.Verdict != verdictWriteCross || strings.Join(r.Readers, ",") != "bob" || !strings.Contains(r.OwnerBy, "the owner's object is gone") {
		t.Errorf("delete row %+v", r)
	}
	// anon DELETE (refused, no owner read), bob DELETE (let), owner GET (gone).
	if want := "DELETE |DELETE 2|GET 1"; strings.Join(log, "|") != want {
		t.Errorf("requests %q", log)
	}
}

// VAmPI's PUT /users/v1/{username}/email changes the caller's email,
// whatever the path says: bob's write on alice's path answers 2xx but
// leaves alice's object unchanged, so it is not a cross write.
func TestReplayWriteCallerObject(t *testing.T) {
	var mu sync.Mutex
	emails := map[string]string{"alice": "alice@x.test", "bob": "bob@x.test"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get("A")
		if caller == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet:
			// /users/v1/{username}: anyone may read it.
			who := strings.TrimPrefix(r.URL.Path, "/users/v1/")
			w.Write([]byte(`{"username":"` + who + `","email":"` + emails[who] + `"}`))
		default:
			// The write changes the caller's email, not the path's.
			var m map[string]any
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &m) == nil {
				if s, ok := m["email"].(string); ok {
					emails[caller] = s
				}
			}
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	obj := srv.URL + "/users/v1/alice"
	before, _ := readAnswer(200, []byte(`{"username":"alice","email":"alice@x.test"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {obj: before}}
	put := writeReq{owner: "alice", method: "PUT", url: srv.URL + "/users/v1/alice/email",
		header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"email":"pwned@x.test"}`), status: 204, from: "alice.har"}
	rows, _, _ := replayWrites(roles, []writeReq{put}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteNoChange {
		t.Fatalf("rows %+v", rows)
	}
	if emails["alice"] != "alice@x.test" {
		t.Errorf("alice's email changed: %q", emails["alice"])
	}
}

// VAmPI's PUT /users/v1/{username}/email: the owner's own GET never shows
// its email, but /users/v1/_debug does (flagged verdictAnyoneSecrets on
// the read run) and the map already has an answer for it. Without that
// read-back the write is merely "accepted"; with it, bob's write is read
// back at _debug and proved.
func TestReplayWriteReadBackFromDebugEndpoint(t *testing.T) {
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
			// The object's own GET never carries the email field.
			who := strings.TrimPrefix(r.URL.Path, "/users/v1/")
			fmt.Fprintf(w, `{"username":%q}`, who)
		default:
			// Vulnerable: the path's user is changed, not the caller's.
			target := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/users/v1/"), "/email")
			var m map[string]string
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &m)
			emails[target] = m["email"]
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	own := map[string]bool{"127.0.0.1": true}
	ownAnswer, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
	debugAnswer, _ := readAnswer(200, []byte(`{"users":[{"username":"alice","email":"alice@x.test"},{"username":"bob","email":"bob@x.test"}]}`), "application/json")
	answers := map[string]map[string]answer{"alice": {
		srv.URL + "/users/v1/alice":  ownAnswer,
		srv.URL + "/users/v1/_debug": debugAnswer,
	}}
	put := writeReq{owner: "alice", method: "PUT", url: srv.URL + "/users/v1/alice/email",
		header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"email":"pwned@x.test"}`), status: 204, from: "alice.har"}
	rows, _, err := replayWrites(roles, []writeReq{put}, answers, own, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if r := rows[0]; r.Verdict != verdictWriteCross || strings.Join(r.Readers, ",") != "bob" {
		t.Fatalf("put row %+v", r)
	}
	if !strings.Contains(rows[0].OwnerBy, "_debug") {
		t.Errorf("owner_by does not say the read-back came from _debug: %q", rows[0].OwnerBy)
	}
}

// A write that replays the owner's exact body is idempotent (nothing to
// read back) unless the field is changed to a value only this replay
// sent: -replay-writes-canary does that, and proves the write a plain
// replay could not.
func TestReplayWriteCanaryProvesAnIdempotentReplay(t *testing.T) {
	var mu sync.Mutex
	notes := map[string]string{"3": "hello"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			fmt.Fprintf(w, `{"id":3,"owner":"alice","note":%q}`, notes["3"])
			return
		}
		var m map[string]string
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &m)
		notes["3"] = m["note"]
		w.WriteHeader(204)
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	u := srv.URL + "/api/notes/3"
	own := map[string]bool{"127.0.0.1": true}
	before, _ := readAnswer(200, []byte(`{"id":3,"owner":"alice","note":"hello"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {u: before}}
	put := writeReq{owner: "alice", method: "PUT", url: u, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"hello"}`), status: 204, from: "alice.har"}

	rows, _, _ := replayWrites(roles, []writeReq{put}, answers, own, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteNoChange {
		t.Fatalf("without the canary, replaying the owner's own value should prove nothing: %+v", rows)
	}

	notes["3"] = "hello" // the plain replay above may have left it as is; reset for a clean compare
	rows, _, _ = replayWrites(roles, []writeReq{put}, answers, own, 0, 100, true)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteCross {
		t.Fatalf("with -replay-writes-canary, the write should be proved: %+v", rows)
	}
	if !strings.Contains(rows[0].OwnerBy, "canary") {
		t.Errorf("owner_by does not mention the canary: %q", rows[0].OwnerBy)
	}
	if string(put.body) != `{"note":"hello"}` {
		t.Errorf("the original write request was mutated: %s", put.body)
	}
}

// A POST to a collection creates a new object; even when the other role is
// let, it is a create, never a cross write. Whose the object is says what the
// create is called: the server here stores it as its sender's, which is what a
// collection every signed-in user may post to does, so nothing shows it
// crosses roles.
func TestReplayWriteCreate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"owner":"` + r.Header.Get("A") + `"}`))
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	post := writeReq{owner: "alice", method: "POST", url: srv.URL + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"title":"t"}`), status: 201, from: "alice.har"}
	rows, _, _ := replayWrites(roles, []writeReq{post}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteAccepted || !slices.Contains(rows[0].Readers, "bob") {
		t.Fatalf("rows %+v", rows)
	}
	if rows[0].CreatedOwner["bob"] != "bob" || !strings.Contains(rows[0].OwnerBy, "belongs to bob") {
		t.Errorf("the object bob's create made is bob's, and the row says so: %v, %q", rows[0].CreatedOwner, rows[0].OwnerBy)
	}
	if !listed(verdictWriteAccepted) || !listed(verdictWriteCreate) {
		t.Errorf("a create another role was let to send is listed by default")
	}
	if txt := rows[0].label(); !strings.Contains(txt, "bob's POST to /books/v1 was accepted") || strings.Contains(txt, "create in the collection") {
		t.Errorf("row text %q", txt)
	}
}

// A create is called "creates in another role's collection" only when the
// answers show it: the anonymous role was let, or the object belongs to the
// role whose request was replayed (by what the session says, not by a name).
func TestReplayWriteCreateCrossesRolesOnlyWhenShown(t *testing.T) {
	idOf := func(names ...string) identity {
		id := newIdentity()
		for _, n := range names {
			id.who[n] = true
			id.keep("username", n)
		}
		return id
	}
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	who := map[string]identity{"alice": idOf("alice", "alice@x.test"), "bob": idOf("bob", "bob@x.test")}
	post := func(url string) writeReq {
		return writeReq{owner: "alice", method: "POST", url: url + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"title":"t"}`), status: 201, from: "alice.har"}
	}
	serve := func(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(handler))
		t.Cleanup(srv.Close)
		return srv
	}
	run := func(srv *httptest.Server) roleRow {
		rows, _, _ := replayWritesAs(who, roles, []writeReq{post(srv.URL)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		if len(rows) != 1 {
			t.Fatalf("rows %+v", rows)
		}
		return rows[0]
	}
	// The create lands in the collection's first owner's account, whoever sends it.
	got := run(serve(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"username":"alice"}`))
	}))
	if got.Verdict != verdictWriteCreate || got.CreatedOwner["bob"] != "alice" || !strings.Contains(got.OwnerBy, "whose request was replayed") {
		t.Errorf("an object that belongs to the recorder: %q %v %q", got.Verdict, got.CreatedOwner, got.OwnerBy)
	}
	// Every caller may create, with no session at all.
	got = run(serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"ok":true}`))
	}))
	if got.Verdict != verdictWriteCreate || !strings.Contains(got.OwnerBy, "anon, a role with no session, was let to create") {
		t.Errorf("the anonymous role was let: %q %q", got.Verdict, got.OwnerBy)
	}
	// The object is its sender's, by what the session says of the sender.
	got = run(serve(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"user":"` + r.Header.Get("A") + `@x.test"}`))
	}))
	if got.Verdict != verdictWriteAccepted || got.CreatedOwner["bob"] != "bob" {
		t.Errorf("an object that belongs to its sender: %q %v", got.Verdict, got.CreatedOwner)
	}
	// An answer that says nothing of whose it is: accepted, and no more.
	got = run(serve(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	if got.Verdict != verdictWriteAccepted || len(got.CreatedOwner) != 0 {
		t.Errorf("an answer with no owner: %q %v", got.Verdict, got.CreatedOwner)
	}
	// A name that only equals a role's, in an answer, is no proof it belongs
	// to the recorder: not "creates in another role's collection".
	noWho := func(srv *httptest.Server) roleRow {
		rows, _, _ := replayWrites(roles, []writeReq{post(srv.URL)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		return rows[0]
	}
	got = noWho(serve(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"owner":"alice"}`))
	}))
	if got.Verdict != verdictWriteAccepted || !strings.Contains(got.OwnerBy, "may belong to alice") {
		t.Errorf("a name is only a lead: %q %q", got.Verdict, got.OwnerBy)
	}
}

// -replay-writes post, without -all: the creates the replay made in another
// role's collection are in the rows and counted, not hidden behind -all.
func TestRolesListsCreatesByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		if user == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/api/notes" {
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"created":true,"by":%q}`, user)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	browse := func(file, user string) string {
		return writeHAR(t, file,
			harEntry("2026-10-29T10:00:00.000Z", "POST", srv.URL+"/api/notes", `{"text":"hi"}`, 201, "Authorization", "Bearer tok-"+user, "Content-Type", "application/json"))
	}
	alice, bob := browse("alice.har", "alice"), browse("bob.har", "bob")
	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", t.TempDir(), "-har", "alice=" + alice, "-har", "bob=" + bob, "-replay-writes", "post"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if n := strings.Count(out, verdictWriteAccepted); n != 2 {
		t.Errorf("want both creates listed, got %d:\n%s", n, out)
	}
	if strings.Contains(errOut, "not listed") && strings.Contains(errOut, verdictWriteAccepted) {
		t.Errorf("the creates are still counted as not listed:\n%s", errOut)
	}
}

// VAmPI's POST /books/v1: when the map already has an answer for the
// member URL the created book would answer at (/books/v1/{title}), it is
// read back as evidence the create is more than a 2xx.
func TestReplayWriteCreateConfirmedByKnownMemberURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"title":"My Book","owner":"bob"}`)
			return
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	post := writeReq{owner: "alice", method: "POST", url: srv.URL + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"title":"My Book"}`), status: 201, from: "alice.har"}
	member := srv.URL + "/books/v1/My%20Book"
	known, _ := readAnswer(200, []byte(`{"title":"My Book","owner":"alice"}`), "application/json")
	answers := map[string]map[string]answer{"anybody": {member: known}}
	rows, _, _ := replayWrites(roles, []writeReq{post}, answers, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteAccepted {
		t.Fatalf("rows %+v", rows)
	}
	if !strings.Contains(rows[0].OwnerBy, "readable back at /books/v1/My Book") {
		t.Errorf("owner_by does not confirm the create: %q", rows[0].OwnerBy)
	}
}

// A create the other roles' requests made the server fail (a unique key it
// already holds: SQLAlchemy's 500) is no refusal, and is said to be neither.
func TestReplayWriteServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(500)
		w.Write([]byte("sqlite3.IntegrityError: UNIQUE constraint failed: books.book_title"))
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	post := writeReq{owner: "alice", method: "POST", url: srv.URL + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"title":"t"}`), status: 200, from: "alice.har"}
	rows, _, _ := replayWrites(roles, []writeReq{post}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteFailed {
		t.Fatalf("rows %+v", rows)
	}
}

// A write one role is refused (401) and another gets a 5xx for is neither
// refused nor failed for everyone: the row names both, and "refused" stays
// for a row whose every answer is a refusal.
func TestReplayWriteRefusedAndServerError(t *testing.T) {
	var mu sync.Mutex
	books := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer t")
		var in struct {
			Title string `json:"book_title"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case user == "":
			w.WriteHeader(401)
		case books[in.Title]:
			w.WriteHeader(500) // a unique key the server already holds
		default:
			books[in.Title] = true
		}
	}))
	defer srv.Close()
	books["shared-title-a"], books["shared-title-b"] = true, true
	post := func(file, user string) string {
		return writeHAR(t, file, harEntry("2026-10-29T10:00:00.000Z", "POST", srv.URL+"/books/v1", `{"book_title":"shared-title-`+user+`"}`, 200,
			"Authorization", "Bearer t"+user, "Content-Type", "application/json"))
	}
	alice, bob := post("a.har", "a"), post("b.har", "b")
	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-all", "-dir", t.TempDir(), "-har", "alice=" + alice, "-har", "bob=" + bob, "-replay-writes", "post"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var row roleRow
		if json.Unmarshal([]byte(l), &row) != nil || row.Method != "POST" {
			continue
		}
		n++
		if row.Verdict != verdictWriteMixed {
			t.Errorf("%s: verdict %q (answers %v), want %q", row.Owner, row.Verdict, row.Status, verdictWriteMixed)
		}
	}
	if n != 2 {
		t.Fatalf("want a row for each owner's POST, got %d:\n%s", n, out)
	}
}

// An empty write that changes the owner's object stops there: nobody
// else is asked.
func TestReplayWriteChangedObject(t *testing.T) {
	var asked []string
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Method+" "+r.Header.Get("A"))
		if r.Method != http.MethodGet {
			n++
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":3,"name":"` + strings.Repeat("x", n) + `"}`))
	}))
	defer srv.Close()
	h := http.Header{}
	h.Set("A", "1")
	roles := []role{{name: "alice", headers: []string{"A: 1"}, session: h}, {name: "bob", headers: []string{"A: 2"}}}
	u := srv.URL + "/api/items/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"name":""}`), "application/json")
	rows, _, _ := replayWrites(roles, []writeReq{{owner: "alice", method: "PATCH", url: u, header: http.Header{}, body: []byte("{}"), empty: true}},
		map[string]map[string]answer{"alice": {u: before}}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteVoid || len(asked) != 2 {
		t.Errorf("rows %+v asked %q", rows, asked)
	}
}

// A route that only takes a write (PUT /users/v1/{username}/email, with no
// GET) still gets an instance filled with each role's own identifier, from
// -id and from learned identity, so -replay-writes has something to send.
func TestWriteOnlyTemplateReplayed(t *testing.T) {
	const route = "http://app.test/users/v1/{username}/email"
	templates := map[string]bool{route: true}
	writes := map[string][]writeOp{route: {{method: "PUT", bodyType: "application/json"}}}

	// With -id.
	rolesID := []role{{name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"A: 2"}}}
	given, err := parseIDs([]string{"alice:username=alice"}, rolesID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]runSeen{"alice": newRunSeen(), "bob": newRunSeen()}
	who := identities(rolesID, map[string]map[string]answer{}, seen, nil)
	made := instances(rolesID, templates, seen, map[string]map[string]answer{}, given, who)
	if in, ok := made["http://app.test/users/v1/alice/email"]; !ok || in.owner != "alice" || in.template != route {
		t.Fatalf("by -id: %+v", made)
	}
	if reqs := mapWrites(made, writes, map[string]bool{"PUT": true}); len(reqs) != 1 || reqs[0].owner != "alice" || string(reqs[0].body) != "{}" {
		t.Fatalf("by -id map writes: %+v", reqs)
	}

	// With learned identity: a /me answer names alice's username.
	me := "http://app.test/me"
	s := newRunSeen()
	s.add(me, map[string][]string{"username": {"alice"}})
	seen2 := map[string]runSeen{"alice": s, "bob": newRunSeen()}
	meAns, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
	answers := map[string]map[string]answer{"alice": {me: meAns}}
	who2 := identities(rolesID, answers, seen2, nil)
	made2 := instances(rolesID, templates, seen2, answers, nil, who2)
	if in, ok := made2["http://app.test/users/v1/alice/email"]; !ok || in.owner != "alice" {
		t.Fatalf("by identity: %+v", made2)
	}
	if reqs := mapWrites(made2, writes, map[string]bool{"PUT": true}); len(reqs) != 1 || reqs[0].owner != "alice" {
		t.Fatalf("by identity map writes: %+v", reqs)
	}
}

func TestReplayWritesFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-replay-writes", "put", "-role", "anon", "-role", "a=A: 1", "--", "-domain", "example.test"},
		{"-har", "a=x.har", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
		{"-replay-writes", "put", "-har", "anon=x.har", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
		{"-replay-writes", "get", "-role", "anon", "-role", "a=A: 1", "--", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1"},
	} {
		if err := cmdRoles(append([]string{"-dir", t.TempDir()}, args...)); exitCode(err) != exitUsage {
			t.Errorf("%q: %v", args, err)
		}
	}
}

func TestURLHostsAreTheWriteScope(t *testing.T) {
	got := urlHosts([]string{"-url", "http://127.0.0.1:5002/", "-depth", "2", "--url=https://App.example.org/x"})
	if strings.Join(got, ",") != "127.0.0.1,app.example.org" {
		t.Fatalf("%v", got)
	}
}

// A map DELETE no other role is let to send is a protected object, not
// an owner refused: its owner was never asked.
func TestReplayWriteDeleteRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()
	h := http.Header{}
	h.Set("A", "1")
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}, session: h}, {name: "bob", headers: []string{"A: 2"}, session: h}}
	rows, _, _ := replayWrites(roles, []writeReq{{owner: "alice", method: "DELETE", url: srv.URL + "/api/items/3", header: http.Header{}}},
		nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteRefused {
		t.Errorf("%+v", rows)
	}
}

// -replay-writes-canary says before it sends which field it will set and
// why it leaves the others, says when none qualifies (VAmPI's email: it
// says whose the object is), and sets a field the user names with
// -replay-writes-field.
func TestReplayWriteCanaryNamesItsFields(t *testing.T) {
	var mu sync.Mutex
	sent := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		if user == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			var m map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &m)
			mu.Lock()
			sent[user] = m["email"]
			mu.Unlock()
			w.WriteHeader(204)
			return
		}
		fmt.Fprint(w, `{"username":"name1"}`)
	}))
	defer srv.Close()
	browse := func(file, user string) string {
		return writeHAR(t, file,
			harEntry("2026-10-29T10:00:00.000Z", "PUT", srv.URL+"/users/v1/name1/email", `{"email":"`+user+`@x.test"}`, 204, "Authorization", "Bearer tok-"+user, "Content-Type", "application/json"))
	}
	alice, bob := browse("alice.har", "alice"), browse("bob.har", "bob")
	run := func(extra ...string) (string, error) {
		args := append([]string{"-json", "-dir", t.TempDir(), "-har", "alice=" + alice, "-har", "bob=" + bob, "-replay-writes", "put", "-replay-writes-canary"}, extra...)
		_, errOut, err := captureBoth(t, func() error { return cmdRoles(args) })
		return errOut, err
	}
	errOut, err := run()
	if err != nil && exitCode(err) == exitUsage {
		t.Fatalf("%v", err)
	}
	for _, want := range []string{"canary: PUT /users/v1/name1/email has no field a canary may set", "email (it says whose the object is)", "-replay-writes-field"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the summary lacks %q:\n%s", want, errOut)
		}
	}
	for u, v := range sent {
		if strings.HasPrefix(v, "azhaq-") {
			t.Errorf("%s's email was set to a canary though no field qualified: %s", u, v)
		}
	}
	clear(sent)
	errOut, err = run("-replay-writes-field", "email")
	if err != nil && exitCode(err) == exitUsage {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(errOut, "canary: PUT /users/v1/name1/email sets email") {
		t.Errorf("the summary does not say the canary sets email:\n%s", errOut)
	}
	if !strings.HasPrefix(sent["bob"], "azhaq-") && !strings.HasPrefix(sent["alice"], "azhaq-") {
		t.Errorf("no canary reached the server: %v", sent)
	}
	args := []string{"-json", "-dir", t.TempDir(), "-har", "alice=" + alice, "-replay-writes-field", "email"}
	if err := cmdRoles(args); err == nil || exitCode(err) != exitUsage {
		t.Errorf("-replay-writes-field alone is a usage error: %v", err)
	}
	args = []string{"-json", "-dir", t.TempDir(), "-har", "alice=" + alice, "-replay-writes-canary"}
	if err := cmdRoles(args); err == nil || exitCode(err) != exitUsage {
		t.Errorf("-replay-writes-canary without -replay-writes is a usage error: %v", err)
	}
}

// A write that gets no answer, and an owner's object that cannot be read
// back, are noted on the row and counted in the summary, not shown as a
// refusal and nothing else.
func TestReplayWritesNoAnswer(t *testing.T) {
	fetch.Reset()
	dead := deadAddr(t)
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "alice", session: h("1")}, {name: "bob", session: h("2")}}
	put := writeReq{owner: "alice", method: "PUT", url: "http://" + dead + "/api/items/3", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"x"}`), status: 200}
	rows, _, err := replayWrites(roles, []writeReq{put}, map[string]map[string]answer{}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if !slices.ContainsFunc(r.Failed, func(f string) bool { return strings.HasPrefix(f, "bob's PUT: ") && strings.Contains(f, "refused") }) ||
		!slices.ContainsFunc(r.Failed, func(f string) bool { return strings.HasPrefix(f, "read back at /api/items/3 as alice: ") }) || !strings.Contains(r.Evidence, "no answer: ") {
		t.Errorf("row failed %q evidence %q", r.Failed, r.Evidence)
	}
	notes, failed := writeNotes(rows)
	if !failed || len(notes) != 1 || !strings.HasPrefix(notes[0], "write replay: ") || !strings.Contains(notes[0], "got no answer") {
		t.Errorf("notes %q failed %v", notes, failed)
	}
}

// A write answered 200 with its body cut keeps the status and is noted.
func TestReplayWritesCutBody(t *testing.T) {
	fetch.Reset()
	site := cutApp(t)
	roles := []role{{name: "alice", session: http.Header{}}, {name: "bob", session: http.Header{}}}
	put := writeReq{owner: "alice", method: "PUT", url: site.URL + "/api/items/3", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"x"}`), status: 200}
	rows, _, err := replayWrites(roles, []writeReq{put}, map[string]map[string]answer{}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if a := rows[0].Answers["bob"]; a.Status != 200 || !slices.ContainsFunc(rows[0].Failed, func(f string) bool { return strings.HasPrefix(f, "bob's PUT: the answer was cut") }) {
		t.Errorf("bob %+v failed %q", a, rows[0].Failed)
	}
}

// The object a replayed create makes is read by every other role too: a
// store where any signed-in user reads any book is a cross read of the book
// the replay made, with a made-up title as its control; a store that gives a
// book to its owner alone is not, and the create stays accepted.
func TestRolesReadsTheObjectAReplayedCreateMade(t *testing.T) {
	tok := func(sub string) string {
		b := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
		return b(`{"alg":"none"}`) + "." + b(`{"sub":"`+sub+`"}`) + "."
	}
	serve := func(ownerOnly bool) *httptest.Server {
		var mu sync.Mutex
		books := map[string]string{"seed": "carol"}
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			who := ""
			if h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); strings.Count(h, ".") == 2 {
				p, _ := base64.RawURLEncoding.DecodeString(strings.Split(h, ".")[1])
				var c struct{ Sub string }
				_ = json.Unmarshal(p, &c)
				who = c.Sub
			}
			reply := func(code int, v any) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(v)
			}
			switch {
			case r.URL.Path == "/openapi.json":
				reply(200, map[string]any{"openapi": "3.0.0", "info": map[string]any{"title": "t", "version": "1"}, "paths": map[string]any{
					"/api/books":              map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "ok"}}}, "post": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "ok"}}}},
					"/api/books/{book_title}": map[string]any{"get": map[string]any{"parameters": []any{map[string]any{"name": "book_title", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}}, "responses": map[string]any{"200": map[string]any{"description": "ok"}}}}}})
			case who == "":
				reply(401, map[string]string{"error": "sign in"})
			case r.Method == http.MethodPost:
				var d struct {
					Title string `json:"book_title"`
				}
				_ = json.NewDecoder(r.Body).Decode(&d)
				books[d.Title] = who
				reply(200, map[string]string{"status": "created"})
			case r.URL.Path == "/api/books":
				reply(200, map[string]any{"books": []any{map[string]string{"book_title": "seed"}}})
			default:
				title := strings.TrimPrefix(r.URL.Path, "/api/books/")
				owner, ok := books[title]
				switch {
				case !ok:
					reply(404, map[string]string{"error": "no such book"})
				case ownerOnly && owner != who && owner != "carol":
					reply(403, map[string]string{"error": "not yours"})
				default:
					reply(200, map[string]string{"book_title": title, "owner": owner})
				}
			}
		}))
	}
	run := func(ownerOnly bool) (rows []roleRow, errOut string) {
		srv := serve(ownerOnly)
		defer srv.Close()
		har := writeHAR(t, "alice.har",
			harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/api/books", "", 200, "Authorization", "Bearer "+tok("alice")),
			harEntry("2026-10-29T10:00:01.000Z", "POST", srv.URL+"/api/books", `{"book_title":"alice-book"}`, 200, "Authorization", "Bearer "+tok("alice"), "Content-Type", "application/json"))
		out, errOut, err := captureBoth(t, func() error {
			return cmdRoles([]string{"-json", "-dir", t.TempDir(), "-role", "anon", "-role", "alice=Authorization: Bearer " + tok("alice"), "-role", "bob=Authorization: Bearer " + tok("bob"),
				"-har", "alice=" + har, "-id", "alice:book_title=alice-book", "-replay-writes", "post", "-all",
				"--", "-url", srv.URL + "/openapi.json", "-allow", strings.TrimPrefix(srv.URL, "http://"), "-no-paths"})
		})
		if err != nil && exitCode(err) != exitLimit {
			t.Fatalf("%v\n%s", err, errOut)
		}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			var row roleRow
			if json.Unmarshal([]byte(l), &row) == nil && row.URL != "" {
				rows = append(rows, row)
			}
		}
		return rows, errOut
	}
	find := func(rows []roleRow, path, method string) *roleRow {
		for i := range rows {
			if strings.HasSuffix(rows[i].URL, path) && rows[i].Method == method {
				return &rows[i]
			}
		}
		return nil
	}

	rows, errOut := run(false)
	book := find(rows, "/api/books/alice-book", "")
	if book == nil || book.Verdict != verdictCross || book.Owner != "bob" || !slices.Contains(book.Readers, "alice") ||
		!strings.Contains(book.OwnerBy, "created by bob's replayed POST /api/books") || book.Confidence != confProved || book.Control == nil || book.Control.Value == "alice-book" {
		t.Fatalf("the book bob's replayed create made is not reported as a cross read:\n%+v\n%s", book, errOut)
	}
	if post := find(rows, "/api/books", "POST"); post == nil || post.Verdict != verdictWriteAccepted {
		t.Errorf("the create's own row: %+v", post)
	}

	rows, errOut = run(true)
	if book := find(rows, "/api/books/alice-book", ""); book != nil && book.Verdict == verdictCross {
		t.Errorf("a book only its owner reads is reported as read by another role: %+v\n%s", book, errOut)
	}
	if post := find(rows, "/api/books", "POST"); post == nil || post.Verdict != verdictWriteAccepted {
		t.Errorf("a create whose object only its sender reads should stay accepted: %+v", post)
	}
}
