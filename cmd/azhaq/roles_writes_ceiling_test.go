package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// stageCeilings checks the cost of a write replay: no stage sent more than
// the ceiling it printed. It returns the stages by name.
func stageCeilings(t *testing.T, rep report) map[string]costStage {
	t.Helper()
	if rep.Cost == nil {
		t.Fatalf("no cost in the summary: %+v", rep)
	}
	got := map[string]costStage{}
	for _, st := range rep.Cost.Stages {
		got[st.Stage] = st
		if st.AtMost == nil || st.Actual == nil {
			continue
		}
		if sent := st.Actual.Requests; sent > *st.AtMost {
			t.Errorf("the %s stage sent %d requests, over its ceiling of %d", st.Stage, sent, *st.AtMost)
		}
	}
	return got
}

// A write replay on objects (PUT, PATCH, DELETE): every read the verification
// sends is counted in its ceiling, and no stage sends more than it says.
func TestRolesWriteReplayStagesStayUnderTheirCeilings(t *testing.T) {
	var mu sync.Mutex
	name := map[string]string{"1": "a-note", "2": "b-note"}
	owner := map[string]string{"1": "alice", "2": "bob"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		w.Header().Set("Content-Type", "application/json")
		id, sub, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/notes/"), "/")
		if _, ok := name[id]; !ok {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if user == "" || sub != "" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprintf(w, `{"id":%s,"title":%q,"owner":%q}`, id, name[id], owner[id])
		case http.MethodPut, http.MethodPatch:
			b, _ := io.ReadAll(r.Body)
			name[id] = strings.Trim(strings.TrimPrefix(string(b), `{"title":`), `"}`) // anyone may write
			fmt.Fprint(w, `{"ok":true}`)
		case http.MethodDelete:
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	har := func(file, user, id string) string {
		return writeHAR(t, file,
			harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/api/notes/"+id, "", 200, "Authorization", "Bearer tok-"+user),
			harEntry("2026-10-29T10:00:01.000Z", "PUT", srv.URL+"/api/notes/"+id, `{"title":"t-`+user+`"}`, 200, "Authorization", "Bearer tok-"+user, "Content-Type", "application/json"),
			harEntry("2026-10-29T10:00:02.000Z", "DELETE", srv.URL+"/api/notes/"+id, "", 403, "Authorization", "Bearer tok-"+user))
	}
	// No history read of the object: the owner's object is found by asking
	// the write's URL and then its parent.
	sub := func(file, user, id string) string {
		return writeHAR(t, file,
			harEntry("2026-10-29T10:00:01.000Z", "PUT", srv.URL+"/api/notes/"+id+"/title", `{"title":"t-`+user+`"}`, 200, "Authorization", "Bearer tok-"+user, "Content-Type", "application/json"))
	}
	for name, hars := range map[string][]string{
		"objects read in the history": {"alice=" + har("a.har", "alice", "1"), "bob=" + har("b.har", "bob", "2")},
		"objects found by asking":     {"alice=" + sub("a.har", "alice", "1"), "bob=" + sub("b.har", "bob", "2")},
	} {
		args := []string{"-role", "anon", "-replay-writes", "put,delete"}
		for _, h := range hars {
			args = append(args, "-har", h)
		}
		_, _, rep, err := rolesJSONReport(t, srv.URL, args...)
		if err != nil {
			t.Fatal(err)
		}
		st := stageCeilings(t, rep)["verification"]
		if st.Actual == nil || st.Actual.Requests == 0 {
			t.Fatalf("%s: the verification sent nothing: %+v", name, st)
		}
		if st.AtMost == nil {
			t.Fatalf("%s: a replay of PUT and DELETE on objects has a ceiling for its verification: %+v", name, st)
		}
	}
}

// A create is looked for where its answer and the collection say it is: the
// verification reads of that are not known before, so the stage says it has
// no ceiling of its own, and -max-requests gives it one that holds.
func TestRolesCreateVerificationCeilingIsOpenUntilBounded(t *testing.T) {
	var mu sync.Mutex
	books := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/books":
			b, _ := io.ReadAll(r.Body)
			title := strings.Trim(strings.TrimPrefix(string(b), `{"title":`), `"}`)
			books[title] = user
			fmt.Fprintf(w, `{"id":%q,"title":%q}`, title, title)
		case r.Method == http.MethodGet && r.URL.Path == "/books":
			fmt.Fprint(w, `[]`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/books/"):
			title := strings.TrimPrefix(r.URL.Path, "/books/")
			if o, ok := books[title]; ok {
				fmt.Fprintf(w, `{"id":%q,"title":%q,"owner":%q}`, title, title, o)
				return
			}
			w.WriteHeader(404)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	har := writeHAR(t, "alice.har",
		harEntry("2026-10-29T10:00:00.000Z", "POST", srv.URL+"/books", `{"title":"t-alice"}`, 200, "Authorization", "Bearer tok-alice", "Content-Type", "application/json"))
	bob := writeHAR(t, "bob.har",
		harEntry("2026-10-29T10:00:00.000Z", "POST", srv.URL+"/books", `{"title":"t-bob"}`, 200, "Authorization", "Bearer tok-bob", "Content-Type", "application/json"))
	for _, extra := range [][]string{nil, {"--", "-url", srv.URL + "/", "-max-requests", "500"}} {
		args := append([]string{"-role", "anon", "-har", "alice=" + har, "-har", "bob=" + bob, "-replay-writes", "post"}, extra...)
		_, _, rep, err := rolesJSONReport(t, srv.URL, args...)
		if err != nil {
			t.Fatalf("%v: %v", extra, err)
		}
		st := stageCeilings(t, rep)["verification"]
		if st.Actual == nil || st.Actual.Requests == 0 {
			t.Fatalf("%v: the verification sent nothing: %+v", extra, st)
		}
		if extra == nil && (st.AtMost != nil || st.NoCeiling == "") {
			t.Errorf("a create's verification reads depend on the answers, and the stage says it has no ceiling: %+v", st)
		}
	}
}
