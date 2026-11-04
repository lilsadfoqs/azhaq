package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A role that signs in with -role-login and whose new session passes its check
// is named as having signed in again, not as its command giving a new one;
// the sign-in itself (Chrome) is stood in by a renewal that sets the session.
func TestRoleNotesASignInThatPassedItsCheckIsNamed(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Header.Get("Authorization") != "t2" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"expired"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"alice","path":"` + req.URL.Path + `"}`))
	}))
	defer srv.Close()
	me, _ := readAnswer(200, []byte(`{"name":"alice","path":"/me"}`), "application/json")
	roles := []role{{name: "alice", user: "alice", session: http.Header{"Authorization": {"t1"}}}}
	found := map[string][]string{}
	for _, p := range []string{"/o/1", "/o/2", "/o/3"} {
		found[srv.URL+p] = []string{"bob"}
	}
	signIn := func(i int) error {
		roles[i].session = http.Header{"Authorization": {"t2"}}
		return nil
	}
	w := &replayWatch{every: 3, canaries: map[string]*canary{"alice": {url: srv.URL + "/me", want: me}}, renew: signIn}
	if _, err := replayAll(roles, map[string]map[string]answer{"alice": {}}, found, nil, map[string]bool{"127.0.0.1": true}, 0, 100, w); err != nil {
		t.Fatal(err)
	}
	if !notesHave(w.notes, "it signed in again") || notesHave(w.notes, "gave a new one", "could not be renewed", "was not renewed") {
		t.Errorf("notes:\n%v", w.notes)
	}
}
