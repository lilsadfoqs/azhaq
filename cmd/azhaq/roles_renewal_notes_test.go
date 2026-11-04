package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// renewalNotes replays three URLs for one role whose session is dead before
// the replay starts (as after a GET to the logout page), with the renewal
// the role has, and returns the replay's notes.
func renewalNotes(t *testing.T, r role) []string {
	t.Helper()
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
	r.name, r.session = "alice", http.Header{"Authorization": {"t1"}}
	roles := []role{r}
	found := map[string][]string{}
	for _, p := range []string{"/o/1", "/o/2", "/o/3"} {
		found[srv.URL+p] = []string{"bob"}
	}
	w := &replayWatch{every: 3, canaries: map[string]*canary{"alice": {url: srv.URL + "/me", want: me}}, renew: renewer(roles, "", true, nil)}
	if _, err := replayAll(roles, map[string]map[string]answer{"alice": {}}, found, nil, map[string]bool{"127.0.0.1": true}, 0, 100, w); err != nil {
		t.Fatal(err)
	}
	return w.notes
}

func notesHave(notes []string, want ...string) bool {
	all := strings.Join(notes, "\n")
	for _, s := range want {
		if !strings.Contains(all, s) {
			return false
		}
	}
	return true
}

// A role with no -role-cmd (its session came from -har or -role) says it
// could not be renewed; no note says a command gave it a new one.
func TestRoleNotesNoCommandSaysItCouldNotBeRenewed(t *testing.T) {
	notes := renewalNotes(t, role{})
	if !notesHave(notes, "could not be renewed", "no -role-cmd or -role-login to renew it") || notesHave(notes, "gave a new one", "signed in again") {
		t.Errorf("notes:\n%s", strings.Join(notes, "\n"))
	}
}

// A -role-cmd that fails: the notes say the renewal failed, and none says it
// gave a new session.
func TestRoleNotesFailingCommandSaysRenewalFailed(t *testing.T) {
	notes := renewalNotes(t, role{cmd: "exit 3"})
	if !notesHave(notes, "could not be renewed", "was not renewed: its renewal failed") || notesHave(notes, "gave a new one") {
		t.Errorf("notes:\n%s", strings.Join(notes, "\n"))
	}
}

// A -role-cmd that gives a session that passes its check is named.
func TestRoleNotesCommandThatRenewsIsNamed(t *testing.T) {
	notes := renewalNotes(t, role{cmd: "echo 'Authorization: t2'"})
	if !notesHave(notes, "its -role-cmd gave a new one") || notesHave(notes, "could not be renewed", "was not renewed") {
		t.Errorf("notes:\n%s", strings.Join(notes, "\n"))
	}
}

// A -role-cmd whose new session fails its check too: the notes say the new
// session failed, not that the command gave a working one.
func TestRoleNotesCommandWhoseNewSessionFailsIsNotCalledARenewal(t *testing.T) {
	notes := renewalNotes(t, role{cmd: "echo 'Authorization: t3'"})
	if !notesHave(notes, "was not renewed: the new session failed its check too") || notesHave(notes, "gave a new one") {
		t.Errorf("notes:\n%s", strings.Join(notes, "\n"))
	}
}
