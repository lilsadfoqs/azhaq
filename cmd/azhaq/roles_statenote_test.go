package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The note for a state-changing GET names the stages that sent it: a role's
// run only found it, but the history read and the replay asked it.
func TestRolesStateChangingGETNoteNamesTheStagesThatSentIt(t *testing.T) {
	var mu sync.Mutex
	logouts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>home</title></head><body><a href="/logout">out</a> <a href="/me">me</a></body></html>`)
		case "/me":
			w.Header().Set("Content-Type", "application/json")
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"login"}`)
				return
			}
			fmt.Fprint(w, `{"user":"x"}`)
		case "/logout":
			mu.Lock()
			logouts++
			mu.Unlock()
			fmt.Fprint(w, "bye")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	har := writeHAR(t, "u1.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/me", "", 200, "Authorization", "Bearer t1"),
		harEntry("2026-10-29T10:01:00.000Z", "GET", srv.URL+"/logout", "", 200, "Authorization", "Bearer t1"))
	_, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", t.TempDir(), "-har", "u1=" + har, "--", "-url", srv.URL + "/", "-sources", "none", "-depth", "1"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep, ok := lastSummary(errOut)
	if !ok {
		t.Fatalf("no summary:\n%s", errOut)
	}
	mu.Lock()
	n := logouts
	mu.Unlock()
	if n == 0 {
		t.Fatal("the stages sent no GET /logout: nothing to say")
	}
	var note string
	for _, x := range rep.Notes {
		if strings.Contains(x, "/logout may change state") {
			note += x + "\n"
		}
	}
	if note == "" || strings.Contains(note, "no request for it was sent in this run") || !strings.Contains(note, "the history reads (") || !strings.Contains(note, "the replay (") {
		t.Errorf("the target saw %d GET /logout; the note must name the stages that sent them:\n%s", n, note)
	}
}
