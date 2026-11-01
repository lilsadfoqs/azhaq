package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// jsonEchoServer reads a JSON body: the field role changes the answer, every
// other name changes nothing. strict makes it a login that refuses a body
// without username with a 400, as one required field at a time.
func jsonEchoServer(t *testing.T, strict bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		w.Header().Set("Content-Type", "application/json")
		if _, ok := in["username"]; strict && !ok {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"status":"fail","message":"Please Provide a valid username"}`)
			return
		}
		if v, ok := in["role"]; ok {
			fmt.Fprintf(w, `{"status":"success","message":"ok","granted":%q,"detail":"%s"}`, fmt.Sprint(v), strings.Repeat("x", 80))
			return
		}
		fmt.Fprint(w, `{"status":"success","message":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// -X JSON finds the one name a body reads among names it ignores.
func TestParamsJSONBodyFindsTheHiddenName(t *testing.T) {
	srv := jsonEchoServer(t, false)
	words := wlist(t, "username", "password", "email", "role", "user", "pass")
	out, rep, code := runContract(t, "params", "-u", srv.URL+"/login", "-w", words, "-X", "JSON", "-allow", "127.0.0.1", "-max-requests", "200")
	if code != exitOK {
		t.Fatalf("exit %d, %q", code, rep.Notes)
	}
	if !strings.Contains(out, `"params":["role"]`) {
		t.Errorf("want only role found: %s", out)
	}
}

// A budget that ends the search keeps what it established: the names found,
// and a note on how far it got; exit 4, and resume searches the page again.
func TestParamsJSONBodyAtABudgetKeepsWhatItEstablished(t *testing.T) {
	srv := jsonEchoServer(t, true)
	words := wlist(t, "username", "password", "email", "role", "user", "pass")
	args := []string{"params", "-u", srv.URL + "/login", "-w", words, "-X", "JSON", "-allow", "127.0.0.1", "-db", t.TempDir() + "/p.db"}
	out, rep, code := runContract(t, append(args, "-max-requests", "20")...)
	if code != exitLimit {
		t.Fatalf("exit %d, want %d", code, exitLimit)
	}
	if !strings.Contains(out, `"username"`) {
		t.Errorf("username was established before the budget ended and is not reported: %q", out)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "the request budget ended the search") || !strings.Contains(notes, " found so far") {
		t.Errorf("the summary does not say how far the search got: %q", notes)
	}
	if rep.Resume == "" {
		t.Errorf("no resume command: %+v", rep)
	}
	// What is left is said when nothing was established, too.
	_, rep, code = runContract(t, append(args[:len(args)-2:len(args)-2], "-db", t.TempDir()+"/q.db", "-max-requests", "6")...)
	if code != exitLimit || !strings.Contains(strings.Join(rep.Notes, "\n"), "the request budget ended the search") {
		t.Errorf("a budget of 6: exit %d, notes %q", code, rep.Notes)
	}
	// A budget that is enough finishes with both names, and no budget note.
	out, rep, code = runContract(t, append(args[:len(args)-2:len(args)-2], "-db", t.TempDir()+"/r.db", "-max-requests", "100")...)
	if code != exitOK || !strings.Contains(out, `"params":["role","username"]`) || strings.Contains(strings.Join(rep.Notes, "\n"), "budget ended") {
		t.Errorf("a budget that is enough: exit %d, %q, notes %q", code, out, rep.Notes)
	}
}
