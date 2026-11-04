package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// endlessApp serves a path that streams events for ever next to ordinary
// paths. The stream sends fast, so a read cut by size comes at once; the
// time window is tested in internal/fetch.
func endlessApp(t *testing.T) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			chunk := []byte(strings.Repeat("data: tick\n", 1500))
			for {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-done:
					return
				case <-r.Context().Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() { close(done); srv.Close() })
	return srv
}

func TestFuzzCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	srv := endlessApp(t)
	start := time.Now()
	out, errOut, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, "admin", "events", "nothing"), "-mc", "200,403", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the stream held the run for %v", took)
	}
	rows := map[string]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		rows[strings.TrimPrefix(m["url"].(string), srv.URL)] = m
	}
	if ev := rows["/events"]; ev == nil || ev["truncated"] != true || ev["status"].(float64) != 200 {
		t.Errorf("/events: %v, want a 200 row with truncated true", ev)
	}
	if ad := rows["/admin"]; ad == nil || ad["truncated"] != nil || ad["length"].(float64) != 9 {
		t.Errorf("/admin: %v, want a whole 403 row of 9 bytes", ad)
	}
	if r := lastReport(t, errOut); r.Exit != 0 {
		t.Errorf("exit %d, notes %q", r.Exit, r.Notes)
	}
}

func TestFuzzTextRowSaysTheBodyWasCut(t *testing.T) {
	srv := endlessApp(t)
	out, errOut, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, "admin", "events"), "-mc", "200,403"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "events") != strings.Contains(l, "Body: cut") {
			t.Errorf("row %q: the stream's row says its body was cut, no other does", l)
		}
	}
	if !strings.Contains(out, "Body: cut") {
		t.Errorf("no row says the body was cut:\n%s", out)
	}
}

func TestParamsCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	srv := endlessApp(t)
	start := time.Now()
	_, errOut, err := captureBoth(t, func() error {
		return cmdParams([]string{"-u", srv.URL + "/events", "-u", srv.URL + "/admin", "-w", wlist(t, "id", "q", "page"), "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("the stream held the run for %v", took)
	}
	rep := lastReport(t, errOut)
	var said, wrong []string
	for _, n := range rep.Notes {
		if strings.Contains(n, "body was cut") {
			said = append(said, n)
			if !strings.Contains(n, "/events") {
				wrong = append(wrong, n)
			}
		}
	}
	if rep.Exit != 0 || len(said) != 1 || len(wrong) != 0 {
		t.Errorf("exit %d; notes %q: want one note about /events saying the answer is a stream cut by the read", rep.Exit, rep.Notes)
	}
}

func TestRolesCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	done := make(chan struct{})
	spec := `{"openapi":"3.0.0","info":{"title":"x","version":"1"},"paths":{"/api/events":{"get":{}},"/api/me":{"get":{}}}}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"x"}`))
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(spec))
		case "/api/me":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"user":{"name":"` + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + `"}}`))
		case "/api/events":
			w.Header().Set("Content-Type", "text/event-stream")
			chunk := []byte(strings.Repeat("data: tick\n", 1500))
			for {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-done:
					return
				case <-r.Context().Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	defer close(done)
	start := time.Now()
	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-all", "-dir", t.TempDir(), "-role", "anon", "-role", "alice=Authorization: Bearer alice",
			"--", "-url", site.URL + "/"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("the stream held the run for %v", took)
	}
	seen := map[string]roleRow{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var row roleRow
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatalf("%v: %s\nstdout %q\nstderr %s", err, l, out, errOut)
		}
		seen[strings.TrimPrefix(row.URL, site.URL)] = row
	}
	ev, ok := seen["/api/events"]
	if !ok || strings.Join(ev.Truncated, ",") != "alice,anon" && strings.Join(ev.Truncated, ",") != "anon,alice" {
		t.Fatalf("/api/events: %+v (rows %v), want both roles' answers marked cut", ev, len(seen))
	}
	for role, a := range ev.Answers {
		if !a.Truncated || a.Status != 200 {
			t.Errorf("%s: answer %+v, want a 200 cut", role, a)
		}
	}
	if me, ok := seen["/api/me"]; !ok || len(me.Truncated) != 0 {
		t.Errorf("/api/me: %+v, want a whole answer", me)
	}
	if r := lastReport(t, errOut); r.Exit != 0 {
		t.Errorf("exit %d, notes %q", r.Exit, r.Notes)
	}
}

// The replay's own readers (a role asked for a URL its run did not reach, a
// control, a write) cut a stream that never ends and mark the answer.
func TestRolesReplayReadersCutAnEndlessAnswer(t *testing.T) {
	srv := endlessApp(t)
	u := srv.URL + "/events"
	ctx := context.Background()
	start := time.Now()
	a, _, err := askFresh(ctx, http.Header{}, u, map[string]bool{"127.0.0.1": true})
	if err != nil || !a.Truncated || a.Status != 200 {
		t.Errorf("askFresh: %+v, %v; want a 200 marked cut", a, err)
	}
	a, err = readAs(ctx, srv.Client(), role{name: "alice"}, u)
	if err != nil || !a.Truncated || a.Status != 200 {
		t.Errorf("readAs: %+v, %v; want a 200 marked cut", a, err)
	}
	a, err = sendWrite(ctx, srv.Client(), role{name: "alice"}, writeReq{method: "POST", url: u})
	if err != nil || !a.Truncated || a.Status != 200 {
		t.Errorf("sendWrite: %+v, %v; want a 200 marked cut", a, err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the stream held the readers for %v", took)
	}
}
