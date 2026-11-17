package fuzz

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func answerOf(status int, body string) *Response {
	return &Response{Status: status, Length: int64(len(body)), Words: int64(len(strings.Fields(body))), Lines: 1, Body: []byte(body), Header: http.Header{}}
}

// A match that answers with an error or a redirect naming its own path and,
// with that taken out, is the answer of a name asked under it (input/<random>)
// is listed with that control and marked as its prefix's catch-all; one control
// for each prefix; a route that answers 500 with a page of its own, naming its
// path too, is listed unmarked.
func TestPrefixCatchAllMatchIsListedWithItsControl(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		p := strings.TrimPrefix(r.URL, "http://h.test")
		switch {
		case p == "/real":
			return answerOf(500, "database is down at "+p), nil
		case p == "/api" || strings.HasPrefix(p, "/api/"):
			return answerOf(500, "<title>Unexpected path: "+html.EscapeString(p)+"</title><p>"+p+"</p><a href='?"+url.QueryEscape(p)+"'>x</a>"), nil
		case p == "/other":
			return answerOf(200, "a page of its own"), nil
		}
		return answerOf(200, strings.Repeat("the shell of the app ", 20)), nil
	}}
	words := []string{"api", "api/v1", "api/a&b", "real", "other"}
	st, out := runFake(t, f, func(c *Config) {
		c.Calibrate, c.Threads = true, 1 // in order: the shorter prefix is asked first
		c.Lists[0].Words = words
	})
	got, marked := map[string]bool{}, map[string]bool{}
	for _, r := range out {
		got[r.Input["FUZZ"]] = true
		if r.Prefix && r.Control != nil && strings.HasPrefix(r.Control.URL, "http://h.test/api/") {
			marked[r.Input["FUZZ"]] = true
		} else if r.Prefix || r.Control != nil {
			t.Errorf("%s: control %v prefix %v", r.Input["FUZZ"], r.Control, r.Prefix)
		}
	}
	if len(out) != 5 || !reflect.DeepEqual(marked, map[string]bool{"api": true, "api/v1": true, "api/a&b": true}) || st.PrefixHit != 3 {
		t.Errorf("listed %v, marked %v, labelled %d", got, marked, st.PrefixHit)
	}
	// 5 words, 6 calibration names, and a control for /api/ (it answers for
	// api/v1 and api/a&b too) and one for /real/.
	if len(f.got) != 5+6+2 {
		t.Errorf("%d requests: %v", len(f.got), f.got)
	}
	// Without -ac every match is listed and no control is asked.
	f2 := &fake{hook: f.hook}
	st, out = runFake(t, f2, func(c *Config) { c.Lists[0].Words = words })
	if len(out) != 5 || st.PrefixHit != 0 || len(f2.got) != 5 {
		t.Errorf("without -ac: %d results, %d labelled, %d requests", len(out), st.PrefixHit, len(f2.got))
	}
}

// With the keyword ending the path, a body is read only for an answer with
// status 300 or above: the sender is asked with KeepFrom, and keeps a 500's
// body and not a 200's.
func TestSenderKeepsOnlyErrorBodiesFromKeepFrom(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/err" {
			w.WriteHeader(500)
		}
		fmt.Fprint(w, "a body of some words")
	}))
	defer srv.Close()
	s := mustSender(t, HTTPOptions{Timeout: 5 * time.Second, Threads: 1})
	tmpl, _ := NewTemplate("", srv.URL+"/FUZZ", "", nil, nil)
	for word, keeps := range map[string]bool{"ok": false, "err": true} {
		req := tmpl.Expand(map[string]string{"FUZZ": word})
		req.KeepFrom = KeepErrorBodies
		r, err := s.Send(context.Background(), &req, false)
		if err != nil || (r.Body != nil) != keeps || r.Words != 5 {
			t.Errorf("%s: kept %v (want %v), %+v, %v", word, r != nil && r.Body != nil, keeps, r, err)
		}
	}
}
