package fuzz

import (
	"html"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func answerOf(status int, body string) *Response {
	return &Response{Status: status, Length: int64(len(body)), Words: int64(len(strings.Fields(body))), Lines: 1, Body: []byte(body), Header: http.Header{}}
}

// A match whose answer names its input and, with that taken out, is the
// answer of a name asked under it (input/<random>) is the catch-all of the
// prefix it opens: held back and counted, one control for each prefix; a route
// that answers 500 with a page of its own, naming its path too, is listed.
func TestPrefixCatchAllIsHeldBackWhenItsControlAnswersTheSame(t *testing.T) {
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
	var got []string
	for _, r := range out {
		got = append(got, r.Input["FUZZ"])
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"other", "real"}) || st.PrefixHeld != 3 {
		t.Errorf("listed %v, held by prefix %d", got, st.PrefixHeld)
	}
	// 5 words, 6 calibration names, and a control for /api/ (it answers for
	// api/v1 and api/a&b too) and one for /real/.
	if len(f.got) != 5+6+2 {
		t.Errorf("%d requests: %v", len(f.got), f.got)
	}
	// Without -ac every match is listed and no control is asked.
	f2 := &fake{hook: f.hook}
	st, out = runFake(t, f2, func(c *Config) { c.Lists[0].Words = words })
	if len(out) != 5 || st.PrefixHeld != 0 || len(f2.got) != 5 {
		t.Errorf("without -ac: %d results, %d held, %d requests", len(out), st.PrefixHeld, len(f2.got))
	}
}
