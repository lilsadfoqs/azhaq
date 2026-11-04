package fuzz

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Without a source -preflight-var-auto looks in the form, the meta tags, the
// cookies and the headers of the answer, and says so when the name is in two
// of them with different values.
func TestFlightVarAutoLooksInAllFourAndSaysWhenTheyDiffer(t *testing.T) {
	page := func(form, meta, cookie, header string) *flightAnswer {
		var b strings.Builder
		b.WriteString("<html><head>")
		if meta != "" {
			b.WriteString(`<meta name="tok" content="` + meta + `">`)
		}
		b.WriteString("</head><body>")
		if form != "" {
			b.WriteString(`<form><input name="tok" value="` + form + `"></form>`)
		}
		b.WriteString("</body></html>")
		h := http.Header{}
		if cookie != "" {
			h.Add("Set-Cookie", "tok="+cookie)
		}
		if header != "" {
			h.Set("Tok", header)
		}
		return &flightAnswer{body: []byte(b.String()), header: h}
	}
	v, err := ParseFlightVar("T:tok", true)
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*flightAnswer{
		"a form field": page("abc", "", "", ""),
		"a meta tag":   page("", "abc", "", ""),
		"a cookie":     page("", "", "abc", ""),
		"a header":     page("", "", "", "abc"),
		"all four":     page("abc", "abc", "abc", "abc"),
	} {
		got, err := (&flightSender{}).extract(&v, a)
		if err != nil || got != "abc" {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	for name, a := range map[string]*flightAnswer{
		"form and meta":     page("abc", "xyz", "", ""),
		"meta and cookie":   page("", "abc", "xyz", ""),
		"cookie and header": page("", "", "abc", "xyz"),
		"form and header":   page("abc", "", "", "xyz"),
	} {
		_, err := (&flightSender{}).extract(&v, a)
		if err == nil || !strings.Contains(err.Error(), "with different values: pin one with NAME:") {
			t.Errorf("%s: want an error that says the name is in two with different values, got %v", name, err)
		}
	}
	if _, err := (&flightSender{}).extract(&v, page("", "", "", "")); err == nil || !strings.Contains(err.Error(), "is in no form, meta tag, cookie or header of the answer") {
		t.Errorf("a name in none: %v", err)
	}
	// Pinned to a source, a name in two is read from that one.
	pinned, _ := ParseFlightVar("T:cookie:tok", true)
	if got, err := (&flightSender{}).extract(&pinned, page("abc", "xyz", "qrs", "")); err != nil || got != "qrs" {
		t.Errorf("pinned to the cookie: %q, %v", got, err)
	}
}

// keepSender notes whether each request asked for the body to be kept.
type keepSender struct {
	mu    sync.Mutex
	keeps []bool
	reply func(*Request) *Response
}

func (s *keepSender) Send(_ context.Context, req *Request, keep bool) (*Response, error) {
	s.mu.Lock()
	s.keeps = append(s.keeps, keep)
	s.mu.Unlock()
	r := s.reply(req)
	r.Request = req
	return r, nil
}

// With -ac on, answers are read into memory until calibration is done (and
// for the whole run with -ach, or when a page shape was learned); without it
// they are only counted.
func TestAnswersAreReadIntoMemoryOnlyWhileCalibrationNeedsThem(t *testing.T) {
	same := func(*Request) *Response {
		return &Response{Status: 200, Header: http.Header{}, Length: 100, Words: 10, Lines: 3, Body: []byte("<html><title>x</title></html>")}
	}
	changing := func() func(*Request) *Response {
		var mu sync.Mutex
		n := 0
		return func(*Request) *Response {
			mu.Lock()
			n++
			k := n
			mu.Unlock()
			body := "<html><title>Console</title><body>" + strings.Repeat(fmt.Sprintf("w%d ", k*7919), 5+k%11) + "</body></html>"
			return &Response{Status: 200, Header: http.Header{}, Length: int64(len(body)), Words: int64(5 + k%11), Lines: int64(1 + k%5), Body: []byte(body)}
		}
	}
	count := func(keeps []bool, want bool) (n int) {
		for _, k := range keeps {
			if k == want {
				n++
			}
		}
		return
	}
	for _, c := range []struct {
		name          string
		mut           func(*Config)
		reply         func(*Request) *Response
		kept, dropped int // requests that kept the body, and that did not
	}{
		{"no calibration", func(c *Config) {}, same, 0, 6},
		{"calibrated on a size", func(c *Config) { c.Calibrate = true }, same, 7, 5}, // the 6 guesses and the answer that came first
		{"calibrated per host", func(c *Config) { c.Calibrate = true; c.Set.PerHost = true }, same, 12, 0},
		{"a page shape learned", func(c *Config) { c.Calibrate = true }, changing(), 12, 0},
	} {
		s := &keepSender{reply: c.reply}
		runFake(t, &fake{hook: func(*Request) (*Response, error) { return nil, nil }}, func(cfg *Config) {
			cfg.Threads, cfg.Sender = 1, s
			c.mut(cfg)
		})
		if k, d := count(s.keeps, true), count(s.keeps, false); k != c.kept || d != c.dropped {
			t.Errorf("%s: %d requests kept the body and %d did not, want %d and %d (%v)", c.name, k, d, c.kept, c.dropped, s.keeps)
		}
	}
}

// Only a match of the status the page was learned from is held back: the
// same page under another status is listed.
func TestAPageOfAnotherStatusIsListed(t *testing.T) {
	var mu sync.Mutex
	n := 0
	reply := func(r *Request) *Response {
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		body := "<html><title>Console</title><body>" + strings.Repeat(fmt.Sprintf("w%d ", k*7919), 5+k%11) + "</body></html>"
		status := 200
		if strings.HasSuffix(r.URL, "/admin") {
			status = 202
		}
		return &Response{Status: status, Header: http.Header{}, Length: int64(len(body)), Words: int64(5 + k%11), Lines: int64(1 + k%5), Body: []byte(body)}
	}
	var got []string
	st, _ := runFake(t, &fake{hook: func(*Request) (*Response, error) { return nil, nil }}, func(cfg *Config) {
		cfg.Threads, cfg.Sender, cfg.Calibrate = 1, &keepSender{reply: reply}, true
		cfg.OnResult = func(r Result) { got = append(got, r.URL) }
	})
	if len(got) != 1 || !strings.HasSuffix(got[0], "/admin") || st.Held != 5 {
		t.Errorf("listed %v, held %d: want only /admin listed and the other 5 held back", got, st.Held)
	}
}
