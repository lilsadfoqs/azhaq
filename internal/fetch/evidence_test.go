package fetch

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEvidenceOfKeepsResponseHeadersAndAnExcerpt(t *testing.T) {
	body := []byte(strings.Repeat("x", 3000))
	res := Result{
		Header: http.Header{"Server": {"a", "b"}, "Set-Cookie": {"sid=SECRET; Path=/; Secure", "t=1"}},
		Body:   body, At: time.Unix(1700000000, 0),
	}
	ev := EvidenceOf(res, 0)
	if len(ev.Excerpt) != ExcerptBytes || !ev.Cut || ev.BodyLength != 3000 {
		t.Errorf("excerpt %d, cut %v, length %d", len(ev.Excerpt), ev.Cut, ev.BodyLength)
	}
	body[0] = 'y'
	if ev.Excerpt[0] != 'x' {
		t.Error("the excerpt shares the body's memory")
	}
	if got := strings.Join(ev.Headers["Set-Cookie"], "|"); got != "sid=[kept out]; Path=/; Secure|t=[kept out]" {
		t.Errorf("cookies: %q", got)
	}
	if len(ev.Headers["Server"]) != 2 || ev.AskedAt.Unix() != 1700000000 {
		t.Errorf("%+v", ev)
	}
	// A body the read cut short is longer than what was read.
	if ev := EvidenceOf(Result{Body: []byte("ab")}, 500); !ev.Cut || ev.BodyLength != 500 {
		t.Errorf("a read stopped short: %+v", ev)
	}
	if ev := EvidenceOf(Result{Body: []byte("ab")}, 0); ev.Cut {
		t.Error("a short body is not cut")
	}
}
