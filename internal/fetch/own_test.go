package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Each URL of a redirect chain keeps the body it answered: the asked URL's own
// answer is its first hop's, and a URL the chain passed through is cached with
// its own body, not the chain's end (#588).
func TestEachURLOfAChainKeepsItsOwnBody(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("to b"))
		case "/b":
			w.Header().Set("Location", "/c")
			w.WriteHeader(http.StatusFound)
		default:
			_, _ = w.Write([]byte("end of the chain"))
		}
	}))
	t.Cleanup(srv.Close)
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/a")
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "end of the chain" {
		t.Fatalf("body %q, the chain's end stays Body", res.Body)
	}
	own := res.Own()
	if string(own.Body) != "to b" || own.Status != 302 || own.URL != srv.URL+"/a" {
		t.Errorf("own answer %q status %d url %s", own.Body, own.Status, own.URL)
	}
	mid, cached, err := Do(context.Background(), srv.Client(), srv.URL+"/b")
	if err != nil || !cached {
		t.Fatalf("/b cached %v err %v", cached, err)
	}
	if o := mid.Own(); len(o.Body) != 0 || o.Status != 302 {
		t.Errorf("the middle URL's own answer %q status %d, want its empty 302", o.Body, o.Status)
	}
	end, _, _ := Do(context.Background(), srv.Client(), srv.URL+"/c")
	if string(end.Own().Body) != "end of the chain" {
		t.Errorf("the last URL's own answer %q", end.Own().Body)
	}
}

// -sr's tap sees each URL of a chain with its own answer: the redirect's file
// holds the redirect, and the URL it leads to is written too, with its own (#588).
func TestTapSeesEachURLOfAChainWithItsOwnAnswer(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(srv.Close)
	got := map[string]Result{}
	Tap = func(raw string, res Result) { got[raw] = res }
	t.Cleanup(func() { Tap = nil })
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	a, b := got[srv.URL+"/a"], got[srv.URL+"/b"]
	if a.Status != 302 || len(a.Body) != 0 || a.Header.Get("Location") != "/b" {
		t.Errorf("/a tapped %d %q", a.Status, a.Body)
	}
	if b.Status != 500 || string(b.Body) != "boom" || b.StatusLine == "" {
		t.Errorf("/b tapped %d %q line %q", b.Status, b.Body, b.StatusLine)
	}
}
