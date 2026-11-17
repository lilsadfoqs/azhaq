package httpcol

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// A URL that answers an empty 302 to a page that sends a stack trace is a row of
// its own answer: no body, no trace; the page it ends at is the row that holds
// the trace (#588).
func TestRedirectRowHoldsItsOwnAnswer(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	trace := "java.lang.IllegalStateException: no cart\n\tat a.B.c(B.java:1)\n\tat a.B.d(B.java:2)\n\tat a.B.e(B.java:3)\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/assets":
			w.Header().Set("Location", "/assets/")
			w.WriteHeader(http.StatusFound)
		case "/.env":
			http.Redirect(w, r, "/.env/", http.StatusFound) // with its own short body
		default:
			w.WriteHeader(500)
			_, _ = w.Write([]byte(trace))
		}
	}))
	defer srv.Close()
	c := New(srv.Client())
	c.NoFavicon = true

	for _, path := range []string{"/assets", "/.env"} {
		p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + path}})
		if p["status"].(float64) != 302 || p["final_status"].(float64) != 500 {
			t.Fatalf("%s: status %v final %v", path, p["status"], p["final_status"])
		}
		for _, k := range []string{"stack_trace", "trace_excerpt", "error_text", "body_url"} {
			if p[k] != nil {
				t.Errorf("%s: row holds %s = %v of the page it redirects to", path, k, p[k])
			}
		}
		own := "" // what the redirect itself sent
		if path == "/.env" {
			own = `<a href="/.env/">Found</a>.` + "\n\n"
		}
		for _, k := range []string{"body_excerpt", "head"} {
			raw, _ := p[k].(string)
			if got, _ := base64.StdEncoding.DecodeString(raw); string(got) != own {
				t.Errorf("%s: %s %q, want its own %q", path, k, got, own)
			}
		}
		if n := p["body_length"].(float64); int(n) != len(own) {
			t.Errorf("%s: body_length %v, want %d", path, n, len(own))
		}
	}

	// The target is asked by its own URL (the redirect's hint names it) and holds the trace.
	p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/assets/"}})
	if tr, _ := p["stack_trace"].(map[string]any); tr == nil || p["status"].(float64) != 500 {
		t.Errorf("the target's row: status %v stack_trace %v", p["status"], p["stack_trace"])
	}
	if ex, _ := p["body_excerpt"].(string); ex == "" || !strings.Contains(p["trace_excerpt"].(string), "IllegalStateException") {
		t.Errorf("the target's row keeps its own body: excerpt %q trace %v", ex, p["trace_excerpt"])
	}
}
