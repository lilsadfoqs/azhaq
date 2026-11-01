package browser

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func pageServer(t *testing.T, html string) *recorder {
	t.Helper()
	srv := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(html))
	})
	t.Cleanup(srv.Close)
	return srv
}

// A page with no script, frame or refresh cannot change after it is drawn:
// with no wait given it is taken once painted, not after a fixed second
// and a half.
func TestPageOfMarkupIsTakenOnceDrawn(t *testing.T) {
	srv := pageServer(t, `<!doctype html><title>plain</title><h1>Plain page</h1><p>Nothing runs here.</p>`)
	b := startChrome(t)
	t0 := time.Now()
	p, err := b.Load(context.Background(), srv.URL, true)
	took := time.Since(t0)
	if err != nil || len(p.Image) == 0 {
		t.Fatalf("no picture: %v", err)
	}
	if took > 1200*time.Millisecond {
		t.Errorf("a page of markup took %s, as long as a wait for scripts", took)
	}
}

// A page with a script may draw after any delay: it is given the time it
// always had, and the shot has what a timer drew a second later.
func TestPageWithAScriptGetsTheTimeToDraw(t *testing.T) {
	srv := pageServer(t, `<!doctype html><title>late</title><p>shell</p>
<script>setTimeout(() => { const h = document.createElement('h1'); h.textContent = 'drawn late'; document.body.appendChild(h) }, 900)</script>`)
	b := startChrome(t)
	p, err := b.Load(context.Background(), srv.URL, true)
	if err != nil || len(p.Image) == 0 {
		t.Fatalf("no picture: %v", err)
	}
	if !strings.Contains(p.HTML, "<h1>drawn late</h1>") {
		t.Errorf("the page was taken before its timer ran:\n%s", p.HTML)
	}
}

// A wait that is given is waited out, whatever the page is.
func TestGivenWaitIsKept(t *testing.T) {
	srv := pageServer(t, `<!doctype html><title>plain</title><h1>Plain page</h1>`)
	b := startChrome(t)
	b.Wait = 1200 * time.Millisecond
	t0 := time.Now()
	if _, err := b.Load(context.Background(), srv.URL, true); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(t0); took < 1200*time.Millisecond {
		t.Errorf("took %s, less than the wait given", took)
	}
}
