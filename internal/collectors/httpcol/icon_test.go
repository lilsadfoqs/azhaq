package httpcol

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/detect"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/icontest"
	"github.com/lilsadfoqs/azhaq/types"
)

// A favicon in the catalog for GitLab, and the read its own template asks.
const (
	gitlabIcon = "1278323681"
	gitlabRead = "/users/sign_in"
	gitlabPage = "<html><body>GitLab https://about.gitlab.com</body></html>"
)

// siteWithIcon serves a plain page and the icon; the read answers as given.
func siteWithIcon(t *testing.T, hash string, read func(w http.ResponseWriter), got *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*got = append(*got, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<html><head><title>Welcome</title></head><body>hello</body></html>"))
		case "/favicon.ico":
			_, _ = w.Write(icontest.Body(hash))
		case gitlabRead:
			read(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func detectedGitlab(t *testing.T, p map[string]any) map[string]any {
	t.Helper()
	rows, _ := p["detected"].([]any)
	for _, r := range rows {
		if m, ok := r.(map[string]any); ok && m["template"] == "favicon-detect" {
			return m
		}
	}
	t.Fatalf("no favicon-detect row in %v", p["detected"])
	return nil
}

// The catalog icon names GitLab on its own. The row says so as a lead (icon),
// asks the product's own read once, and says what came back.
func TestIconAloneIsMarkedAndTheProductsReadIsAskedOnce(t *testing.T) {
	fetch.Reset()
	if hits := detect.Match(detect.Response{Path: "/favicon.ico", Status: 200, Body: icontest.Body(gitlabIcon)}); len(hits) == 0 || !hits[0].Icon {
		t.Fatalf("the catalog icon is not an icon hit: %+v", hits)
	}
	var got []string
	srv := siteWithIcon(t, gitlabIcon, func(w http.ResponseWriter) { http.NotFound(w, nil) }, &got)
	c := New(srv.Client())
	p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}})
	row := detectedGitlab(t, p)
	if row["icon"] != "1" || row["version"] != nil {
		t.Errorf("an icon alone is not marked: %v", row)
	}
	if want := "GET " + gitlabRead + " answered 404 and no template of the product matched"; row["ask"] != want {
		t.Errorf("ask %q, want %q", row["ask"], want)
	}
	reads := 0
	for _, g := range got {
		if g == gitlabRead {
			reads++
		}
	}
	if reads != 1 {
		t.Errorf("the product's read was sent %d times: %v", reads, got)
	}
}

// An answer the product's template matches makes it a detection: the icon
// mark goes and the row carries the read that proved it.
func TestIconConfirmedByTheProductsRead(t *testing.T) {
	fetch.Reset()
	var got []string
	srv := siteWithIcon(t, gitlabIcon, func(w http.ResponseWriter) { _, _ = w.Write([]byte(gitlabPage)) }, &got)
	c := New(srv.Client())
	p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}})
	row := detectedGitlab(t, p)
	if _, marked := row["icon"]; marked {
		t.Errorf("a confirmed icon is still marked: %v", row)
	}
	if want := "GET " + gitlabRead + " answered 200 and the template gitlab-detect matched"; row["ask"] != want {
		t.Errorf("ask %q, want %q", row["ask"], want)
	}
}

// With the product checks off the run reads nothing for an icon, and says so.
func TestIconIsNotReadWhenProductChecksAreOff(t *testing.T) {
	fetch.Reset()
	var got []string
	srv := siteWithIcon(t, gitlabIcon, func(w http.ResponseWriter) { _, _ = w.Write([]byte(gitlabPage)) }, &got)
	c := New(srv.Client())
	c.NoProductReads = true
	p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}})
	row := detectedGitlab(t, p)
	if row["icon"] != "1" || row["ask"] != "not asked: the product checks are off (-no-paths)" {
		t.Errorf("row %v", row)
	}
	for _, g := range got {
		if g == gitlabRead {
			t.Errorf("the read was sent with the product checks off: %v", got)
		}
	}
}
