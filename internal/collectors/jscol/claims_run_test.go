package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// A base without a leading slash is the page's, as a browser resolves it:
// a page at /shop/ whose script gives its client baseURL "server/index.php?s="
// asks /shop/server/index.php?s=/item/list, and the same script on a page at
// the root asks /server/index.php?s=/item/list.
func TestABaseWithoutALeadingSlashIsThePages(t *testing.T) {
	for _, c := range []struct{ page, want string }{
		{"/shop/", "/shop/server/index.php?s=/item/list"},
		{"/", "/server/index.php?s=/item/list"},
	} {
		fetch.Reset()
		t.Cleanup(fetch.Reset)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case c.page:
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><script src="app.js"></script>`))
			case c.page + "app.js":
				w.Header().Set("Content-Type", "application/javascript")
				_, _ = w.Write([]byte(`var http=axios.create({baseURL:"server/index.php?s="});function a(){return http.get("/item/list")}`))
			default:
				http.NotFound(w, r)
			}
		}))
		var rows []string
		_, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + c.page}}, func(o types.Observation) error {
			if o.Kind == "url" {
				var p map[string]any
				_ = json.Unmarshal(o.Payload, &p)
				if p["via"] == "js-call" {
					rows = append(rows, strings.TrimPrefix(p["url"].(string), srv.URL))
				}
			}
			return nil
		})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0] != c.want {
			t.Errorf("page %s: the call is %v, want %s", c.page, rows, c.want)
		}
	}
}
