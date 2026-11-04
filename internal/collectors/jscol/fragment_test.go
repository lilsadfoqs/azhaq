package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// A route with a placeholder is not cut at the placeholder: the part after it
// is no route of its own, so no request is made for it, whatever shape the
// placeholder has.
func TestTemplateRouteMakesNoRequestForItsTail(t *testing.T) {
	cases := map[string]string{
		"double-quoted ${}":      `var a="/y/${id}/z.php";`,
		"template literal":       "var a=`/y/${id}/z.php`;",
		"braces":                 `var a="/y/{id}/z.php";`,
		"brackets":               `var a="/y/[id]/z.php";`,
		"colon":                  `var a="/y/:id/z.php";`,
		"concatenation":          `var a="/y/"+id+"/z.php";`,
		"concatenation, a call":  `var a="/y/"+enc(id)+"/z.php";`,
		"concatenation in fetch": `fetch("/y/" + id + "/z.php");`,
		"template in fetch":      "fetch(`/y/${id}/z.php`);",
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			fetch.Reset()
			mux := http.NewServeMux()
			mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<!doctype html><title>App</title><script src="/app.js"></script>`))
			})
			mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/javascript")
				_, _ = w.Write([]byte(js))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			var rows []string
			rejected := 0
			meta, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/app"}}, func(o types.Observation) error {
				var p struct {
					URL    string `json:"url"`
					String string `json:"string"`
				}
				_ = json.Unmarshal(o.Payload, &p)
				if o.Kind == "url" {
					rows = append(rows, strings.TrimPrefix(p.URL, srv.URL))
				}
				if o.Kind == "rejected" && strings.Contains(p.String, "z.php") {
					rejected++
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if r == "/z.php" || r == "/id/z.php" {
					t.Errorf("%s: a row for the tail %s: %q", js, r, rows)
				}
			}
			if rejected == 0 {
				t.Errorf("%s: the tail is not listed as rejected", js)
			}
			for _, h := range meta.NextHints {
				if u := strings.TrimPrefix(h.Keys["url"], srv.URL); u == "/z.php" || u == "/id/z.php" {
					t.Errorf("%s: a request is hinted for the tail %s", js, u)
				}
			}
		})
	}
}

// What stands alone is still a route, and a base joined to a path is not a
// route with a placeholder.
func TestRouteNamedAloneOrJoinedToABaseStays(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>App</title><script src="/app.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`var a="/z.php"; var base=window.API; fetch(base+"/health"); var b="/y/${id}/w.php";`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	var got []string
	_, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/app"}}, func(o types.Observation) error {
		var p struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		if o.Kind == "url" {
			got = append(got, strings.TrimPrefix(p.URL, srv.URL))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/z.php", "/health"} {
		if !has(got, want) {
			t.Errorf("%s missing from %q", want, got)
		}
	}
	if has(got, "/w.php") {
		t.Errorf("the tail of /y/${id}/w.php is a row: %q", got)
	}
}

func TestPartOfRoute(t *testing.T) {
	for js, want := range map[string]bool{
		`"/y/"+id+"/z.php"`:      true,
		`"/y/" + id + "/z.php"`:  true,
		`"/y/"+enc(id)+"/z.php"`: true,
		`"/y/"+a.b[0]+"/z.php"`:  true,
		`"/y/"+"/z.php"`:         true,
		`base+"/z.php"`:          false,
		`this.host+"/z.php"`:     false,
		`"/z.php"`:               false,
		`"x"+id+"/z.php"`:        false, // the left string is not a path
		`"/y/${a}"+id+"/z.php"`:  false,
		`a++"/z.php"`:            false,
		`("/y/"+id)+"/z.php"`:    false, // not read: kept, as a route named on its own
	} {
		i := strings.LastIndex(js, `"/z.php"`)
		if got := webextract.PartOfRoute(js, i); got != want {
			t.Errorf("%s: %v, want %v", js, got, want)
		}
	}
}
