package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/types"
)

// The counts of a run are disjoint and cover every stored row, so they add
// up to "stored", and each is the number `query` lists with its filter.
func TestRunCountsAreDisjointAndMatchQuery(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages := map[string][2]string{
			"/":          {"text/html", "<title>home</title><script src='/app.js'></script><img src='/logo.png'><a href='/about'>a</a><a href='/api/users'>u</a><a href='/admin'>x</a><a href='/secret'>s</a>"},
			"/about":     {"text/html", "<title>about</title>"},
			"/app.js":    {"application/javascript", "fetch('/api/items');"},
			"/logo.png":  {"image/png", "\x89PNG\r\n\x1a\n"},
			"/api/users": {"application/json", `[{"id":1}]`},
			"/api/items": {"application/json", `[{"id":2}]`},
		}
		code, ctype, body := 404, "text/plain", ""
		if p, ok := pages[r.URL.Path]; ok {
			code, ctype, body = 200, p[0], p[1]
		}
		switch r.URL.Path {
		case "/admin":
			code = 401
		case "/secret":
			code = 403
		}
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	_, rep, _ := runContract(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover",
		"-no-paths", "-no-favicon", "-no-tech", "-db", "a.db")
	sum := 0
	for _, n := range rep.Counts {
		sum += n
	}
	if sum != rep.Stored || rep.Stored != rep.Results {
		t.Errorf("counts add up to %d, stored %d, results %d (no row folds here): %v", sum, rep.Stored, rep.Results, rep.Counts)
	}
	filters := map[string][]string{
		"pages":     {"-type", "URL", "-role", "page,app"},
		"api":       {"-type", "URL", "-role", "api"},
		"auth":      {"-type", "URL", "-role", "auth"},
		"forbidden": {"-type", "URL", "-role", "forbidden"},
		"scripts":   {"-type", "URL", "-role", "script"},
		"assets":    {"-type", "URL", "-role", "asset"},
	}
	for key, want := range map[string]int{"pages": 2, "api": 2, "auth": 1, "forbidden": 1, "scripts": 1, "assets": 1} {
		if rep.Counts[key] != want {
			t.Errorf("counts[%q] = %d, want %d: %v", key, rep.Counts[key], want, rep.Counts)
		}
		out, _, err := captureBoth(t, func() error { return run(append([]string{"query", "-db", "a.db", "-json"}, filters[key]...)) })
		if err != nil {
			t.Fatal(err)
		}
		if got := len(lines(out)); got != rep.Counts[key] {
			t.Errorf("%s: the summary counts %d, query %v lists %d", key, rep.Counts[key], filters[key], got)
		}
	}
	// query -type URL lists every URL row: the counts of URLs add up to it.
	out, _, _ := captureBoth(t, func() error { return run([]string{"query", "-db", "a.db", "-json", "-type", "URL"}) })
	urls := 0
	for k, n := range rep.Counts {
		switch k {
		case "pages", "api", "auth", "forbidden", "scripts", "assets", "client routes", "websockets", "source maps", "manifests":
			urls += n
		}
	}
	if got := len(lines(out)); got != urls {
		t.Errorf("query -type URL lists %d rows, the URL counts add up to %d: %v", got, urls, rep.Counts)
	}
}

// Every kind of row has a count, dead and wildcard names included, and a
// map whose templated rows fold says how many stored rows it holds.
func TestCountsCoverEveryKindOfRow(t *testing.T) {
	ent := func(typ types.SeedType, key string) types.Entity { return types.Entity{Type: typ, Key: key} }
	rows := []engine.MapEntry{
		{Entity: ent(types.TypeURL, "http://a.test/"), Role: "app"},
		{Entity: ent(types.TypeURL, "http://a.test/x"), Role: "page"},
		{Entity: ent(types.TypeURL, "http://a.test/api/u"), Role: "api"},
		{Entity: ent(types.TypeURL, "http://a.test/admin"), Role: "auth"},
		{Entity: ent(types.TypeURL, "http://a.test/s"), Role: "forbidden"},
		{Entity: ent(types.TypeURL, "http://a.test/a.js"), Role: "script"},
		{Entity: ent(types.TypeURL, "http://a.test/a.js.map"), Role: "sourcemap"},
		{Entity: ent(types.TypeURL, "http://a.test/manifest.json"), Role: "manifest"},
		{Entity: ent(types.TypeURL, "http://a.test/logo.png"), Role: "asset"},
		{Entity: ent(types.TypeURL, "http://a.test/#/home"), Role: "client-route"},
		{Entity: ent(types.TypeURL, "ws://a.test/ws"), Role: "websocket"},
		{Entity: ent(types.TypeHostname, "www.a.test"), Role: "live"},
		{Entity: ent(types.TypeHostname, "old.a.test"), Role: "dead"},
		{Entity: ent(types.TypeHostname, "x.wild.a.test"), Role: "wildcard"},
		{Entity: ent(types.TypePort, "127.0.0.1:80/tcp"), State: "open"},
		{Entity: ent(types.TypePort, "127.0.0.1:53/udp"), State: "open|filtered"},
		{Entity: ent(types.TypeIPAddress, "127.0.0.1"), Role: "addr"},
		{Entity: ent(types.TypePrefix, "127.0.0.0/24")},
		{Entity: ent(types.TypeDomain, "a.test"), Role: "domain"},
		{Entity: ent(types.TypeCertificate, "abc")},
	}
	// Three URLs of one template fold into one row.
	for i := 1; i <= 3; i++ {
		rows = append(rows, engine.MapEntry{Entity: ent(types.TypeURL, fmt.Sprintf("http://a.test/item/%d", i)), Role: "page", Template: "http://a.test/item/{n}"})
	}
	rep := newReport("run")
	fillReport(rep, "", nil, nil, nil, rows)
	sum := 0
	for k, n := range rep.Counts {
		sum += n
		if n < 1 {
			t.Errorf("count %q is %d", k, n)
		}
	}
	if sum != len(rows) || rep.Stored != len(rows) {
		t.Errorf("counts add up to %d, stored %d, rows %d: %v", sum, rep.Stored, len(rows), rep.Counts)
	}
	if rep.Counts["pages"] != 5 || rep.Counts["dead hostnames"] != 1 || rep.Counts["wildcard hostnames"] != 1 || rep.Counts["hostnames"] != 1 {
		t.Errorf("counts %v", rep.Counts)
	}
	if want := len(rows) - rep.Results; want != 2 {
		t.Errorf("3 templated URLs fold into 1 row: %d stored, %d results", rep.Stored, rep.Results)
	}
	var sb strings.Builder
	rep.print(&sb)
	if !strings.Contains(sb.String(), "stored:") || !strings.Contains(sb.String(), "2 folded into templated rows") {
		t.Errorf("the text summary does not say what is folded:\n%s", sb.String())
	}
}
