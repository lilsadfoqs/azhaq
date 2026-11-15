package detect

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadStats(t *testing.T) {
	s := Load()
	if s.Compiled < 2000 {
		t.Fatalf("compiled %d units, want at least 2000", s.Compiled)
	}
	sum := 0
	for reason, n := range s.Reasons {
		if reason == "" || n <= 0 {
			t.Errorf("bad skip reason %q: %d", reason, n)
		}
		sum += n
	}
	if sum != s.Skipped || s.Skipped == 0 {
		t.Errorf("skipped %d, reasons sum to %d", s.Skipped, sum)
	}
	s.Reasons["tampered"] = 1
	if _, ok := Load().Reasons["tampered"]; ok {
		t.Error("Load shares its reasons map")
	}
}

func TestEmbeddedPaths(t *testing.T) {
	ps := Paths()
	if len(ps) < 500 {
		t.Fatalf("only %d paths", len(ps))
	}
	seen := map[string]bool{}
	for i, p := range ps {
		if p == "/" || strings.Contains(p, "{{") || !strings.HasPrefix(p, "/") {
			t.Errorf("bad path %q", p)
		}
		if seen[p] || i > 0 && ps[i-1] > p {
			t.Errorf("paths are not unique and sorted at %q", p)
		}
		seen[p] = true
	}
	for _, want := range []string{"/login", "/solr/", "/favicon.ico"} {
		if !seen[want] {
			t.Errorf("missing path %s", want)
		}
	}
}

func find(hits []Hit, template string) (Hit, bool) {
	for _, h := range hits {
		if h.Template == template {
			return h, true
		}
	}
	return Hit{}, false
}

func TestRealisticGrafana(t *testing.T) {
	body := `<!DOCTYPE html><html><head><title>Grafana</title></head><body>` +
		`<script>window.grafanaBootData = {"settings":{"buildInfo":{"version":"10.2.3"}}}</script>` +
		`<div class="login">Welcome to Grafana</div></body></html>`
	for _, path := range []string{"/login", "/graph/login"} {
		hits := Match(Response{Path: path, Status: 200, Body: []byte(body)})
		h, ok := find(hits, "grafana-detect")
		if !ok {
			t.Fatalf("%s: no grafana-detect hit in %+v", path, hits)
		}
		if h.Product != "Grafana" {
			t.Errorf("%s: product %q", path, h.Product)
		}
	}
	// The extractor reads the version out of the page.
	body += ` {"subTitle":"Grafana v10.2.3 (abc)"}`
	h, _ := find(Match(Response{Path: "/login", Status: 200, Body: []byte(body)}), "grafana-detect")
	if h.Version != "10.2.3" {
		t.Errorf("version %q, extracted %q", h.Version, h.Extracted)
	}
	if hits := Match(Response{Path: "/login", Status: 200, Body: []byte("<title>Login</title>")}); len(hits) != 0 {
		if _, ok := find(hits, "grafana-detect"); ok {
			t.Error("grafana matched a page that is not Grafana")
		}
	}
}

func TestRealisticSolr(t *testing.T) {
	body := `<html><head><title>Solr Admin</title><link rel="icon" type="image/x-icon" href="img/favicon.ico?_=9.4.1"></head></html>`
	hits := Match(Response{Path: "/solr/", Status: 200, Body: []byte(body)})
	h, ok := find(hits, "solr-panel-exposure")
	if !ok {
		t.Fatalf("no solr hit in %+v", hits)
	}
	if !strings.Contains(h.Product, "Solr") || h.Version != "9.4.1" {
		t.Errorf("hit = %+v", h)
	}
}

func TestRealisticNginx(t *testing.T) {
	hits := Match(Response{Path: "/", Status: 200,
		Header: http.Header{"Server": {"nginx/1.31.8"}, "Content-Type": {"text/html"}},
		Body:   []byte("<html><body>hi</body></html>")})
	h, ok := find(hits, "nginx-version")
	if !ok {
		t.Fatalf("no nginx-version hit in %+v", hits)
	}
	if h.Product != "Nginx" || h.Version != "1.31.8" || h.Extracted != "nginx/1.31.8" {
		t.Errorf("hit = %+v", h)
	}
	if hits := Match(Response{Path: "/", Status: 404, Header: http.Header{"Server": {"nginx/1.31.8"}}}); func() bool { _, ok := find(hits, "nginx-version"); return ok }() {
		t.Error("nginx-version needs status 200")
	}
}

func TestRealisticMatcherNames(t *testing.T) {
	// tech-detect and the plugin list name products through matcher names.
	body := `<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.css">`
	hits := Match(Response{Path: "/", Status: 200, Body: []byte(body)})
	var found bool
	for _, h := range hits {
		if h.Template == "wordpress-plugin-detect" && h.Product == "elementor" && h.Matcher == "elementor" {
			found = true
		}
	}
	if !found {
		t.Errorf("elementor plugin not named: %+v", hits)
	}
}

func TestRealisticFavicon(t *testing.T) {
	// Any icon whose hash is in favicon-detect would do; the engine path is
	// the same as a hash that is not listed, which must not match.
	hits := Match(Response{Path: "/favicon.ico", Status: 200, Body: []byte("not an icon")})
	if len(hits) != 0 {
		t.Errorf("unlisted favicon matched: %+v", hits)
	}
}

// Matching with the literal prefilter must equal matching without it on the
// real data, for pages built from the needles themselves.
func TestEmbeddedPrefilterEqualsDirect(t *testing.T) {
	var d Data
	decode(&d)
	var stripped Data
	stripped.Units = make([]Unit, len(d.Units))
	for i, u := range d.Units {
		ms := make([]Matcher, len(u.Matchers))
		copy(ms, u.Matchers)
		for j := range ms {
			ms[j].Lits = nil
		}
		u.Matchers = ms
		stripped.Units[i] = u
	}
	without := build(&stripped)

	var bodies []string
	var picked []string
	for _, u := range d.Units {
		if len(u.Paths) == 0 || u.Paths[0] != "/" {
			continue
		}
		for j, m := range u.Matchers {
			if len(m.Lits) > 0 && (j+len(bodies))%29 == 0 && len(picked) < 600 {
				picked = append(picked, strings.Join(m.Lits[0], " "))
			}
		}
	}
	for i := 0; i+8 <= len(picked); i += 8 {
		bodies = append(bodies, "<html><title>x</title>"+strings.Join(picked[i:i+8], " ")+"</html>")
	}
	bodies = append(bodies, "", "<html></html>")
	for _, body := range bodies {
		r := Response{Path: "/", Status: 200, Header: http.Header{"Server": {"Apache/2.4.1"}}, Body: []byte(body)}
		a, b := fmt.Sprint(Match(r)), fmt.Sprint(without.match(r))
		if a != b {
			t.Fatalf("body %.120q: prefiltered hits differ from direct evaluation\n%.400s\n%.400s", body, a, b)
		}
	}
}

func TestLoadBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("budget check")
	}
	var d Data
	start := time.Now()
	decode(&d)
	idx := build(&d)
	took := time.Since(start)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if took > 1500*time.Millisecond && !raceEnabled {
		t.Errorf("load took %v, budget 1.5s", took)
	}
	if mb := ms.HeapAlloc >> 20; mb > 150 {
		t.Errorf("live heap %d MB, budget 150 MB", mb)
	}
	runtime.KeepAlive(idx)
}
