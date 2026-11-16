package detect

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

var updatePins = flag.Bool("update-pins", false, "rewrite testdata/pins.golden.gz")

// pinResponses are the answers every path of the embedded data is asked
// with, so that a change of how matching is done cannot change what it names:
// a catch-all page, the same page carrying many products' words, a JSON
// 404, a Grafana login page, and for each path a page of its own units'
// words.
func pinResponses(d *Data) (shared map[string]Response, perPath map[string]Response) {
	words := map[string][]string{} // request path -> positive words of its units
	var all []string
	for _, u := range d.Units {
		for _, m := range u.Matchers {
			if m.Type != "word" || m.Neg || len(m.Vals) == 0 || m.Part != "" {
				continue
			}
			w := m.Vals
			if !m.And {
				w = w[:1]
			}
			for _, p := range u.Paths {
				words[requestPath(p)] = append(words[requestPath(p)], w...)
			}
			if len(all) < 4000 {
				all = append(all, w...)
			}
		}
	}
	spa := string(page(50 << 10))
	html := http.Header{"Content-Type": {"text/html; charset=utf-8"}, "Server": {"nginx/1.24.0"}}
	shared = map[string]Response{
		"spa":  {Status: 200, Header: html, Body: []byte(spa)},
		"soup": {Status: 200, Header: html, Body: []byte(spa + strings.Join(all, " "))},
		"json404": {Status: 404, Header: http.Header{"Content-Type": {"application/json"}},
			Body: []byte(`{"error":"not found"}`)},
		"grafana": {Status: 200, Header: html, Body: []byte(`<!DOCTYPE html><html><head><title>Grafana</title></head><body>` +
			`<script>window.grafanaBootData = {"settings":{"buildInfo":{"version":"10.2.3"}}}</script>` +
			`<div class="login">Welcome to Grafana</div>{"subTitle":"Grafana v10.2.3 (abc)"}</body></html>`)},
	}
	perPath = map[string]Response{}
	for p, w := range words {
		perPath[p] = Response{Status: 200, Header: html, Body: []byte("<html><title>x</title>" + strings.Join(w, " ") + "</html>")}
	}
	return shared, perPath
}

// pinLines renders what Match names for each pin, one line per answer and
// path that named anything.
func pinLines(match func(Response) []Hit, d *Data) []string {
	shared, perPath := pinResponses(d)
	idx := build(d)
	paths := append([]string{"/"}, sortedPaths(idx)...)
	var lines []string
	add := func(name, path string, r Response) {
		r.Path = path
		hits := match(r)
		for _, h := range hits {
			lines = append(lines, fmt.Sprintf("%s %s | %s | %s | %s | %s | %s | %v", name, path, h.Product, h.Version, h.Template, h.Matcher, h.Extracted, h.Many))
		}
		if again := match(r); fmt.Sprint(again) != fmt.Sprint(hits) { // served from what the first left behind
			lines = append(lines, fmt.Sprintf("%s %s: asked twice, answered differently: %v then %v", name, path, hits, again))
		}
	}
	names := make([]string, 0, len(shared))
	for n := range shared {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, p := range paths {
		for _, n := range names {
			add(n, p, shared[n])
		}
		if r, ok := perPath[p]; ok {
			add("own", p, r)
		}
	}
	return lines
}

func sortedPaths(idx *index) []string { return idx.paths() }

// TestPinnedDetections pins what the embedded templates name for fixed
// answers on every path they ask: the file was written by the code before
// the product checks were made cheaper.
func TestPinnedDetections(t *testing.T) {
	var d Data
	decode(&d)
	idx := build(&d)
	got := pinLines(idx.match, &d)
	text := strings.Join(got, "\n") + "\n"
	const file = "testdata/pins.golden.gz"
	if *updatePins {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(text))
		_ = zw.Close()
		if err := os.WriteFile(file, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	zipped, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != text {
		wl, gl := strings.Split(string(want), "\n"), strings.Split(text, "\n")
		for i := 0; i < max(len(wl), len(gl)); i++ {
			var a, b string
			if i < len(wl) {
				a = wl[i]
			}
			if i < len(gl) {
				b = gl[i]
			}
			if a != b {
				t.Fatalf("line %d differs (want %d lines, got %d)\nwant %.300s\ngot  %.300s", i+1, len(wl), len(gl), a, b)
			}
		}
	}
	if len(got) < 100 {
		t.Errorf("only %d pinned lines: the pins do not name much", len(got))
	}
	for _, must := range []string{"grafana /login | Grafana | 10.2.3 | grafana-detect", "own /login |", "soup / |"} {
		if !strings.Contains(text, must) {
			t.Errorf("pins lack %q", must)
		}
	}
}

// With the side index and its memo, matching equals matching without the
// literal prefilter, on every path of the real data.
func TestEmbeddedPrefilterEqualsDirectOnEveryPath(t *testing.T) {
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
	with := build(&d)
	a := strings.Join(pinLines(with.match, &d), "\n")
	b := strings.Join(pinLines(without.match, &d), "\n")
	if a != b {
		al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
		for i := 0; i < min(len(al), len(bl)); i++ {
			if al[i] != bl[i] {
				t.Fatalf("line %d: with prefilter\n%.300s\ndirect\n%.300s", i, al[i], bl[i])
			}
		}
		t.Fatalf("with prefilter %d lines, direct %d", len(al), len(bl))
	}
}

// Many goroutines matching one page on many paths (what the product checks
// do) get what one goroutine gets.
func TestSharedScanIsConcurrencySafe(t *testing.T) {
	var d Data
	decode(&d)
	idx := build(&d)
	shared, perPath := pinResponses(&d)
	paths := idx.paths()
	want := map[string]string{}
	for _, p := range paths {
		r := shared["soup"]
		r.Path = p
		want[p] = fmt.Sprint(idx.match(r))
	}
	other := shared["spa"]
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, p := range paths {
				r := shared["soup"]
				r.Path = p
				if i%3 == 0 { // another page between, so the memo turns over
					o := other
					o.Path = p
					idx.match(o)
				}
				if got := fmt.Sprint(idx.match(r)); got != want[p] {
					errs <- fmt.Sprintf("%s: %s, want %s", p, got, want[p])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if e, ok := <-errs; ok {
		t.Fatal(e)
	}
	_ = perPath
}
