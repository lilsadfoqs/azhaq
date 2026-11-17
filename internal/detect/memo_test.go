package detect

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// productChecks are the answers a catch-all server gives to every path the
// templates ask: one 50 KB page, with headers that vary by answer.
func productChecks(idx *index, hdr func(i int) http.Header) []Response {
	body := page(50 << 10)
	paths := idx.paths()
	out := make([]Response, len(paths))
	for i, p := range paths {
		out[i] = Response{Path: p, Status: 200, Header: hdr(i), Body: body}
	}
	return out
}

var headerVariants = map[string]func(i int) http.Header{
	"same": func(int) http.Header {
		return http.Header{"Content-Type": {"text/html"}, "Server": {"nginx/1.24.0"}}
	},
	// Date moves on every second; about a hundred answers a second.
	"date": func(i int) http.Header {
		return http.Header{"Content-Type": {"text/html"}, "Server": {"nginx/1.24.0"},
			"Date": {fmt.Sprintf("Mon, 16 Nov 2026 10:00:%02d GMT", i/100%60)}}
	},
	"reqid": func(i int) http.Header {
		return http.Header{"Content-Type": {"text/html"}, "Server": {"nginx/1.24.0"},
			"Date":         {fmt.Sprintf("Mon, 16 Nov 2026 10:00:%02d GMT", i/100%60)},
			"X-Request-Id": {fmt.Sprintf("req-%08d", i)}}
	},
}

func BenchmarkProductChecks(b *testing.B) {
	var d Data
	decode(&d)
	idx := build(&d)
	for _, name := range []string{"same", "date", "reqid"} {
		rs := productChecks(idx, headerVariants[name])
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				idx.memo.hit.Store(0)
				idx.memo.miss.Store(0)
				idx.memo = scanMemo{}
				for _, r := range rs {
					idx.match(r)
				}
			}
			b.ReportMetric(float64(len(rs)), "answers/op")
			b.ReportMetric(float64(idx.memo.hit.Load()), "memo-hits/op")
			b.ReportMetric(float64(idx.memo.miss.Load()), "memo-misses/op")
		})
	}
}

func hitText(hits []Hit) string { return fmt.Sprintf("%+v", hits) }

// Headers that change on every answer neither change what is named nor
// defeat the memo: the body is scanned once.
func TestMemoIgnoresHeaders(t *testing.T) {
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
	with, direct := build(&d), build(&stripped)
	shared, _ := pinResponses(&d)
	named := 0
	for _, name := range []string{"same", "date", "reqid"} {
		for _, page := range []string{"spa", "soup"} {
			with.memo = scanMemo{}
			n := 0
			for i, p := range with.paths() {
				r := shared[page]
				r.Path, r.Header = p, headerVariants[name](i)
				a, b := hitText(with.match(r)), hitText(direct.match(r))
				if a != b {
					t.Fatalf("%s/%s %s: memoised\n%.300s\ndirect\n%.300s", name, page, p, a, b)
				}
				if a != "[]" {
					named++
				}
				n++
			}
			if miss := with.memo.miss.Load(); miss > 2 {
				t.Errorf("%s/%s: %d answers scanned the body %d times", name, page, n, miss)
			}
			if hit := with.memo.hit.Load(); hit < int64(n)-int64(n)/20 {
				t.Errorf("%s/%s: only %d of %d answers hit the memo", name, page, hit, n)
			}
		}
	}
	if named == 0 {
		t.Error("no answer named anything: the comparison proves nothing")
	}
}

// A needle that only the headers hold is found whatever the other headers
// say, and one that reads across the blank line between headers and body is
// not lost by scanning them apart.
func TestSideScansHeadersAndBoundary(t *testing.T) {
	pad := strings.Repeat("<p>filler text</p>", 100)
	units := []Unit{
		{ID: "hdr", Paths: []string{"/x"}, Matchers: []Matcher{{Type: "word", CI: true, Part: "headers", Vals: []string{"x-powered-by: zz-engine"}}}},
		{ID: "cross", Paths: []string{"/x"}, Matchers: []Matcher{{Type: "word", CI: true, Part: "response", Vals: []string{"end-of-head\r\n\r\nstart-of-body"}}}},
		{ID: "lf", Paths: []string{"/x"}, Matchers: []Matcher{{Type: "word", CI: true, Part: "response", Vals: []string{"\n<start-lf-body"}}}},
	}
	with := testIndex(t, units...)
	if with.side.cross == 0 {
		t.Fatal("the needles that read across the blank line were not noticed")
	}
	d := &Data{Version: 1}
	for _, u := range units {
		u.Matchers = []Matcher{{Type: "word", CI: true, Part: u.Matchers[0].Part, Vals: u.Matchers[0].Vals}}
		d.Units = append(d.Units, u)
	}
	direct := build(d)
	for _, tc := range []struct {
		hdr  http.Header
		body string
		want string
	}{
		{http.Header{"X-Powered-By": {"zz-engine"}}, pad, "hdr"},
		{http.Header{"Z-Last": {"end-of-head"}}, "start-of-body" + pad, "cross"},
		{http.Header{"Z-Last": {"end-of-head"}}, "start-OF-body" + pad, "cross"},
		{http.Header{"Z-Last": {"end-of-head"}}, " start-of-body" + pad, ""},
		{http.Header{"X-Powered-By": {"zz-engine"}, "Z-Last": {"end-of-head"}}, "start-of-body" + pad, "hdr,cross"},
		{http.Header{}, "<start-lf-body" + pad, "lf"},
		{http.Header{"A": {"b"}}, "<start-lf-body" + pad, "lf"},
		{http.Header{"A": {"b"}}, " <start-lf-body" + pad, ""},
	} {
		for i := 0; i < 3; i++ { // the second and third answers hit the memo
			tc.hdr.Set("X-Request-Id", fmt.Sprint(i))
			r := Response{Path: "/x", Status: 200, Header: tc.hdr, Body: []byte(tc.body)}
			a, b := hitIDs(with.match(r)), hitIDs(direct.match(r))
			if a != b {
				t.Errorf("%v %.20q: prefiltered %q, direct %q", tc.hdr, tc.body, a, b)
			}
			if a != tc.want {
				t.Errorf("%v %.20q: named %q, want %q", tc.hdr, tc.body, a, tc.want)
			}
		}
	}
	if with.memo.hit.Load() == 0 {
		t.Error("the memo never hit")
	}
}

// A hash of the body that several paths ask for is worked out once for a
// page that answers them all, and an answer with another body is judged by
// its own.
func TestBodyHashIsKeptForTheBody(t *testing.T) {
	page := page(8 << 10)
	want := Mmh3String(base64Py(page))
	expr := "mmh3(base64_py(body)) == '" + want + "'"
	var units []Unit
	for _, p := range []string{"/a", "/b", "/c"} {
		units = append(units, Unit{ID: "icon" + p, Product: "Icon" + p, Paths: []string{p},
			Matchers: []Matcher{{Type: "dsl", Vals: []string{expr}}}})
	}
	idx := testIndex(t, units...)
	for i, p := range []string{"/a", "/b", "/c", "/a"} {
		hdr := http.Header{"X-Request-Id": {fmt.Sprint(i)}}
		if hits := idx.match(Response{Path: p, Status: 200, Header: hdr, Body: page}); len(hits) != 1 {
			t.Fatalf("%s: %d hits for the page whose hash it asks", p, len(hits))
		}
	}
	other := append(bytes.Clone(page), "<!-- another page -->"...)
	if hits := idx.match(Response{Path: "/a", Status: 200, Header: http.Header{}, Body: other}); len(hits) != 0 {
		t.Errorf("a page with another hash was named: %v", hits)
	}
	e := idx.memo.entry(page)
	if e == nil || len(e.vals) != 1 || e.vals["mmh3(base64_py(body))"].s != want {
		t.Errorf("the body's memo is %+v", e)
	}
}
