package detect

import (
	"net/http"
	"strings"
	"testing"
)

// testIndex prepares the matchers of the units and indexes them.
func testIndex(t *testing.T, units ...Unit) *index {
	t.Helper()
	d := &Data{Version: 1}
	for _, u := range units {
		for i := range u.Matchers {
			if err := Prepare(&u.Matchers[i]); err != nil {
				t.Fatalf("%s matcher %d: %v", u.ID, i, err)
			}
		}
		for i := range u.Extractors {
			if err := PrepareExtractor(&u.Extractors[i]); err != nil {
				t.Fatalf("%s extractor %d: %v", u.ID, i, err)
			}
		}
		if len(u.Paths) == 0 {
			u.Paths = []string{"/"}
		}
		d.Units = append(d.Units, u)
	}
	return build(d)
}

func word(vals ...string) Matcher { return Matcher{Type: "word", Vals: vals} }

func resp(body string, hdr ...string) Response {
	h := http.Header{}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Add(hdr[i], hdr[i+1])
	}
	return Response{Path: "/", Status: 200, Header: h, Body: []byte(body)}
}

func hitIDs(hits []Hit) string {
	var ids []string
	for _, h := range hits {
		ids = append(ids, h.Template)
	}
	return strings.Join(ids, ",")
}

func TestMatchersConditionOrAnd(t *testing.T) {
	idx := testIndex(t,
		Unit{ID: "or", Product: "Or", Matchers: []Matcher{word("alpha-marker"), word("beta-marker")}},
		Unit{ID: "and", Product: "And", And: true, Matchers: []Matcher{word("alpha-marker"), word("beta-marker")}},
	)
	for body, want := range map[string]string{
		"alpha-marker":             "or",
		"beta-marker":              "or",
		"alpha-marker beta-marker": "or,and",
		"nothing here":             "",
	} {
		if got := hitIDs(idx.match(resp(body))); got != want {
			t.Errorf("%q hits = %q, want %q", body, got, want)
		}
	}
}

func TestMatcherCondition(t *testing.T) {
	and := word("alpha-marker", "beta-marker")
	and.And = true
	or := word("alpha-marker", "beta-marker")
	idx := testIndex(t,
		Unit{ID: "wand", Matchers: []Matcher{and}},
		Unit{ID: "wor", Matchers: []Matcher{or}},
	)
	if got := hitIDs(idx.match(resp("alpha-marker"))); got != "wor" {
		t.Errorf("one word: %q", got)
	}
	if got := hitIDs(idx.match(resp("alpha-marker beta-marker"))); got != "wand,wor" {
		t.Errorf("both words: %q", got)
	}
}

func TestNegativeAndCaseInsensitive(t *testing.T) {
	neg := word("forbidden-marker")
	neg.Neg = true
	ci := word("MiXeD-Marker")
	ci.CI = true
	cs := word("MiXeD-Marker")
	rci := Matcher{Type: "regex", Vals: []string{"mixed-[a-z]+"}, CI: true}
	idx := testIndex(t,
		Unit{ID: "neg", And: true, Matchers: []Matcher{word("ok-marker"), neg}},
		Unit{ID: "ci", Matchers: []Matcher{ci}},
		Unit{ID: "cs", Matchers: []Matcher{cs}},
		Unit{ID: "rci", Matchers: []Matcher{rci}},
	)
	if got := hitIDs(idx.match(resp("ok-marker"))); got != "neg" {
		t.Errorf("negative absent: %q", got)
	}
	if got := hitIDs(idx.match(resp("ok-marker forbidden-marker"))); got != "" {
		t.Errorf("negative present: %q", got)
	}
	if got := hitIDs(idx.match(resp("mixed-marker"))); got != "ci,rci" {
		t.Errorf("case-insensitive: %q", got)
	}
	if got := hitIDs(idx.match(resp("MiXeD-Marker"))); got != "ci,cs,rci" {
		t.Errorf("exact case: %q", got)
	}
}

func TestParts(t *testing.T) {
	in := func(part string, vals ...string) Unit {
		m := word(vals...)
		m.Part = part
		return Unit{ID: "p-" + part + "/" + vals[0], Matchers: []Matcher{m}}
	}
	idx := testIndex(t,
		in(partHeaders, "X-Token: abc123"),
		in(partResponse, "X-Token: abc123\r\n\r\n<b>body-mark"),
		in(partBody, "body-mark"),
		in(partHeader+"Server", "nginx"),
		in(partHeader+"Content-Type", "text/html"),
		in(partHeader+"Set-Cookie", "session=1"),
		in(partBody, "X-Token"),
	)
	r := resp("<b>body-mark", "X-Token", "abc123", "Alpha", "1", "Server", "nginx/1.31.8",
		"Content-Type", "text/html; charset=utf-8", "Set-Cookie", "session=1")
	want := "p-headers/X-Token: abc123,p-response/X-Token: abc123\r\n\r\n<b>body-mark,p-/body-mark,p-header:Server/nginx,p-header:Content-Type/text/html,p-header:Set-Cookie/session=1"
	if got := hitIDs(idx.match(r)); got != want {
		t.Errorf("hits = %q\nwant   %q", got, want)
	}
	// A header word must not match the body, nor a body word the headers.
	if got := hitIDs(idx.match(resp("X-Token: abc123"))); got != "p-/X-Token" {
		t.Errorf("header word matched the body: %q", got)
	}
}

func TestNormalizePart(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "body": "", "BODY": "", "header": partHeaders, "all_headers": partHeaders,
		"response": partResponse, "all": partResponse,
		"server": "header:Server", "content_type": "header:Content-Type", "set_cookie": "header:Set-Cookie",
	} {
		got, ok := NormalizePart(in)
		if !ok || got != want {
			t.Errorf("NormalizePart(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"body_1", "title", "interactsh_request", "x_unknown"} {
		if _, ok := NormalizePart(bad); ok {
			t.Errorf("NormalizePart(%q) accepted", bad)
		}
	}
}

func TestStatusMatcher(t *testing.T) {
	st := Matcher{Type: "status", Status: []int{200, 403}}
	idx := testIndex(t, Unit{ID: "s", And: true, Matchers: []Matcher{word("marker-here"), st}})
	r := resp("marker-here")
	for status, want := range map[int]string{200: "s", 403: "s", 404: "", 500: ""} {
		r.Status = status
		if got := hitIDs(idx.match(r)); got != want {
			t.Errorf("status %d: %q, want %q", status, got, want)
		}
	}
}

func TestPathSelection(t *testing.T) {
	idx := testIndex(t,
		Unit{ID: "root", Matchers: []Matcher{word("root-marker")}},
		Unit{ID: "deep", Paths: []string{"/a/b", "/c"}, Matchers: []Matcher{word("root-marker")}},
	)
	if got := hitIDs(idx.match(Response{Path: "", Status: 200, Body: []byte("root-marker")})); got != "root" {
		t.Errorf("empty path is the root: %q", got)
	}
	for _, p := range []string{"/a/b", "/c"} {
		if got := hitIDs(idx.match(Response{Path: p, Status: 200, Body: []byte("root-marker")})); got != "deep" {
			t.Errorf("%s: %q", p, got)
		}
	}
	if got := idx.match(Response{Path: "/other", Status: 200, Body: []byte("root-marker")}); got != nil {
		t.Errorf("unknown path: %v", got)
	}
	if got := strings.Join(idx.paths(), " "); got != "/a/b /c" {
		t.Errorf("paths = %q", got)
	}
}

func TestMatcherNamesAreProducts(t *testing.T) {
	var ms []Matcher
	for _, n := range []string{"alpha-one", "beta_two", "gamma", "delta", "epsilon"} {
		m := word(n + "-marker")
		m.Name = n
		ms = append(ms, m)
	}
	dup := word("alpha-other")
	dup.Name = "alpha-one"
	ms = append(ms, dup)
	idx := testIndex(t,
		Unit{ID: "shared", Product: "Shared Technology", Multi: true, Matchers: ms},
		Unit{ID: "single", Product: "Single", Matchers: []Matcher{ms[0], ms[1]}},
	)
	hits := idx.match(resp("alpha-one-marker alpha-other beta_two-marker"))
	var got []string
	for _, h := range hits {
		got = append(got, h.Template+":"+h.Product+":"+h.Matcher)
	}
	want := "shared:alpha one:alpha-one,shared:beta two:beta_two,single:Single:alpha-one"
	if strings.Join(got, ",") != want {
		t.Errorf("hits = %v\nwant   %s", got, want)
	}
}

func TestExtractors(t *testing.T) {
	idx := testIndex(t,
		Unit{ID: "rx", Product: "Rx", Matchers: []Matcher{word("rx-marker")}, Extractors: []Extractor{
			{Type: "regex", Vals: []string{`nomatch-([0-9]+)`, `rx-marker v([0-9.]+)-beta`}, Group: 1},
		}},
		Unit{ID: "hdr", Product: "Hdr", Matchers: []Matcher{word("rx-marker")}, Extractors: []Extractor{
			{Type: "regex", Part: partHeaders, Vals: []string{`nginx/[0-9.]+`}},
		}},
		Unit{ID: "kv", Product: "Kv", Matchers: []Matcher{word("rx-marker")}, Extractors: []Extractor{
			{Type: "kval", Vals: []string{"x_missing", "X_Jenkins"}},
		}},
		Unit{ID: "none", Product: "None", Matchers: []Matcher{word("rx-marker")}, Extractors: []Extractor{
			{Type: "regex", Vals: []string{`absent-([0-9]+)`}, Group: 1},
		}},
		Unit{ID: "whole", Product: "Whole", Matchers: []Matcher{word("rx-marker")}, Extractors: []Extractor{
			{Type: "regex", Vals: []string{`v[0-9.]+-beta`}},
		}},
	)
	r := resp("rx-marker v2.40.1-beta", "Server", "nginx/1.31.8", "X-Jenkins", "2.452.1")
	got := map[string][2]string{}
	for _, h := range idx.match(r) {
		got[h.Template] = [2]string{h.Extracted, h.Version}
	}
	want := map[string][2]string{
		"rx":    {"2.40.1", "2.40.1"},
		"hdr":   {"nginx/1.31.8", "1.31.8"},
		"kv":    {"2.452.1", "2.452.1"},
		"none":  {"", ""},
		"whole": {"v2.40.1-beta", "2.40.1-beta"},
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: extracted/version = %q, want %q", id, got[id], w)
		}
	}
}

func TestVersionOf(t *testing.T) {
	for in, want := range map[string]string{
		"nginx/1.31.8":      "1.31.8",
		"Apache/2.4.58 (Un": "2.4.58",
		"v10.5.2-rc1":       "10.5.2-rc1",
		"4":                 "",
		"":                  "",
		"build 3.1_beta+x":  "3.1_beta",
	} {
		if got := versionOf(in); got != want {
			t.Errorf("versionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDSLMatcherAndFavicon(t *testing.T) {
	icon := make([]byte, 300)
	for i := range icon {
		icon[i] = byte(i * 7)
	}
	idx := testIndex(t,
		Unit{ID: "fav", Product: "Fav", Paths: []string{"/favicon.ico"}, Multi: false, Matchers: []Matcher{
			{Type: "dsl", Name: "acme", Vals: []string{`status_code==200 && ("1507977274" == mmh3(base64_py(body)))`}},
		}},
		Unit{ID: "dslw", Product: "Dslw", Matchers: []Matcher{
			{Type: "dsl", And: true, Vals: []string{`regex("/plugins/elementor/", body)`, `status_code == 200`}},
		}},
	)
	if got := hitIDs(idx.match(Response{Path: "/favicon.ico", Status: 200, Body: icon})); got != "fav" {
		t.Errorf("favicon: %q", got)
	}
	if got := hitIDs(idx.match(Response{Path: "/favicon.ico", Status: 404, Body: icon})); got != "" {
		t.Errorf("favicon with 404: %q", got)
	}
	if got := hitIDs(idx.match(resp(`<link href="/wp-content/plugins/elementor/x.css">`))); got != "dslw" {
		t.Errorf("dsl and: %q", got)
	}
	r := resp(`<link href="/wp-content/plugins/elementor/x.css">`)
	r.Status = 404
	if got := hitIDs(idx.match(r)); got != "" {
		t.Errorf("dsl and with 404: %q", got)
	}
}

func TestPrepare(t *testing.T) {
	m := Matcher{Type: "regex", Vals: []string{`(?i)<title>[^<]*grafana[^<]*</title>`}}
	if err := Prepare(&m); err != nil || len(m.Lits) != 1 || strings.Join(m.Lits[0], "|") != "</title>|<title>|grafana" && strings.Join(m.Lits[0], "|") != "<title>|grafana|</title>" {
		t.Errorf("regex cover = %v, %v", m.Lits, err)
	}
	for _, bad := range []Matcher{
		{Type: "regex", Vals: []string{"("}},
		{Type: "dsl", Vals: []string{"compare_versions(version, '<1')"}},
		{Type: "xpath", Vals: []string{"/a"}},
		{Type: "word"},
	} {
		if err := Prepare(&bad); err == nil {
			t.Errorf("Prepare accepted %+v", bad)
		}
	}
	neg := Matcher{Type: "word", Vals: []string{"abcdef"}, Neg: true}
	if err := Prepare(&neg); err != nil || neg.Lits != nil {
		t.Errorf("a negative matcher must not be prefiltered: %v %v", neg.Lits, err)
	}
	short := Matcher{Type: "word", Vals: []string{"ab"}}
	if err := Prepare(&short); err != nil || short.Lits != nil {
		t.Errorf("a two-byte needle must not prefilter: %v %v", short.Lits, err)
	}
}

// The prefilter may only skip work: matching with it equals matching without.
func TestPrefilterEqualsDirect(t *testing.T) {
	units := []Unit{
		{ID: "w", Matchers: []Matcher{word("Alpha-Marker", "beta-marker")}},
		{ID: "r", Matchers: []Matcher{{Type: "regex", Vals: []string{`foo(?:bar|baz)+[0-9]{2}qux`, `zzz-[a-z]+-end`}}}},
		{ID: "d", And: true, Matchers: []Matcher{{Type: "dsl", Vals: []string{`contains_any(to_lower(body), "gamma-mark", "delta-mark") && !contains(body, "veto-mark")`}}, {Type: "status", Status: []int{200}}}},
		{ID: "n", Matchers: []Matcher{{Type: "word", Vals: []string{"neg-marker"}, Neg: true}}},
		{ID: "ci", Matchers: []Matcher{{Type: "word", Vals: []string{"Case-Marker"}, CI: true}}},
	}
	with := testIndex(t, units...)
	d := &Data{Version: 1}
	for _, u := range units {
		u.Paths = []string{"/"}
		ms := make([]Matcher, len(u.Matchers))
		copy(ms, u.Matchers)
		for i := range ms {
			ms[i].Lits = nil
		}
		u.Matchers = ms
		d.Units = append(d.Units, u)
	}
	without := build(d)
	for _, body := range []string{
		"", "alpha-marker", "Alpha-Marker", "beta-marker", "foobarbaz12qux", "foobar1qux", "zzz-abc-end",
		"gamma-mark", "DELTA-MARK", "gamma-mark veto-mark", "neg-marker", "case-marker CASE-MARKER", "plain",
	} {
		a, b := hitIDs(with.match(resp(body))), hitIDs(without.match(resp(body)))
		if a != b {
			t.Errorf("%q: with prefilter %q, direct %q", body, a, b)
		}
	}
}

func TestAhoOverlaps(t *testing.T) {
	b := newACBuilder()
	for i, n := range []string{"he", "she", "his", "hers", "\xe2\x82\xac"} {
		b.add(n, int32(i))
	}
	a := b.build()
	hit := func(text string) map[int32]bool {
		got := map[int32]bool{}
		a.scan(text, func(id int32) { got[id] = true })
		return got
	}
	if g := hit("ushers"); !g[0] || !g[1] || g[2] || !g[3] || g[4] {
		t.Errorf("ushers: %v", g)
	}
	if g := hit("his"); g[0] || g[1] || !g[2] || g[3] {
		t.Errorf("his: %v", g)
	}
	if g := hit("price: 5 \xe2\x82\xac"); !g[4] {
		t.Errorf("multibyte needle: %v", g)
	}
}

func TestAhoDeepNeedles(t *testing.T) {
	// Needles deeper than the dense table exercise the sparse edges and
	// failure links.
	needles := []string{"/plugins/elementor/", "/plugins/elementor-pro/", "/plugins/woocommerce/", "ugins/wo", "s/elem"}
	b := newACBuilder()
	for i, n := range needles {
		b.add(n, int32(i))
	}
	a := b.build()
	got := map[int32]bool{}
	a.scan("xx/plugins/elementor-pro/yy /plugins/wooc", func(id int32) { got[id] = true })
	want := map[int32]bool{1: true, 3: true, 4: true}
	for i := range needles {
		if got[int32(i)] != want[int32(i)] {
			t.Errorf("needle %q found=%v want=%v", needles[i], got[int32(i)], want[int32(i)])
		}
	}
}

func TestMatchIsConcurrencySafe(t *testing.T) {
	idx := testIndex(t,
		Unit{ID: "w", Matchers: []Matcher{word("alpha-marker")}},
		Unit{ID: "r", Matchers: []Matcher{{Type: "regex", Vals: []string{`beta-[0-9]+-marker`}}}},
		Unit{ID: "d", Matchers: []Matcher{{Type: "dsl", Vals: []string{`contains(to_lower(body), "gamma-marker")`}}}},
	)
	done := make(chan string, 8)
	for i := 0; i < 8; i++ {
		go func() {
			var last string
			for j := 0; j < 200; j++ {
				last = hitIDs(idx.match(resp("alpha-marker beta-12-marker GAMMA-MARKER")))
			}
			done <- last
		}()
	}
	for i := 0; i < 8; i++ {
		if got := <-done; got != "w,r,d" {
			t.Errorf("hits = %q", got)
		}
	}
}

// A fragment is not sent: a template asking "/#/login" is matched on the root.
func TestRequestPathDropsTheFragment(t *testing.T) {
	for in, want := range map[string]string{"/#/login": "/", "/#!/auth": "/", "/a#b": "/a", "/x?y=1": "/x?y=1", "": "/"} {
		if got := requestPath(in); got != want {
			t.Errorf("requestPath(%q) = %q, want %q", in, got, want)
		}
	}
	for _, p := range Paths() {
		if strings.Contains(p, "#") {
			t.Fatalf("Paths() holds %q", p)
		}
	}
}
