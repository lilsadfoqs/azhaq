package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/lilsadfoqs/azhaq/internal/detect"
)

const fixtures = "../../internal/detect/testdata"

func TestCompileFixtures(t *testing.T) {
	res, err := compileTree(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	units := map[string]detect.Unit{}
	for _, u := range res.data.Units {
		units[u.ID] = u
	}
	if len(units) != 4 {
		t.Fatalf("compiled %d units, want 4: %v", len(units), keys(units))
	}

	panel := units["acme-panel"]
	if panel.Product != "Acme Control" || !panel.And || strings.Join(panel.Paths, " ") != "/acme/login /acme/" {
		t.Errorf("acme-panel = %+v", panel)
	}
	if len(panel.Matchers) != 2 || panel.Matchers[0].Type != "word" || len(panel.Matchers[0].Lits) != 1 ||
		panel.Matchers[1].Type != "status" || panel.Matchers[1].Status[0] != 200 {
		t.Errorf("acme-panel matchers = %+v", panel.Matchers)
	}
	if len(panel.Extractors) != 1 || panel.Extractors[0].Group != 1 {
		t.Errorf("acme-panel extractors = %+v", panel.Extractors)
	}

	widget := units["widget-detect"]
	if widget.Product != "Widget" || strings.Join(widget.Paths, " ") != "/" || widget.Matchers[0].Type != "dsl" || !widget.Matchers[0].And {
		t.Errorf("widget-detect = %+v", widget)
	}
	if got := widget.Matchers[0].Lits; len(got) != 1 || strings.Join(got[0], "|") != "</title>|<title>|widget" && strings.Join(got[0], "|") != "<title>|widget|</title>" {
		t.Errorf("widget-detect prefilter = %v", got)
	}

	fav := units["acme-favicon"]
	if fav.Paths[0] != "/favicon.ico" || !strings.Contains(fav.Matchers[0].Vals[0], "mmh3(base64_py(body))") {
		t.Errorf("acme-favicon = %+v", fav)
	}

	shared := units["shared-detect"]
	if !shared.Multi || len(shared.Matchers) != 5 || shared.Matchers[3].Part != "headers" || !shared.Matchers[4].CI {
		t.Errorf("shared-detect = %+v", shared)
	}

	want := map[string]int{"dsl function compare_versions": 1, "raw request": 1}
	for r, n := range want {
		if res.data.Skipped[r] != n {
			t.Errorf("skipped[%q] = %d, want %d (all: %v)", r, res.data.Skipped[r], n, res.data.Skipped)
		}
	}
	if total(res.data.Skipped) != 2 || res.templates != 4 {
		t.Errorf("skipped %v, templates %d", res.data.Skipped, res.templates)
	}
}

func keys(m map[string]detect.Unit) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRunIsDeterministic(t *testing.T) {
	read := func(dir string) map[string][]byte {
		out := map[string][]byte{}
		for _, name := range []string{"templates.json.gz", "SOURCE.md", "LICENSE.md"} {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			out[name] = b
		}
		return out
	}
	a, b := t.TempDir(), t.TempDir()
	for _, dir := range []string{a, b} {
		if err := run(fixtures, dir, "v0.0.1", "abc123"); err != nil {
			t.Fatal(err)
		}
	}
	ra, rb := read(a), read(b)
	for name := range ra {
		if !bytes.Equal(ra[name], rb[name]) {
			t.Errorf("%s differs between runs", name)
		}
	}
	src := string(ra["SOURCE.md"])
	for _, want := range []string{"v0.0.1", "abc123", "Compiled: 4 requests", "Skipped: 2", "raw request: 1", "dsl function compare_versions: 1", "go run ./scripts/detectgen"} {
		if !strings.Contains(src, want) {
			t.Errorf("SOURCE.md lacks %q:\n%s", want, src)
		}
	}
	if !bytes.Contains(ra["LICENSE.md"], []byte("MIT")) {
		t.Error("LICENSE.md is not the source license")
	}
	zr, err := gzip.NewReader(bytes.NewReader(ra["templates.json.gz"]))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	var d detect.Data
	if err := json.Unmarshal(raw, &d); err != nil || len(d.Units) != 4 || d.Version != 1 {
		t.Errorf("data does not round-trip: %v, %d units", err, len(d.Units))
	}
}

func TestSkipReasons(t *testing.T) {
	// Each case overrides keys of a request that would otherwise compile.
	cases := []struct{ name, yaml, reason string }{
		{"payloads", "payloads: {x: [a]}\nattack: batteringram", "payloads"},
		{"raw", "raw: [\"GET / HTTP/1.1\"]", "raw request"},
		{"body", "body: a=b", "request body"},
		{"headers", "headers: {X-A: b}", "custom request headers"},
		{"post", "method: POST", "method POST"},
		{"redirects off", "redirects: false", "redirects disabled"},
		{"unknown key", "unsafe: true", "unsupported request key unsafe"},
		{"path variable", "path: [\"{{BaseURL}}/{{id}}\"]", "path uses variables"},
		{"absolute path", "path: [\"http://example.com/\"]", "path is not relative to the base URL"},
		{"internal extractor", "extractors: [{type: regex, internal: true, name: t, regex: [a]}]", "internal extractor"},
		{"status 3xx", "matchers: [{type: status, status: [302]}]", "status 3xx needs an unfollowed redirect"},
		{"xpath", "matchers: [{type: xpath, xpath: [\"//a\"]}]", "matcher type xpath"},
		{"binary", "matchers: [{type: binary, binary: [\"4d5a\"]}]", "matcher type binary"},
		{"unknown part", "matchers: [{type: word, part: body_1, words: [abcdef]}]", "part body_1"},
		{"bad regex", "matchers: [{type: regex, regex: [\"(unclosed\"]}]", "regex does not compile"},
		{"matcher variable", "matchers: [{type: word, words: [\"{{token}}\"]}]", "matcher uses variables"},
		{"unknown function", "matchers: [{type: dsl, dsl: [\"json_minify(body) == 'x'\"]}]", "dsl function json_minify"},
		{"unknown identifier", "matchers: [{type: dsl, dsl: [\"contains(raw_version, 'x')\"]}]", "dsl identifier raw_version"},
		{"internal matcher", "matchers: [{type: word, internal: true, words: [abcdef]}]", "internal matcher"},
		{"matcher key", "matchers: [{type: word, encoding: hex, words: [abcdef]}]", "unsupported matcher key encoding"},
		{"no matchers", "matchers: []", "no matchers"},
		{"bad condition", "matchers-condition: xor", "matchers-condition xor"},
	}
	for _, c := range cases {
		block := map[string]any{
			"path":     []any{"{{BaseURL}}"},
			"matchers": []any{map[string]any{"type": "word", "words": []any{"abcdef"}}},
		}
		var over map[string]any
		if err := yaml.Unmarshal([]byte(c.yaml), &over); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for k, v := range over {
			block[k] = v
		}
		if _, _, reason := compileBlock(&template{ID: "t"}, block); reason != c.reason {
			t.Errorf("%s: reason %q, want %q", c.name, reason, c.reason)
		}
	}
	// The unmodified request compiles, so every reason above is the override's.
	ok := map[string]any{"path": []any{"{{BaseURL}}"}, "matchers": []any{map[string]any{"type": "word", "words": []any{"abcdef"}}}}
	if u, _, reason := compileBlock(&template{ID: "t"}, ok); u == nil || reason != "" {
		t.Errorf("base request skipped: %q", reason)
	}
}

func TestTemplateLevelSkips(t *testing.T) {
	for name, doc := range map[string]string{
		"flow":           "id: t\nflow: http(1)\nhttp:\n  - path: [\"{{BaseURL}}\"]\n    matchers:\n      - type: word\n        words: [abcdef]\n",
		"self-contained": "id: t\nself-contained: true\nhttp:\n  - path: [\"{{BaseURL}}\"]\n    matchers:\n      - type: word\n        words: [abcdef]\n",
	} {
		var tpl template
		if err := yaml.Unmarshal([]byte(doc), &tpl); err != nil {
			t.Fatal(err)
		}
		if _, _, reason := compileBlock(&tpl, tpl.HTTP[0]); reason != name {
			t.Errorf("%s: reason %q", name, reason)
		}
	}
}

func TestPathsAndDroppedExtractors(t *testing.T) {
	doc := `id: t
info:
  name: Foo Panel
http:
  - path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/"
      - "{{RootURL}}/admin/"
      - "{{BaseURL}}?x=1"
    host-redirects: true
    max-redirects: 2
    stop-at-first-match: true
    matchers:
      - type: word
        part: server
        words: ["nginx"]
    extractors:
      - type: json
        json: [".a"]
      - type: kval
        kval: [server]
      - type: regex
        regex: ["(unclosed"]
`
	var tpl template
	if err := yaml.Unmarshal([]byte(doc), &tpl); err != nil {
		t.Fatal(err)
	}
	u, dropped, reason := compileBlock(&tpl, tpl.HTTP[0])
	if reason != "" {
		t.Fatal(reason)
	}
	if got := strings.Join(u.Paths, " "); got != "/ /admin/ /?x=1" {
		t.Errorf("paths = %q", got)
	}
	if dropped != 2 || len(u.Extractors) != 1 || u.Extractors[0].Type != "kval" {
		t.Errorf("dropped %d, extractors %+v", dropped, u.Extractors)
	}
	if u.Product != "Foo" || u.Matchers[0].Part != "header:Server" {
		t.Errorf("unit = %+v", u)
	}
}

// One payload variable that only the paths use is a longer path list; any
// other use of payloads stays skipped.
func TestPayloadsInPathsAreExpanded(t *testing.T) {
	block := func(extra string) map[string]any {
		var b map[string]any
		doc := "path: [\"{{BaseURL}}\", \"{{BaseURL}}/{{p}}/\"]\npayloads: {p: [db, sql]}\n" + extra +
			"matchers: [{type: word, words: [abcdef]}]\n"
		if err := yaml.Unmarshal([]byte(doc), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	u, _, reason := compileBlock(&template{ID: "t"}, block("attack: pitchfork\nthreads: 3\n"))
	if reason != "" || strings.Join(u.Paths, " ") != "/ /db/ /sql/" {
		t.Fatalf("reason %q, paths %v", reason, u)
	}
	for name, b := range map[string]map[string]any{
		"in a matcher":  block("extractors: [{type: regex, regex: [\"{{p}}-([0-9]+)\"]}]\n"),
		"file":          {"path": []any{"{{BaseURL}}/{{p}}"}, "payloads": map[string]any{"p": "words.txt"}, "matchers": []any{map[string]any{"type": "word", "words": []any{"abcdef"}}}},
		"two variables": {"path": []any{"{{BaseURL}}/{{p}}"}, "payloads": map[string]any{"p": []any{"a"}, "q": []any{"b"}}, "matchers": []any{map[string]any{"type": "word", "words": []any{"abcdef"}}}},
		"not in a path": {"path": []any{"{{BaseURL}}"}, "payloads": map[string]any{"p": []any{"a"}}, "matchers": []any{map[string]any{"type": "word", "words": []any{"abcdef"}}}},
	} {
		if _, _, reason := compileBlock(&template{ID: "t"}, b); reason != "payloads" {
			t.Errorf("%s: reason %q, want payloads", name, reason)
		}
	}
}
