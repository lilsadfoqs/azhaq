package detect

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
)

func evalExpr(t *testing.T, expr string, r Response) bool {
	t.Helper()
	n, err := parseDSL(expr)
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	return evalNode(n, newCtx(r)).truthy()
}

func TestDSLEval(t *testing.T) {
	r := Response{
		Status: 200,
		Header: http.Header{"Server": {"nginx/1.2"}, "Content-Type": {"text/html; charset=utf-8"}, "X-Powered-By": {"PHP/8"}},
		Body:   []byte("<html><title>Hello World</title> 42 </html>"),
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`status_code == 200`, true},
		{`status_code != 200`, false},
		{`status_code >= 200 && status_code < 300`, true},
		{`status_code > 200 || status_code <= 100`, false},
		{`!(status_code == 404)`, true},
		{`"200" == status_code`, true},
		{`contains(body, "Hello")`, true},
		{`contains(body, "hello")`, false},
		{`contains(to_lower(body), "hello world")`, true},
		{`contains(tolower(body), 'hello')`, true},
		{`contains(to_upper(body), "HELLO")`, true},
		{`contains_any(body, "nope", "World")`, true},
		{`contains_any(body, "nope", "zip")`, false},
		{`contains_all(body, "Hello", "World")`, true},
		{`contains_all(body, "Hello", "Mars")`, false},
		{`regex("<title>[^<]+</title>", body)`, true},
		{`regex('(?i)hello\s+WORLD', body)`, true},
		{`regex("^v[0-9]+", body)`, false},
		{`regex("\\d+", body)`, true},
		{`len(body) > 10`, true},
		{`len("abc") == 3`, true},
		{`concat("a", "b", 1) == "ab1"`, true},
		{`server == "nginx/1.2"`, true},
		{`contains(server, "nginx")`, true},
		{`contains(content_type, "text/html")`, true},
		{`contains(x_powered_by, "PHP")`, true},
		{`contains(header, "Server: nginx")`, true},
		{`contains(all_headers, "X-Powered-By: PHP/8")`, true},
		{`content_length == len(body)`, true},
		{`md5("a") == "0cc175b9c0f1b6a831c399e269772661"`, true},
		{`sha1("a") == "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"`, true},
		{`(status_code == 200 && contains(body, "Hello")) && !contains(body, "Mars")`, true},
		{`contains(body, "a\"b")`, false},
		{`1 + 2 == 3`, true},
	}
	for _, c := range cases {
		if got := evalExpr(t, c.expr, r); got != c.want {
			t.Errorf("%s = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestDSLRejectsUnsupported(t *testing.T) {
	for expr, want := range map[string]string{
		`compare_versions(version, '<2.0')`: "function compare_versions",
		`contains(body_1, "x")`:             "identifier body_1",
		`json_minify(body) == "x"`:          "function json_minify",
		`company`:                           "identifier company",
		`200`:                               "not boolean",
		`status_code == 200 &`:              "unsupported character",
		`contains(body, "x"`:                "bad call",
		`regex("(", body)`:                  "does not compile",
		`contains(body, "x`:                 "unterminated",
		`contains(body)`:                    "takes 2",
	} {
		err := ParseDSL(expr)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseDSL(%q) = %v, want error with %q", expr, err, want)
		}
	}
}

func TestMmh3Base64Py(t *testing.T) {
	for _, n := range []int{1, 4, 57, 58, 76, 300, 2048} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*7 + n)
		}
		want := fingerprint.Mmh3(b)
		if got := Mmh3String(base64Py(b)); got != want {
			t.Errorf("len %d: mmh3(base64_py) = %s, fingerprint.Mmh3 = %s", n, got, want)
		}
		expr := `mmh3(base64_py(body)) == "` + want + `"`
		if !evalExpr(t, expr, Response{Body: b}) {
			t.Errorf("len %d: expression %s was false", n, expr)
		}
	}
	// Python's base64.encodebytes: 76 columns, closing newline.
	enc := base64Py(make([]byte, 100))
	lines := strings.Split(strings.TrimSuffix(enc, "\n"), "\n")
	if len(lines) != 2 || len(lines[0]) != 76 || !strings.HasSuffix(enc, "\n") {
		t.Errorf("base64Py layout: %q", enc)
	}
}

func TestDSLMemo(t *testing.T) {
	c := newCtx(Response{Body: []byte("body")})
	n, err := parseDSL(`mmh3(base64_py(body)) == "1"`)
	if err != nil {
		t.Fatal(err)
	}
	evalNode(n, c)
	if _, ok := c.memo["mmh3(base64_py(body))"]; !ok {
		t.Fatalf("pure call over body not cached: %v", c.memo)
	}
}
