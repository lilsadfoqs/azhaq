package httpcol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/types"
)

// fitRows fails the test for a payload that httprow.Row does not hold whole: a
// key the writer emits and the type lacks. It returns what the run wrote.
func fitRows(t *testing.T, scenario string, payloads []string) []httprow.Row {
	t.Helper()
	if len(payloads) == 0 {
		t.Errorf("%s: no row", scenario)
	}
	var rows []httprow.Row
	for _, raw := range payloads {
		r, err := httprow.ParseRowStrict([]byte(raw))
		if err != nil {
			t.Errorf("%s: %v in %s", scenario, err, raw)
		}
		rows = append(rows, r)
	}
	return rows
}

// runFor runs c on a URL and returns the payload of each row, by kind.
func runFor(t *testing.T, c *Collector, raw string) (payloads []string, kinds []string) {
	t.Helper()
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}}
	_, _ = c.Run(context.Background(), seed, func(o types.Observation) error {
		if o.Collector != Name {
			t.Errorf("collector %q", o.Collector)
		}
		payloads = append(payloads, string(o.Payload))
		kinds = append(kinds, o.Kind)
		return nil
	})
	return payloads, kinds
}

const pythonTrace = "Traceback (most recent call last):\n  File \"/app/a.py\", line 1, in <module>\n    run()\n  File \"/app/b.py\", line 2, in run\n    go()\n  File \"/app/c.py\", line 3, in go\n    boom()\nValueError: bad value\n"

func contractServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Add("Server", "nginx/1.18.0")
			w.Header().Add("X-Powered-By", "PHP/7.4.3")
			w.Header().Add("Set-Cookie", "sid=abc; HttpOnly; Secure; SameSite=Lax")
			w.Header().Add("Set-Cookie", "plain=1")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Home</title><meta name="generator" content="WordPress 6.4"><link rel="icon" href="/favicon.ico">` +
				`<meta http-equiv="Content-Security-Policy" content="default-src cdn.example.org; img-src static.example.net"></head>` +
				`<body><form><input type="password" name="p"></form> see https://api.example.org/v1 and www.example.com</body></html>`))
		case "/favicon.ico":
			_, _ = w.Write([]byte("\x00\x00\x01\x00icon-bytes"))
		case "/login":
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin Console"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/old":
			http.Redirect(w, r, "/", http.StatusFound)
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"u1","name":"a"},{"id":"u2","name":"b"}],"total":2}`))
		case "/boom":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(pythonTrace + "You have an error in your SQL syntax; check the manual"))
		case "/.env":
			_, _ = w.Write([]byte("APP_KEY=base64:abc\nDB_PASSWORD=secret\n"))
		default: // every other path: the same page, a catch-all
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><title>Welcome</title><body>nothing here</body></html>"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Every row the collector writes fits httprow.Row, key for key: the answers of
// a run (default and probe), a failure, a port that is not web, a name with no
// web port, and the answers a run drops.
func TestEveryRowTheCollectorWritesFitsRow(t *testing.T) {
	srv := contractServer(t)
	reached := map[string]bool{}
	note := func(payloads []string) {
		for _, raw := range payloads {
			var m map[string]json.RawMessage
			_ = json.Unmarshal([]byte(raw), &m)
			for k := range m {
				reached[k] = true
			}
		}
	}
	t.Run("run", func(t *testing.T) {
		fetch.Reset()
		for _, path := range []string{"/", "/login", "/old", "/api", "/boom", "/.env", "/nowhere"} {
			c := New(srv.Client())
			payloads, kinds := runFor(t, c, srv.URL+path)
			rows := fitRows(t, path, payloads)
			note(payloads)
			if kinds[0] != "application" || rows[0].URL == "" || rows[0].Status == 0 {
				t.Errorf("%s: %v %+v", path, kinds, rows[0])
			}
		}
	})
	t.Run("probe", func(t *testing.T) {
		fetch.Reset()
		spec := &Spec{Follow: true, Hashes: []string{"md5", "sha256"}, Preview: 20, Evidence: true, CSPProbe: true, EFQDN: true,
			CPE: true, WP: true, KB: true, HTTP2: true, Pipeline: true, SNI: "named.example.org",
			Extract: []Extract{{Name: "urls", Pattern: `https?://[a-z./0-9]+`}}}
		if err := spec.Apply(); err != nil {
			t.Fatal(err)
		}
		c := New(srv.Client())
		c.Probe, c.Spec = true, spec
		payloads, _ := runFor(t, c, srv.URL+"/")
		rows := fitRows(t, "probe", payloads)
		note(payloads)
		if len(rows[0].Hash) == 0 || rows[0].CSP == nil || len(rows[0].Extracts) == 0 || rows[0].Knowledgebase == nil || rows[0].Method != "GET" || rows[0].ElapsedNS == 0 {
			t.Errorf("probe fields: %+v", rows[0])
		}
	})
	t.Run("failure", func(t *testing.T) {
		fetch.Reset()
		spec := &Spec{Ports: []PortSpec{{Port: 1}, {Port: 2}}}
		if err := spec.Apply(); err != nil {
			t.Fatal(err)
		}
		c := New(nil)
		c.Probe, c.Spec = true, spec
		seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "127.0.0.1"}}
		c.Spec.Bare = []string{"127.0.0.1"}
		var payloads []string
		_, _ = c.Run(context.Background(), seed, func(o types.Observation) error {
			payloads = append(payloads, string(o.Payload))
			return nil
		})
		if len(payloads) > 0 {
			fitRows(t, "failure", payloads)
			note(payloads)
		}
	})
	// The rows of the kinds with no answer in them: the keys the collector writes for them.
	for kind, row := range map[string]string{
		KindNotHTTP: `{"url":"http://127.0.0.1:21/","host":"127.0.0.1","port":21}`,
		"noweb":     `{"host":"example.org","ports":"443 or 80"}`,
		"dropped":   `{"answered_at":"https://example.org/"}`,
		"error":     `{"error":"dial tcp: refused","url":"http://127.0.0.1:1/"}`,
	} {
		t.Run(kind, func(t *testing.T) { fitRows(t, kind, []string{row}) })
	}
	// What the scenarios above must reach, so that they stay a check of the writer.
	for _, k := range []string{"url", "status", "final_url", "content_type", "server", "title", "location", "body_hash", "tech", "length", "words", "lines", "ms",
		"ip", "cookies", "headers", "hops", "final_status", "json_keys", "json_ids", "json_items", "generator", "realm", "login", "catchall", "control",
		"control_exact", "favicon", "favicon_url", "response_headers", "body_excerpt", "body_length", "asked_at", "stack_trace", "trace_excerpt",
		"trace_offset", "error_text", "error_sample", "head", "head_kept", "method", "elapsed_ns", "hash", "body_preview", "extracts", "csp", "knowledgebase"} {
		if !reached[k] {
			t.Errorf("no scenario reaches the key %q", k)
		}
	}
}

// tlsData is httpx's tls object: its keys are fields of httprow.TLS.
func TestTLSObjectFitsRow(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	cert := srv.TLS.Certificates[0].Certificate[0]
	data := tlsData(srv.URL, &fetch.TLSInfo{Version: tls.VersionTLS13, Cipher: tls.TLS_AES_128_GCM_SHA256, ServerName: "x.example.org", Certs: [][]byte{cert}})
	if data == nil {
		t.Fatal("no tls data")
	}
	raw, _ := json.Marshal(map[string]any{"tls": data})
	rows := fitRows(t, "tls", []string{string(raw)})
	if got := rows[0].TLS; got == nil || got.TLSVersion != "tls13" || got.FingerprintHash.SHA256 == "" || got.SNI != "x.example.org" || got.Host == "" {
		t.Errorf("tls %+v", got)
	}
	// Read and written again, the object keeps its bytes.
	again, _ := json.Marshal(rows[0])
	var a, b map[string]json.RawMessage
	_ = json.Unmarshal(again, &a)
	_ = json.Unmarshal(raw, &b)
	if string(a["tls"]) != string(b["tls"]) {
		t.Errorf("\n got %s\nwant %s", a["tls"], b["tls"])
	}
}

// The keys named in the writer's source are all fields of Row: a key added to
// a row without its field fails here even if no scenario above reaches it.
func TestWriterKeysAreRowFields(t *testing.T) {
	tags := map[string]bool{}
	rt := reflect.TypeOf(httprow.Row{})
	for i := 0; i < rt.NumField(); i++ {
		tags[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	var keys []string
	fset := token.NewFileSet()
	for file, funcs := range map[string][]string{
		"http.go":        {"fetchFirst", "describe", "Run"},
		"probefields.go": {"probeFields", "extras"},
	} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !slices.Contains(funcs, fd.Name.Name) {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.IndexExpr: // row["k"], out["k"]
					if id, ok := x.X.(*ast.Ident); ok && (id.Name == "row" || id.Name == "out") {
						keys = append(keys, litKeys(x.Index)...)
					}
				case *ast.AssignStmt: // out := map[string]any{"k": …}
					if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name == "out" && fd.Name.Name == "describe" {
						if cl, ok := x.Rhs[0].(*ast.CompositeLit); ok {
							for _, el := range cl.Elts {
								keys = append(keys, litKeys(el.(*ast.KeyValueExpr).Key)...)
							}
						}
					}
				case *ast.CallExpr: // json.Marshal(map[string]…{"k": …})
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Marshal" && len(x.Args) == 1 {
						if cl, ok := x.Args[0].(*ast.CompositeLit); ok {
							if _, isMap := cl.Type.(*ast.MapType); isMap {
								for _, el := range cl.Elts {
									keys = append(keys, litKeys(el.(*ast.KeyValueExpr).Key)...)
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	if len(keys) < 40 {
		t.Fatalf("found %d keys in the source: the walk no longer matches it", len(keys))
	}
	slices.Sort(keys)
	for _, k := range slices.Compact(keys) {
		if !tags[k] {
			t.Errorf("the writer emits %q, which httprow.Row has no field for", k)
		}
	}
}

func litKeys(e ast.Expr) []string {
	if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
		if s, err := strconv.Unquote(bl.Value); err == nil {
			return []string{s}
		}
	}
	return nil
}
