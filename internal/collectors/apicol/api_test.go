package apicol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
	"github.com/lilsadfoqs/azhaq/types"
)

const openapi3 = `{
  "openapi": "3.0.1",
  "info": {"title": "VAmPI", "version": "0.1"},
  "servers": [{"url": ""}],
  "paths": {
    "/users/v1": {"get": {}},
    "/users/v1/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}}}},
    "/users/v1/{username}": {"parameters": [{"name": "username", "in": "path"}], "get": {}, "delete": {}},
    "/createdb": {"get": {"description": "Creates and populates the database"}}
  },
  "components": {"schemas": {"Login": {"properties": {"username": {}, "password": {}}}}}
}`

const swagger2 = `swagger: "2.0"
info:
  title: Pets
host: localhost:8080
basePath: /v2
paths:
  /pet/{petId}:
    get:
      parameters:
        - $ref: "#/parameters/petId"
    post:
      parameters:
        - name: name
          in: formData
`

// holding makes runSpec run with the policy that holds state-changing GETs.
var holding bool

type op struct {
	URL     string   `json:"url"`
	Methods []string `json:"methods"`
	Params  []string `json:"params"`
	Ops     []struct {
		Method      string `json:"method"`
		Description string `json:"description"`
		StateChange string `json:"state_change"`
	} `json:"ops"`
}

func runSpec(t *testing.T, path, ctype, body string) (map[string]op, types.RunMeta, int) {
	t.Helper()
	fetch.Reset()
	if holding {
		egress.SetStateWords(statechange.OfURL, nil, true)
		t.Cleanup(egress.Reset)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			calls++
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	ops := map[string]op{}
	emit := func(o types.Observation) error {
		if o.Kind != "url" {
			return nil
		}
		var p op
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			t.Fatal(err)
		}
		ops[strings.TrimPrefix(p.URL, srv.URL)] = p
		return nil
	}
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + path},
	}, emit)
	if err != nil {
		t.Fatal(err)
	}
	return ops, meta, calls
}

func TestOpenAPI3(t *testing.T) {
	ops, meta, calls := runSpec(t, "/openapi.json", "application/json", openapi3)
	if len(ops) != 4 {
		t.Fatalf("ops %v", ops)
	}
	u := ops["/users/v1/{username}"]
	if strings.Join(u.Methods, ",") != "GET,DELETE" || strings.Join(u.Params, ",") != "username" {
		t.Errorf("templated path %+v", u)
	}
	if got := strings.Join(ops["/users/v1/login"].Params, ","); got != "password,username" {
		t.Errorf("body params %q", got)
	}
	// The description is kept and the GET it declares a state change is
	// marked, so plan and run can name it; nothing is withheld by it.
	created := ops["/createdb"]
	if len(created.Ops) != 1 || created.Ops[0].Description != "Creates and populates the database" || created.Ops[0].StateChange == "" {
		t.Errorf("GET /createdb is not marked with its description: %+v", created.Ops)
	}
	if len(ops["/users/v1"].Ops) != 1 || ops["/users/v1"].Ops[0].StateChange != "" {
		t.Errorf("a plain read is marked: %+v", ops["/users/v1"].Ops)
	}
	// GETs that need no parameter are handed on: the run asks them, or
	// lists one whose name says it does something as skipped.
	var hints []string
	for _, h := range meta.NextHints {
		hints = append(hints, strings.TrimPrefix(h.Keys["url"], srv(meta)))
	}
	slices.Sort(hints)
	if strings.Join(hints, ",") != "/createdb,/users/v1" || calls != 0 {
		t.Errorf("hints %v, calls %d: want /createdb and /users/v1 handed on, nothing called here", hints, calls)
	}
}

// srv is the origin of the first hint.
func srv(meta types.RunMeta) string {
	if len(meta.NextHints) == 0 {
		return ""
	}
	u := meta.NextHints[0].Keys["url"]
	if i := strings.Index(u[len("http://"):], "/"); i >= 0 {
		return u[:len("http://")+i]
	}
	return u
}

func TestSwagger2YAML(t *testing.T) {
	ops, _, _ := runSpec(t, "/docs/swagger.yaml", "application/yaml", swagger2)
	p, ok := ops["/v2/pet/{petId}"]
	if !ok {
		t.Fatalf("basePath on the serving origin: %v", ops)
	}
	if strings.Join(p.Methods, ",") != "GET,POST" {
		t.Errorf("methods %v", p.Methods)
	}
}

func TestNotASpec(t *testing.T) {
	ops, meta, _ := runSpec(t, "/assets/i18n/en.json", "application/json", `{"paths": {"/x": {}}, "title": "x"}`)
	if len(ops) != 0 || meta.EmitCount != 0 {
		t.Errorf("plain JSON read as a spec: %v", ops)
	}
	if New(nil).Skip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://h/api/Users"}}) == false {
		t.Error("API route should be skipped at plan time")
	}
}

// Swagger UI's init script carries the whole document (Juice Shop's B2B API).
const swaggerUIInit = `
window.onload = function() {
  var url = window.location.search.match(/url=([^&]+)/);
  var options = {
  "swaggerDoc": {
    "openapi": "3.0.0",
    "servers": [{"url": "/b2b/v2"}],
    "info": {"version": "2.0.0", "title": "NextGen B2B API", "description": "New & secure {JSON} \"API\""},
    "paths": {
      "/orders": {"post": {"operationId": "createCustomerOrder"}}
    }
  },
  "customOptions": {}
};
  url = options.swaggerUrl || url
  var urls = options.swaggerUrls
  window.ui = SwaggerUIBundle({spec: options.swaggerDoc})
}`

func TestSpecInSwaggerUIScript(t *testing.T) {
	ops, _, _ := runSpec(t, "/api-docs/swagger-ui-init.js", "application/javascript", swaggerUIInit)
	o, ok := ops["/b2b/v2/orders"]
	if !ok || strings.Join(o.Methods, ",") != "POST" {
		t.Fatalf("embedded spec: %v", ops)
	}
	if embedded(`var spec = {"openapi": "3.0.0", "paths": {"/a": {"get": {}}}}`) != "" {
		t.Error("a bare assignment is not a spec key")
	}
	if got := embedded(`SwaggerUIBundle({spec: {"swagger": "2.0", "paths": {}}, dom_id: "#x"})`); got != `{"swagger": "2.0", "paths": {}}` {
		t.Errorf("spec option: %q", got)
	}
}

// A UI whose script carries the document is not asked for the usual names
// next to it: the description is in hand.
func TestSwaggerUIWithEmbeddedDocumentAsksNoSiblings(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api-docs/":
			_, _ = w.Write([]byte(`<html><title>Swagger UI</title><script src="./swagger-ui-init.js"></script></html>`))
		case "/api-docs/swagger-ui-init.js":
			_, _ = w.Write([]byte(swaggerUIInit))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	var hints []string
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/api-docs/"},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range meta.NextHints {
		hints = append(hints, h.Keys["url"])
	}
	if len(asked) != 2 {
		t.Errorf("asked %v: want the page and its script only", asked)
	}
	if len(hints) != 1 || hints[0] != srv.URL+"/api-docs/swagger-ui-init.js" {
		t.Errorf("hints %v: want the script", hints)
	}
	if !fetch.Described(srv.URL) {
		t.Error("the origin is not marked as described")
	}
}

// VAmPI's root operation has a description that says the app "was created":
// that is prose about the app, not the request's own name, so GET / is not
// marked. An operation named by its operationId is, and the run is told to
// hold that GET back though its path says nothing.
const vampiShaped = `{
  "openapi": "3.0.1",
  "info": {"title": "VAmPI", "version": "0.1", "description": "VAmPI was created to be vulnerable"},
  "servers": [{"url": ""}],
  "paths": {
    "/": {"get": {"operationId": "home", "summary": "VAmPI home", "description": "VAmPI was created as a vulnerable API"}},
    "/createdb": {"get": {"summary": "Creates and populates the database"}},
    "/books/v1": {"get": {"operationId": "deleteBooks"}},
    "/users/v1": {"get": {"summary": "List users"}}
  }
}`

func TestOperationNameNotAppProseMarksStateChange(t *testing.T) {
	holding = true
	t.Cleanup(func() { holding = false })
	ops, meta, _ := runSpec(t, "/openapi.json", "application/json", vampiShaped)
	got := map[string]string{}
	for path, o := range ops {
		for _, x := range o.Ops {
			got[path] = x.StateChange
		}
	}
	want := map[string]string{"/": "", "/createdb": "createdb", "/books/v1": "delete", "/users/v1": ""}
	for path, w := range want {
		if got[path] != w {
			t.Errorf("GET %s is marked %q, want %q", path, got[path], w)
		}
	}
	// The operationId's word reached the policy: the run holds /books/v1 back
	// though its path has no such word, and holds nothing else of it.
	for _, h := range meta.NextHints {
		u := h.Keys["url"]
		w := egress.HeldWord(u)
		switch {
		case strings.HasSuffix(u, "/books/v1"):
			if w != "delete" {
				t.Errorf("%s is held for %q, want delete", u, w)
			}
		case strings.HasSuffix(u, "/createdb"):
			if w != "createdb" {
				t.Errorf("%s is held for %q, want createdb", u, w)
			}
		default:
			if w != "" {
				t.Errorf("%s is held for %q", u, w)
			}
		}
	}
}
