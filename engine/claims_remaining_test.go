package engine_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/gqlschema"
	"github.com/lilsadfoqs/azhaq/types"
)

func obsBy(collector, kind, entity, payload string) types.StoredObservation {
	return types.StoredObservation{EntityID: entity, Observation: types.Observation{Collector: collector, Kind: kind, Payload: json.RawMessage(payload)}}
}

// A route that Chrome wrote to, and whose GET answers 404 or the catch-all
// page, stays a hint; a GET that answers 405 makes it visited, with the 405.
func TestBrowserWritesStayHintsUnder404AndTheCatchAllButNotUnder405(t *testing.T) {
	ents := []types.Entity{
		{ID: "root", Type: types.TypeURL, Key: "https://app.test/"},
		{ID: "a", Type: types.TypeURL, Key: "https://app.test/api/a"},
		{ID: "b", Type: types.TypeURL, Key: "https://app.test/api/b"},
		{ID: "c", Type: types.TypeURL, Key: "https://app.test/api/c"},
	}
	obs := []types.StoredObservation{httpObs("root", `{"status":200,"url":"https://app.test/"}`)}
	for _, k := range []string{"a", "b", "c"} {
		obs = append(obs, obsBy("azhaq-render", "url", "root", `{"url":"https://app.test/api/`+k+`","via":"browser","seen":"write","role":"api","methods":["POST"],"ops":[{"method":"POST","source":"browser"}]}`))
	}
	obs = append(obs,
		httpObs("a", `{"status":404,"url":"https://app.test/api/a"}`),
		httpObs("b", `{"status":405,"url":"https://app.test/api/b"}`),
		httpObs("c", `{"status":200,"catchall":true,"url":"https://app.test/api/c"}`))
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.test/"}}}
	got := map[string]engine.MapEntry{}
	for _, m := range engine.BuildMap(ents, seeds, obs, nil, false) {
		got[strings.TrimPrefix(m.Entity.Key, "https://app.test")] = m
	}
	if m := got["/api/a"]; m.Coverage != "hint" || m.Proof != "GET answers 404; called with POST" || m.Evidence != engine.EvBrowser {
		t.Errorf("a GET that answers 404: %s %q %s, want a hint seen by the browser", m.Coverage, m.Proof, m.Evidence)
	}
	if m := got["/api/c"]; m.Coverage != "hint" || m.Proof != "GET answers like an unknown path" {
		t.Errorf("a GET that answers the catch-all page: %s %q, want a hint", m.Coverage, m.Proof)
	}
	if m := got["/api/b"]; m.Coverage != "visited" || m.Status != 405 {
		t.Errorf("a GET that answers 405: %s %d, want visited with 405", m.Coverage, m.Status)
	}
}

// The route's body is the body field names of all its operations, whatever
// described them: a script's call, an API description, a GraphQL schema (its
// argument names) and a request taken in from katana. No field is named on
// the route itself: each comes from an operation.
func TestARoutesBodyIsTheBodyNamesOfAllItsOperations(t *testing.T) {
	answer, err := os.ReadFile("../internal/gqlschema/testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	schema, _, ok := gqlschema.Read(answer)
	if !ok {
		t.Fatal("fixture")
	}
	const u = "https://api.test/graphql"
	ents := []types.Entity{{ID: "g", Type: types.TypeURL, Key: u}}
	op := func(method, src string, names ...string) string {
		b, _ := json.Marshal(names)
		return `"methods":["` + method + `"],"ops":[{"method":"` + method + `","source":"` + src + `","body":` + string(b) + `}]`
	}
	obs := []types.StoredObservation{
		httpObs("g", `{"status":400,"url":"`+u+`"}`),
		obsBy("azhaq-js", "url", "g", `{"url":"`+u+`","via":"js-call","role":"api",`+op("PUT", "js-call", "from_script")+`}`),
		obsBy("azhaq-api", "url", "g", `{"url":"`+u+`","via":"openapi","role":"api",`+op("PATCH", "openapi", "from_description")+`}`),
		obsBy("katana", "url", "g", `{"url":"`+u+`","via":"katana",`+op("DELETE", "katana", "from_katana")+`}`),
		schemaObs("g", `{"introspection":true,"url":"`+u+`","role":"graphql","status":200,"schema":`+string(schema)+`}`),
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://api.test/"}}}
	rows := engine.BuildMap(ents, seeds, obs, nil, false)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	for _, name := range []string{"from_script", "from_description", "from_katana", "username", "password"} {
		if !slices.Contains(rows[0].Body, name) {
			t.Errorf("the route's body %v lacks %s", rows[0].Body, name)
		}
	}
}

// The Markdown and the empty-shell signs for a map with Chrome count only
// when fewer than 10 routes were found on the page's origin: 9 do, 10 do
// not. Three template expressions count whatever the map holds.
func TestBrowserHintMarkdownAndShellNeedFewerThanTenRoutesTemplatesDoNot(t *testing.T) {
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://dvna.test/"}}}
	hint := func(routes int, what string) string {
		ents := []types.Entity{{ID: "root", Type: types.TypeURL, Key: "http://dvna.test/"}}
		obs := []types.StoredObservation{httpObs("root", `{"status":200,"url":"http://dvna.test/"}`)}
		for i := 1; i < routes; i++ { // the front page is the first route
			id := "r" + string(rune('a'+i))
			key := "http://dvna.test/page-" + id
			ents = append(ents, types.Entity{ID: id, Type: types.TypeURL, Key: key})
			obs = append(obs, httpObs(id, `{"status":200,"url":"`+key+`"}`))
		}
		obs = append(obs, crawlObs("root", "meta", `{"url":"http://dvna.test/","unrendered":`+what+`}`))
		return engine.BrowserHint(engine.BuildMap(ents, seeds, obs, nil, false), obs)
	}
	for _, c := range []struct {
		what, mark string
	}{{`{"markdown":5}`, "Markdown"}, {`{"shell":true}`, "an empty page its scripts draw"}} {
		if h := hint(9, c.what); !strings.Contains(h, c.mark) {
			t.Errorf("%s with 9 routes: %q, want the hint", c.what, h)
		}
		if h := hint(10, c.what); h != "" {
			t.Errorf("%s with 10 routes: %q, want none", c.what, h)
		}
	}
	if h := hint(30, `{"templates":3}`); !strings.Contains(h, "{{templates}}") {
		t.Errorf("3 templates with 30 routes: %q, want the hint", h)
	}
}
