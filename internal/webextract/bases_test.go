package webextract

import "testing"

func TestBases(t *testing.T) {
	cases := []struct {
		name, script string
		want         []Call // Path, Base only
	}{
		{"instance", `const e=r.a.create({baseURL:"/api/v2/"});e.get("/a")`, []Call{{Path: "/api/v2/a", Base: "/api/v2/"}}},
		{"query", `var h=axios.create({baseURL:"server/index.php?s="});h.get("/item/list")`, []Call{{Path: "server/index.php?s=/item/list", Base: "server/index.php?s="}}},
		{"defaults", `axios.defaults.baseURL="https://api.x.test/v1";axios.post("/a")`, []Call{{Path: "https://api.x.test/v1/a", Base: "https://api.x.test/v1"}}},
		{"constant", `const API="/api/v3";const c={baseURL:API};const k=axios.create(c);k.get("/a")`, []Call{{Path: "/api/v3/a", Base: "/api/v3"}}},
		{"config of an unnamed client", `const API="/api/v3";const c={baseURL:API};k.get("/a")`, []Call{{Path: "/a"}}},
		{"alias", `const e=axios.create({baseURL:"/api"});const f=e;this.$http=f;this.$http.get("/a")`, []Call{{Path: "/api/a", Base: "/api"}}},
		{"another receiver keeps its path", `const e=axios.create({baseURL:"/api"});e.get("/users");api.get("/api/frontend/settings");this.http.get("/api/x");getBackendSrv().get("/api/y")`,
			[]Call{{Path: "/api/users", Base: "/api"}, {Path: "/api/frontend/settings"}, {Path: "/api/x"}, {Path: "/api/y"}}},
		{"path already under the base", `const e=axios.create({baseURL:"/api"});e.get("/api/admin/settings");e.get("/apis/x");e.get("/users")`,
			[]Call{{Path: "/api/admin/settings"}, {Path: "/api/apis/x", Base: "/api"}, {Path: "/api/users", Base: "/api"}}},
		{"path already under an absolute base", `const e=axios.create({baseURL:"https://api.x.test/v1"});e.get("/v1/a")`,
			[]Call{{Path: "https://api.x.test/v1/a", Base: "https://api.x.test/v1"}}},
		{"unnamed default axios without defaults", `const e=axios.create({baseURL:"/api"});axios.get("/a")`, []Call{{Path: "/a"}}},
		{"two instances", `var a=axios.create({baseURL:"/one"}),b=axios.create({baseURL:"/two"});a.get("/x");b.get("/y");c.get("/z")`,
			[]Call{{Path: "/one/x", Base: "/one"}, {Path: "/two/y", Base: "/two"}, {Path: "/z"}}},
		{"absolute url", `var a=axios.create({baseURL:"/one"});a.get("https://o.test/x")`, []Call{{Path: "https://o.test/x"}}},
		{"root base", `var a=axios.create({baseURL:"/"});a.get("/x")`, []Call{{Path: "/x"}}},
		{"run-time base", `var a=axios.create({baseURL:process.env.API});a.get("/x")`, []Call{{Path: "/x"}}},
	}
	for _, c := range cases {
		got := Calls(c.script)
		if len(got) != len(c.want) {
			t.Errorf("%s: %d calls, want %d: %+v", c.name, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i].Path != c.want[i].Path || got[i].Base != c.want[i].Base {
				t.Errorf("%s: call %d is %q on base %q, want %q on %q", c.name, i, got[i].Path, got[i].Base, c.want[i].Path, c.want[i].Base)
			}
		}
	}
}

// The triage page: one based client, other objects called with /api paths.
func TestBaseOnlyOnItsOwnClient(t *testing.T) {
	script := `export const client = axios.create({ baseURL: "/api" });
client.get("/api/admin/settings");
client.get("/users");
api.get("/api/frontend/settings");
fetch("/api/dashboards/db");`
	want := map[string]string{
		"/api/admin/settings":    "",     // already under the base
		"/api/users":             "/api", // joined
		"/api/frontend/settings": "",
		"/api/dashboards/db":     "",
	}
	got := map[string]string{}
	for _, c := range Calls(script) {
		got[c.Path] = c.Base
	}
	for p, b := range want {
		if base, ok := got[p]; !ok || base != b {
			t.Errorf("%s: base %q (present %v), want %q; calls %v", p, base, ok, b, got)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("unexpected call %s", p)
		}
	}
}
