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
		{"constant", `const API="/api/v3";const c={baseURL:API};k.get("/a")`, []Call{{Path: "/api/v3/a", Base: "/api/v3"}}},
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
