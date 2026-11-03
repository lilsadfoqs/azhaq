package engine

import (
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func foldRow(key, coverage, role string, status int) MapEntry {
	return MapEntry{Entity: types.Entity{Type: types.TypeURL, Key: key}, Coverage: coverage, Role: role, Status: status}
}

// A row folds only for what the run measured: the answer the origin gives a
// path that cannot exist, a 404 of its own, a file no request asked for, a
// string only scripts name. A route a script calls with a method, or an
// API description lists, is a lead and stays.
func TestFolderClass(t *testing.T) {
	f := NewFolder(nil)
	scriptsOnly := foldRow("https://h/old", "hint", "page", 404)
	scriptsOnly.Proof = "GET answers 404; " + ProofScriptsOnly
	named := foldRow("https://h/named", "hint", "page", 0)
	named.Evidence, named.EvidenceFrom = EvLinked, []string{"azhaq-js"}
	called := foldRow("https://h/api/x", "hint", "api", 0)
	called.Evidence, called.EvidenceFrom, called.Methods = EvCalled, []string{"azhaq-js"}, []string{"POST"}
	described := foldRow("https://h/api/y", "hint", "api", 0)
	described.Evidence, described.EvidenceFrom = EvDescribed, []string{"azhaq-api"}
	pageLinked := foldRow("https://h/p", "hint", "page", 0)
	pageLinked.Evidence, pageLinked.EvidenceFrom = EvLinked, []string{"azhaq-crawl", "azhaq-js"}
	host := MapEntry{Entity: types.Entity{Type: types.TypeHostname, Key: "h"}, Coverage: "gone"}
	for name, c := range map[string]struct {
		row  MapEntry
		want string
	}{
		"answered":            {foldRow("https://h/a", "visited", "page", 200), ""},
		"gated":               {foldRow("https://h/a", "visited", "auth", 401), ""},
		"catchall":            {foldRow("https://h/a", "catchall", "page", 200), FoldCatchAll},
		"gone":                {foldRow("https://h/a", "gone", "page", 404), FoldNotFound},
		"a 404 only scripts":  {scriptsOnly, FoldNotFound},
		"asset not asked":     {foldRow("https://h/a.png", "hint", "asset", 0), FoldBeyondDepth},
		"asset past a limit":  {foldRow("https://h/a.png", "capped", "asset", 0), FoldBeyondDepth},
		"asset answered":      {foldRow("https://h/a.png", "visited", "asset", 200), ""},
		"script not asked":    {foldRow("https://h/lib.js", "hint", "script", 0), ""},
		"string in scripts":   {named, FoldUnrequested},
		"call with a method":  {called, ""},
		"api description":     {described, ""},
		"link and script":     {pageLinked, ""},
		"a name, not a route": {host, ""},
	} {
		if got := f.Class(c.row); got != c.want {
			t.Errorf("%s: class %q, want %q", name, got, c.want)
		}
	}
}

// The groups count the rows of each class, a catch-all origin on its own
// with the control its answers were compared with, and the 404s by template.
func TestFolderGroups(t *testing.T) {
	var rows []MapEntry
	for _, p := range []string{"/a", "/b", "/c"} {
		rows = append(rows, foldRow("https://h"+p, "catchall", "page", 200))
	}
	rows = append(rows, foldRow("https://other/a", "catchall", "page", 200))
	for _, p := range []string{"/api/F/1", "/api/F/2", "/api/F/3", "/rest/m"} {
		rows = append(rows, foldRow("https://h"+p, "gone", "api", 404))
	}
	rows = append(rows, foldRow("https://h/x.png", "hint", "asset", 0), foldRow("https://h/ok", "visited", "page", 200))
	f := NewFolder(nil)
	f.controls["https://h"] = nil
	gs := f.Groups(rows)
	if len(gs) != 4 || gs[0].Class != FoldCatchAll || gs[1].Class != FoldCatchAll || gs[2].Class != FoldNotFound || gs[3].Class != FoldBeyondDepth {
		t.Fatalf("groups: %+v", gs)
	}
	if gs[0].Count+gs[1].Count != 4 || gs[0].Origin == gs[1].Origin {
		t.Errorf("each catch-all origin is a group of its own: %+v", gs[:2])
	}
	nf := gs[2]
	if nf.Count != 4 || nf.Templated != 2 || nf.Templates[0].Count != 3 || !strings.HasSuffix(nf.Templates[0].Template, "/api/F/{n}") || nf.Statuses[404] != 4 {
		t.Errorf("not-found group: %+v", nf)
	}
	if line := nf.Line(); !strings.Contains(line, "4 URLs answered 404 or 410, in 2 templates: /api/F/{n} ×3, /rest/m ×1") {
		t.Errorf("line: %q", line)
	}
	if gs[3].NotAsked != 1 {
		t.Errorf("beyond-depth: %+v", gs[3])
	}
}
