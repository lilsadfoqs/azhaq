package main

import (
	"fmt"
	"strings"
	"testing"
)

// Two names share one address and port and serve different root pages, one
// naming its application in its <title> (a rule of the port scan's own) and
// one in a generator meta tag, with a version. Each name has one identification
// row for its application, keyed name:port, with the source of the name and a
// version only where one was stated; the default site, which names no
// application, has none. `report -findings` and the default `hunt` list them.
func TestRunNamesEachAppOfAVirtualHost(t *testing.T) {
	lab := newNamesLabPages(t, map[string]string{
		"grafana." + namesZone: `<html><head><title>Grafana</title></head><body>sign in</body></html>`,
		"wiki." + namesZone:    `<html><head><title>Our site</title><meta name="generator" content="Acme CMS 3.1"></head><body>hello</body></html>`,
	})
	t.Chdir(t.TempDir())
	db := "apps.db"
	_, rep, code := runContract(t, append([]string{"run"}, lab.urlArgs("-db", db, "-no-paths", "-no-favicon")...)...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	out, _, err := captureBoth(t, func() error {
		return run([]string{"report", "-findings", "-db", db, "-format", "jsonl"})
	})
	if err != nil {
		t.Fatal(err)
	}
	type key struct{ host, product string }
	rows := map[key][]map[string]any{}
	for _, r := range jsonLines(t, out) {
		if r["type"] == "identification" {
			rows[key{fmt.Sprint(r["host"]), fmt.Sprint(r["product"])}] = append(rows[key{fmt.Sprint(r["host"]), fmt.Sprint(r["product"])}], r)
		}
	}
	graf := rows[key{"grafana." + namesZone, "Grafana"}]
	wp := rows[key{"wiki." + namesZone, "Acme CMS"}]
	if len(graf) != 1 || graf[0]["source"] != "page title" || graf[0]["version"] != nil || fmt.Sprint(graf[0]["port"]) != lab.port {
		t.Fatalf("Grafana by title: %v (all %v)", graf, rows)
	}
	if len(wp) == 0 || wp[0]["source"] != "generator" || wp[0]["version"] != "3.1" {
		t.Fatalf("Acme CMS by generator: %v", wp)
	}
	if !strings.Contains(fmt.Sprint(graf[0]["evidence"]), "<title>Grafana</title>") || graf[0]["excerpt_part"] != "body" {
		t.Errorf("the proof is the page's own words: %v", graf[0])
	}
	for k := range rows {
		if k.host == "127.0.0.2" && (k.product == "Grafana" || k.product == "Acme CMS") {
			t.Errorf("the default site names no application: %v", k)
		}
	}
	// hunt lists the same rows.
	hout, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, r := range jsonLines(t, hout) {
		if r["tier"] != "identification" {
			continue
		}
		if k := fmt.Sprint(r["key"]); k == fmt.Sprintf("grafana.%s:%s", namesZone, lab.port) || k == fmt.Sprintf("wiki.%s:%s", namesZone, lab.port) {
			seen++
			if r["source"] == nil {
				t.Errorf("hunt row %v names no source", r)
			}
		}
	}
	if seen < 2 {
		t.Errorf("hunt lists %d of the 2 names' rows:\n%s", seen, hout)
	}
}
