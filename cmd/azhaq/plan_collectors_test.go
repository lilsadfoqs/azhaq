package main

import (
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/collectors"
)

// Every flag that asks run for a collector is in the plan, by name: in its
// active techniques or in what it sends. Chrome's two flags also list the
// collector, since it runs on the targets given. The flags are the catalog's
// own (the collectors a flag turns on) and the two that start Chrome.
func TestPlanListsEveryCollectorFlag(t *testing.T) {
	dir := t.TempDir()
	// flag → its arguments and the collector on the targets (empty: it works on what is found).
	asks := map[string]struct {
		args      []string
		collector string
	}{
		"ports":       {[]string{"-ports", "22,80"}, ""},
		"params":      {[]string{"-params", wlist(t, "q")}, ""},
		"dns-brute":   {[]string{"-dns-brute", wlist(t, "www")}, ""},
		"permute":     {[]string{"-permute"}, ""},
		"graphql":     {[]string{"-graphql"}, ""},
		"dirs":        {[]string{"-dirs", wlist(t, "admin")}, ""},
		"screenshots": {[]string{"-screenshots", dir}, "azhaq-shots"},
		"browser":     {[]string{"-browser"}, "azhaq-render"},
	}
	cat := catalog.New()
	collectors.RegisterAll(cat, nil)
	for _, n := range cat.Names() {
		c, _ := cat.Get(n)
		if f := catalog.InfoOf(c).Flag; f != "" {
			if _, ok := asks[f]; !ok {
				t.Errorf("%s is asked for by -%s, and this test has no arguments for it", n, f)
			}
		}
	}
	for flag, a := range asks {
		for _, probe := range []bool{false, true} {
			args := append([]string{"-domain", "example.com", "-url", "http://127.0.0.1:3001/", "-sources", "none"}, a.args...)
			if probe {
				args = append(args, "-probe")
			}
			p := planJSON(t, args...)
			listed := a.collector == ""
			for name := range p.Collectors {
				listed = listed || name == a.collector
			}
			if !listed {
				t.Errorf("-%s (probe %v): the plan does not list %s: %v", flag, probe, a.collector, p.Collectors)
			}
			text := strings.Join(p.Sends, "\n") + strings.Join(p.Active, " ")
			if !strings.Contains(text, "-"+flag) {
				t.Errorf("-%s (probe %v): the plan does not say what it sends:\n%s", flag, probe, text)
			}
		}
	}
}

// -screenshots says where the pictures go and that Chrome fetches more
// than the page.
func TestPlanSaysWhatScreenshotsSend(t *testing.T) {
	dir := t.TempDir()
	p := planJSON(t, "-url", "http://127.0.0.1:3001/", "-sources", "none", "-screenshots", dir)
	text := strings.Join(p.Sends, "\n")
	for _, want := range []string{"Chrome loads the front page", "screenshot in " + dir, "scripts, styles and images"} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan lacks %q:\n%s", want, text)
		}
	}
}
