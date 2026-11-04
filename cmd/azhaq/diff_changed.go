package main

import (
	"encoding/json"
	"strings"
)

// changedRow is one thing that was there in both runs and differs: a route
// whose methods or fields changed, a page that answers differently, a host
// whose open ports changed. They are watch's "~" sections, one row each.
type changedRow struct {
	what string       // route, page, ports
	text string       // the change as watch words it
	rt   *routeChange // the route change, for a route
}

// changedRows lists the "~" changes of ch. A route that is new or gone is
// an entity added or removed, not a change.
func changedRows(ch changes) []changedRow {
	var out []changedRow
	hosts := map[string]bool{}
	for _, r := range ch.Routes {
		if r.Kind == "methods" || r.Kind == "fields" {
			hosts[r.Host] = true
		}
	}
	for i, r := range ch.Routes {
		if r.Kind == "methods" || r.Kind == "fields" {
			out = append(out, changedRow{what: "route", text: r.text(len(hosts) > 1), rt: &ch.Routes[i]})
		}
	}
	for _, c := range ch.Changed {
		out = append(out, changedRow{what: "page", text: c})
	}
	for _, p := range ch.Ports {
		out = append(out, changedRow{what: "ports", text: p})
	}
	return out
}

// json is the row as a diff -json line.
func (c changedRow) json() map[string]any {
	m := map[string]any{"kind": "changed", "what": c.what, "detail": strings.TrimPrefix(c.text, "~ ")}
	if c.rt != nil {
		raw, _ := json.Marshal(c.rt)
		var f map[string]any
		_ = json.Unmarshal(raw, &f)
		delete(f, "kind")
		f["change"] = c.rt.Kind
		for k, v := range f {
			m[k] = v
		}
	}
	return m
}

// line is the row as a line of the text report.
func (c changedRow) line() string {
	if c.what == "route" {
		return "  " + c.text // already starts with "~ "
	}
	return "  ~ " + c.what + " " + c.text
}
