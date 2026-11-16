package hunt

import (
	"encoding/json"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/types"
)

func TestProvedPredicates(t *testing.T) {
	for title, want := range map[string]bool{"Index of /files": true, "listing directory /ftp": true, "Directory listing for /": true, "Acme": false, "Welcome to the index of things": false} {
		if IsListing(title) != want {
			t.Errorf("IsListing(%q) = %v", title, !want)
		}
	}
	r := urlRow("http://t.test/graphql", "api", "visited", 200, func(r *engine.MapEntry) { r.Ops = []engine.Op{{Method: "POST", Source: "graphql", Partial: true}} })
	if what, partial := GraphQLRead(r); what != GraphQLSchema || !partial {
		t.Errorf("a recovered schema is a partial read: %q %v", what, partial)
	}
	ide := urlRow("http://t.test/graphiql", "api", "visited", 200, func(r *engine.MapEntry) { r.Proof = "status=200 role=graphql" })
	if what, _ := GraphQLRead(ide); what != GraphQLIDE {
		t.Errorf("an IDE path: %q", what)
	}
	if what, _ := GraphQLRead(urlRow("http://t.test/graphql", "api", "visited", 400, func(r *engine.MapEntry) { r.Proof = "status=400 role=graphql" })); what != "" {
		t.Errorf("an answer that only looks like GraphQL proves nothing: %q", what)
	}
	for _, c := range []struct {
		row  RoleRow
		want bool
	}{
		{RoleRow{Verdict: "reads another role's object", Confidence: "proved"}, true},
		{RoleRow{Verdict: "reads another role's object"}, true},
		{RoleRow{Verdict: "reads another role's object", Confidence: "likely"}, false},
		{RoleRow{Verdict: "same for every role", Confidence: "proved"}, false},
	} {
		if c.row.Proved() != c.want {
			t.Errorf("%+v Proved = %v", c.row, !c.want)
		}
	}
	if !ProvedErrorText("sql") || !ProvedErrorText("debug") || ProvedErrorText("stack") {
		t.Error("SQL error text and a debug page are findings; a stack trace is its own record's")
	}
}

// A finding of these kinds is a row of its own, ranked as the signal always was,
// and the route has no lead that repeats it; a 5xx with SQL text that no record
// covers weighs as a lead.
func TestMeasuredWebFindingsAreRowsAndNoLeads(t *testing.T) {
	const o = "http://t.test"
	rows := []engine.MapEntry{
		urlRow(o+"/files/", "page", "visited", 200, func(r *engine.MapEntry) { r.Title = "Index of /files" }),
		urlRow(o+"/e1", "api", "visited", 500, func(r *engine.MapEntry) { r.Title = "Error" }),
		urlRow(o+"/e2", "api", "visited", 500, func(r *engine.MapEntry) { r.Title = "Error" }),
	}
	payload := func(sample string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"url": o, "status": 500, "error_text": "sql", "error_sample": sample})
		return b
	}
	obs := []types.StoredObservation{
		{EntityID: o + "/e1", Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: payload("SQLSTATE[HY000]")}},
		{EntityID: o + "/e2", Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: payload("SQLSTATE[HY000]")}},
	}
	got := Build(Input{DB: "w.db", Rows: rows, Obs: obs, Now: now,
		Measured: []Measured{
			{Kind: "directory-listing", Type: "URL", Host: o + "/files/", Severity: "low", Evidence: "HTTP 200: listing"},
			{Kind: "sql-error", Type: "URL", Host: o + "/e1", Severity: "medium", Evidence: "HTTP 500: SQL error text"},
		}})
	by := map[string]Row{}
	for _, r := range got {
		if _, dup := by[r.Key]; dup {
			t.Errorf("%s is listed twice: %+v", r.Key, got)
		}
		by[r.Key] = r
	}
	if r := by[o+"/files/"]; r.Tier != proof.TierFinding || r.Score != 55 || r.Reasons[0].Signal != "directory-listing" {
		t.Errorf("listing %+v", r)
	}
	if r := by[o+"/e1"]; r.Tier != proof.TierFinding || r.Score != serverErrorSQL {
		t.Errorf("sql error %+v", r)
	}
	if r := by[o+"/e2"]; r.Tier != proof.TierLead || r.Score != serverErrorSQL || !has(&r, "server-error") {
		t.Errorf("SQL text no record covers is a lead of the same weight: %+v", r)
	}
	if len(got) != 3 {
		t.Errorf("rows %+v", got)
	}
}

// A proved roles verdict adds no route row: its record is the finding.
func TestProvedRoleVerdictAddsNoRouteRow(t *testing.T) {
	got := Build(Input{Now: now, Roles: []RoleRow{{URL: "http://t.test/x", Verdict: "reads another role's object", Confidence: "proved"}}})
	if len(got) != 0 {
		t.Errorf("%+v", got)
	}
	got = Build(Input{Now: now, Measured: []Measured{{Kind: "cross-role-access", Type: "URL", Host: "http://t.test/x", Severity: "high", Score: 95, Next: "azhaq roles show -dir D http://t.test/x"}}})
	if len(got) != 1 || got[0].Score != 95 || got[0].Next != "azhaq roles show -dir D http://t.test/x" || got[0].Tier != proof.TierFinding {
		t.Errorf("%+v", got)
	}
}
