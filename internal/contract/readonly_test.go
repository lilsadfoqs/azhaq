package contract

import (
	"path/filepath"
	"testing"
)

// Plan, query, show, export, diff, hunt, ledger, report and ingest read what
// a run left or print what one would do, and send nothing: no request, no
// connection, no new line in the ledger, and `requests` of 0 in the summary.
func TestCommandsThatReadSendNothing(t *testing.T) {
	l := newLabs(t)
	l.Cmd("run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db", "-proxy", l.Proxy.URL)
	l.Cmd("run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db", "-proxy", l.Proxy.URL)
	l.Cmd("roles", "-role", "anon", "-role", "alice=Authorization: Bearer t-alice", "-replay", "-dir", "rd", "-proxy", l.Proxy.URL, "--", "-url", l.Site.URL, "-allow", l.Allow())
	l.File("httpx.jsonl", `{"url":"`+l.Site.URL+`/ingested","status_code":200}`+"\n")

	ledger := filepath.Join(l.Dir, "w.db.ledger.jsonl")
	linesBefore := len(readLedger(t, ledger))
	wireBefore := l.Site.Wire.Total() + l.Proxy.Wire.Total()

	for _, args := range [][]string{
		{"plan", "-url", l.Site.URL, "-allow", l.Allow(), "-json"},
		{"query", "-db", "w.db", "-type", "URL", "-json"},
		{"show", "-db", "w.db", "-json", l.Site.URL + "/about"},
		{"export", "-db", "w.db", "-format", "urls"},
		{"export", "-db", "w.db", "-format", "openapi"},
		{"export", "-db", "w.db", "-format", "html"},
		{"diff", "-db", "w.db", "-json"},
		{"hunt", "-db", "w.db", "-json"},
		{"report", "-dir", "rd"},
		{"ledger", "-summary", "w.db.ledger.jsonl", "-json"},
		{"ledger", "-csv", "w.db.ledger.jsonl"},
		{"ingest", "-db", "in.db", "-json", "httpx.jsonl"},
	} {
		t.Run(args[0]+" "+args[1], func(t *testing.T) {
			r := RunRaw(t, l.Dir, nil, args...)
			if r.Code != 0 && r.Code != 3 {
				t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
			}
			if r.Has && r.Summary.Requests != 0 {
				t.Errorf("the summary says %d requests", r.Summary.Requests)
			}
		})
	}
	if got := l.Site.Wire.Total() + l.Proxy.Wire.Total(); got != wireBefore {
		t.Errorf("the reading commands sent %d requests to the site and the proxy", (got-wireBefore)/2)
	}
	if got := len(readLedger(t, ledger)); got != linesBefore {
		t.Errorf("the ledger holds %d new lines", got-linesBefore)
	}
}
