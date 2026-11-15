package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// foldLab serves one application that a run reaches as its address and as
// localhost: a dashboard its own title names (a finding), an admin path whose
// answer does not show a panel (a lead), an API description (a lead) and a
// script that names a route.
func foldLab(t *testing.T) (db, byAddr, byName string) {
	t.Helper()
	if addrs, err := net.LookupHost("localhost"); err != nil || !slices.Contains(addrs, "127.0.0.1") {
		t.Skipf("localhost does not resolve to 127.0.0.1: %v %v", addrs, err)
	}
	egress.Reset()
	t.Cleanup(egress.Reset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>lab</title></head><body><a href="/dashboard">d</a> <a href="/admin">a</a></body></html>`)
		case "/dashboard", "/admin":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>Dashboard</title></head><body>ops dashboard</body></html>")
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, foldSwagger)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	byAddr, byName = "http://127.0.0.1:"+port, "http://localhost:"+port
	t.Chdir(t.TempDir())
	db = filepath.Join(t.TempDir(), "fold.db")
	_, rep, code := runContract(t, "run", "-url", byAddr+"/", "-url", byName+"/", "-allow", "127.0.0.1:"+port, "-allow", "localhost:"+port,
		"-sources", "none", "-no-history", "-no-favicon", "-db", db)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	return db, byAddr, byName
}

// One service reached by its address and by a name that resolves to it is one
// finding in `report -findings` and in `export -format findings`, as it is one
// row in hunt, with the other URL in also_at.
func TestFindingsOneRecordForAServiceReachedByAddressAndName(t *testing.T) {
	db, byAddr, byName := foldLab(t)
	for name, get := range map[string]func() (string, error){
		"report": func() (string, error) {
			out, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl"}) })
			return out, err
		},
		"export": func() (string, error) {
			out, _, err := captureBoth(t, func() error { return run([]string{"export", "-db", db, "-format", "findings"}) })
			return out, err
		},
	} {
		out, err := get()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var panels []map[string]any
		for _, r := range jsonLines(t, out) {
			if r["type"] == "finding" && r["kind"] == "exposed-panel" {
				panels = append(panels, r)
			}
		}
		if len(panels) != 1 {
			t.Fatalf("%s: %d dashboard findings, want 1 (one service, two names):\n%s", name, len(panels), out)
		}
		url := panels[0]["url"].(string)
		other := byName + "/dashboard"
		if url == other {
			other = byAddr + "/dashboard"
		}
		if also, _ := panels[0]["also_at"].([]any); len(also) != 1 || also[0] != other {
			t.Errorf("%s: the finding names %v as answering the same, want [%s]", name, panels[0]["also_at"], other)
		}
	}
	// Markdown says it too.
	md, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md, "the same answer at "+byName+"/dashboard") && !strings.Contains(md, "the same answer at "+byAddr+"/dashboard") {
		t.Errorf("the Markdown finding does not name the other URL:\n%s", md)
	}
}

// hunt and `report -findings` read one workspace: the finding count is the
// same, a row both list has the same tier, and each says what its identification
// and lead counts are of, since hunt ranks routes and hosts with a signal and the
// findings output lists hints and checks.
func TestHuntAndReportCountTheSameFindingsAndTierOfARow(t *testing.T) {
	db, _, _ := foldLab(t)
	g, err := readGraph(db)
	if err != nil {
		t.Fatal(err)
	}
	set := buildFindings(g)
	rows := huntRows(g, db, nil, 7*24*time.Hour)
	hc, rc := countRows(rows), set.counts()
	if hc.Findings != rc.Findings || hc.Findings != 1 {
		t.Errorf("hunt counts %d findings, report %d, want 1 and 1 (the dashboard, once)", hc.Findings, rc.Findings)
	}
	if hc.IdentificationsOf == "" || hc.LeadsOf == "" || rc.IdentificationsOf == "" || rc.LeadsOf == "" || hc.LeadsOf == rc.LeadsOf {
		t.Errorf("the counts do not say what they are of: hunt %+v, report %+v", hc, rc)
	}
	// The tier of the same row.
	tierOf := map[string]string{}
	for _, list := range [][]findingRecord{set.Findings, set.Leads} {
		for _, r := range list {
			if r.URL != "" && r.Kind != "hint" {
				tierOf[r.URL] = r.Tier
				for _, a := range r.Also {
					tierOf[a] = r.Tier
				}
			}
		}
	}
	shared := 0
	for _, r := range rows {
		if got, ok := tierOf[r.Key]; ok {
			shared++
			if got != r.Tier {
				t.Errorf("%s is %s in hunt and %s in report", r.Key, r.Tier, got)
			}
		}
	}
	if shared < 2 {
		t.Errorf("only %d rows are in both lists; the lab holds a finding and a lead both list: hunt %v, report %v", shared, rows, tierOf)
	}
	// A parsed API description is a lead in hunt, and in no tier above it.
	for _, r := range rows {
		if strings.HasSuffix(r.Key, "/openapi.json") && r.Tier != "lead" {
			t.Errorf("the API description is a %s in hunt, want lead: %+v", r.Tier, r)
		}
	}
	// The text of both says what the counts are of.
	_, errOut, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db}) })
	if err != nil || !strings.Contains(errOut, "counted: identifications are "+huntIdentificationsOf+"; leads are "+huntLeadsOf) {
		t.Errorf("hunt's summary does not say what it counts: %v %s", err, errOut)
	}
	_, jsonErr, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json"}) })
	if err != nil || !strings.Contains(jsonErr, `"identifications_of":"`+huntIdentificationsOf+`","leads_of":"`+huntLeadsOf+`"`) {
		t.Errorf("hunt's JSON summary lacks the basis of its counts: %v %s", err, jsonErr)
	}
	md, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db}) })
	if err != nil || !strings.Contains(md, "Counted: identifications are "+reportIdentificationsOf+"; leads are "+reportLeadsOf) {
		t.Errorf("report -findings does not say what it counts: %v\n%.400s", err, md)
	}
	// Both commands count with one function: hunt's rows through the report's.
	var asRows []tierRow
	for _, r := range rows {
		asRows = append(asRows, tierRow{Tier: r.Tier})
	}
	if got := countTiers(asRows, huntIdentificationsOf, huntLeadsOf); got != hc {
		t.Errorf("hunt counts %+v, countTiers %+v", hc, got)
	}
}
