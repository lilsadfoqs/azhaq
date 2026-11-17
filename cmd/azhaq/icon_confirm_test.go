package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/hunt"
)

func iconRun(t *testing.T, srv *httptest.Server, extra ...string) *graphView {
	t.Helper()
	t.Chdir(t.TempDir())
	args := append([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db", "-ledger", "w.ledger"}, extra...)
	if _, stderr, code := cli(t, args...); code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	g, err := readGraph("w.db")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// An icon alone leaves the lead, and the lead says what was asked and what came back.
func TestRunSaysWhatItAskedOfAnIconAndWhatCameBack(t *testing.T) {
	g := iconRun(t, iconSite(t, iconGitlab, false))
	ident, lead := hasProduct(buildFindings(g), "gitlab")
	if ident != nil || lead == nil {
		t.Fatalf("identification %+v, lead %+v", ident, lead)
	}
	if want := "gitlab: GET " + iconGitlabRead + " answered 404 and no template of the product matched"; !strings.Contains(lead.Evidence, want) {
		t.Errorf("evidence %q lacks %q", lead.Evidence, want)
	}
}

// When the product's own read answers as its template says, the name is an
// identification with that proof, and nothing is left of the lead.
func TestRunNamesTheProductWhenItsOwnReadConfirmsTheFavicon(t *testing.T) {
	g := iconRun(t, iconSite(t, iconGitlab, true))
	set := buildFindings(g)
	ident, lead := hasProduct(set, "gitlab")
	if lead != nil {
		t.Errorf("a lead beside the confirming read: %+v", lead)
	}
	if ident == nil {
		t.Fatalf("the confirming read named no identification (identifications %+v)", set.Identifications)
	}
	if !strings.Contains(ident.Evidence, "GET "+iconGitlabRead+" answered 200") {
		t.Errorf("evidence %q does not name the read", ident.Evidence)
	}
	var row *hunt.Row
	for _, r := range huntRows(g, "w.db", nil, 7*24*time.Hour) {
		if r.Ident != nil && strings.EqualFold(r.Product, "gitlab") {
			row = &r
		}
	}
	if row == nil || row.Tier != "identification" {
		t.Errorf("hunt row %+v", row)
	}
}

// With -no-paths nothing asks the product's read, and the lead says so.
func TestRunKeepsTheFaviconALeadWhenNoReadIsAsked(t *testing.T) {
	g := iconRun(t, iconSite(t, iconGitlab, true), "-no-paths")
	ident, lead := hasProduct(buildFindings(g), "gitlab")
	if ident != nil || lead == nil || !strings.Contains(lead.Evidence, "not asked: the product checks are off (-no-paths)") {
		t.Errorf("identification %+v, lead %+v", ident, lead)
	}
}
