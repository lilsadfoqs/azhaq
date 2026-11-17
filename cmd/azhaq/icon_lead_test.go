package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/icontest"
)

// GitLab's catalog icon, and the one read its own template asks. See
// internal/detect: the icon alone is all the shared favicon template reads.
const (
	iconGitlab     = "1278323681"
	iconGitlabRead = "/users/sign_in"
)

// iconSite serves a bare page, the icon of hash and, when read is set, the
// product's own page at its path; every other path answers 404.
func iconSite(t *testing.T, hash string, read bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			_, _ = w.Write([]byte("<html><head><title>Welcome</title></head><body>hello</body></html>"))
		case r.URL.Path == "/favicon.ico":
			_, _ = w.Write(icontest.Body(hash))
		case r.URL.Path == iconGitlabRead && read:
			_, _ = w.Write([]byte("<html><body>GitLab https://about.gitlab.com</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func hasProduct(set findingSet, product string) (ident, lead *findingRecord) {
	for i, r := range set.Identifications {
		if strings.EqualFold(r.Product, product) {
			ident = &set.Identifications[i]
		}
	}
	for i, r := range set.Leads {
		if strings.EqualFold(r.Product, product) {
			lead = &set.Leads[i]
		}
	}
	return ident, lead
}

// A favicon in the catalog names GitLab on a page that is not GitLab: every
// path of the product answers 404. It is a lead that says what matched and
// what was asked, with no version and no advisory; the tiers, hunt and the
// findings output count it as a lead, and hunt ranks it below the
// identification another listener has.
func TestRunTreatsAFaviconAloneAsALead(t *testing.T) {
	express := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("<html><title>api</title></html>"))
	}))
	t.Cleanup(express.Close)
	srv := iconSite(t, iconGitlab, false)
	t.Chdir(t.TempDir())
	_, stderr, code := cli(t, "run", "-url", srv.URL+"/", "-url", express.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db", "-ledger", "w.ledger")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	g, err := readGraph("w.db")
	if err != nil {
		t.Fatal(err)
	}
	set := buildFindings(g)
	ident, lead := hasProduct(set, "gitlab")
	if ident != nil {
		t.Errorf("a favicon alone is an identification: %+v", ident)
	}
	if lead == nil {
		t.Fatalf("no lead for the favicon (leads %d)", len(set.Leads))
	}
	if lead.Tier != "lead" || lead.Kind != "favicon-match" || lead.Version != "" || lead.AdvisoryID != "" {
		t.Errorf("lead %+v", lead)
	}
	for _, want := range []string{"favicon matches gitlab", iconGitlab} {
		if !strings.Contains(lead.Evidence, want) {
			t.Errorf("evidence %q lacks %q", lead.Evidence, want)
		}
	}
	for _, a := range set.Identifications {
		if strings.EqualFold(a.Product, "gitlab") {
			t.Errorf("advisory or identification of the favicon's product: %+v", a)
		}
	}
	if c := set.counts(); c.Leads == 0 {
		t.Errorf("the lead is not counted: %+v", c)
	}
	if !strings.Contains(set.headline(), "lead") {
		t.Errorf("headline %q", set.headline())
	}

	rows := huntRows(g, "w.db", nil, 7*24*time.Hour)
	var leadAt, identAt = -1, -1
	for i, r := range rows {
		switch {
		case r.Tier == "lead" && len(r.Reasons) > 0 && r.Reasons[0].Signal == "favicon":
			leadAt = i
			if !strings.Contains(r.Reasons[0].Detail, "favicon matches gitlab") || r.Check == "" {
				t.Errorf("hunt lead %+v", r)
			}
		case r.Ident != nil && r.Tier == "identification":
			identAt = i
		}
		if r.Ident != nil && strings.EqualFold(r.Product, "gitlab") {
			t.Errorf("hunt names the favicon's product on a listener: %+v", r.Ident)
		}
	}
	if leadAt < 0 || identAt < 0 || leadAt < identAt {
		t.Errorf("lead at %d, identification at %d: the lead ranks below every identification (%d rows)", leadAt, identAt, len(rows))
	}
	if n := countRows(rows); n.Leads == 0 || n.Identifications == 0 {
		t.Errorf("hunt tiers %+v", n)
	}

	stdout, _, code := cli(t, "report", "-findings", "-db", "w.db")
	if _, leads, ok := strings.Cut(stdout, "## Leads"); code != 0 || !ok || !strings.Contains(leads, "favicon-match") || !strings.Contains(leads, "favicon matches gitlab") {
		t.Errorf("report -findings (exit %d) lists no such lead among its leads:\n%s", code, stdout)
	}
	jsonl, _, code := cli(t, "export", "-format", "findings", "-db", "w.db")
	if code != 0 || !strings.Contains(jsonl, `"kind":"favicon-match"`) || !strings.Contains(jsonl, `"tier":"lead"`) {
		t.Errorf("export -format findings (exit %d) lists no such lead:\n%s", code, jsonl)
	}
}
