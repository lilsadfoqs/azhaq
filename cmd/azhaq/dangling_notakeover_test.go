package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// danglingCounts are the dangling-dns records of a workspace, by name, and the
// findings count the run summary gave.
func danglingFindings(t *testing.T, db string) map[string]map[string]any {
	t.Helper()
	out, _, err := captureBoth(t, func() error {
		return run([]string{"report", "-findings", "-db", db, "-format", "jsonl"})
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, r := range jsonLines(t, out) {
		if r["type"] == "finding" && r["kind"] == "dangling-dns" {
			got[r["host"].(string)] = r
		}
	}
	return got
}

// underDomain are the questions asked about a name at or below domain.
func underDomain(asked []string, domain string) []string {
	var out []string
	for _, q := range asked {
		name, _, _ := strings.Cut(q, " ")
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		if name == domain || strings.HasSuffix(name, "."+domain) {
			out = append(out, q)
		}
	}
	return out
}

// -no-takeover stops the questions about a CNAME target's domain, not the
// finding the name's own answer makes: `dns` (A, and -cname alone, which asks A
// once for the name itself) and `run` both make the dangling-dns finding, the
// run's summary counts it, and no question names the target or its domain.
func TestNoTakeoverKeepsTheDanglingFinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(res, db string) []string
	}{
		{"dns", func(res, db string) []string {
			return []string{"dns", "-d", "shop.example.org,old.example.org,legacy.example.org", "-r", res, "-no-takeover", "-allow", "example.org", "-allow", "nobody-holds.com", "-db", db, "-json"}
		}},
		{"dns -cname", func(res, db string) []string {
			return []string{"dns", "-d", "shop.example.org,old.example.org,legacy.example.org", "-r", res, "-cname", "-no-takeover", "-allow", "example.org", "-allow", "nobody-holds.com", "-db", db, "-json"}
		}},
		{"run, targets outside the scope", func(res, db string) []string {
			return []string{"run", "-domain", "example.org", "-resolvers", res, "-sources", "none", "-no-takeover", "-no-history",
				"-allow", "example.org", "-db", db}
		}},
		{"run", func(res, db string) []string {
			return []string{"run", "-domain", "example.org", "-resolvers", res, "-sources", "none", "-no-takeover", "-no-history",
				"-allow", "example.org", "-allow", "azurewebsites.net", "-allow", "nobody-holds.com", "-db", db}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, asked := danglingLabAsked(t)
			db := filepath.Join(t.TempDir(), "w.db")
			t.Chdir(t.TempDir())
			args := tc.args(res, db)
			var rep report
			if args[0] == "run" {
				_, rep, _ = runContract(t, args...)
			} else {
				_, rep, _ = dnsOut(t, args[1:]...)
			}
			got := danglingFindings(t, db)
			if got["shop.example.org"] == nil || got["old.example.org"] == nil || got["legacy.example.org"] == nil {
				t.Fatalf("dangling-dns findings %v, want shop, old and legacy", got)
			}
			for _, d := range []string{"azurewebsites.net", "nobody-holds.com", "cloudprovider.example"} {
				if q := underDomain(asked(), d); len(q) > 0 {
					t.Errorf("-no-takeover asked about %s: %v", d, q)
				}
			}
			if rep.Tiers != nil && rep.Tiers.Findings < 2 {
				t.Errorf("the run's findings count %+v leaves out the dangling names", rep.Tiers)
			}
			hout, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db}) })
			if err != nil || !strings.Contains(hout, "dangling-dns") {
				t.Errorf("hunt (%v):\n%s", err, hout)
			}
		})
	}
}

// The counter above sees the questions the flag stops: without -no-takeover
// the check asks for the registration of the target's domain.
func TestNoTakeoverCounterSeesTheQuestionsItStops(t *testing.T) {
	res, asked := danglingLabAsked(t)
	t.Chdir(t.TempDir())
	if _, _, code := dnsOut(t, "-d", "legacy.example.org", "-r", res, "-allow", "example.org", "-allow", "nobody-holds.com", "-json"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if q := underDomain(asked(), "nobody-holds.com"); len(q) == 0 {
		t.Errorf("without -no-takeover nothing was asked about nobody-holds.com: %v", asked())
	}
}

// The dangling-dns row says what was measured and nothing is unverified in it;
// the takeover lead beside it says "unverified" of who can claim the name only,
// and hunt's row for it points to the dangling finding for the record itself.
func TestDanglingAndTakeoverRowsDoNotReadAsOneClaim(t *testing.T) {
	res := danglingLab(t)
	db := filepath.Join(t.TempDir(), "w.db")
	t.Chdir(t.TempDir())
	if _, _, code := dnsOut(t, "-d", "shop.example.org", "-r", res, "-db", db, "-json"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	out, _, err := captureBoth(t, func() error {
		return run([]string{"report", "-findings", "-db", db, "-format", "jsonl"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var finding, lead string
	for _, r := range jsonLines(t, out) {
		switch {
		case r["kind"] == "dangling-dns":
			finding, _ = r["evidence"].(string)
		case r["kind"] == "takeover":
			lead, _ = r["evidence"].(string)
		}
	}
	if !strings.Contains(finding, "points by CNAME at gone.azurewebsites.net") || !strings.Contains(finding, "a name that does not exist") ||
		strings.Contains(finding, "unverified") || strings.Contains(strings.ToLower(finding), "proven") {
		t.Errorf("dangling evidence %q", finding)
	}
	if !strings.Contains(lead, "Who can claim the name is unverified") || strings.Contains(lead, "Candidate, unverified") {
		t.Errorf("takeover evidence %q", lead)
	}
	hunt, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db}) })
	if err != nil || !strings.Contains(hunt, "unverified who can claim gone.azurewebsites.net") || !strings.Contains(hunt, "the dangling-dns finding") {
		t.Errorf("hunt (%v):\n%s", err, hunt)
	}
}
