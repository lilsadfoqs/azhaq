package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/hunt"
)

const needQuote = "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly."

// needFindings is a listener's advisories: a conditional top that waits on
// HTTP/2, another on a module, and one a probe settled.
func needFindings() findingSet {
	var set findingSet
	add := func(id, label string, cvss float64, needs []string, pre, settled string) {
		set.Identifications = append(set.Identifications, findingRecord{
			Tier: "identification", Kind: "advisory-precondition", Label: label, Severity: "info", Host: "10.0.0.5", Port: 443,
			Product: "nginx", Version: "1.11.13", AdvisoryID: id, CVSS: cvss, Needs: needs, Precondition: pre, Settled: settled,
			Lead: "10.0.0.5:443 nginx", Evidence: "e", Command: "azhaq run",
		})
	}
	add("CVE-2023-44487", "conditional", 7.5, []string{"HTTP/2"}, `needs HTTP/2: "`+needQuote+`"`, "")
	add("CVE-2024-38475", "conditional", 9.1, []string{"mod_rewrite"}, `needs mod_rewrite: "Improper escaping of output in mod_rewrite"`, "")
	add("CVE-2023-0001", "version-only", 5.0, nil, "", "HTTP/2 offered (ALPN h2)")
	sortFindings(&set)
	return set
}

func sortFindings(set *findingSet) {
	for i := 1; i < len(set.Identifications); i++ {
		for j := i; j > 0 && findingLess(set.Identifications[j], set.Identifications[j-1]); j-- {
			set.Identifications[j], set.Identifications[j-1] = set.Identifications[j-1], set.Identifications[j]
		}
	}
}

// The findings Markdown names what a conditional advisory waits on in the
// fold, and the bullet of a conditional top says the condition with its
// quote; what the run settled is said where it did.
func TestFindingsMarkdownSaysTheCondition(t *testing.T) {
	set := needFindings()
	md := string(findingsMarkdown(set))
	for _, want := range []string{
		"CVE-2023-0001 (version-only, CVSS 5.0), CVE-2024-38475 (conditional: needs mod_rewrite, CVSS 9.1), CVE-2023-44487 (conditional: needs HTTP/2, CVSS 7.5)",
		"; settled: HTTP/2 offered (ALPN h2)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	// Alone, a conditional record shows its condition with the quote.
	var only findingSet
	for _, r := range set.Identifications {
		if r.AdvisoryID == "CVE-2023-44487" {
			only.Identifications = append(only.Identifications, r)
		}
	}
	if md := string(findingsMarkdown(only)); !strings.Contains(md, `; precondition: needs HTTP/2: "`+needQuote+`"`) {
		t.Errorf("markdown of a conditional record:\n%s", md)
	}
	// The JSON Lines carry it for each record, with the label.
	jl := string(findingsJSONL(set))
	for _, want := range []string{`"label":"conditional"`, `"needs":["HTTP/2"]`, `"precondition":"needs HTTP/2: \"The HTTP/2 protocol`, `"settled":"HTTP/2 offered (ALPN h2)"`} {
		if !strings.Contains(jl, want) {
			t.Errorf("JSON Lines lack %q:\n%s", want, jl)
		}
	}
}

// A hunt row says what its conditional top advisory waits on, with the quote,
// and names the next ones with what they wait on.
func TestHuntRowSaysTheCondition(t *testing.T) {
	set := needFindings()
	// All conditional: the top is the first, the next one follows.
	set.Identifications = set.Identifications[1:]
	ls := listenersOf(set)
	if len(ls) != 1 || ls[0].Ident.Label != "conditional" || ls[0].Ident.Precondition == "" {
		t.Fatalf("listeners %+v", ls)
	}
	rows := hunt.ListenerRows(ls, "w.db")
	var detail string
	for _, r := range rows[0].Reasons {
		if r.Signal == "advisory" {
			detail = r.Detail
		}
	}
	for _, want := range []string{
		`CVE-2024-38475 conditional, CVSS 9.1; precondition: needs mod_rewrite: "Improper escaping of output in mod_rewrite"`,
		"; 2 advisories match this version, then CVE-2023-44487 (conditional: needs HTTP/2, CVSS 7.5)",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("advisory reason %q lacks %q", detail, want)
		}
	}
	// A row whose top a probe settled says so.
	ls = listenersOf(needFindings())
	if got := hunt.ListenerRows(ls, "w.db")[0]; !strings.Contains(fmt.Sprint(got.Reasons), "settled: HTTP/2 offered (ALPN h2)") {
		t.Errorf("reasons %v", got.Reasons)
	}
}

// http10Server answers HTTP/1.0 and closes, with the Server header given: a
// listener that cannot speak HTTP/2.
func http10Server(t *testing.T, server string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				c.Read(buf)
				body := "<html><head><title>ok</title></head><body>hello</body></html>"
				fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", server, len(body), body)
			}()
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

// On a loopback listener the embedded index matches, a record whose text
// needs HTTP/2 (an HTTP/1.0-only nginx) or mod_rewrite (an Apache httpd) is
// conditional with the words it was read from and ranks below every
// version-only match with nothing open; the stored lead, report -findings and
// its JSON Lines say so, and every match stays listed.
func TestRunRanksATextConditionBelowAPlainMatch(t *testing.T) {
	useBuiltinIndex(t)
	for _, c := range []struct{ server, id, need string }{
		{"nginx/1.11.13", "CVE-2023-44487", "HTTP/2"},
		{"Apache/2.4.54 (Unix)", "CVE-2024-38475", "mod_rewrite"},
	} {
		url := http10Server(t, c.server)
		db := filepath.Join(t.TempDir(), "w.db")
		_, errOut, err := captureBoth(t, func() error {
			return cmdRun([]string{"-db", db, "-json", "-depth", "0", "-no-paths", "-no-tech", "-no-favicon", "-url", url})
		})
		if err != nil {
			t.Fatalf("run: %v\n%s", err, errOut)
		}
		rep := withStoredAdvisories(t, db, lastReport(t, errOut))
		if len(rep.Advisories) != 1 {
			t.Fatalf("%s: %d leads", c.server, len(rep.Advisories))
		}
		lead := rep.Advisories[0]
		if lead.Label != advisory.LabelAffected || lead.AdvisoryID == c.id || len(lead.Needs) != 0 {
			t.Errorf("%s: the top is %s (%s %v)", c.server, lead.AdvisoryID, lead.Label, lead.Needs)
		}
		seenConditional, found := false, false
		for _, r := range lead.Advisories {
			if r.Label == advisory.LabelConditional {
				seenConditional = true
			}
			if r.Label == advisory.LabelAffected && seenConditional && r.Component == "" {
				t.Errorf("%s: %s (affected) is listed after a conditional match", c.server, r.ID)
			}
			if r.ID == c.id {
				found = true
				if r.Label != advisory.LabelConditional || len(r.Needs) == 0 || r.Needs[0] != c.need || !strings.Contains(r.Precondition, `needs `+c.need+`: "`) {
					t.Errorf("%s: %s is %s %v %q", c.server, r.ID, r.Label, r.Needs, r.Precondition)
				}
			}
		}
		if !found {
			t.Errorf("%s: %s is not listed", c.server, c.id)
		}
		// report -findings: the JSON Lines record of the advisory says the condition with its label.
		jl, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl"}) })
		if err != nil {
			t.Fatal(err)
		}
		line := ""
		for _, l := range strings.Split(jl, "\n") {
			if strings.Contains(l, `"advisory_id":"`+c.id+`"`) {
				line = l
			}
		}
		if !strings.Contains(line, `"label":"conditional"`) || !strings.Contains(line, `"precondition":"needs `+c.need+`: `) {
			t.Errorf("%s: the findings record of %s: %s", c.server, c.id, line)
		}
		md, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db, "-format", "md"}) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(md, "conditional") || !strings.Contains(md, " more: ") {
			t.Errorf("%s: markdown does not count the conditional ones:\n%s", c.server, md)
		}
		_ = os.Remove(db)
	}
}
