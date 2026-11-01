package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// The unit lists name the same sections a run takes.
func TestUnitsCoverSections(t *testing.T) {
	all := append(slices.Clone(cmpSections), onceSections...)
	slices.Sort(all)
	want := slices.Clone(sections)
	slices.Sort(want)
	if !slices.Equal(all, want) {
		t.Errorf("units hold sections %v, -only knows %v", all, want)
	}
	for _, s := range cmpSections {
		if !perProfile[s] {
			t.Errorf("%s is a comparison section but not a perProfile one", s)
		}
	}
	if len(perProfile) != len(cmpSections) {
		t.Errorf("%d perProfile sections, %d comparison units", len(perProfile), len(cmpSections))
	}
	if n := len(claimCaseIDs()); n != 11 {
		t.Errorf("%d claims cases", n)
	}
	units := canonicalUnits()
	if len(units) != 2*(len(cmpSections)-1+len(domainList()))+len(onceSections)-1+len(claimCaseIDs()) {
		t.Errorf("%d units: %v", len(units), units)
	}
	if len(units) != len(slices.Compact(slices.Sorted(slices.Values(units)))) {
		t.Errorf("a unit is listed twice: %v", units)
	}
}

func TestUnitsParse(t *testing.T) {
	got, err := parseUnits("default:apps, polite:dirs,claims:5,once:dropin,")
	if err != nil || strings.Join(got, " ") != "default:apps polite:dirs claims:5 once:dropin" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"apps", "default:claims", "once:apps", "claims:12", "polite:docs"} {
		if _, err := parseUnits(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// The plan's input: the profiles chosen, a section's own answer.
func TestUnitsPlannedByProfileAndSection(t *testing.T) {
	on := func(unit, section string) bool { return section != "ports" && section != "docs" && section != "claims" }
	got := plannedUnits([]string{profPolite}, on)
	if slices.Contains(got, "default:apps") || !slices.Contains(got, "polite:apps") || slices.Contains(got, "polite:ports") {
		t.Errorf("polite only: %v", got)
	}
	if !slices.Contains(got, "once:dropin") || slices.Contains(got, "once:docs") || slices.Contains(got, "claims:1") {
		t.Errorf("once sections: %v", got)
	}
	// What the units list says is the order a run takes them.
	if !slices.IsSortedFunc(got, func(a, b string) int { return unitRank(a) - unitRank(b) }) {
		t.Errorf("not in the order of a run: %v", got)
	}
	politeDomains = domainList()
	defer func() { politeDomains = nil }()
	all := plannedUnits(profileOrder, func(string, string) bool { return true })
	if !slices.Equal(all, canonicalUnits()) {
		t.Errorf("everything selected: %v", all)
	}
}

func TestUnitsTrackWhatEachWrote(t *testing.T) {
	rec = record{}
	prof = profDefault
	defer func() { prof, rec = "", record{} }()
	runUnit("default:apps", func() { addCheck("a", true, ""); addCheck("b", true, "") })
	runUnit("default:dirs", func() { rec.Runs = append(rec.Runs, runMeasure{Tool: "ffuf"}) })
	n := 0
	trackUnit("claims:1", func() int { return n }, func() { n = 3; addCheck("c", true, "") })
	want := []unitSpan{{"default:apps", 2, 0, 0}, {"default:dirs", 0, 1, 0}, {"claims:1", 1, 0, 3}}
	if !slices.Equal(rec.Units, want) {
		t.Errorf("spans %+v, want %+v", rec.Units, want)
	}
}

// The domains are units of their own, the polite profile's only those it looks up.
func TestUnitsOneDomainEach(t *testing.T) {
	politeDomains = []string{"hackerone.com", "vulnweb.com"}
	defer func() { politeDomains = nil }()
	got := plannedUnits(profileOrder, func(u, s string) bool { return s == "domains" })
	want := []string{"default:domains/hackerone.com", "default:domains/tesla.com", "default:domains/vulnweb.com", "polite:domains/hackerone.com", "polite:domains/vulnweb.com"}
	if !slices.Equal(got, want) {
		t.Errorf("units %v, want %v", got, want)
	}
	if unitSection(got[0]) != "domains" || unitSection("claims:3") != "claims" || unitSection("once:docs") != "docs" {
		t.Error("unitSection")
	}
	if _, err := parseUnits("default:domains,polite:domains/nowhere.example"); err == nil {
		t.Error("a domains unit without a domain, or of a domain not in the list, was accepted")
	}
}

// A unit that runs alone must bring up the docker apps it measures: every
// section whose file names an app of bench/compose.yaml needs them, or it
// measures a refused connection (openapi once exported "0 paths" in a job
// that held no section starting them).
func TestUnitsStartTheAppsTheyUse(t *testing.T) {
	for _, s := range sections {
		raw, err := os.ReadFile(s + ".go")
		if err != nil {
			continue
		}
		src := string(raw)
		if (strings.Contains(src, "juiceURL") || strings.Contains(src, "vampiURL")) && s != "apps" && !slices.Contains(dockerParts, s) {
			t.Errorf("%s.go uses the docker apps but %q is not in dockerParts", s, s)
		}
	}
	for _, s := range []string{"openapi", "probe", "dirs", "fuzz", "scope", "scale"} { // main.go hands them the apps
		if !slices.Contains(dockerParts, s) {
			t.Errorf("%q is not in dockerParts", s)
		}
	}
}

// A unit that dies through fatal or a panic is a failed check; the units
// before it keep their results and the ones after it still run.
func TestUnitThatDiesKeepsTheOthers(t *testing.T) {
	rec = record{}
	prof = profDefault
	defer func() { prof, rec, inUnit = "", record{}, "" }()
	runUnit("default:fuzz", func() { addCheck("fuzz ok", true, "") })
	runUnit("default:dns", func() {
		addCheck("dns started", true, "")
		fatal("listen tcp 127.0.0.1:1: bind: address already in use")
	})
	runUnit("default:ports", func() { var m map[string]int; m["x"] = 1 })
	runUnit("default:notify", func() { addCheck("notify ok", true, "") })
	var names []string
	for _, c := range rec.Checks {
		names = append(names, fmt.Sprintf("%s=%v", c.Name, c.Pass))
	}
	want := "[default] fuzz ok=true [default] dns started=true [default] unit default:dns: ran to its end=false [default] unit default:ports: ran to its end=false [default] notify ok=true"
	if strings.Join(names, " ") != want {
		t.Errorf("checks %v", names)
	}
	if rec.Checks[2].Detail != "listen tcp 127.0.0.1:1: bind: address already in use" || !strings.HasPrefix(rec.Checks[3].Detail, "panic: ") {
		t.Errorf("details %q %q", rec.Checks[2].Detail, rec.Checks[3].Detail)
	}
	if len(rec.Units) != 4 || rec.Units[1].Checks != 2 || rec.Units[2].Checks != 1 || inUnit != "" {
		t.Errorf("spans %+v", rec.Units)
	}
}

func TestListenPairSharesOnePort(t *testing.T) {
	pc, ln, err := listenPair()
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	defer ln.Close()
	if pc.LocalAddr().String() != ln.Addr().String() {
		t.Errorf("udp %v, tcp %v", pc.LocalAddr(), ln.Addr())
	}
}
