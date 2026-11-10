package main

import (
	"strings"
	"testing"
)

func TestSmallBarIsOneQuarterInTimeAndTwiceInPrivateMemory(t *testing.T) {
	old, oldProf, oldGone := rec, prof, refGone
	defer func() { rec, prof, refGone = old, oldProf, oldGone }()
	prof = profDefault
	refGone = map[string]string{}
	cases := []struct {
		name string
		r    smallRow
		pass [3]bool // results, time, memory
	}{
		{"within every bar", smallRow{Azhaq: 3, Ref: 3, AzhaqSecs: 0.625, RefSecs: 0.5, AzhaqAnon: 10, RefAnon: 5}, [3]bool{true, true, true}},
		{"slower than 1.25×", smallRow{Azhaq: 3, Ref: 3, AzhaqSecs: 0.63, RefSecs: 0.5, AzhaqAnon: 10, RefAnon: 5}, [3]bool{true, false, true}},
		{"more than twice the private memory", smallRow{Azhaq: 3, Ref: 3, AzhaqSecs: 0.5, RefSecs: 0.5, AzhaqAnon: 10.1, RefAnon: 5}, [3]bool{true, true, false}},
		// The resident peak counts the binary's file pages: thrice the
		// reference's there, with the private memory within the bar, passes.
		{"a resident peak thrice the reference's", smallRow{Azhaq: 3, Ref: 3, AzhaqSecs: 0.5, RefSecs: 0.5, memPair: memPair{39, 13}, AzhaqAnon: 9, RefAnon: 5}, [3]bool{true, true, true}},
		{"fewer results", smallRow{Azhaq: 2, Ref: 3, AzhaqSecs: 0.5, RefSecs: 0.5, AzhaqAnon: 4, RefAnon: 5}, [3]bool{false, true, true}},
		{"a peak not measured", smallRow{Azhaq: 3, Ref: 3, AzhaqSecs: 0.5, RefSecs: 0.5, memPair: memPair{10, 13}, AzhaqAnon: 4}, [3]bool{true, true, false}},
	}
	for _, c := range cases {
		rec = record{}
		barSmall("small", c.r, "evidence", "azhaq dirs vs ffuf -ac", "")
		if len(rec.Checks) != 3 {
			t.Fatalf("%s: %d checks", c.name, len(rec.Checks))
		}
		for i, ck := range rec.Checks {
			if ck.Pass != c.pass[i] {
				t.Errorf("%s: check %q pass %v, want %v (%s)", c.name, ck.Name, ck.Pass, c.pass[i], ck.Detail)
			}
		}
	}
	rec = record{}
	barSmall("small", cases[0].r, "e", "azhaq dirs vs ffuf -ac", "[azhaq: exit status 2]")
	if rec.Checks[1].Pass {
		t.Error("a run of azhaq that failed has no time to compare")
	}
	rec = record{}
	markGone("ffuf", "no such file")
	barSmall("small", cases[0].r, "e", "azhaq dirs vs ffuf -ac", "")
	for _, ck := range rec.Checks {
		if ck.Pass || !strings.Contains(ck.Detail, "did not run") {
			t.Errorf("a reference that did not run: %q passed or lacks the reason: %s", ck.Name, ck.Detail)
		}
	}
}
