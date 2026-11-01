package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Wherever a row shows a time ratio it shows the memory ratio beside it.
func TestRatiosShowMemoryBesideTime(t *testing.T) {
	got := ratios(5, 10, memPair{AzhaqRSS: 30, RefRSS: 20})
	for _, want := range []string{"time ×0.50 of the reference", "memory ×1.50 of the reference", "30 MB against 20 MB"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
	// A peak that was not measured (an old record) says nothing about memory.
	if got := ratios(5, 10, memPair{}); got != "time ×0.50 of the reference" {
		t.Errorf("no memory: %q", got)
	}
	if got := ratios(5, 0, memPair{AzhaqRSS: 30, RefRSS: 20}); strings.Contains(got, "time") || !strings.Contains(got, "memory ×1.50") {
		t.Errorf("no reference time: %q", got)
	}
}

// The peaks are kept in the record beside the seconds, and the README's
// table, made from the record, shows them in the cells.
func TestRowsKeepMemoryAndTheTableShowsIt(t *testing.T) {
	row := &servicesRow{Ports: 15, AzhaqNamed: 15, NmapNamed: 12, AzhaqSecs: 2.8, NmapSecs: 145}
	row.AzhaqRSS, row.RefRSS = 46, 89
	raw, _ := json.Marshal(row)
	if !strings.Contains(string(raw), `"azhaq_rss_mb":46`) || !strings.Contains(string(raw), `"reference_rss_mb":89`) {
		t.Errorf("record: %s", raw)
	}
	var back servicesRow
	if err := json.Unmarshal(raw, &back); err != nil || back.AzhaqRSS != 46 || back.RefRSS != 89 {
		t.Errorf("read back: %+v %v", back, err)
	}
	rows := tableRows(&profileSet{Services: row})
	if len(rows) != 1 || !strings.Contains(rows[0].azhaq, "2.8 s, 46 MB") || !strings.Contains(rows[0].ref, "145 s, 89 MB") {
		t.Errorf("table: %+v", rows)
	}
	// An older record has no peaks, and its cells are as they were.
	old := tableRows(&profileSet{Services: &servicesRow{Ports: 15, AzhaqSecs: 2.8, NmapSecs: 145}})
	if strings.Contains(old[0].azhaq, "MB") {
		t.Errorf("old record: %+v", old)
	}
}

// The median of the runs is what a row keeps, for memory as for time.
func TestMedianOfRuns(t *testing.T) {
	if median(nil) != 0 || median([]float64{3}) != 3 || median([]float64{9, 1, 5}) != 5 || median([]float64{4, 1}) != 4 {
		t.Error("median")
	}
}
