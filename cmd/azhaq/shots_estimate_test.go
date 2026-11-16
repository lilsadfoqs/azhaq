package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// The estimate of -screenshots has a shots stage: a floor of one page load
// for each web service, that names what Chrome asks for besides.
func TestPlanEstimateHasAShotsStage(t *testing.T) {
	dir := t.TempDir()
	p := planJSON(t, "-url", "http://127.0.0.1:3001/", "-url", "http://127.0.0.1:3002/", "-sources", "none", "-screenshots", dir)
	var shots *costStage
	for i, st := range p.Estimate.Stages {
		if st.Stage == "shots" {
			shots = &p.Estimate.Stages[i]
		}
	}
	if shots == nil {
		t.Fatalf("the estimate has no shots stage: %+v", p.Estimate.Stages)
	}
	if shots.Estimate == nil || shots.Estimate.Requests != 2 || !shots.AtLeast {
		t.Errorf("shots stage: %+v, want a floor of 2 page loads", shots)
	}
	if !strings.Contains(shots.NotCounted, "the page's scripts, styles and images, which Chrome asks for as the page names them") {
		t.Errorf("shots stage not_counted: %q", shots.NotCounted)
	}
	if !strings.Contains(strings.Join(p.Sends, "\n"), "shots stage counts one page load for each web service") {
		t.Errorf("the plan text does not agree with the estimate:\n%s", strings.Join(p.Sends, "\n"))
	}
	text, _, _ := cli(t, "plan", "-url", "http://127.0.0.1:3001/", "-sources", "none", "-screenshots", dir)
	if !strings.Contains(text, "shots        at least 1 request") {
		t.Errorf("the text plan has no shots line:\n%s", text)
	}
	// Without the flag there is no such stage.
	for _, st := range planJSON(t, "-url", "http://127.0.0.1:3001/", "-sources", "none").Estimate.Stages {
		if st.Stage == "shots" {
			t.Errorf("a plan without -screenshots has a shots stage")
		}
	}
}

// What Chrome sends for a screenshot is the shots stage's in a run's account,
// and a request with no collector stays in "other".
func TestChromeRequestsOfShotsAreCountedInTheShotsStage(t *testing.T) {
	before := ledger.Account()
	ctx := ledger.WithCollector(context.Background(), "azhaq-shots")
	for range 3 {
		ledger.Chrome(ctx, "GET", "http://127.0.0.1:1/a.js")
	}
	ledger.Chrome(context.Background(), "GET", "http://127.0.0.1:1/b.js")
	byStage := map[string]int64{}
	for _, st := range accountCost(nil, before, nil).Stages {
		byStage[st.Stage] = st.Actual.Requests
	}
	if byStage["shots"] != 3 || byStage["other"] != 1 {
		t.Errorf("stages of Chrome's requests: %v, want shots 3 and other 1", byStage)
	}
}

// A shots job's account puts Chrome's requests in the shots stage: the page
// and its stylesheet, and nothing under "other".
func TestShotsSummaryCountsChromesRequestsInTheShotsStage(t *testing.T) {
	_, sum, _ := shotsCost(t, "http://127.0.0.1:PORT/", "127.0.0.1")
	st := stagesOf(t, sum)
	if got := sentIn(st["shots"]); got < 2 {
		t.Errorf("the shots stage sent %v requests, want the page and its stylesheet: %v", got, st)
	}
	if _, ok := st["other"]; ok {
		t.Errorf("Chrome's requests are in the other stage: %v", st["other"])
	}
}
