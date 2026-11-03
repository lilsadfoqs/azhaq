package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/urlcol"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
)

// liveCheck is what urls -live found out about the URLs it asked: for each,
// the status the live site answered or why it did not.
type liveCheck struct {
	rate     float64
	asked    map[string]bool   // normalised URL → was asked
	status   map[string]int    // answered with this status
	failed   map[string]string // asked, no answer: why
	junk     int               // not asked: looks like junk
	notAsked int               // not asked: past -live-max
}

// answered reports whether the live site still serves the URL: it answered
// with a status other than 404 or 410.
func answered(status int) bool { return status != 0 && status != 404 && status != 410 }

// verdict sets the row's -live fields from what the check found out.
func (o *urlOut) verdict(c *liveCheck, u string) {
	n, err := normalize.URL(u)
	if err != nil {
		n = u
	}
	if !c.asked[n] {
		return
	}
	ok := answered(c.status[n])
	o.Verified = &ok
	o.VerifiedStatus = c.status[n]
	o.VerifiedError = c.failed[n]
}

// verifyURLs asks the live site for each URL once, at rate requests a second:
// a GET, not followed, so a redirect is the answer. At most max are asked
// when max is above 0, spread evenly over the sorted list. A URL that looks
// like junk (a scanner's payload) is never sent.
func verifyURLs(c *common, rows []urlcol.Row, rate float64, max int, proxy string, rep *report) (*liveCheck, error) {
	chk := &liveCheck{rate: rate, asked: map[string]bool{}, status: map[string]int{}, failed: map[string]string{}}
	var eligible []string
	for _, r := range rows {
		if r.Junk != "" && r.Junk != "asset" {
			chk.junk++
			continue
		}
		if n, err := normalize.URL(r.URL); err == nil {
			eligible = append(eligible, n)
		}
	}
	pick := eligible
	if max > 0 && len(eligible) > max {
		pick = make([]string, 0, max)
		for i := 0; i < max; i++ {
			pick = append(pick, eligible[i*len(eligible)/max])
		}
		chk.notAsked = len(eligible) - max
	}
	if len(pick) == 0 {
		return chk, nil
	}
	path, rm, err := tempList(pick)
	if err != nil {
		return nil, err
	}
	defer rm()
	raw, _ := json.Marshal(&httpcol.Spec{TargetRate: rate})
	probeRep := newReport("probe")
	args := []string{"-list", path, "-probe", "-probe-opts", string(raw), "-no-favicon", "-no-tech"}
	if proxy != "" {
		args = append(args, "-proxy", proxy)
	}
	st, done, err := runPreset(c, args, probeRep, nil)
	if err != nil {
		return nil, err
	}
	defer done()
	for _, u := range pick {
		chk.asked[u] = true
	}
	obs, _ := st.Observations()
	for _, ob := range obs {
		if ob.Collector != "azhaq-http" {
			continue
		}
		var p struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Error  string `json:"error"`
		}
		if json.Unmarshal(ob.Payload, &p) != nil || p.URL == "" {
			continue
		}
		n, err := normalize.URL(p.URL)
		if err != nil || !chk.asked[n] {
			continue
		}
		switch {
		case ob.Kind == "error":
			if _, ok := chk.status[n]; !ok {
				chk.failed[n] = p.Error
			}
		case p.Status > 0:
			chk.status[n] = p.Status
			delete(chk.failed, n)
		}
	}
	for _, u := range pick {
		if chk.status[u] == 0 && chk.failed[u] == "" {
			chk.failed[u] = "no answer"
		}
	}
	rep.Requests += probeRep.Requests
	rep.Notes = append(rep.Notes, probeRep.Notes...)
	return chk, nil
}

// note says what the check asked, at what rate, and what it found, so the
// counts of verified rows add up.
func (c *liveCheck) note(rep *report) {
	live, gone, silent := 0, 0, 0
	for u := range c.asked {
		switch {
		case c.status[u] == 0:
			silent++
		case answered(c.status[u]):
			live++
		default:
			gone++
		}
	}
	if rep.Counts == nil {
		rep.Counts = map[string]int{}
	}
	rep.Counts["verified live"] = live
	rep.Counts["gone (404, 410)"] = gone
	rep.Counts["no answer"] = silent
	if c.notAsked > 0 {
		rep.Counts["not asked (-live-max)"] = c.notAsked
	}
	if c.junk > 0 {
		rep.Counts["not asked (junk)"] = c.junk
	}
	parts := []string{fmt.Sprintf("%d asked at %g requests a second (-live-rate): %d answered and are verified, %d are gone (404 or 410), %d gave no answer", len(c.asked), c.rate, live, gone, silent)}
	if c.notAsked > 0 {
		parts = append(parts, fmt.Sprintf("%d not asked (-live-max)", c.notAsked))
	}
	if c.junk > 0 {
		parts = append(parts, fmt.Sprintf("%d not asked because they look like junk", c.junk))
	}
	rep.Notes = append(rep.Notes, "-live: "+strings.Join(parts, "; ")+"; rows without \"verified\" were not asked")
}
