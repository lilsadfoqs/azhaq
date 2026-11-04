package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/types"
)

// watchSession gives a signed-in run its session check (fetch.Session): a
// page the run asks with its session and without it, whose answers differ,
// asked every 50 requests and when an answer looks like the end of the
// session (a 401, a response that clears a session cookie, a redirect to the
// sign-in page: -login's, else the one the check page sends a visitor to).
// renew signs in again (-login); nil for a session given with -cookie or
// -header, which the run cannot renew.
func watchSession(ctx context.Context, seeds []types.Seed, home, loginURL string, renew func(context.Context) error, rep *report) {
	if !fetch.HasSession() {
		return
	}
	s := fetch.Session{Renew: renew, SignIn: loginURL}
	if renew == nil {
		s.Why = "the session was given with -cookie or -header: give a fresh one and run azhaq resume"
	}
	var candidates []string
	if home != "" {
		candidates = append(candidates, home)
	}
	for _, sd := range seeds {
		if sd.Type == types.TypeURL && len(candidates) < 4 {
			candidates = append(candidates, sd.Key())
		}
	}
	var tried []string
	for _, c := range candidates {
		with, without, err := fetch.Measure(ctx, c)
		if err != nil {
			continue
		}
		if with != without && with.Status != 0 {
			s.Check, s.Want = c, with
			if s.SignIn == "" {
				s.SignIn = without.Loc // where a visitor without the session is sent
			}
			break
		}
		tried = append(tried, c)
	}
	if s.Check == "" && len(candidates) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("session check: %s answered the same with the session and without it, so the run looks for a JSON answer that tells, tests a 401 by signing in again, and notices a response that clears the session cookie", strings.Join(tried, ", ")))
	}
	fetch.WatchSession(s)
}

// sessionLossReport is the summary's account of a session that ended and
// was not renewed.
type sessionLossReport struct {
	FirstAnswer  string   `json:"first_answer,omitempty"` // the URL whose answer first looked like the end; empty when a check found it
	InFlight     int      `json:"in_flight"`              // GETs answered after that answer: already in the air, possibly answered without the session
	InFlightURLs []string `json:"in_flight_urls,omitempty"`
	Asked        int      `json:"asked_since_good_check"` // GETs asked since the last check that held
}

func sessionLoss(err error) *sessionLossReport {
	var sl *neterr.SessionLost
	if !errors.As(err, &sl) {
		return nil
	}
	return &sessionLossReport{FirstAnswer: sl.Answer, InFlight: len(sl.InFlight), InFlightURLs: sl.InFlight, Asked: sl.Asked}
}
