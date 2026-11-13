package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/types"
)

// watchSession gives a signed-in run its session check (fetch.Session): a
// page the run asks with its session and without it, whose answers differ,
// asked every -session-every requests (50), when 10 s passed since the last
// good check, before each stage that sends many requests, and when an answer
// looks like the end of the session (a 401, a response that clears a session cookie, a redirect to the
// sign-in page: -login's, else the one the check page sends a visitor to).
// renew signs in again (-login); nil for a session given with -cookie or
// -header, which the run cannot renew. landed is what the sign-in saw of the
// page it ended on (nil without -login).
func watchSession(ctx context.Context, seeds []types.Seed, home, loginURL string, renew func(context.Context) error, landed *landing, rep *report, every int) {
	if !fetch.HasSession() {
		return
	}
	s := fetch.Session{Renew: renew, SignIn: loginURL, Every: every}
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
	var away *turnedAway
	for _, c := range candidates {
		if landed != nil && c == home && landed.ok() {
			// Chrome's own answer is the "with" side: the page answered 2xx
			// with the session moments ago.
			sent := egress.Departed() - landed.At
			got, err := fetch.Ask(ctx, c, true)
			if err != nil {
				continue
			}
			if fetch.LooksEnded(got, s.SignIn) {
				s.Check, s.Want = c, fetch.Print{Status: landed.Status}
				fetch.WatchSession(s)
				_ = fetch.EndedAtStart(ctx, c, landed.Status, got, sent)
				return
			}
			without, err := fetch.Ask(ctx, c, false)
			if err != nil {
				continue
			}
			if got != without && got.Status != 0 {
				s.Check, s.Want = c, got
				if s.SignIn == "" {
					s.SignIn = without.Loc
				}
				break
			}
			tried = append(tried, c)
			continue
		}
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
		if renew == nil && away == nil && with == without && (with.Status == 401 || with.Status >= 300 && with.Status < 400) {
			// A session the run cannot renew, that a page turns away as it
			// turns away a visitor, may never have held: TurnsAway looks.
			if got, how, ok, err := fetch.TurnsAway(ctx, c); err == nil && ok {
				away = &turnedAway{c, got, how}
			}
		}
	}
	if s.Check == "" && away != nil {
		// No page showed the session live, and one turned it away: it never held.
		fetch.WatchSession(s)
		_ = fetch.NeverHeld(ctx, away.page, away.got, away.how)
		return
	}
	if s.Check == "" && len(candidates) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("session check: no page showed the session live (%s answered the same with it and without it), so the run looks for a JSON answer that tells, tests a 401 by signing in again, and notices a response that clears the session cookie", strings.Join(tried, ", ")))
	}
	fetch.WatchSession(s)
}

// turnedAway is a page that sent a session the run cannot renew to sign in,
// as it does a visitor without one.
type turnedAway struct {
	page string
	got  fetch.Print
	how  string
}

// landing is what a sign-in saw of the page it ended on.
type landing struct {
	URL    string
	Status int   // what Chrome got for that page's document; 0: not known
	At     int64 // requests departed when that page was answered
}

// ok says Chrome got a 2xx for the page: a session that was live then.
func (l landing) ok() bool { return l.Status >= 200 && l.Status < 300 }

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
