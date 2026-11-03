package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/store"
)

// shotMiss is a target given that has no picture: its row says why.
// failed is false when the reason is an answer or a choice (no web service
// on the ports guessed, a scope, a -shot-codes list) and not a failure.
type shotMiss struct {
	target string
	why    string
	failed bool
	by     string // the collector whose answer it is, for a failure the run did not record
}

// shotTargetMatches says a picture's page url is the one target asks for:
// a URL is one page; a name, address or host:port is any page of that host
// (and port, when given), whichever scheme answered.
func shotTargetMatches(target, page string) bool {
	if strings.Contains(target, "://") {
		n, err := normalize.URL(target)
		return page == target || err == nil && page == n
	}
	host, port := strings.Trim(target, "[]"), ""
	if h, p, err := net.SplitHostPort(target); err == nil {
		host, port = h, p
	}
	u, err := url.Parse(page)
	if err != nil || !strings.EqualFold(u.Hostname(), normalize.Hostname(host)) {
		return false
	}
	return port == "" || shotPort(u) == port
}

func shotPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// unshot lists the targets given, once each and in order, that no picture's
// page answers.
func unshot(given, pages []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range given {
		if seen[t] {
			continue
		}
		seen[t] = true
		found := false
		for _, p := range pages {
			if shotTargetMatches(t, p) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, t)
		}
	}
	return out
}

// shotMisses ends a shots run: every target given ends as a row, a picture
// or the reason it has none. The reasons come from what the run recorded;
// a target with no recorded reason is a failure of the run's own, named in
// the summary, so no target ends without a word. A stopped run leaves the
// targets it did not reach alone: azhaq resume asks them. guessed are the
// host:port lines a scan file only guessed to be web services: a port that
// gives no page is the answer "no web service there", no row.
func shotMisses(rep *report, st *store.Store, given, pages []string, guessed map[string]bool) []shotMiss {
	var todo []string
	for _, t := range unshot(given, pages) {
		if !guessed[t] && !guessed[engineHostPort(t)] {
			todo = append(todo, t)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	var failures []engine.FailedTarget
	for _, f := range engine.FailedTargets(ents, obs) {
		if f.Collector == "azhaq-http" || f.Collector == "azhaq-shots" || f.Collector == "azhaq-dns" {
			failures = append(failures, f)
		}
	}
	dnsErr, _ := dnsAnswerErrors(obs)
	noweb, nothttp := map[string]string{}, map[string]bool{}
	notes := map[string]string{} // page → why its picture was not taken
	for _, o := range obs {
		m := payloadOf(o.Observation)
		switch {
		case o.Kind == engine.KindNoWeb:
			h, _ := m["host"].(string)
			ports, _ := m["ports"].(string)
			noweb[h] = "no web service on " + ports + " (connection refused)"
		case o.Kind == engine.KindNotHTTP:
			h, _ := m["host"].(string)
			nothttp[h] = true
		case o.Collector == "azhaq-shots" && o.Kind == "note":
			n, _ := m["note"].(string)
			if rest, ok := strings.CutPrefix(n, "screenshot of "); ok {
				if page, why, ok := strings.Cut(rest, " not taken: "); ok {
					notes[page] = "not taken: " + why
				}
			}
		}
	}
	skipped := map[string]string{}
	for _, sk := range rep.Skipped {
		skipped[sk.Target] = sk.Reason
	}
	var out []shotMiss
	for _, t := range todo {
		host := shotHost(t)
		miss := shotMiss{target: t}
		switch why := failureOf(failures, t, host); {
		case why != "":
			miss.why, miss.failed = why, true
		case dnsErr[host] != "":
			miss.why, miss.failed, miss.by = dnsErr[host], true, "azhaq-dns"
		case noweb[host] != "":
			miss.why = noweb[host]
		case nothttp[host]:
			miss.why = "open, but not a web service (answered something other than HTTP)"
		case skipped[t] != "":
			miss.why = skipped[t]
		case pageNote(notes, t) != "":
			miss.why = pageNote(notes, t)
		case rep.Stopped != "":
			continue // not asked yet
		default:
			miss.why, miss.failed, miss.by = "no screenshot taken and no reason recorded", true, "azhaq-shots"
		}
		out = append(out, miss)
	}
	return out
}

// failureOf is why target failed, from the failures the run recorded: its
// own, or those of the pages tried for a name. "" when none was recorded.
func failureOf(failures []engine.FailedTarget, target, host string) string {
	var msgs, urls []string
	seen := map[string]bool{}
	for _, f := range failures {
		if f.Target != host && !shotTargetMatches(target, f.Target) {
			continue
		}
		if k := f.Target + "\x00" + f.Error; !seen[k] {
			seen[k] = true
			msgs, urls = append(msgs, f.Error), append(urls, f.Target)
		}
	}
	switch {
	case len(msgs) == 0:
		return ""
	case strings.Contains(target, "://") || len(msgs) == 1:
		return msgs[0]
	}
	for i := range msgs {
		msgs[i] = urls[i] + ": " + msgs[i]
	}
	return strings.Join(msgs, "; ")
}

// pageNote is the reason a picture of target's page was not taken, from the
// notes the shot collector left: a note names the page's URL.
func pageNote(notes map[string]string, target string) string {
	for page, why := range notes {
		if shotTargetMatches(target, page) {
			return why
		}
	}
	return ""
}

// shotHost is the name of a target given, as the run's records spell it.
func shotHost(t string) string {
	if strings.Contains(t, "://") {
		return normalize.HostFromURL(t)
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return normalize.Hostname(h)
	}
	return normalize.Hostname(strings.Trim(t, "[]"))
}

func engineHostPort(t string) string {
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil {
			return net.JoinHostPort(u.Hostname(), shotPort(u))
		}
	}
	return t
}

// shotMissRow is the row of a miss: the target as given and why.
func shotMissRow(m shotMiss) map[string]any {
	row := map[string]any{"url": m.target}
	if m.failed {
		row["failed"], row["error"] = true, m.why
	} else {
		row["failed"], row["note"] = false, m.why
	}
	return row
}

// shotMissLine is the text line of a miss.
func shotMissLine(m shotMiss) string {
	if m.failed {
		return fmt.Sprintf("%s  failed: %s", m.target, m.why)
	}
	return fmt.Sprintf("%s  no screenshot: %s", m.target, m.why)
}

// shotNamed says the summary already names target as failed.
func shotNamed(rep *report, target string) bool {
	host := shotHost(target)
	for _, f := range rep.Failed {
		for _, t := range f.Targets {
			if t == target || shotTargetMatches(target, t) || t == host {
				return true
			}
		}
	}
	for _, u := range rep.Unreachable {
		if u == target || shotTargetMatches(target, u) {
			return true
		}
	}
	return false
}
