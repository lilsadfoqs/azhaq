package contract

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// failureListed names what a summary lists as failed, "" when nothing.
func failureListed(s Summary) string {
	switch {
	case len(s.Failed) > 0:
		return "failed: " + s.Failed[0].Collector + " " + s.Failed[0].Error
	case len(s.Unreachable) > 0:
		return "unreachable: " + s.Unreachable[0]
	case s.Degraded:
		return "degraded"
	}
	return ""
}

// checkSummary is what holds for the summary of every run: the exit code
// the process gave is the one it says, 0 is a run that did its job (with the
// failures it names counted in `failures`; none at all under -strict-exit),
// 4 is a run a limit stopped, and 3 says what failed.
func checkSummary(v *Inv, r Result) {
	s := r.Summary
	if s.Exit != r.Code {
		v.Errorf("the summary says exit %d, the process gave %d", s.Exit, r.Code)
	}
	if (s.Stopped != "") != (r.Code == 4) {
		v.Errorf("stopped %q with exit %d", s.Stopped, r.Code)
	}
	if s.Complete != (r.Code == 0) {
		v.Errorf("complete %v with exit %d", s.Complete, r.Code)
	}
	if r.Code == 1 || r.Code == 2 {
		return // an error's summary says the error, and nothing was run to count
	}
	if s.Failures == nil {
		v.Errorf("the summary has no failures count")
	} else if why := failureListed(s); why != "" && *s.Failures == 0 {
		v.Errorf("the summary lists %s and counts no failure", why)
	}
	if why := failureListed(s); why != "" && r.Code == 0 && slices.Contains(r.Args, "-strict-exit") {
		v.Errorf("the summary lists %s and -strict-exit gave exit 0", why)
	}
	if r.Code == 3 && failureListed(s) == "" && len(s.Notes) == 0 && (s.Failures == nil || *s.Failures == 0) {
		v.Errorf("exit 3 and nothing says why")
	}
}

// exitCase is a command and a lab shaped to force one outcome.
type exitCase struct {
	name  string
	known string
	want  int
	// failures is the summary's count of failures, when the case forces some.
	failures int
	// shape sets the lab up and returns the command line.
	shape func(l *Labs) []string
	env   Env
	// chrome: the case starts Chrome, so it needs one.
	chrome bool
	// then asserts what else the outcome holds.
	then func(v *Inv, l *Labs, r Result)
}

func TestExitCodeFollowsTheOutcome(t *testing.T) {
	deadPort := func(l *Labs) string { return newPortLab(l.T).Gone }
	cases := []exitCase{
		{name: "clean probe", want: 0, shape: func(l *Labs) []string { return []string{"probe", "-u", l.Site.URL} }},
		{name: "clean crawl", want: 0, shape: func(l *Labs) []string { return []string{"crawl", "-u", l.Site.URL, "-d", "2"} }},
		{name: "clean run", want: 0, shape: func(l *Labs) []string {
			return []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db"}
		}},
		{name: "clean ports", want: 0, shape: func(l *Labs) []string {
			l.Ports = newPortLab(l.T)
			return []string{"ports", "-host", "127.0.0.1", "-p", portOf(l.Ports.Banner), "-allow", "127.0.0.1"}
		}},

		// A failed target of those the user named.
		{name: "probe: connection refused", want: 3, shape: func(l *Labs) []string { return []string{"probe", "-u", "http://" + deadPort(l)} },
			then: func(v *Inv, l *Labs, r Result) {
				if len(r.Summary.Unreachable) == 0 && len(r.Summary.Failed) == 0 {
					v.Errorf("exit 3 and no target is listed")
				}
			}},
		{name: "probe: no answer in time", want: 3, shape: func(l *Labs) []string {
			l.Site.SetDelay(3 * time.Second)
			return []string{"probe", "-u", l.Site.URL, "-req-timeout", "300ms"}
		}},
		// All of the targets it was given fail: the run did not do its job.
		{name: "probe: both targets fail", want: 3, shape: func(l *Labs) []string {
			return []string{"probe", "-u", "http://" + deadPort(l), "-u", "http://" + deadPort(l)}
		}},
		{name: "run: both URLs fail", want: 3, shape: func(l *Labs) []string {
			return []string{"run", "-url", "http://" + deadPort(l), "-url", "http://" + deadPort(l), "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db"}
		}},
		{name: "probe: a name that does not resolve", want: 3, shape: func(l *Labs) []string {
			return []string{"probe", "-u", "no-such-name.invalid"}
		}},
		// Some of the targets fail and the run names each: it did its job, exit 0.
		// -strict-exit keeps the rule that any failure exits 3.
		{name: "probe: one of two targets fails", want: 0, failures: 1, shape: func(l *Labs) []string {
			return []string{"probe", "-u", l.Site.URL, "-u", "http://" + deadPort(l)}
		}, then: func(v *Inv, l *Labs, r Result) {
			if r.Summary.Results != 2 {
				v.Errorf("the failed target is a row too: %d results, want 2", r.Summary.Results)
			}
		}},
		{name: "probe -strict-exit: one of two targets fails", want: 3, failures: 1, shape: func(l *Labs) []string {
			return []string{"probe", "-u", l.Site.URL, "-u", "http://" + deadPort(l), "-strict-exit"}
		}},
		{name: "probe: a name that does not resolve among others", want: 0, failures: 1, shape: func(l *Labs) []string {
			return []string{"probe", "-u", l.Site.URL, "-u", "no-such-name.invalid"}
		}},
		{name: "run: one of two URLs fails", want: 0, failures: 1, shape: func(l *Labs) []string {
			return []string{"run", "-url", l.Site.URL, "-url", "http://" + deadPort(l), "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db"}
		}},
		{name: "run -strict-exit: one of two URLs fails", want: 3, failures: 1, shape: func(l *Labs) []string {
			return []string{"run", "-url", l.Site.URL, "-url", "http://" + deadPort(l), "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db", "-strict-exit"}
		}},
		{name: "crawl: one of two URLs fails", want: 0, failures: 1, shape: func(l *Labs) []string {
			return []string{"crawl", "-u", l.Site.URL, "-u", "http://" + deadPort(l), "-d", "1"}
		}},
		{name: "dirs: one of two targets fails", want: 0, failures: 1, shape: func(l *Labs) []string {
			l.File("w.txt", "a\nb\n")
			return []string{"dirs", "-u", l.Site.URL, "-u", "http://" + deadPort(l), "-w", "w.txt"}
		}},
		// A failure on a URL the crawl found: a failed target among the pages it asked.
		{name: "crawl: a page it found closes the connection", want: 0, failures: 1, shape: func(l *Labs) []string {
			l.Site.SetBroken("/broken")
			return []string{"crawl", "-u", l.Site.URL, "-d", "2"}
		}},
		{name: "crawl -strict-exit: a page it found closes the connection", want: 3, failures: 1, shape: func(l *Labs) []string {
			l.Site.SetBroken("/broken")
			return []string{"crawl", "-u", l.Site.URL, "-d", "2", "-strict-exit"}
		}},
		{name: "run: a page it found closes the connection", want: 0, failures: 1, shape: func(l *Labs) []string {
			l.Site.SetBroken("/broken")
			return []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db"}
		}},
		{name: "run -strict-exit: a page it found closes the connection", want: 3, failures: 1, shape: func(l *Labs) []string {
			l.Site.SetBroken("/broken")
			return []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db", "-strict-exit"}
		}},
		{name: "dirs: every request fails", want: 3, shape: func(l *Labs) []string {
			l.File("w.txt", "a\nb\n")
			return []string{"dirs", "-u", "http://" + deadPort(l), "-w", "w.txt"}
		}},
		// An open port that is not a web server answers the question "is this HTTP?" by closing.
		{name: "run -ports: a port that closes on the HTTP request", known: "", want: 0, shape: func(l *Labs) []string {
			l.Ports = newPortLab(l.T)
			// As the RMI registry does: it reads what it is sent, and closes.
			rmi := listenCounted(l.T, l.Ports.Wire, func(c net.Conn) {
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(make([]byte, 512))
				c.Close()
			})
			return []string{"run", "-cidr", "127.0.0.1/32", "-ports", portOf(rmi.Addr), "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db"}
		}},
		{name: "run -ports: a port that holds the request", want: 3, shape: func(l *Labs) []string {
			l.Ports = newPortLab(l.T)
			hold := listenCounted(l.T, l.Ports.Wire, func(c net.Conn) { time.Sleep(3 * time.Second); c.Close() })
			return []string{"run", "-cidr", "127.0.0.1/32", "-ports", portOf(hold.Addr), "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db", "-request-timeout", "500ms"}
		}},
		// A source that failed: the subdomain sources, held behind a proxy nobody listens on.
		{name: "subs: every source fails", want: 3, shape: func(l *Labs) []string {
			dead := "http://" + deadPort(l)
			// The proxy is the only way out: the environment's says the same, so nothing leaves the machine.
			l.env = Env{"HTTP_PROXY=" + dead, "HTTPS_PROXY=" + dead}
			return []string{"subs", "-d", "contract-lab.org", "-proxy", dead, "-no-history", "-source-timeout", "5s"}
		}, then: func(v *Inv, l *Labs, r Result) {
			if len(r.Summary.Failed) == 0 && !r.Summary.Degraded {
				v.Errorf("exit 3 and no source is listed as failed")
			}
		}},

		// A limit.
		{name: "run: -max-requests", want: 4, shape: func(l *Labs) []string {
			return []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-max-requests", "12", "-db", "w.db"}
		}, then: func(v *Inv, l *Labs, r Result) {
			if !strings.Contains(r.Summary.Stopped, "-max-requests") || r.Summary.Resume == "" {
				v.Errorf("stopped %q, resume %q: the limit and the way on are not named", r.Summary.Stopped, r.Summary.Resume)
			}
		}},
		{name: "crawl: -max-requests", want: 4, shape: func(l *Labs) []string {
			return []string{"crawl", "-u", l.Site.URL, "-d", "3", "-max-requests", "5"}
		}},
		{name: "dirs: -max-requests", want: 4, shape: func(l *Labs) []string {
			l.File("w.txt", "a\nb\nc\nd\ne\nf\ng\nh\n")
			return []string{"dirs", "-u", l.Site.URL, "-w", "w.txt", "-max-requests", "4"}
		}},
		{name: "run: -timeout", want: 4, shape: func(l *Labs) []string {
			l.Site.SetDelay(150 * time.Millisecond)
			return []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-timeout", "1s", "-db", "w.db"}
		}},
		{name: "run: the kill file exists", want: 4, shape: func(l *Labs) []string {
			if err := os.WriteFile(filepath.Join(l.Dir, "w.db.stop"), nil, 0o644); err != nil {
				l.T.Fatal(err)
			}
			return []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db"}
		}, then: func(v *Inv, l *Labs, r Result) {
			if n := l.Site.Wire.Total(); n != 0 {
				v.Errorf("%d requests reached the site with the kill file in place", n)
			}
		}},

		// Usage.
		{name: "an unknown flag", want: 2, shape: func(l *Labs) []string { return []string{"probe", "-u", l.Site.URL, "-no-such-flag"} }, then: func(v *Inv, l *Labs, r Result) {
			if l.Site.Wire.Total() != 0 {
				v.Errorf("usage error, and a request was sent")
			}
		}},
		{name: "every target outside the scope", want: 2, shape: func(l *Labs) []string {
			return []string{"run", "-url", l.Site.URL, "-allow", "127.0.0.2", "-sources", "none", "-db", "w.db"}
		}, then: func(v *Inv, l *Labs, r Result) {
			if l.Site.Wire.Total() != 0 {
				v.Errorf("every target is outside the scope, and a request was sent")
			}
		}},

		// Notes that are not failures: what a setting of the user caused.
		{name: "a -deny-path rule keeps URLs out", want: 0, shape: func(l *Labs) []string {
			return []string{"crawl", "-u", l.Site.URL, "-d", "3", "-deny-path", "^/admin"}
		}, then: func(v *Inv, l *Labs, r Result) {
			for k := range l.Site.Wire.HTTP() {
				if strings.Contains(k, "/admin") {
					v.Errorf("the site got %s though a rule keeps it out", k)
				}
			}
		}},
		{name: "Chrome: assets outside the scope are refused", want: 0, chrome: true, shape: func(l *Labs) []string {
			l.Other = newSite(l.T)
			l.Site.SetEmbed(l.Other.URL + "/pixel")
			return []string{"shots", "-u", l.Site.URL + "/embed", "-allow", l.Allow(), "-dir", "sh"}
		}, then: func(v *Inv, l *Labs, r Result) {
			if n := l.Other.Wire.Total(); n != 0 {
				v.Errorf("%d requests reached a site outside the scope", n)
			}
			refused := 0
			for _, sk := range r.Summary.Skipped {
				if strings.Contains(sk.Reason, "outside the scope") {
					refused++
				}
			}
			if refused == 0 {
				v.Errorf("the assets Chrome was refused are not in skipped")
			}
			if rows := r.Rows(v.t); len(rows) != 1 || rows[0]["partial"] != true {
				v.Errorf("the picture drawn without them is not marked partial")
			}
		}},
		{name: "Chrome with the explicit opt-in", want: 0, chrome: true, env: Env{"AZHAQ_CHROME_NO_SANDBOX=1"}, shape: func(l *Labs) []string {
			return []string{"shots", "-u", l.Site.URL, "-dir", "sh"}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			if _, err := lookChrome(); c.chrome && err != nil {
				t.Skip("no Chrome on this machine")
			}
			args := c.shape(l)
			r := RunRaw(t, l.Dir, append(slices.Clone(c.env), l.env...), append(args, "-json")...)
			if !r.Has {
				t.Fatalf("no summary (exit %d)\n%s", r.Code, r.Stderr)
			}
			if c.chrome && r.Code != c.want && strings.Contains(r.Stderr, "sandbox") {
				t.Skipf("Chrome would not start here without a sandbox: %s", strings.TrimSpace(r.Stderr))
			}
			v := newInv(t, c.known)
			if r.Code != c.want {
				v.Errorf("exit %d, want %d: %s\n%s", r.Code, c.want, failureListed(r.Summary), strings.Join(r.Summary.Notes, "\n"))
			}
			checkSummary(v, r)
			if c.failures > 0 && (r.Summary.Failures == nil || *r.Summary.Failures != c.failures) {
				v.Errorf("failures %v, want %d", r.Summary.Failures, c.failures)
			}
			if c.then != nil {
				c.then(v, l, r)
			}
			v.Done()
		})
	}
}
