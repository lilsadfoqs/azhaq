package contract

import (
	"fmt"
	"strings"
	"testing"
)

// Every number a summary publishes is the one its emitted rows give. These
// tests derive each count from the rows on stdout, with a ruler of their own,
// and compare: a summary that disagrees with its rows is a failed run.

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func TestCrawlCountsAreDerivedFromTheRowsEmitted(t *testing.T) {
	for _, flags := range [][]string{{"-hints", "-assets"}, {"-hints"}, nil} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			l := newLabs(t)
			r := l.Cmd(append([]string{"crawl", "-u", l.Site.URL, "-d", "3"}, flags...)...)
			s, rows := r.Summary, r.Rows(t)
			byClass, byCoverage := map[string]int{}, map[string]int{}
			for _, row := range rows {
				byClass[str(row, "class")]++
				byCoverage[str(row, "coverage")]++
			}
			v := newInv(t, "")
			v.Equal("results, against the rows printed", int64(s.Results), int64(len(rows)))
			// With every row listed, a class is counted as many times as its rows are printed.
			if len(flags) == 2 {
				for class, key := range map[string]string{"observed": "observed routes", "linked": "linked routes", "hint": "hint routes", "named": "named strings"} {
					v.Equal(fmt.Sprintf("counts[%q], against the %s rows printed", key, class), int64(s.Counts[key]), int64(byClass[class]))
				}
			}
			for cov, n := range byCoverage {
				if cov == "" {
					continue
				}
				v.Equal(fmt.Sprintf("counts[%q], against the rows printed with that coverage", cov), int64(s.Counts[cov]), int64(n))
			}
			v.Done()
		})
	}
}

// keyOf is the ruler: the count a map row of a run belongs to, written here from the docs, not taken from the code.
func keyOf(row map[string]any) string {
	switch str(row, "type") {
	case "URL":
		switch str(row, "coverage") {
		case "catchall", "skipped":
			return str(row, "coverage")
		}
		switch role := str(row, "role"); role {
		case "api", "auth", "forbidden":
			return role
		case "websocket":
			return "websockets"
		case "client-route":
			return "client routes"
		case "script":
			return "scripts"
		case "asset":
			return "assets"
		case "sourcemap":
			return "source maps"
		case "manifest":
			return "manifests"
		}
		return "pages"
	case "Hostname":
		switch role := str(row, "role"); role {
		case "dead", "wildcard":
			return role + " hostnames"
		}
		return "hostnames"
	case "Port":
		if str(row, "state") == "open|filtered" {
			return "open|filtered ports"
		}
		return "ports"
	case "IPAddress":
		return "addresses"
	case "Domain":
		return "domains"
	}
	return strings.ToLower(str(row, "type")) + "s"
}

// held is how many stored rows a printed one stands for.
func held(row map[string]any) int {
	if n, ok := row["count"].(float64); ok && n > 1 {
		return int(n)
	}
	if n, ok := row["folded"].(float64); ok && n > 0 {
		return int(n)
	}
	return 1
}

func TestRunCountsAreDerivedFromTheRowsEmitted(t *testing.T) {
	for _, c := range []struct {
		name  string
		flags []string
	}{
		{"templated pages", nil},
		{"-no-catchall", []string{"-no-catchall"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			if c.name == "-no-catchall" {
				l.Site.SetSPA()
			}
			r := l.Cmd(append([]string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db"}, c.flags...)...)
			s, rows := r.Summary, r.Rows(t)
			total, grouped := 0, 0
			by := map[string]int{}
			for _, row := range rows {
				n := held(row)
				total += n
				if n > 1 {
					grouped++
				}
				by[keyOf(row)] += n
			}
			v := newInv(t, "")
			v.Equal("results, against the rows printed", int64(s.Results), int64(len(rows)))
			v.Equal("stored less left_out, against the stored rows the printed rows stand for", int64(s.Stored-s.LeftOut), int64(total))
			if s.Folded != nil {
				v.Equal("folded, against the stored rows the printed rows hold beyond themselves", int64(*s.Folded), int64(total-len(rows)))
			}
			if grouped == 0 && s.LeftOut == 0 {
				for k, n := range s.Counts {
					v.Equal(fmt.Sprintf("counts[%q], against the rows printed of that kind", k), int64(n), int64(by[k]))
				}
				for k, n := range by {
					v.Equal(fmt.Sprintf("the %q rows printed, against counts", k), int64(n), int64(s.Counts[k]))
				}
			}
			v.Done()
		})
	}
}

func TestPortsCountsAreDerivedFromTheRowsEmitted(t *testing.T) {
	l := newLabs(t)
	l.Ports = newPortLab(t)
	l.UDP = listenUDP(t, l.Ports.Wire)
	r := l.Cmd("ports", "-host", "127.0.0.1", "-p", l.Ports.List(), "-pu", portOf(l.UDP), "-allow", "127.0.0.1")
	s, rows := r.Summary, r.Rows(t)
	byState := map[string]int{}
	for _, row := range rows {
		st := str(row, "state")
		if st == "" && str(row, "protocol") == "tcp" {
			st = "open" // a TCP row is an open port: only a UDP row says its state
		}
		byState[st]++
	}
	v := newInv(t, "")
	v.Equal("results, against the rows printed", int64(s.Results), int64(len(rows)))
	if _, ok := s.Counts["open|filtered"]; ok || s.Counts["open"] > 0 {
		v.Equal("counts[open], against the open rows printed", int64(s.Counts["open"]), int64(byState["open"]))
		v.Equal("counts[open|filtered], against the open|filtered rows printed", int64(s.Counts["open|filtered"]), int64(byState["open|filtered"]))
	}
	v.Equal("counts[addresses], against the addresses scanned", int64(s.Counts["addresses"]), 1)
	v.Done()
}

func TestSubsCountsAreDerivedFromTheRowsEmitted(t *testing.T) {
	l := newLabs(t)
	l.Resolver = newResolver(t, "lab.test", "www", "api")
	w := l.File("words.txt", "www\napi\nnope\nfoo\n")
	r := l.Cmd("subs", "-d", "lab.test", "-sources", "none", "-w", w, "-live", "-resolvers", l.Resolver.Addr, "-no-history")
	s, rows := r.Summary, r.Rows(t)
	c := s.Counts
	v := newInv(t, "")
	v.Equal("results, against the rows printed", int64(s.Results), int64(len(rows)))
	// The names the sources and the guesses gave, less what was left out, plus what DNS added, are the rows.
	got := c["from sources"] + c["asked by guessing"] + c["found as CNAME targets"]
	for _, k := range []string{"the domain itself", "did not resolve", "guesses held back", "not checked", "no answer", "not asked",
		"left out by -m/-f", "listed under another domain", "cut by -max-names"} {
		got -= c[k]
	}
	v.Equal("the names the counts give, against the rows printed", int64(got), int64(len(rows)))
	v.Done()
}

func TestRolesCountsAreDerivedFromTheRowsEmitted(t *testing.T) {
	l := newLabs(t)
	h := l.File("alice.har", har(l.Site, [2]string{"GET", "/api/v1/items/1"}, [2]string{"GET", "/api/v1/users/7"}))
	r := l.Cmd("roles", "-role", "anon", "-role", "bob=Authorization: Bearer t-bob", "-har", "alice="+h, "-dir", "rd", "--", "-url", l.Site.URL, "-allow", l.Allow())
	s, rows := r.Summary, r.Rows(t)
	by := map[string]int{}
	for _, row := range rows {
		by[str(row, "verdict")]++
	}
	v := newInv(t, "")
	v.Equal("results, against the rows printed", int64(s.Results), int64(len(rows)))
	for k, n := range s.Counts {
		v.Equal(fmt.Sprintf("counts[%q], against the rows printed with that verdict", k), int64(n), int64(by[k]))
	}
	for k, n := range by {
		v.Equal(fmt.Sprintf("the %q rows printed, against counts", k), int64(n), int64(s.Counts[k]))
	}
	v.Done()
}
