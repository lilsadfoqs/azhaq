package contract

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A summary says nothing that cannot be derived from the rows and the
// ledger: the counts of crawl and run add up to the rows they printed and
// stored, and what a rule left out is a number, never a gap.

var leftOutNote = []*regexp.Regexp{
	regexp.MustCompile(`(\d+) hints? and (\d+) named URLs? (?:was|were) left out of the list`),
	regexp.MustCompile(`(\d+) rows? (?:was|were) left out of the list by the default extension list`),
	regexp.MustCompile(`(\d+) rows? (?:was|were) left out of the list by -em, -ef, -mr or -fr`),
	regexp.MustCompile(`(\d+) rows? (?:was|were) left out of the list: a route with a parameter`),
}

// leftOutOfList is how many URL rows the notes say the list does not hold.
func leftOutOfList(notes []string) int {
	n := 0
	for _, note := range notes {
		for _, re := range leftOutNote {
			if m := re.FindStringSubmatch(note); m != nil {
				for _, d := range m[1:] {
					k, _ := strconv.Atoi(d)
					n += k
				}
			}
		}
	}
	return n
}

func TestCrawlCountsAddUpToTheRows(t *testing.T) {
	for _, c := range []struct {
		name  string
		known string
		flags []string
		all   bool // every URL row is printed: -hints and -assets
	}{
		{"default", "", nil, false},
		{"-hints", "", []string{"-hints"}, false},
		{"-hints -assets", "", []string{"-hints", "-assets"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			r := l.Cmd(append([]string{"crawl", "-u", l.Site.URL, "-d", "3"}, c.flags...)...)
			s := r.Summary
			rows := len(r.Rows(t))
			v := newInv(t, c.known)
			v.Equal("results, against the rows printed", int64(s.Results), int64(rows))
			byClass := s.Counts["observed routes"] + s.Counts["linked routes"] + s.Counts["hint routes"] + s.Counts["named strings"]
			byRequest := s.Counts["requested"] + s.Counts["not requested"] + s.Counts["templates"]
			v.Equal("observed + linked + hint + named routes, against requested + not requested + templates", int64(byClass), int64(byRequest))
			// The rows the list left out are counted where the notes say them.
			v.Equal("the rows printed and the rows the notes say were left out, against the URL rows counted by class",
				int64(rows+leftOutOfList(s.Notes)), int64(byClass))
			if c.all {
				v.Equal("with every row listed, results against the URL rows counted", int64(s.Results), int64(byClass))
			}
			v.Done()
		})
	}
}

func TestRunCountsAddUpToTheRows(t *testing.T) {
	for _, c := range []struct {
		name  string
		spa   bool
		flags []string
	}{
		{"templated pages", false, nil},
		{"-no-catchall", true, []string{"-no-catchall"}},
		{"-deny-path", false, []string{"-deny-path", "^/item/1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			if c.spa {
				l.Site.SetSPA()
			}
			r := l.Cmd(append([]string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db"}, c.flags...)...)
			s := r.Summary
			var sum int
			for _, n := range s.Counts {
				sum += n
			}
			t.Run("counts add up to stored", func(t *testing.T) {
				v := newInv(t, "")
				v.Equal("the counts' sum, against stored", int64(sum), int64(s.Stored))
				v.Done()
			})
			t.Run("results are the rows printed", func(t *testing.T) {
				v := newInv(t, "")
				v.Equal("results, against the rows printed", int64(s.Results), int64(len(r.Rows(t))))
				v.Done()
			})
			t.Run("results + folded + left_out = stored", func(t *testing.T) {
				v := newInv(t, "")
				if s.Folded == nil {
					v.Errorf("the JSON summary has no folded: results %d + left_out %d does not give stored %d without the docs", s.Results, s.LeftOut, s.Stored)
				} else {
					v.Equal(fmt.Sprintf("results %d + folded %d + left_out %d, against stored", s.Results, *s.Folded, s.LeftOut), int64(s.Results+*s.Folded+s.LeftOut), int64(s.Stored))
				}
				v.Done()
			})
			t.Run("each count is what query lists", func(t *testing.T) {
				v := newInv(t, "")
				// catchall and skipped are left out: query folds the templates they hold, as the docs say.
				for key, filter := range map[string][]string{
					"auth":      {"-type", "URL", "-role", "auth"},
					"scripts":   {"-type", "URL", "-role", "script"},
					"assets":    {"-type", "URL", "-role", "asset"},
					"addresses": {"-type", "IPAddress"},
					"pages":     {"-type", "URL", "-role", "page,app"},
				} {
					q := RunRaw(t, l.Dir, nil, append([]string{"query", "-db", "w.db", "-json"}, filter...)...)
					v.Equal(fmt.Sprintf("counts[%q], against the rows azhaq query %v lists", key, filter), int64(s.Counts[key]), int64(q.Summary.Results))
				}
				v.Done()
			})
		})
	}
}

// -stream prints one found line per map row, ports included: the keys of the
// found lines are the keys of the rows, each once. (URLs the map folds into a
// template are left out of the comparison: their lines are the rows folded.)
func TestRunStreamFoundLinesAreMapRows(t *testing.T) {
	l := newLabs(t)
	l.Ports = newPortLab(t)
	r := l.Cmd("run", "-url", l.Site.URL, "-ports", l.Ports.List(), "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-depth", "0", "-stream", "-db", "w.db")
	found := map[string]int{}
	rows := map[string]bool{}
	for _, row := range r.Rows(t) {
		key, _ := row["key"].(string)
		switch row["type"] {
		case "found":
			found[key]++
		case "summary":
		default:
			rows[key] = true
		}
	}
	v := newInv(t, "")
	ports := 0
	for key, n := range found {
		if strings.HasPrefix(key, "http") && !rows[key] {
			continue
		}
		if n != 1 {
			v.Errorf("found key %q printed %d times", key, n)
		}
		if !rows[key] {
			v.Errorf("found key %q is no map row", key)
		}
		if strings.Contains(key, "/tcp") {
			ports++
		}
	}
	for key := range rows {
		if strings.Contains(key, "/tcp") && found[key] == 0 {
			v.Errorf("port row %q has no found line", key)
		}
	}
	if ports < 2 {
		v.Errorf("%d port lines for a lab with open ports: %v", ports, found)
	}
	v.Done()
}
