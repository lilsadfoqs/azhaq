package main

import (
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// urlsFlag is a repeatable URL flag that also takes a comma list. One rule
// for every command: a comma ends a URL only where the next URL starts
// (",http://" or ",https://"), since a comma in a path or query is legal.
type urlsFlag stringsFlag

func (s *urlsFlag) String() string { return strings.Join(*s, ", ") }

func (s *urlsFlag) Set(v string) error {
	parts := splitURLList(v)
	if len(parts) == 0 {
		parts = []string{v} // empty: let the command's own check name it
	}
	*s = append(*s, parts...)
	return nil
}

var nextURLStart = lazyre.New(`(?i),\s*https?://`)

// splitURLList cuts a value at each comma that is followed by a scheme. A
// piece that is no URL at all (a bare host, host:port or address: no / ? #)
// splits at every comma, as a host list always did.
func splitURLList(v string) []string {
	var cut []string
	last := 0
	for _, m := range nextURLStart.FindAllStringIndex(v, -1) {
		cut = append(cut, v[last:m[0]])
		last = m[0] + 1
	}
	cut = append(cut, v[last:])
	var out []string
	for _, p := range cut {
		if !strings.ContainsAny(p, "/?#") {
			for _, h := range strings.Split(p, ",") {
				if h = strings.TrimSpace(h); h != "" {
					out = append(out, h)
				}
			}
			continue
		}
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// holdsSecondURL reports a value that two URLs were glued into.
func holdsSecondURL(v string) bool { return nextURLStart.MatchString(v) }
