package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// -all asks the types its help names, no others: nine of them, not ANY, not
// PTR for a name, not AXFR.
func TestDNSAllAsksTheTypesItsHelpNames(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-all", "-no-takeover")
	asked := map[string]bool{}
	lab.qtypes.Range(func(k, _ any) bool {
		asked[dns.TypeToString[k.(uint16)]] = true
		return true
	})
	help := flagsOf("dns").Lookup("all").Usage
	named := map[string]bool{}
	for _, w := range regexp.MustCompile(`\b[A-Z]{1,5}\b`).FindAllString(help, -1) {
		if _, ok := dns.StringToType[w]; ok && w != "ANY" && w != "AXFR" && w != "PTR" {
			named[w] = true
		}
	}
	if len(named) != 9 || fmt.Sprint(named) != fmt.Sprint(asked) {
		t.Errorf("-all asked %v; its help names %v: %q", asked, named, help)
	}
}

// docPlaceholder reports whether a value in a doc stands for something the
// reader fills in (FILE, N, a=N/s, socks5://…) rather than a value to run.
func docPlaceholder(v string) bool {
	return v == "x" || strings.ContainsAny(v, "…{}") || regexp.MustCompile(`[A-Z]{2,}|\bN\b|=N`).MatchString(v)
}

// migrationFlagsParse runs the flags of an azhaq column through the flag
// parsers of the commands a section names, each flag with the value the doc
// gives it: a row whose flag or value its command refuses cannot run.
func migrationFlagsParse(name, doc string) []string {
	var bad []string
	var ctx []string
	for _, l := range strings.Split(doc, "\n") {
		t := strings.TrimSpace(l)
		if m := regexp.MustCompile(`^<!-- azhaq: (.*) -->$`).FindStringSubmatch(t); m != nil {
			ctx = strings.Fields(m[1])
			continue
		}
		if strings.HasPrefix(t, "#") {
			ctx = nil
		}
		if len(ctx) == 0 || !strings.HasPrefix(t, "|") {
			continue
		}
		cells := regexp.MustCompile(`[^\\]\|`).Split(" "+t, -1) // "", the tool's cell, azhaq's, the note
		if len(cells) < 3 {
			continue
		}
		for _, sp := range codeSpans(cells[2]) {
			for _, words := range shellWords(strings.TrimPrefix(sp, "azhaq ")) {
				for i, w := range words {
					n := docFlagName(w)
					if n == "" || n == "h" || n == "help" || foreignFlags[n] {
						continue
					}
					var args []string
					known, ran := false, false
					var why error
					for _, c := range ctx {
						fs := flagsOf(c)
						if fs == nil || fs.Lookup(n) == nil {
							continue
						}
						known = true
						args = []string{w}
						if b, ok := fs.Lookup(n).Value.(interface{ IsBoolFlag() bool }); !(ok && b.IsBoolFlag()) && !strings.Contains(w, "=") {
							if i+1 >= len(words) || docFlagName(words[i+1]) != "" || docPlaceholder(words[i+1]) {
								ran = true // no value to run
								break
							}
							args = append(args, words[i+1])
						}
						if why = fs.Parse(args); why == nil {
							ran = true
							break
						}
					}
					if known && !ran {
						bad = append(bad, fmt.Sprintf("%s: `%s` does not run in %v: %v", name, strings.Join(args, " "), ctx, why))
					}
				}
			}
		}
	}
	return bad
}

// The azhaq column of each MIGRATING table runs through the flag parsers:
// each flag with the value its row gives (katana's -kf takes one value).
func TestMigratingFlagsRunThroughTheFlagParsers(t *testing.T) {
	doc := readDoc(t, "../../docs/MIGRATING.md")
	for _, b := range migrationFlagsParse("docs/MIGRATING.md", doc) {
		t.Error(b)
	}
	// The check catches a row that cannot run.
	for _, row := range []string{
		"| `-kf robotstxt,sitemapxml` | `-kf robotstxt,sitemapxml` | |",
		"| `-rl x` | `-rl fast` | |",
	} {
		if bad := migrationFlagsParse("x.md", "<!-- azhaq: crawl -->\n"+row); len(bad) == 0 {
			t.Errorf("not caught: %s", row)
		}
	}
}

// katana's -kf takes one value; a comma list is a usage error at the flag,
// for crawl and run alike.
func TestKnownFilesTakesOneValue(t *testing.T) {
	for _, args := range [][]string{
		{"crawl", "-u", "http://127.0.0.1:1/", "-kf", "robotstxt,sitemapxml"},
		{"run", "-url", "http://127.0.0.1:1/", "-known-files", "all,robotstxt"},
	} {
		if _, errOut, code := cli(t, args...); code != exitUsage || !strings.Contains(errOut, "takes one value") {
			t.Errorf("%v: exit %d: %s", args, code, errOut)
		}
	}
}
