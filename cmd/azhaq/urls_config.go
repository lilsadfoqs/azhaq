package main

import (
	"flag"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/collectors/urlcol"
)

// A gau config file (~/.gau.toml) is flat TOML: key = value lines, string
// arrays, and the [urlscan] and [filters] tables. This reads that subset;
// keys come back as "key" or "table.key", lists as []string.
func readGauConfig(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	table, pending, key := "", "", ""
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(stripTOMLComment(line))
		if pending != "" {
			pending += " " + line
			if !strings.Contains(line, "]") {
				continue
			}
			line = key + " = " + pending
			pending = ""
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && !strings.Contains(line, "=") {
			table = strings.Trim(line, "[] ")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: not a key = value line", path, n+1)
		}
		key, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.HasPrefix(v, "[") && !strings.Contains(v, "]") {
			pending = v
			continue
		}
		val, err := tomlValue(v)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, n+1, err)
		}
		if table != "" {
			out[table+"."+key] = val
		} else {
			out[key] = val
		}
	}
	return out, nil
}

func stripTOMLComment(s string) string {
	quote := rune(0)
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			return s[:i]
		}
	}
	return s
}

func tomlValue(v string) (any, error) {
	switch {
	case strings.HasPrefix(v, "["):
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "]")[1:])
		var list []string
		for _, item := range strings.Split(inner, ",") {
			if item = strings.TrimSpace(item); item == "" {
				continue
			}
			s, err := tomlValue(item)
			if err != nil {
				return nil, err
			}
			list = append(list, fmt.Sprint(s))
		}
		return list, nil
	case strings.HasPrefix(v, `"`):
		s, err := strconv.Unquote(v)
		if err != nil {
			return nil, fmt.Errorf("bad string %s", v)
		}
		return s, nil
	case strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") && len(v) >= 2:
		return v[1 : len(v)-1], nil
	case v == "true", v == "false":
		return v == "true", nil
	}
	if i, err := strconv.Atoi(v); err == nil {
		return i, nil
	}
	return nil, fmt.Errorf("cannot read %s", v)
}

// gauConfigPath is the file urls reads: -config, else ~/.gau.toml when it
// exists.
func gauConfigPath(given string) (string, error) {
	if given != "" {
		if _, err := os.Stat(given); err != nil {
			return "", usagef("-config %s: %v", given, err)
		}
		return given, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil
	}
	p := filepath.Join(home, ".gau.toml")
	if _, err := os.Stat(p); err != nil {
		return "", nil
	}
	return p, nil
}

// gauFlag is a config key and the urls flag it sets when that flag was
// not given on the command line.
var gauFlags = []struct{ key, flag string }{
	{"threads", "urls-threads"}, {"retries", "retries"}, {"subdomains", "subs"}, {"parameters", "fp"},
	{"providers", "providers"}, {"blacklist", "blacklist"}, {"proxy", "proxy"}, {"json", "json"}, {"verbose", "v"},
	{"filters.from", "from"}, {"filters.to", "to"},
	{"filters.matchstatuscodes", "mc"}, {"filters.filterstatuscodes", "fc"},
	{"filters.matchmimetypes", "mt"}, {"filters.filtermimetypes", "ft"},
}

// applyGauConfig sets the urls flags the file names and the command line
// did not, and returns a note saying the file was read.
func applyGauConfig(fs *flag.FlagSet, path string) ([]string, error) {
	cfg, err := readGauConfig(path)
	if err != nil {
		return nil, err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for _, g := range gauFlags {
		v, ok := cfg[g.key]
		if !ok {
			continue
		}
		name := g.flag
		if name == "urls-threads" && given["threads"] {
			continue
		}
		if given[name] {
			continue
		}
		var s string
		switch x := v.(type) {
		case []string:
			if len(x) == 0 {
				continue
			}
			s = strings.Join(x, ",")
		case string:
			if x == "" {
				continue
			}
			s = x
		case bool:
			if !x {
				continue
			}
			s = "true"
		case int:
			if x <= 0 {
				continue
			}
			s = strconv.Itoa(x)
		}
		if err := fs.Set(name, s); err != nil {
			return nil, fmt.Errorf("%s: %s: %v", path, g.key, err)
		}
	}
	if k, _ := cfg["urlscan.apikey"].(string); k != "" {
		urlscanKey = k
	}
	if h, _ := cfg["urlscan.host"].(string); h != "" && !given["archive"] {
		_ = fs.Set("archive", "urlscan="+strings.TrimRight(h, "/")+"/api/v1/search/")
	}
	if h, _ := cfg["otx"].(string); h != "" && !given["archive"] {
		_ = fs.Set("archive", "otx="+strings.TrimRight(h, "/")+"/api/v1/indicators")
	}
	notes := []string{"read " + path}
	if _, ok := cfg["timeout"]; ok {
		notes[0] += " (its timeout is per request in gau and is not used: -urls-timeout bounds each archive per domain)"
	}
	return notes, nil
}

// isKeyFile says a -providers value is the API-key file, not a list of
// archives: it has a path separator, or is a file that exists.
func isKeyFile(v string) bool {
	if strings.ContainsAny(v, `/\`) {
		return true
	}
	fi, err := os.Stat(v)
	return err == nil && !fi.IsDir()
}

func stdoutTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// archiveBases reads NAME=URL pairs: the address an archive is asked at.
func archiveBases(list []string) (map[string]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	for _, kv := range list {
		name, addr, ok := strings.Cut(kv, "=")
		if !ok || addr == "" {
			return nil, fmt.Errorf("%q: give NAME=URL", kv)
		}
		if err := urlcol.CheckSources([]string{name}); err != nil {
			return nil, err
		}
		if u, err := url.Parse(addr); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%q: %s is not an http(s) address", kv, addr)
		}
		out[name] = addr
	}
	return out, nil
}

// urlsNotes says what the archives left partial: a source that stopped at
// its page cap, URLs past the cap, and the URLs of archives that cannot
// apply a filter, which are listed unfiltered.
func urlsNotes(rep *report, ps []map[string]any, failCapped bool) {
	type unfiltered struct {
		what, by string
		urls     int
	}
	loose := map[string]*unfiltered{}
	cut := map[string]map[string]int{}   // archive -> flag -> URLs left out
	blind := map[string]map[string]int{} // archive -> "status (-mc)" -> URLs with none
	server := map[string]string{}        // archive -> flags it applied itself
	for _, p := range ps {
		domain, _ := p["domain"].(string)
		if caps, _ := p["capped"].([]any); len(caps) > 0 {
			var names []string
			for _, c := range caps {
				names = append(names, fmt.Sprint(c))
			}
			note := fmt.Sprintf("%s: %s stopped at its page cap with more to read, so some URLs are missing; -urls-pages 0 reads them all", domain, strings.Join(names, ", "))
			rep.Notes = append(rep.Notes, note)
			if failCapped && rep.Stopped == "" {
				rep.Stopped = fmt.Sprintf("%s: %s hit the page cap", domain, strings.Join(names, ", "))
			}
		}
		if n, _ := p["truncated"].(float64); n > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d URLs past -urls-max were left out", domain, int(n)))
			if failCapped && rep.Stopped == "" {
				rep.Stopped = domain + ": -urls-max reached"
			}
		}
		srcs, _ := p["sources"].(map[string]any)
		for name, v := range srcs {
			row, _ := v.(map[string]any)
			for flag, n := range asMap(row["left_out"]) {
				if cut[name] == nil {
					cut[name] = map[string]int{}
				}
				cut[name][flag] += intOf(n)
			}
			for _, k := range []string{"status", "type"} {
				if n := intOf(row["no_"+k]); n > 0 {
					if blind[name] == nil {
						blind[name] = map[string]int{}
					}
					by, _ := row["no_"+k+"_by"].(string)
					blind[name][k+" ("+by+")"] += n
				}
			}
			if by, _ := row["filtered_by_archive"].(string); by != "" {
				server[name] = by
			}
			if what, _ := row["unfiltered"].(string); what != "" {
				u := loose[name]
				if u == nil {
					u = &unfiltered{what: what}
					loose[name] = u
				}
				u.by, _ = row["unfiltered_by"].(string)
				u.urls += intOf(row["count"])
			}
		}
		if why, _ := p["skipped"].(string); why != "" && domain != "" {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: no archive was asked: %s", domain, why))
		}
	}
	for _, n := range slices.Sorted(maps.Keys(loose)) {
		if u := loose[n]; u.urls > 0 {
			rep.Notes = append(rep.Notes, unfilteredNote(n, u.what, u.by, u.urls))
		}
	}
	filterNotes(rep, cut, blind, server)
}

// filterNotes says what the filters did to the rows of each archive that
// gave a status or a type: the URLs they left out (counted by flag), the
// URLs that carried none and were kept unjudged, and the flags an archive
// applied in its own query, whose rejects nobody sees.
func filterNotes(rep *report, cut, blind map[string]map[string]int, server map[string]string) {
	for _, a := range slices.Sorted(maps.Keys(cut)) {
		for _, flag := range slices.Sorted(maps.Keys(cut[a])) {
			n := cut[a][flag]
			if n == 0 {
				continue
			}
			if rep.Counts == nil {
				rep.Counts = map[string]int{}
			}
			rep.Counts["left out by "+flag] += n
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %s left out %s", a, flag, urlWord(n)))
		}
	}
	for _, a := range slices.Sorted(maps.Keys(blind)) {
		for _, k := range slices.Sorted(maps.Keys(blind[a])) {
			field, by, _ := strings.Cut(strings.TrimSuffix(k, ")"), " (")
			n, has, they := blind[a][k], "have", "they are"
			if n == 1 {
				has, they = "has", "it is"
			}
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %s %s no recorded %s, which %s needs: %s kept, not judged", a, urlWord(n), has, field, by, they))
		}
	}
	if len(server) > 0 {
		var parts []string
		for _, a := range slices.Sorted(maps.Keys(server)) {
			parts = append(parts, a+" "+server[a])
		}
		rep.Notes = append(rep.Notes, "applied in the archive's own query, so the URLs they left out are not counted: "+strings.Join(parts, "; "))
	}
}

func urlWord(n int) string {
	if n == 1 {
		return "1 URL"
	}
	return fmt.Sprintf("%d URLs", n)
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// unfilteredNote says that an archive keeps no status, type or date of its
// captures, so its URLs were not judged by the flag given for it.
func unfilteredNote(archive, what, by string, urls int) string {
	n := fmt.Sprintf("its %d URLs are", urls)
	if urls == 1 {
		n = "its 1 URL is"
	}
	return fmt.Sprintf("%s has no %s of its captures: %s not filtered by %s", archive, what, n, by)
}

// urlsJunk says how many URLs on the domains were left out as junk and
// why: scanner payloads and probes, placeholders, links cut short. They
// are in the summary, not on stdout; -raw prints them.
func urlsJunk(rep *report, ps []map[string]any) {
	by := map[string]int{}
	total := 0
	for _, p := range ps {
		junk, _ := p["junk"].(map[string]any)
		for reason, n := range junk {
			by[reason] += intOf(n)
			total += intOf(n)
		}
	}
	if total == 0 {
		return
	}
	rep.Junk = by
	if rep.Counts == nil {
		rep.Counts = map[string]int{}
	}
	rep.Counts["dropped as junk"] = total
	reasons := make([]string, 0, len(by))
	for _, k := range sortedCountKeys(by) {
		reasons = append(reasons, fmt.Sprintf("%d %s", by[k], k))
	}
	word := "URLs"
	if total == 1 {
		word = "URL"
	}
	rep.Notes = append(rep.Notes, fmt.Sprintf("%d %s dropped as junk (%s; -raw keeps them)", total, word, strings.Join(reasons, ", ")))
}

// urlsStatics says how many of the rows listed are static files (junk
// "asset"): they are part of results, not of dropped as junk.
func urlsStatics(rep *report, n int) {
	if n == 0 {
		return
	}
	if rep.Counts == nil {
		rep.Counts = map[string]int{}
	}
	rep.Counts["static files listed"] = n
	word := "static files"
	if n == 1 {
		word = "static file"
	}
	rep.Notes = append(rep.Notes, fmt.Sprintf("%d %s listed, labelled asset: they are in the results, not in dropped as junk", n, word))
}
