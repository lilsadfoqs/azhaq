package main

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/internal/scopefile"
)

func isPlatform(v string) bool { _, ok := scopefile.Platforms[v]; return ok }

// fuzzFileFlags take a file or directory: it is stored by its full path, so
// azhaq resume works from another directory.
var fuzzFileFlags = map[string]bool{
	"request": true, "preflight": true, "postflight": true, "ledger": true, "seal-to": true, "kill-file": true,
	"o": true, "od": true, "control": true, "debug-log": true, "config": true, "cc": true, "ck": true, "scope": true,
}

// keptFuzzArgs are the fuzz options stored for azhaq resume, as keptArgs is
// for run: everything but the database and what carries a secret (-b and
// -cookie, a -H whose name sounds like a credential, the password of a proxy
// URL); files are made absolute. dropped names what was left out, for the
// resume to say it was not given again.
func keptFuzzArgs(args []string) (kept, dropped []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			kept = append(kept, a)
			continue
		}
		name, val, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		value := func() string {
			if !inline && i+1 < len(args) {
				val = args[i+1]
				i++
			}
			return val
		}
		switch name {
		case "db":
			value()
		case "b", "cookie":
			value()
			dropped = append(dropped, "-b")
		case "H", "header":
			if v := value(); secretHeader(v) {
				h, _, _ := strings.Cut(v, ":")
				dropped = append(dropped, "-H "+strings.TrimSpace(h))
			} else {
				kept = append(kept, "-H="+v)
			}
		case "x", "proxy", "replay-proxy":
			v := value()
			if bare := withoutUserinfo(v); bare != v {
				dropped = append(dropped, "-"+name+" credentials")
				v = bare
			}
			kept = append(kept, "-"+name+"="+v)
		case "w":
			kept = append(kept, "-w="+absWordlists(value()))
		default:
			if fuzzFileFlags[name] {
				v := value()
				if v != "" && !(name == "ledger" && v == "off") && !(name == "scope" && isPlatform(v)) && !strings.Contains(v, "://") {
					if abs, err := filepath.Abs(v); err == nil {
						v = abs
					}
				}
				kept = append(kept, "-"+name+"="+v)
				continue
			}
			kept = append(kept, a)
		}
	}
	return kept, dropped
}

// withoutUserinfo is a URL without its user and password.
func withoutUserinfo(raw string) string {
	if i := strings.LastIndex(raw, "@"); i >= 0 && !strings.Contains(raw, "://") {
		return raw[i+1:] // host:port with credentials in front
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

// absWordlists makes the files of a -w value ("FILE[:KEYWORD]", a comma list
// being several) absolute.
func absWordlists(v string) string {
	specs := fuzz.SplitWordlists([]string{v})
	for i, spec := range specs {
		path, _ := fuzz.ParseWordlist(spec)
		if path == "-" || path == "" {
			continue
		}
		if abs, err := filepath.Abs(path); err == nil {
			specs[i] = abs + spec[len(path):]
		}
	}
	return strings.Join(specs, ",")
}
