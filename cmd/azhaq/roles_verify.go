package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// A verification step the user attaches to a replayed write with
// -replay-writes-verify: after a write another role sent was accepted,
// azhaq asks one more request the user named and reports the write
// proved, accepted-not-verified or refuted. Without a step, a write that
// was let but could not be read back is accepted-not-verified: accepted
// is not proved.
type verifyWrite struct {
	kind  string // "read" or "login"
	url   string // may hold {owner} and {writer}
	field string // read: the JSON field that must hold the written value
	value string // read: the value it must hold; empty takes the write body's
	raw   string
}

// parseVerifyWrites reads -replay-writes-verify SPECs:
//
//	login:URL                          sign in as the owner at URL with the
//	                                   password the write set
//	read:URL[;field=NAME[=VALUE]]      GET URL as the writer ({owner} and
//	                                   {writer} are replaced); with field,
//	                                   that field must hold VALUE, or the
//	                                   value the write set in it
func parseVerifyWrites(specs []string) ([]verifyWrite, error) {
	var out []verifyWrite
	for _, s := range specs {
		parts := strings.Split(s, ";")
		kind, u, ok := strings.Cut(strings.TrimSpace(parts[0]), ":")
		if !ok || u == "" || kind != "read" && kind != "login" {
			return nil, usagef("-replay-writes-verify %q: want login:URL or read:URL[;field=NAME[=VALUE]]", s)
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			// The kind's colon was the URL's scheme colon (read:http://…):
			// strings.Cut took "read" then "http", leaving "//…".
			if kind == "read" || kind == "login" {
				// Rebuild: the spec was kind:URL where URL itself has ://.
				// parts[0] as given is the whole kind:URL, so take after
				// the first colon as URL only when it starts with http.
				full := strings.TrimSpace(parts[0])
				if rest := full[len(kind)+1:]; strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
					u = rest
				}
			}
		}
		v := verifyWrite{kind: kind, url: u, raw: s}
		for _, p := range parts[1:] {
			k, val, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok || k != "field" || val == "" {
				return nil, usagef("-replay-writes-verify %q: want ;field=NAME[=VALUE]", s)
			}
			if f, fv, ok := strings.Cut(val, "="); ok {
				v.field, v.value = f, fv
			} else {
				v.field = val
			}
		}
		if v.kind == "login" && v.field != "" {
			return nil, usagef("-replay-writes-verify %q: login takes no field", s)
		}
		out = append(out, v)
	}
	return out, nil
}

func (v verifyWrite) fill(owner, writer string) string {
	u := strings.ReplaceAll(v.url, "{owner}", owner)
	return strings.ReplaceAll(u, "{writer}", writer)
}

// passwordOf is the value a write body sets in a password field, if any.
func passwordOf(body []byte) string {
	for _, p := range bodyPairs(body) {
		if strings.Contains(norm(p[0]), "password") || norm(p[0]) == "passwd" || norm(p[0]) == "pwd" {
			return p[1]
		}
	}
	return ""
}

// writtenValue is the value a write body sets in field, if any.
func writtenValue(body []byte, field string) string {
	for _, p := range bodyPairs(body) {
		if norm(p[0]) == norm(field) {
			return p[1]
		}
	}
	return ""
}

// verifyOutcome runs the steps for one let sender of a write and says
// proved, refuted or "" (nothing decided: accepted-not-verified). read
// and send count against the replay's budget, as every replay request
// does. A login step is sent with no session: the credentials are the
// owner's name and the password the write set, in JSON, which is what
// the user asked for by giving the step.
func verifyOutcome(steps []verifyWrite, w writeReq, sender role, ownerName string, read func(role, string) (answer, bool), send func(role, writeReq) (answer, error)) string {
	decided := ""
	for _, v := range steps {
		u := v.fill(ownerName, sender.name)
		switch v.kind {
		case "login":
			pw := passwordOf(w.body)
			if pw == "" {
				continue
			}
			body, _ := json.Marshal(map[string]string{"username": ownerName, "password": pw})
			req := writeReq{owner: ownerName, method: http.MethodPost, url: u, header: http.Header{"Content-Type": {"application/json"}}, body: body}
			a, err := send(role{name: sender.name}, req)
			if err != nil {
				continue
			}
			switch {
			case reads(a):
				return verifyProved
			case a.Status == 401 || a.Status == 403 || a.Error || a.Refusal:
				decided = verifyRefuted
			}
		case "read":
			a, ok := read(sender, u)
			if !ok || a.Status == 0 {
				continue
			}
			if v.field == "" {
				if reads(a) {
					return verifyProved
				}
				if a.Status == 401 || a.Status == 403 {
					decided = verifyRefuted
				}
				continue
			}
			want := v.value
			if want == "" {
				want = writtenValue(w.body, v.field)
			}
			want = strings.ReplaceAll(strings.ReplaceAll(want, "{owner}", ownerName), "{writer}", sender.name)
			vs := a.vals[norm(v.field)]
			switch {
			case len(vs) == 0:
				// The field is not in the answer: nothing decided.
			case want != "" && containsString(vs, want):
				return verifyProved
			case want != "":
				decided = verifyRefuted
			default:
				return verifyProved
			}
		}
	}
	return decided
}

func containsString(vs []string, want string) bool {
	for _, v := range vs {
		if v == want {
			return true
		}
	}
	return false
}
