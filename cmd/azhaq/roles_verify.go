package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
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
	user  string // the application user name of the owner, when the user gives it (a role is a label)
	raw   string
}

// parseVerifyWrites reads -replay-writes-verify SPECs:
//
//	login:URL[;user=NAME]              sign in as the owner at URL with the
//	                                   password the write set
//	read:URL[;field=NAME[=VALUE]][;user=NAME]
//	                                   GET URL as the writer ({owner} and
//	                                   {writer} are replaced); with field,
//	                                   that field must hold VALUE, or the
//	                                   value the write set in it
//
// {owner} and the sign-in name are the owner's application user, not the
// role's name: user=NAME gives it, else the run's identity of the role or the
// written URL's path says (ownerUser).
func parseVerifyWrites(specs []string) ([]verifyWrite, error) {
	var out []verifyWrite
	for _, s := range specs {
		parts := strings.Split(s, ";")
		kind, u, ok := strings.Cut(strings.TrimSpace(parts[0]), ":")
		if !ok || u == "" || kind != "read" && kind != "login" {
			return nil, usagef("-replay-writes-verify %q: want login:URL[;user=NAME] or read:URL[;field=NAME[=VALUE]][;user=NAME]", s)
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
			if !ok || k != "field" && k != "user" || val == "" {
				return nil, usagef("-replay-writes-verify %q: want ;field=NAME[=VALUE] or ;user=NAME", s)
			}
			if k == "user" {
				v.user = val
			} else if f, fv, ok := strings.Cut(val, "="); ok {
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

// ownerUser is the application user name of the role that owns a write's
// object: what the step gives, else what the run learned of the role (a
// username or email its session or /me answer names, the one the written
// URL's path holds when there are several), else the segment of the path that
// follows a user noun (/users/alice/password). firm is false only for that
// last one, which is a reading of the URL and not an observation of the
// role: a sign-in or read that fails with it decides nothing. "" when
// nothing names a user: a role is a label, never tried as the user.
func ownerUser(step verifyWrite, owner string, w writeReq, who map[string]identity) (name string, firm bool, how string) {
	if step.user != "" {
		return step.user, true, "given on the step"
	}
	var segs []string
	if u, err := url.Parse(w.url); err == nil {
		for _, sg := range strings.Split(u.Path, "/") {
			if sg, err = url.PathUnescape(sg); err == nil && sg != "" {
				segs = append(segs, sg)
			}
		}
	}
	id := who[owner]
	known := append(slices.Clone(id.own["username"]), id.own["email"]...)
	for _, sg := range segs {
		if slices.Contains(known, sg) {
			return sg, true, "what the run learned of " + owner + "'s session names it"
		}
	}
	if n := id.own["username"]; len(n) > 0 {
		return n[0], true, "what the run learned of " + owner + "'s session names it"
	}
	// A route the runs found names the parameter: {username} holds a user name.
	if tu, err := url.Parse(w.route); err == nil && w.route != "" {
		ts := slices.DeleteFunc(strings.Split(tu.Path, "/"), func(x string) bool { return x == "" })
		if len(ts) == len(segs) {
			for i, t := range ts {
				if strings.HasPrefix(t, "{") && userParams[norm(strings.Trim(t, "{}"))] {
					return segs[i], false, "the " + t + " of the route " + tu.Path
				}
			}
		}
	}
	for i := 0; i+1 < len(segs); i++ {
		switch strings.ToLower(segs[i]) {
		case "user", "users", "account", "accounts", "member", "members", "profile", "profiles":
			j := i + 1
			for j < len(segs) && versionSeg.MatchString(norm(segs[j])) {
				j++ // /users/v1/alice: v1 is no user
			}
			if j < len(segs) {
				return segs[j], false, "the segment after " + segs[i] + " in the written URL's path"
			}
		}
	}
	return "", false, ""
}

// userParams are the route parameters (folded) that hold a user name.
var userParams = map[string]bool{"username": true, "user": true, "login": true, "handle": true, "account": true, "accountname": true}

// verifyOutcome runs the steps for one let sender of a write and says
// proved, refuted or "" (nothing decided: accepted-not-verified), with what
// it could not try or could not decide. read and send count against the
// replay's budget, as every replay request does. A login step is sent with
// no session: the credentials are the owner's application user and the
// password the write set, in JSON, which is what the user asked for by
// giving the step. A step that needs the user and has none is not sent.
func verifyOutcome(steps []verifyWrite, w writeReq, sender role, ownerRole string, who map[string]identity, read func(role, string) (answer, bool), send func(role, writeReq) (answer, error)) (string, []string) {
	decided := ""
	var notes []string
	for _, v := range steps {
		user, firm, how := ownerUser(v, ownerRole, w, who)
		if user == "" && (v.kind == "login" || strings.Contains(v.url+v.value, "{owner}")) {
			notes = append(notes, fmt.Sprintf("the %s step was not sent: no application user is known for role %s (a role is a label: %q was not tried as a user name); give ;user=NAME on the step", v.kind, ownerRole, ownerRole))
			continue
		}
		// refuted is the word only for what an observed user got: a name read
		// off the URL may not be the owner's, so its failure says nothing.
		refuted := func(what string) {
			if firm {
				decided = verifyRefuted
				return
			}
			notes = append(notes, fmt.Sprintf("the %s step as %q (%s) %s, which decides nothing: that name was not observed to be role %s's user", v.kind, user, how, what, ownerRole))
		}
		u := v.fill(user, sender.name)
		switch v.kind {
		case "login":
			pw := passwordOf(w.body)
			if pw == "" {
				continue
			}
			body, _ := json.Marshal(map[string]string{"username": user, "password": pw})
			req := writeReq{owner: ownerRole, method: http.MethodPost, url: u, header: http.Header{"Content-Type": {"application/json"}}, body: body}
			a, err := send(role{name: sender.name}, req)
			if err != nil {
				continue
			}
			switch {
			case reads(a):
				return verifyProved, notes
			case a.Status == 401 || a.Status == 403 || a.Error || a.Refusal:
				refuted("was refused")
			}
		case "read":
			a, ok := read(sender, u)
			if !ok || a.Status == 0 {
				continue
			}
			if v.field == "" {
				if reads(a) {
					return verifyProved, notes
				}
				if a.Status == 401 || a.Status == 403 {
					refuted("was refused")
				}
				continue
			}
			want := v.value
			if want == "" {
				want = writtenValue(w.body, v.field)
			}
			want = strings.ReplaceAll(strings.ReplaceAll(want, "{owner}", user), "{writer}", sender.name)
			vs := a.vals[norm(v.field)]
			switch {
			case len(vs) == 0:
				// The field is not in the answer: nothing decided.
			case want != "" && containsString(vs, want):
				return verifyProved, notes
			case want != "":
				refuted("did not show the written value")
			default:
				return verifyProved, notes
			}
		}
	}
	return decided, notes
}

func containsString(vs []string, want string) bool {
	for _, v := range vs {
		if v == want {
			return true
		}
	}
	return false
}
