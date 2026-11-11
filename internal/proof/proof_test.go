package proof

import (
	"strings"
	"testing"
	"time"
)

func ans(origin, path string, status int, ct, title, hash, body string) Answer {
	return Answer{URL: origin + path, Origin: origin, Path: path, Status: status, ContentType: ct, Title: title, Hash: hash,
		Head: []byte(body), Read: true, Via: "azhaq-paths", Observed: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)}
}

const o = "http://h.test"

func TestAFileIsAFindingOnlyWhenItsOwnBytesShowIt(t *testing.T) {
	root := ans(o, "/", 200, "text/html", "Acme", "idx", "<html><title>Acme</title></html>")
	cases := []struct {
		name string
		a    Answer
		tier string
	}{
		{"env", ans(o, "/.env", 200, "text/plain", "", "e1", "APP_ENV=production\nDB_PASSWORD=x\n"), TierFinding},
		{"env as the index", ans(o, "/.env", 200, "text/html", "Acme", "idx", "<html><title>Acme</title></html>"), ""},
		{"env as html", ans(o, "/.env", 200, "text/html", "Env", "e2", "<html><body>FOO=bar</body></html>"), TierLead},
		{"git head", ans(o, "/.git/HEAD", 200, "text/plain", "", "g1", "ref: refs/heads/main\n"), TierFinding},
		{"zip", ans(o, "/site.zip", 200, "application/zip", "", "z1", "PK\x03\x04rest"), TierFinding},
		{"zip as a page", ans(o, "/site.zip", 200, "text/html", "Download", "z2", "<html>no</html>"), TierLead},
		{"sql dump", ans(o, "/db.sql", 200, "application/sql", "", "s1", "-- MySQL dump 10.13\nCREATE TABLE users (id int);"), TierFinding},
		{"redirect", ans(o, "/backup", 302, "", "", "", ""), TierLead},
		{"guarded", ans(o, "/.env", 403, "text/html", "Forbidden", "f", "<html>Forbidden</html>"), TierLead},
		{"backup page", ans(o, "/backup", 200, "text/html", "Backups", "b1", "<html><title>Backups</title></html>"), TierLead},
		{"missing", ans(o, "/.env", 404, "text/html", "Not Found", "n", "x"), ""},
	}
	for _, c := range cases {
		v := Judge([]Answer{root, c.a})[c.a.URL]
		switch {
		case c.tier == "" && !v.Dropped():
			t.Errorf("%s: %+v, want dropped", c.name, v)
		case c.tier != "" && v.Tier != c.tier:
			t.Errorf("%s: tier %q (%s%s), want %q", c.name, v.Tier, v.Reason, v.Drop, c.tier)
		}
		if v.Tier == TierFinding && (!v.Proof.Complete() || v.Proof.ExcerptOffset == nil) {
			t.Errorf("%s: finding without a complete proof: %+v", c.name, v.Proof)
		}
		if v.Tier == TierLead && (v.Check == "" || v.Proof != nil) {
			t.Errorf("%s: a lead has a check and no proof: %+v", c.name, v)
		}
	}
}

func TestABaselineIsDropped(t *testing.T) {
	root := ans(o, "/", 200, "text/html", "Acme", "idx", "<html>")
	login := ans(o, "/login", 200, "text/html", "Sign in", "lg", `<form><input type="password">`)
	login.Login = true
	adminAsLogin := ans(o, "/admin", 200, "text/html", "Sign in", "lg", `<form><input type="password">`)
	adminAsLogin.Login = true
	dashRedirect := ans(o, "/dashboard", 302, "", "", "", "")
	dashRedirect.Location = "/login?next=/dashboard"
	consoleRedirect := ans(o, "/console", 302, "", "", "", "")
	consoleRedirect.Location = "/signin"
	soft := ans(o, "/phpinfo.php", 200, "text/html", "404 Not Found", "sf", "<html>")
	catch := ans(o, "/metrics", 200, "text/html", "x", "c", "x")
	catch.Catchall = true
	index := ans(o, "/swagger-ui.html", 200, "text/html", "Acme", "idx", "<html>")
	// Three paths answered by one body: the host's catch-all, though it is not the root.
	var many []Answer
	for _, p := range []string{"/backup", "/db", "/graphiql"} {
		many = append(many, ans(o, p, 200, "text/html", "Welcome", "same", "<html>w"))
	}
	all := append([]Answer{root, login, adminAsLogin, dashRedirect, consoleRedirect, soft, catch, index}, many...)
	got := Judge(all)
	for _, a := range []Answer{adminAsLogin, dashRedirect, consoleRedirect, soft, catch, index, many[0], many[1], many[2]} {
		if v := got[a.URL]; !v.Dropped() {
			t.Errorf("%s: %+v, want dropped (equals a baseline)", a.Path, v)
		}
	}
}

func TestAPanelIsAFindingByItsOwnTitle(t *testing.T) {
	root := ans(o, "/", 200, "text/html", "Acme", "idx", "<html>")
	panel := ans(o, "/admin", 200, "text/html", "Acme Admin Console", "a1", "<html><head><title>Acme Admin Console</title>")
	other := ans(o, "/dashboard", 200, "text/html", "Welcome", "a2", "<html><head><title>Welcome</title>")
	got := Judge([]Answer{root, panel, other})
	if v := got[panel.URL]; v.Tier != TierFinding || v.Kind != "exposed-panel" || !strings.Contains(v.Proof.Excerpt, "<title>Acme Admin Console") {
		t.Errorf("admin: %+v", v)
	}
	if v := got[panel.URL]; v.Proof.ExcerptOffset == nil || *v.Proof.ExcerptOffset != strings.Index(string(panel.Head), "<title") {
		t.Errorf("the offset of the title is wrong: %+v", v.Proof)
	}
	if v := got[other.URL]; v.Tier != TierLead || v.Check == "" {
		t.Errorf("dashboard titled Welcome: %+v, want a lead", v)
	}
}

func TestACheckWithNoBodyKeptIsALead(t *testing.T) {
	a := Answer{URL: o + "/.env", Origin: o, Path: "/.env", Status: 200, Via: "azhaq-dirs"}
	if v := Judge([]Answer{a})[a.URL]; v.Tier != TierLead || !strings.Contains(v.Reason, "not kept") {
		t.Errorf("%+v", v)
	}
}

func TestExcerptsAreBoundedAndCommandsQuoted(t *testing.T) {
	big := []byte(strings.Repeat("A", 5000))
	if s, off := Window(big, 10); len([]rune(s)) > MaxExcerpt || *off != 10 {
		t.Errorf("window %d runes at %d", len([]rune(s)), *off)
	}
	if got := Printable([]byte("a\r\nb\x00\xff"), 100); got != `a\r\nb\x00\xff` {
		t.Errorf("printable %q", got)
	}
	if c := Curl("GET", "http://h/a'b"); !strings.Contains(c, `'http://h/a'\''b'`) {
		t.Errorf("curl %s", c)
	}
	if c := NC("h", 6379, []byte("INFO\r\n")); c != `printf '%b' 'INFO\x0d\x0a' | nc -w 3 h 6379` {
		t.Errorf("nc %s", c)
	}
	if c := NC("h", 22, nil); c != "nc -w 3 h 22 < /dev/null" {
		t.Errorf("nc %s", c)
	}
	if c := OpenSSL("h", 443, nil); !strings.HasPrefix(c, "openssl s_client -connect h:443 ") {
		t.Errorf("openssl %s", c)
	}
}
