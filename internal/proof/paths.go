package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/types"
)

// What a path check's answer became.
const (
	Dropped = "dropped" // the answer is one of the host's baselines: it says nothing of the path
	Kept    = "kept"    // a tier (finding or lead) was decided
)

// HeadBytes is how much of the start of an answer's body the web stage keeps
// for a path that names a file or a panel, so that the answer is judged by its
// own bytes and never asked again.
const HeadBytes = 1024

// Answer is what one request to a path was answered, as the web stage stored
// it.
type Answer struct {
	URL, Origin, Path string
	Via               string // the stage that asked it: azhaq-paths, azhaq-dirs or azhaq-http
	Status            int
	ContentType       string
	Location          string
	Title             string
	Hash              string // of the whole body, as the web stage records it
	Head              []byte // the first HeadBytes of the body
	Login             bool   // the body holds a password field
	Catchall          bool   // the same answer as a name that cannot exist
	Observed          time.Time
	Read              bool // the body was kept: Head is what came, even when it is empty
}

// Verdict is what the answer to one path check amounts to.
type Verdict struct {
	URL      string `json:"url"`
	Tier     string `json:"tier,omitempty"`    // finding or lead; "" when dropped
	Drop     string `json:"dropped,omitempty"` // why the answer says nothing, when it was dropped
	Kind     string `json:"kind,omitempty"`    // exposed-file or exposed-panel
	Severity string `json:"severity,omitempty"`
	What     string `json:"what,omitempty"`   // what the path names ("an environment file")
	Reason   string `json:"reason,omitempty"` // for a lead: why the answer does not prove it
	Check    string `json:"check,omitempty"`  // for a lead: the check that would prove it
	Proof    *Proof `json:"proof,omitempty"`  // for a finding
	Status   int    `json:"status,omitempty"`
}

// Dropped says the answer is a baseline.
func (v Verdict) Dropped() bool { return v.Drop != "" }

type pathCheck struct {
	kind, what string
	match      func(path string) bool
	// show finds the bytes of the answer that hold what the path names: where
	// they start and how long they are. nil: nothing an answer can show names it.
	show  func(a Answer) (at int, ok bool)
	check string // what would prove it
}

func baseOf(path string) string {
	p := strings.ToLower(strings.TrimRight(path, "/"))
	return p[strings.LastIndex(p, "/")+1:]
}

func is(names ...string) func(string) bool {
	return func(p string) bool {
		b := baseOf(p)
		for _, n := range names {
			if b == n {
				return true
			}
		}
		return false
	}
}

func ends(suffixes ...string) func(string) bool {
	return func(p string) bool {
		b := baseOf(p)
		for _, s := range suffixes {
			if strings.HasSuffix(b, s) {
				return true
			}
		}
		return false
	}
}

func isHTML(a Answer) bool {
	if strings.Contains(strings.ToLower(a.ContentType), "html") {
		return true
	}
	h := bytes.ToLower(bytes.TrimSpace(a.Head))
	return bytes.HasPrefix(h, []byte("<!doctype html")) || bytes.HasPrefix(h, []byte("<html")) || bytes.Contains(h, []byte("<body"))
}

func prefixShow(magic string) func(Answer) (int, bool) {
	return func(a Answer) (int, bool) {
		if bytes.HasPrefix(a.Head, []byte(magic)) && !isHTML(a) {
			return 0, true
		}
		return 0, false
	}
}

func regexShow(re *lazyre.Regexp) func(Answer) (int, bool) {
	return func(a Answer) (int, bool) {
		if isHTML(a) {
			return 0, false
		}
		if m := re.FindIndex(a.Head); m != nil {
			return m[0], true
		}
		return 0, false
	}
}

func titleShow(re *lazyre.Regexp) func(Answer) (int, bool) {
	return func(a Answer) (int, bool) {
		if !re.MatchString(a.Title) {
			return 0, false
		}
		if i := bytes.Index(bytes.ToLower(a.Head), []byte("<title")); i >= 0 {
			return i, true
		}
		return -1, true // the title is what shows it; the bytes were not at hand to count
	}
}

func anyShow(shows ...func(Answer) (int, bool)) func(Answer) (int, bool) {
	return func(a Answer) (int, bool) {
		for _, s := range shows {
			if at, ok := s(a); ok {
				return at, true
			}
		}
		return 0, false
	}
}

var (
	envLine    = lazyre.New(`(?m)^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=\S*`)
	sqlDump    = lazyre.New(`(?i)-- (?:MySQL|MariaDB|PostgreSQL) dump|-- Dumping (?:data|structure)|\bCREATE TABLE\b|\bINSERT INTO\b|\bDROP TABLE\b`)
	pemBegin   = lazyre.New(`-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----`)
	htpasswd   = lazyre.New(`(?m)^[^:\s]+:(?:\$apr1\$|\{SHA\}|\$2[aby]\$)`)
	phpSource  = lazyre.New(`^\s*<\?php`)
	gitConfig  = lazyre.New(`^\s*\[core\]`)
	promMetric = lazyre.New(`(?m)^# (?:HELP|TYPE) \S+`)
	actuator   = lazyre.New(`"_links"|"propertySources"|"status"\s*:\s*"(?:UP|DOWN)"`)
)

func jsonShow(re *lazyre.Regexp) func(Answer) (int, bool) {
	return func(a Answer) (int, bool) {
		if !strings.Contains(strings.ToLower(a.ContentType), "json") {
			return 0, false
		}
		if m := re.FindIndex(a.Head); m != nil {
			return m[0], true
		}
		return 0, false
	}
}

func archiveShow(a Answer) (int, bool) {
	return anyShow(prefixShow("PK\x03\x04"), prefixShow("\x1f\x8b"))(a)
}

// checks are the paths whose answers are judged: each names a file or a
// panel, and what its answer must hold to show it. A path that names a thing
// an answer cannot show (a bare /backup) has no show: it is a lead whatever
// answers.
var checks = []pathCheck{
	{"exposed-file", "an environment file", func(p string) bool { b := baseOf(p); return b == ".env" || strings.HasPrefix(b, ".env.") },
		regexShow(envLine), "GET it: the body is NAME=value lines, not a page"},
	{"exposed-file", "a git repository's HEAD", func(p string) bool {
		return strings.HasSuffix(strings.ToLower(strings.TrimRight(p, "/")), "/.git/head")
	},
		regexShow(lazyre.New(`^ref: refs/`)), "GET it: the body is `ref: refs/heads/...`"},
	{"exposed-file", "a git repository's config", func(p string) bool {
		return strings.HasSuffix(strings.ToLower(strings.TrimRight(p, "/")), "/.git/config")
	},
		regexShow(gitConfig), "GET it: the body starts with [core]"},
	{"exposed-file", "a git repository", func(p string) bool { return baseOf(p) == ".git" },
		nil, "GET /.git/HEAD: the body is `ref: refs/heads/...`"},
	{"exposed-file", "a database dump", ends(".sql"), regexShow(sqlDump), "GET it: the body holds CREATE TABLE or INSERT INTO statements"},
	{"exposed-file", "a zip archive", ends(".zip"), prefixShow("PK\x03\x04"), "GET it: the first bytes are PK\\x03\\x04"},
	{"exposed-file", "a gzip archive", ends(".tar.gz", ".tgz", ".gz"), prefixShow("\x1f\x8b"), "GET it: the first bytes are \\x1f\\x8b"},
	{"exposed-file", "a KeePass database", ends(".kdbx"), prefixShow("\x03\xd9\xa2\x9a"), "GET it: the first bytes are the KeePass signature"},
	{"exposed-file", "a SQLite database", ends(".db", ".sqlite", ".sqlite3"), prefixShow("SQLite format 3\x00"), "GET it: the first bytes are `SQLite format 3`"},
	{"exposed-file", "a private key or certificate", ends(".pem", ".key", "id_rsa", "id_ecdsa", "id_ed25519"), regexShow(pemBegin), "GET it: the body holds a -----BEGIN ... block"},
	{"exposed-file", "an editor swap file", ends(".swp"), prefixShow("b0VIM"), "GET it: the first bytes are `b0VIM`"},
	{"exposed-file", "a macOS directory file", is(".ds_store"), prefixShow("\x00\x00\x00\x01Bud1"), "GET it: the first bytes hold `Bud1`"},
	{"exposed-file", "a password file", is(".htpasswd"), regexShow(htpasswd), "GET it: the body is user:hash lines"},
	{"exposed-file", "a backup of a source file", ends(".bak", ".old", ".orig", "~"),
		anyShow(regexShow(phpSource), regexShow(pemBegin), archiveShow), "GET it: the body is the source or the archive it backs up, not a page"},
	{"exposed-file", "a backup", is("backup", "backups", "dump", "db"), archiveShow, "GET it: the body is an archive (PK or gzip bytes), not a page"},
	{"exposed-file", "a configuration", is("config", "configuration", "settings"), nil, "GET it: the body is the configuration (JSON, YAML or INI of settings), not a page"},
	{"exposed-panel", "an admin panel", is("admin", "administrator", "administration"),
		titleShow(lazyre.New(`(?i)\badmin(?:istrat\w+)?\b|control panel`)), "GET it: the page is the panel (its own title), not a login form"},
	{"exposed-panel", "a dashboard", is("dashboard"), titleShow(lazyre.New(`(?i)\bdashboard\b`)), "GET it: the page is the dashboard (its own title), not a login form"},
	{"exposed-panel", "phpMyAdmin", is("phpmyadmin", "pma"), titleShow(lazyre.New(`(?i)phpMyAdmin`)), "GET it: the page's title is phpMyAdmin"},
	{"exposed-panel", "Adminer", is("adminer", "adminer.php"), titleShow(lazyre.New(`(?i)adminer`)), "GET it: the page's title is Adminer"},
	{"exposed-panel", "a console", is("console"), titleShow(lazyre.New(`(?i)\bconsole\b`)), "GET it: the page is the console (its own title)"},
	{"exposed-panel", "a Spring Boot actuator", func(p string) bool { return strings.Contains(strings.ToLower(p), "/actuator") },
		jsonShow(actuator), "GET it: the answer is JSON with _links, propertySources or a status"},
	{"exposed-panel", "Swagger UI", is("swagger-ui.html", "swagger-ui", "swagger"), titleShow(lazyre.New(`(?i)swagger ui`)), "GET it: the page's title is Swagger UI"},
	{"exposed-panel", "a GraphQL IDE", is("graphiql", "playground", "altair"), titleShow(lazyre.New(`(?i)graphiql|graphql playground|altair`)), "GET it: the page's title names the IDE"},
	{"exposed-panel", "phpinfo", is("phpinfo.php", "info.php", "phpinfo"),
		anyShow(titleShow(lazyre.New(`phpinfo\(\)`)), regexShow(lazyre.New(`PHP Version`))), "GET it: the page is phpinfo() output"},
	{"exposed-panel", "Apache server status", is("server-status", "server-info"), titleShow(lazyre.New(`(?i)apache (?:status|server information)`)), "GET it: the page's title is Apache Status"},
	{"exposed-panel", "a metrics endpoint", is("metrics"), regexShow(promMetric), "GET it: the body is Prometheus text (# HELP, # TYPE lines)"},
}

func checkOf(path string) *pathCheck {
	for i := range checks {
		if checks[i].match(path) {
			return &checks[i]
		}
	}
	return nil
}

// Wants says the answer to this path is judged, so the web stage keeps the
// head of its body.
func Wants(path string) bool { return checkOf(path) != nil }

var softPage = lazyre.New(`(?i)\b(?:404|not found|page not found|does(?:n't| not) exist|no such (?:file|page)|nothing here)\b`)

// loginWords name the pages a host sends an unauthenticated request to.
func loginPath(p string) bool {
	p = strings.ToLower(p)
	for _, w := range []string{"login", "signin", "sign-in", "sign_in", "logon", "/sso", "/auth", "/oauth", "/account/", "/session"} {
		if strings.Contains(p, w) {
			return true
		}
	}
	return false
}

var loginTitleRE = lazyre.New(`(?i)\b(?:log ?in|sign ?in|sign on|authenticat\w+)\b`)

func loginTitle(t string) bool { return loginTitleRE.MatchString(t) }

// locationKey is a redirect's target as a baseline compares it: its path,
// without the query that carries where to return to.
func locationKey(origin, loc string) string {
	u, err := url.Parse(strings.TrimPrefix(loc, origin))
	if err != nil {
		return loc
	}
	return u.Path
}

type baselines struct {
	root     map[string]string          // origin → the hash of its root page
	sameBody map[string]map[string]bool // origin\x00hash → paths that answered 2xx with it
	loginPg  map[string]bool            // origin\x00hash of a page asked at a path that names a login
	sameLoc  map[string]map[string]bool // origin\x00target → paths that redirected to it
}

func newBaselines(answers []Answer) *baselines {
	b := &baselines{root: map[string]string{}, sameBody: map[string]map[string]bool{}, loginPg: map[string]bool{}, sameLoc: map[string]map[string]bool{}}
	for _, a := range answers {
		if a.Path == "/" || a.Path == "" {
			if a.Status >= 200 && a.Status < 300 && a.Hash != "" {
				b.root[a.Origin] = a.Hash
			}
		}
		if a.Status >= 200 && a.Status < 300 && a.Hash != "" {
			k := a.Origin + "\x00" + a.Hash
			if b.sameBody[k] == nil {
				b.sameBody[k] = map[string]bool{}
			}
			b.sameBody[k][a.Path] = true
			if loginPath(a.Path) {
				b.loginPg[k] = true
			}
		}
		if a.Status >= 300 && a.Status < 400 && a.Location != "" {
			k := a.Origin + "\x00" + locationKey(a.Origin, a.Location)
			if b.sameLoc[k] == nil {
				b.sameLoc[k] = map[string]bool{}
			}
			b.sameLoc[k][a.Path] = true
		}
	}
	return b
}

// Judge decides, for each answer to a path that names a file or a panel, the
// tier it is in, or that it is dropped.
func Judge(answers []Answer) map[string]Verdict {
	b := newBaselines(answers)
	out := map[string]Verdict{}
	for _, a := range answers {
		c := checkOf(a.Path)
		if c == nil {
			continue
		}
		out[a.URL] = judge(a, c, b)
	}
	return out
}

func judge(a Answer, c *pathCheck, b *baselines) Verdict {
	v := Verdict{URL: a.URL, Kind: c.kind, What: c.what, Status: a.Status, Severity: severityOf(c)}
	drop := func(why string) Verdict { v.Drop, v.Kind, v.What = why, "", ""; return v }
	lead := func(reason, check string) Verdict {
		v.Tier, v.Reason, v.Check = TierLead, reason, check
		return v
	}
	if a.Catchall {
		return drop("the answer is the host's answer for a path that does not exist")
	}
	switch {
	case a.Status == 401 || a.Status == 403:
		return lead(fmt.Sprintf("answers %d: the path is there and guarded, the answer shows nothing of what it names", a.Status),
			"the same GET with a session of the role that may read it (azhaq roles)")
	case a.Status >= 300 && a.Status < 400:
		key := a.Origin + "\x00" + locationKey(a.Origin, a.Location)
		if len(b.sameLoc[key]) >= 2 {
			return drop("the redirect is the one the host sends other paths to")
		}
		if loginPath(locationKey(a.Origin, a.Location)) {
			return drop("a redirect to the host's login")
		}
		return lead(fmt.Sprintf("answers %d: a redirect shows nothing of what the path names", a.Status), "follow it: curl -sSIL on the URL, then judge the page it ends on: "+c.check)
	case a.Status < 200 || a.Status >= 300:
		return drop(fmt.Sprintf("answers %d", a.Status))
	}
	if !a.Read {
		return lead("the answer's body was not kept: only its status is on record", c.check)
	}
	if a.Hash != "" {
		k := a.Origin + "\x00" + a.Hash
		if a.Hash == b.root[a.Origin] {
			return drop("the answer is the host's own index page")
		}
		if len(b.sameBody[k]) >= 3 {
			return drop("the same body answers three or more paths of the host: it is the host's catch-all")
		}
		if (a.Login || loginTitle(a.Title)) && (b.loginPg[k] || len(b.sameBody[k]) >= 2) {
			return drop("the answer is the host's login page")
		}
	}
	if a.Login || loginTitle(a.Title) {
		return lead("answers with a login form: the panel's own login, no content of it", c.check)
	}
	if softPage.MatchString(a.Title) {
		return drop("the answer is a soft 404 (status 200, a title that says not found)")
	}
	if c.show == nil {
		return lead(fmt.Sprintf("answers %d: nothing in an answer shows what this path names", a.Status), c.check)
	}
	at, ok := c.show(a)
	if !ok {
		return lead(fmt.Sprintf("answers %d %s: the body does not hold what the path names", a.Status, typeOrBody(a)), c.check)
	}
	v.Tier = TierFinding
	p := &Proof{
		ObservedAt: a.Observed.UTC().Format(time.RFC3339), Method: "GET", Target: a.URL,
		Status: a.Status, ContentType: a.ContentType, ExcerptPart: "body", How: a.Via, Reproduce: Curl("GET", a.URL),
	}
	if at >= 0 {
		p.Excerpt, p.ExcerptOffset = Window(a.Head, at)
	} else {
		p.Excerpt = fmt.Sprintf("title: %s", Printable([]byte(a.Title), MaxExcerpt))
	}
	if p.Excerpt == "" {
		p.Excerpt = "(empty)"
	}
	v.Proof = p
	return v
}

func typeOrBody(a Answer) string {
	if a.ContentType != "" {
		return strings.TrimSpace(strings.SplitN(a.ContentType, ";", 2)[0])
	}
	return "answer"
}

// AnswersOf reads the answers to path requests a workspace holds: the web
// stage's rows (with the head of the body where the path names a file or a
// panel), and the path and directory sweeps' rows for a URL the web stage has
// no row for, whose body was never kept.
func AnswersOf(obs []types.StoredObservation) []Answer {
	byURL := map[string]*Answer{}
	var order []string
	via := map[string]string{}
	for _, o := range obs {
		if o.Collector == "azhaq-paths" || o.Collector == "azhaq-dirs" {
			var p struct {
				URL string `json:"url"`
			}
			if json.Unmarshal(o.Payload, &p) == nil && p.URL != "" && via[p.URL] == "" {
				via[p.URL] = o.Collector
			}
		}
	}
	for _, o := range obs {
		var p struct {
			URL         string `json:"url"`
			Status      int    `json:"status"`
			ContentType string `json:"content_type"`
			Title       string `json:"title"`
			Location    string `json:"location"`
			BodyHash    string `json:"body_hash"`
			AnswerType  string `json:"answer_type"`
			AnswerTitle string `json:"answer_title"`
			AnswerLoc   string `json:"answer_location"`
			AnswerHash  string `json:"answer_hash"`
			Head        []byte `json:"head"`
			HeadKept    bool   `json:"head_kept"`
			Login       bool   `json:"login"`
			Catchall    bool   `json:"catchall"`
		}
		switch {
		case o.Collector == "azhaq-http" && o.Kind == "application":
		case (o.Collector == "azhaq-paths" || o.Collector == "azhaq-dirs") && o.Kind == "url":
		default:
			continue
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" {
			continue
		}
		// The path sweep's rows name what its answer holds apart from the fields the map reads.
		p.ContentType, p.Title, p.Location, p.BodyHash = first(p.ContentType, p.AnswerType), first(p.Title, p.AnswerTitle), first(p.Location, p.AnswerLoc), first(p.BodyHash, p.AnswerHash)
		a := &Answer{URL: p.URL, Origin: u.Scheme + "://" + u.Host, Path: u.Path, Status: p.Status, ContentType: p.ContentType,
			Title: p.Title, Location: p.Location, Hash: p.BodyHash, Head: p.Head, Login: p.Login, Catchall: p.Catchall,
			Observed: o.ObservedAt, Read: p.HeadKept || len(p.Head) > 0}
		a.Via = o.Collector
		if v := via[p.URL]; v != "" {
			a.Via = v
		}
		if prev, ok := byURL[p.URL]; ok {
			// The row that kept the body decides; the other adds what it saw.
			a.Catchall = a.Catchall || prev.Catchall
			if a.Read && !prev.Read || !prev.Read && !a.Read && o.Collector == "azhaq-http" {
				*prev = *a
			} else {
				prev.Catchall = a.Catchall
			}
			continue
		}
		byURL[p.URL] = a
		order = append(order, p.URL)
	}
	out := make([]Answer, 0, len(order))
	for _, k := range order {
		out = append(out, *byURL[k])
	}
	return out
}

// severityOf ranks what a path names, the way the findings state it: a file that
// holds secrets or data is high, a panel or a console medium, a page that
// documents or measures low.
func severityOf(c *pathCheck) string {
	switch c.what {
	case "Swagger UI", "a GraphQL IDE", "a metrics endpoint", "Apache server status", "a macOS directory file", "an editor swap file":
		return "low"
	}
	if c.kind == "exposed-file" {
		return "high"
	}
	return "medium"
}

var (
	titleRE    = lazyre.New(`(?is)<title[^>]*>(.*?)</title>`)
	passwordRE = lazyre.New(`(?i)<input[^>]*\btype\s*=\s*["']?password`)
)

// Fields are what a web stage stores of an answer for the path checks, beside
// its status: the content type, the page's title, a hash of the body, whether it
// holds a password field and, for a path that names a file or a panel, the head of
// the body. Anything the sweep itself received, never asked again.
func Fields(path, contentType string, body []byte) map[string]any {
	out := map[string]any{}
	if contentType != "" {
		out["answer_type"] = contentType
	}
	sum := sha256.Sum256(body)
	out["answer_hash"] = hex.EncodeToString(sum[:8])
	if m := titleRE.FindSubmatch(body[:min(len(body), 64<<10)]); len(m) == 2 {
		if t := strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " "); utf8.ValidString(t) {
			out["answer_title"] = t
		}
	}
	if passwordRE.Match(body[:min(len(body), 64<<10)]) {
		out["login"] = true
	}
	if Wants(path) {
		out["head"], out["head_kept"] = body[:min(len(body), HeadBytes)], true
	}
	return out
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
