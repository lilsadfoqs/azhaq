package hunt

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

var braces = strings.NewReplacer("%7B", "{", "%7D", "}", "%7b", "{", "%7d", "}")

// GroupKey is the route template of a URL: numbers, UUIDs and hashes in
// the path and every query value fold to a placeholder, so /basket/6 and
// /basket/7 are one route and ?page=a and ?page=b are one. A client-side
// route keeps its fragment.
func GroupKey(raw string, clientRoute bool) string {
	if clientRoute {
		return raw
	}
	t := braces.Replace(webextract.Template(raw))
	u, err := url.Parse(t)
	if err != nil {
		return t
	}
	if u.RawQuery == "" {
		if u.Path != "/" && strings.HasSuffix(t, "/") && u.Fragment == "" {
			t = strings.TrimSuffix(t, "/")
		}
		return t
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return t
	}
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for i, k := range names {
		names[i] = k + "={v}"
	}
	return strings.TrimSuffix(t, "?"+u.RawQuery) + "?" + strings.Join(names, "&")
}

var wordSplit = lazyre.New(`[^a-z0-9]+`)

// wordsOf are the lower-case words of a path or a host, with the
// hyphenated ones ("api-docs") kept whole too.
func wordsOf(s string) []string {
	s = strings.ToLower(s)
	out := wordSplit.Split(s, -1)
	if strings.Contains(strings.ReplaceAll(s, "_", "-"), "api-docs") {
		out = append(out, "api-docs")
	}
	for i := 0; i+1 < len(out); i++ {
		// sign-in, log_in, sign/up: one word written as two.
		switch w := out[i] + out[i+1]; w {
		case "signin", "signup", "signon", "login", "logon":
			out = append(out, w)
		}
	}
	return out
}

// singular folds a plural to its word (users, addresses).
func singular(w string) string {
	if _, ok := pathWords[w]; ok {
		return w
	}
	for _, suf := range []string{"es", "s"} {
		if t := strings.TrimSuffix(w, suf); t != w {
			if _, ok := pathWords[t]; ok {
				return t
			}
		}
	}
	return w
}

func staticURL(r engine.MapEntry) bool {
	switch r.Role {
	case "asset", "script":
		return true
	}
	c := webextract.ClassifyURL(r.Entity.Key)
	return (c == "asset" || c == "script") && r.Role != "sourcemap"
}

// url reads the signals of one map row into its route's candidate.
func (h *hunter) url(r engine.MapEntry) {
	if r.Coverage == "catchall" || r.Coverage == "gone" || staticURL(r) {
		return
	}
	raw := r.Entity.Key
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	h.status[raw] = r.Status
	// The answer to a path that names a file or a panel equals a baseline of
	// the host (its soft 404, its login, its index): it says nothing of the path.
	verdict, judged := h.verdicts[raw]
	if judged && verdict.Dropped() {
		return
	}
	if r.Role == "sourcemap" {
		// One row per host for its maps (sourceMaps), not one per bundle.
		if h.maps == nil {
			h.maps = map[string][]engine.MapEntry{}
		}
		origin := u.Scheme + "://" + u.Host
		h.maps[origin] = append(h.maps[origin], r)
		return
	}
	key := GroupKey(raw, r.Role == "client-route")
	c := h.get("URL", key, r.Scope)
	c.instances = append(c.instances, raw)
	c.origin = u.Scheme + "://" + u.Host
	if r.Entity.FirstSeen.After(h.cut) {
		c.fresh = true
	}
	st := r.Status
	fetched := r.Coverage == "visited"
	ok := fetched && st >= 200 && st < 300
	unfetched := r.Coverage == "hint" || r.Coverage == "skipped" || r.Coverage == "capped" || st == 0
	known := unfetched && len(r.Methods) > 0 // not asked, but a script or a description says it takes requests
	// A script names it and its GET found nothing: the client calls it, the
	// server was not shown to have it (a POST-only route answers so too).
	named404 := r.Coverage == "hint" && (st == 404 || st == 410)
	if named404 {
		c.named++
		c.namedGET = st
	}
	path := u.Path

	// Path words, one signal per class.
	words := map[string]pathWord{} // class → the word that weighs most
	wordOf := map[string]string{}
	signIn, otherAuth := false, false
	page := r.Role != "api" && len(r.Ops) == 0
	for _, w := range wordsOf(path) {
		pw, isWord := pathWords[singular(w)]
		if !isWord {
			continue
		}
		if pw.signal == "path-auth" && page {
			if signInWords[singular(w)] {
				pw.w, signIn = signInWeight, true
			} else {
				otherAuth = true
			}
		}
		switch {
		case named404:
			continue
		case ok, st >= 500, known, answeredButNotGET(st):
		case st == 401 || st == 403:
			if !guardedWords[pw.signal] {
				continue
			}
			if pw.signal != "path-data" {
				pw.w = pw.w * 3 / 4 // data behind a login is the target; a guarded admin page less so
			}
		case unfetched || (st >= 300 && st < 400):
			pw.w /= 2
		default:
			continue
		}
		if pw.w > words[pw.signal].w {
			words[pw.signal], wordOf[pw.signal] = pw, w
		}
	}
	if signIn && !otherAuth {
		// A sign-in page is where the user data words are about the form.
		if pw, ok := words["path-data"]; ok && pw.w > signInWeight {
			pw.w = signInWeight
			words["path-data"] = pw
		}
	}
	for sig, pw := range words {
		how := "answers " + fmt.Sprint(st)
		switch {
		case st == 401 || st == 403:
			how += ": guarded, but there"
		case st == 0:
			how = "named, not requested"
		}
		c.addW(sig, pw.w, fmt.Sprintf("%q in %s, %s", wordOf[sig], path, how))
	}
	switch {
	case st == 401:
		c.add("gated", "answers 401: authentication requested")
	case st == 403:
		// Nothing here shows a session would change it.
		c.addW("gated", forbiddenWeight, "answers 403: forbidden")
	case st >= 500:
		h.serverError(c, r, raw)
	}
	// Backup and secret-bearing files, and panels: a finding only when the
	// answer's own bytes show what the path names (internal/proof), else a lead.
	w, what := exposedFile(path)
	switch {
	case judged && verdict.Tier == proof.TierFinding:
		c.proof = verdict.Proof
		sig := "exposed-file"
		if verdict.Kind == "exposed-panel" {
			sig = "exposed-panel"
		}
		c.addProved(sig, max(w, weights[sig]), verdict.What+" served: "+verdict.Proof.Excerpt)
	case judged:
		c.check = verdict.Check
		if w > 0 {
			c.addW("exposed-file", w/2, what+" named, "+verdict.Reason)
		}
	case w > 0:
		switch {
		case ok:
			c.addW("exposed-file", w, what+" served, its bytes not judged")
		case named404:
		case st == 401 || st == 403 || unfetched:
			c.addW("exposed-file", w*fileUnseen/100, what+" named, "+map[bool]string{true: "answers " + fmt.Sprint(st), false: "not requested"}[st != 0])
		}
	}
	if ok && isListing(r.Title) {
		c.addProved("listing", weights["listing"], "directory listing: "+clip(r.Title, 60))
	}
	if ok && h.apiDoc[r.Entity.ID] {
		c.addProved("api-description", weights["api-description"], "API description served at "+path)
	} else if ok && apiDocPath(path) {
		c.add("api-description", "API description named at "+path)
	}
	h.graphql(c, r, path)
	h.objects(c, r, path)
	h.params(c, r, raw, u)
	h.writes(c, r, ok, st)
	h.bodies(c, r)
	for _, f := range r.Forms {
		if strings.EqualFold(f.Method, "GET") && passwordField(f.Fields) != "" {
			c.add("password-in-url", "a GET form sends "+passwordField(f.Fields)+" in the URL")
		}
		if len(f.Files) > 0 {
			c.add("upload", fmt.Sprintf("file field %s in a %s form to %s", strings.Join(f.Files, ", "), f.Method, f.Action))
		}
	}
	if names := h.own(r, inputNames(r)); len(names) > 0 {
		w := weights["input"]
		if writesBody(r) {
			w = writeInputWeight // a body sent with a write is input that matters more than a query name
		}
		c.addW("input", w, "takes "+join(names, 5))
	}
}

// answeredButNotGET says a 4xx other than a refusal or a not-found shows the
// route exists: it answered, only not to this request (405, 400, 415, 422).
func answeredButNotGET(st int) bool {
	return st >= 400 && st < 500 && st != 401 && st != 403 && st != 404 && st != 410
}

// writeInputWeight is the input signal of a route a script or a description
// writes to with named fields.
const writeInputWeight = 12

// writesBody says whether a write operation of the route sends named fields.
func writesBody(r engine.MapEntry) bool {
	for _, o := range r.Ops {
		if writeMethods[strings.ToUpper(o.Method)] && len(o.Body) > 0 {
			return true
		}
	}
	return false
}

// bodies reads the content types the operations take: XML, files.
func (h *hunter) bodies(c *cand, r engine.MapEntry) {
	for _, o := range r.Ops {
		t := strings.ToLower(o.BodyType)
		switch {
		case strings.Contains(t, "xml"):
			c.add("xml", fmt.Sprintf("%s takes %s", o.Method, o.BodyType))
		case strings.Contains(t, "multipart") || strings.Contains(t, "octet-stream"):
			c.add("upload", fmt.Sprintf("%s takes a file upload (%s)", o.Method, o.BodyType))
		}
	}
}

// serverError weighs a 5xx by what the row shows besides the status: the
// body's error text, a parameter that came back in the answer; alone it is
// a lead, and the weaker when the plain request lacked the input the route
// takes.
func (h *hunter) serverError(c *cand, r engine.MapEntry, raw string) {
	st := r.Status
	e := h.errs[r.Entity.ID]
	without := r.Answer != ""
	switch {
	case e.kind == webextract.ErrSQL:
		c.addProved("server-error", serverErrorSQL, fmt.Sprintf("answers %d and the body has SQL error text: %q", st, e.sample))
	case e.kind == webextract.ErrDebug:
		c.addProved("server-error", serverErrorDebug, fmt.Sprintf("answers %d with a framework's debug page: %q", st, e.sample))
	case h.reflected[webextract.RouteKey(raw)]:
		c.addW("server-error", serverErrorReflected, fmt.Sprintf("answers %d, and a parameter's value comes back in the answer", st))
	case e.kind == webextract.ErrStack && without:
		c.addProved("server-error", serverErrorStackBare, fmt.Sprintf("answers %d to a request without its input, with a stack trace: %q", st, e.sample))
	case e.kind == webextract.ErrStack:
		c.addProved("server-error", serverErrorStack, fmt.Sprintf("answers %d with a stack trace: %q", st, e.sample))
	case without:
		c.addW("server-error", serverErrorBare, fmt.Sprintf("answers %d to a request without the input it takes (%s): a lead, nothing in the answer points further", st, join(h.own(r, inputNames(r)), 3)))
	default:
		c.add("server-error", fmt.Sprintf("answers %d: %s", st, clip(r.Title, 60)))
	}
}

var passField = lazyre.New(`(?i)pass(word|wd)?(_|$)`)

func passwordField(fields []string) string {
	for _, n := range fields {
		if passField.MatchString(n) {
			return n
		}
	}
	return ""
}

func exposedFile(path string) (int, string) {
	p := strings.ToLower(path)
	if strings.Contains(p, "/.git/") || strings.HasSuffix(p, "/.git") {
		return gitWeight, "git repository"
	}
	for _, e := range fileExt {
		if strings.HasSuffix(p, e.ext) {
			return e.w, e.ext + " file"
		}
	}
	return 0, ""
}

func isListing(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	return strings.HasPrefix(t, "index of") || strings.Contains(t, "listing directory") || strings.HasPrefix(t, "directory listing for")
}

func apiDocPath(path string) bool {
	p := strings.ToLower(strings.TrimSuffix(path, "/"))
	for _, s := range []string{"/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/api-docs", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html", "/v2/api-docs", "/v3/api-docs"} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

func (h *hunter) graphql(c *cand, r engine.MapEntry, path string) {
	schema := false
	for _, op := range r.Ops {
		if op.Source == "graphql" {
			schema = true
		}
	}
	switch p := strings.ToLower(path); {
	case schema:
		c.addProved("graphql", graphqlStrong, "GraphQL endpoint, schema read by introspection")
	case strings.Contains(r.Proof, "role=graphql") && strings.Contains(p, "graphiql"), strings.Contains(strings.ToLower(r.Title), "graphiql"):
		c.addProved("graphql", graphqlStrong, "GraphQL IDE answers at "+path)
	case strings.Contains(r.Proof, "role=graphql"):
		c.add("graphql", "answers like GraphQL at "+path)
	}
}

// objects finds an object identifier in the path or in a parameter's name.
func (h *hunter) objects(c *cand, r engine.MapEntry, path string) {
	w := weights["object-id"]
	if len(r.Methods) > 0 && !slices.Contains(r.Methods, "GET") {
		w = objectWriteOnly // nothing reads it that we know of
	}
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			c.addW("object-id", w, seg+" in the path")
			return
		}
	}
	for _, p := range engine.Watch(r) {
		if strings.HasSuffix(p, "(id)") {
			c.addW("object-id", w, "identifier parameter "+strings.TrimSuffix(p, " (id)"))
			return
		}
	}
}

// extraKinds are names the engine's kinds leave out: what a form passes
// to a shell, and what a search feeds a query.
var extraKinds = []struct {
	kind string
	re   *lazyre.Regexp
}{
	{"command", lazyre.New(`(?i)^(ip|ip_?address|address|addr|hostname|eqn|expr|expression)$`)},
	{"query", lazyre.New(`(?i)^(q|query|search|keyword|term|filter|sort|order|order_?by|s)$`)},
}

// fileish are selectors that name a file only when their value looks like
// one (?page=file1.php); a page number is not.
var fileish = lazyre.New(`(?i)^(page|view|module|doc)$`)

// chromeMin is how many pages of an origin carry an input name, and chromeShare
// (in percent) what share of its fetched pages, for the name to belong to the
// site's template: a search box or a sign-in form on every page.
const (
	chromeMin   = 5
	chromeShare = 40
)

// chromeInputs finds the input names the pages of an origin carry in common,
// by origin and name. Such a name says what the template holds, not what
// each route takes: its own route, the form's action, is where it counts. A
// name in the URL's own query is the route's.
func chromeInputs(rows []engine.MapEntry) map[string]*chromeInfo {
	pages := map[string]map[string]bool{} // origin → route templates fetched
	carry := map[string]map[string]bool{} // origin and name → route templates
	first := map[string]engine.MapEntry{} // origin and name → the page it was first seen on
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL || r.Coverage != "visited" || r.Status < 200 || r.Status >= 500 || staticURL(r) {
			continue
		}
		u, err := url.Parse(r.Entity.Key)
		if err != nil {
			continue
		}
		origin, key := u.Scheme+"://"+u.Host, GroupKey(r.Entity.Key, r.Role == "client-route")
		if pages[origin] == nil {
			pages[origin] = map[string]bool{}
		}
		pages[origin][key] = true
		own := u.Query()
		for _, n := range inputNames(r) {
			if _, ok := own[n]; ok {
				continue
			}
			id := origin + "\x00" + n
			if carry[id] == nil {
				carry[id] = map[string]bool{}
			}
			carry[id][key] = true
			if f, ok := first[id]; !ok || r.Entity.FirstSeen.Before(f.Entity.FirstSeen) ||
				r.Entity.FirstSeen.Equal(f.Entity.FirstSeen) && r.Entity.Key < f.Entity.Key {
				first[id] = r
			}
		}
	}
	out := map[string]*chromeInfo{}
	for id, routes := range carry {
		origin, name, _ := strings.Cut(id, "\x00")
		if n := len(routes); n >= chromeMin && n*100 >= len(pages[origin])*chromeShare {
			out[id] = &chromeInfo{origin: origin, name: name, pages: n, of: len(pages[origin]), first: first[id]}
		}
	}
	return out
}

// chromeInfo is an input name the pages of an origin carry in common: on
// how many of its fetched pages, and the page it was first seen on.
type chromeInfo struct {
	origin, name string
	pages, of    int
	first        engine.MapEntry
}

// templates gives each such input one row of its own: a site-wide search
// box can be the way in, so it is listed once per origin, on the page it
// was first seen on, ranked by what its name says, while the pages that
// only carry it have no signal for it.
func (h *hunter) templates() {
	for _, ci := range h.chrome {
		raw := ci.first.Entity.Key
		c := h.get("URL", raw+"\x00template\x00"+ci.name, ci.first.Scope)
		c.instances = []string{raw}
		c.origin = ci.origin
		c.tmpl = &Template{Input: ci.name, Pages: ci.pages, Of: ci.of}
		detail := fmt.Sprintf("input %s on %d of %d pages of %s (the site's template)", ci.name, ci.pages, ci.of, ci.origin)
		c.add("input", detail)
		seen := map[string]bool{}
		note := func(kind string) {
			if kind != "id" && !seen[kind] {
				seen[kind] = true
				c.add("param-"+kind, detail)
			}
		}
		for _, w := range engine.Watch(engine.MapEntry{Params: []string{ci.name}}) {
			if i := strings.LastIndex(w, " ("); i > 0 {
				note(strings.TrimSuffix(w[i+2:], ")"))
			}
		}
		for _, k := range extraKinds {
			if k.re.MatchString(ci.name) {
				note(k.kind)
			}
		}
	}
}

// own is the names of a route's input that its own page takes, not those
// its origin's template carries on most pages.
func (h *hunter) own(r engine.MapEntry, names []string) []string {
	u, err := url.Parse(r.Entity.Key)
	if err != nil || len(h.chrome) == 0 {
		return names
	}
	var out []string
	for _, n := range names {
		if _, inQuery := u.Query()[n]; inQuery || h.chrome[u.Scheme+"://"+u.Host+"\x00"+n] == nil {
			out = append(out, n)
		}
	}
	return out
}

func (h *hunter) params(c *cand, r engine.MapEntry, raw string, u *url.URL) {
	seen := map[string]bool{}
	note := func(kind, name string) {
		if kind == "id" || seen[kind+name] {
			return // identifiers are the object-id signal
		}
		seen[kind+name] = true
		c.add("param-"+kind, name)
	}
	for _, w := range engine.Watch(r) {
		if i := strings.LastIndex(w, " ("); i > 0 && len(h.own(r, []string{w[:i]})) > 0 {
			note(strings.TrimSuffix(w[i+2:], ")"), w[:i])
		}
	}
	for _, name := range h.own(r, allNames(r, u)) {
		for _, k := range extraKinds {
			if k.re.MatchString(name) {
				note(k.kind, name)
			}
		}
		if fileish.MatchString(name) {
			if v := u.Query().Get(name); strings.ContainsAny(v, "./") {
				note("file", name+"="+clip(v, 30))
			}
		}
	}
}

func allNames(r engine.MapEntry, u *url.URL) []string {
	var out []string
	out = append(out, r.Params...)
	out = append(out, r.Body...)
	for _, o := range r.Ops {
		out = append(out, o.Query...)
		out = append(out, o.Body...)
	}
	for _, f := range r.Forms {
		out = append(out, f.Fields...)
	}
	for k := range u.Query() {
		out = append(out, k)
	}
	return out
}

func inputNames(r engine.MapEntry) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n == "" || seen[n] || strings.EqualFold(n, "submit") {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range r.Params {
		add(n)
	}
	for _, n := range r.Body {
		add(n)
	}
	for _, f := range r.Forms {
		for _, n := range f.Fields {
			add(n)
		}
	}
	return out
}

var writeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// writes: a write method no description asks credentials for, on a route
// that did not turn the plain request away.
func (h *hunter) writes(c *cand, r engine.MapEntry, ok bool, st int) {
	if st == 401 || st == 403 || strings.Contains(r.Proof, "auth=") {
		return // the run held a session, or the route wants one
	}
	guarded := map[string]bool{}
	for _, o := range r.Ops {
		if o.Auth {
			guarded[strings.ToUpper(o.Method)] = true
		}
	}
	var ms []string
	for _, m := range r.Methods {
		if m = strings.ToUpper(m); writeMethods[m] && !guarded[m] {
			ms = append(ms, m)
		}
	}
	if len(ms) == 0 {
		return
	}
	if ok {
		c.add("unauth-write", strings.Join(ms, ", ")+": nothing that names it asks for credentials, and a GET of it answers without a session (the write was not tried)")
	} else {
		c.addW("unauth-write", unauthWriteDry, strings.Join(ms, ", ")+": nothing that names it asks for credentials (not tried)")
	}
}

// host reads the signals of a hostname: a word that names a staging or
// internal machine.
func (h *hunter) host(r engine.MapEntry) {
	if r.Role != "live" && r.Role != "sibling" {
		return
	}
	var c *cand
	labels := strings.Split(r.Entity.Key, ".")
	if len(labels) < 3 {
		return // the registered domain's own label is not a hint
	}
	for _, w := range wordsOf(strings.Join(labels[:len(labels)-2], ".")) {
		pw, ok := pathWords[w]
		if !ok || pw.signal == "path-function" || pw.signal == "path-data" || pw.signal == "path-auth" || pw.signal == "path-search" {
			continue // for routes, not for names
		}
		if c == nil {
			c = h.get("Hostname", r.Entity.Key, r.Scope)
			if r.Entity.FirstSeen.After(h.cut) {
				c.fresh = true
			}
		}
		c.addW(pw.signal, pw.w, fmt.Sprintf("%q in the host name, which resolves", w))
	}
}

func (h *hunter) secrets() {
	// The strongest first: a row keeps the first reason of a weight, so a
	// file's row names its strongest secret, not the first found.
	secrets := slices.Clone(h.in.Secrets)
	slices.SortStableFunc(secrets, func(a, b Secret) int {
		if wa, wb := secretWeight[a.Severity], secretWeight[b.Severity]; wa != wb {
			return wb - wa
		}
		return cmp.Compare(b.Entropy, a.Entropy)
	})
	for _, s := range secrets {
		w := secretWeight[s.Severity]
		if w == 0 {
			w = secretWeight["info"]
		}
		c := h.get("URL", s.Where, "target")
		c.instances = append(c.instances, s.Where)
		if s.Known {
			c.addProved("secret", w, secretDetail(s))
		} else {
			c.addW("secret", w, secretDetail(s))
		}
	}
}

func (h *hunter) takeovers() {
	for _, t := range h.in.Takeovers {
		c := h.get("Hostname", t.Host, "target")
		if t.Dangling && !t.Strong {
			c.dangling = true
			c.addW("takeover-candidate", weights["takeover-candidate"], t.Detail)
			continue
		}
		w := weights["takeover"]
		if t.Strong {
			w = takeoverStrong
		}
		if t.Strong {
			c.addProved("takeover", w, t.Detail)
		} else {
			c.addW("takeover", w, t.Detail)
		}
	}
}

// secretDetail is what a reader needs to judge a candidate: where, the name
// it was assigned to, the value redacted, and the rule that listed it.
func secretDetail(s Secret) string {
	d := fmt.Sprintf("%s (%s) in %s", s.Kind, s.Severity, s.Where)
	var ev []string
	if s.Name != "" {
		ev = append(ev, "name "+s.Name)
	}
	if s.Preview != "" {
		ev = append(ev, "value "+s.Preview)
	}
	if s.Rule != "" {
		ev = append(ev, "rule: "+s.Rule)
	}
	if s.Entropy > 0 {
		ev = append(ev, fmt.Sprintf("entropy %.1f", s.Entropy))
	}
	if len(ev) > 0 {
		d += "; " + strings.Join(ev, ", ")
	}
	return d
}

// sourceMaps gives each host one row for the source maps azhaq read there,
// weighted by what they expose: the app's own code (sourcesContent) or only
// the names of its files. azhaq already fetched and parsed each map.
func (h *hunter) sourceMaps() {
	if len(h.maps) == 0 {
		return
	}
	read := mapsRead(h.in.Obs)
	for _, origin := range slices.Sorted(maps.Keys(h.maps)) {
		rows := h.maps[origin]
		slices.SortFunc(rows, func(a, b engine.MapEntry) int { return strings.Compare(a.Entity.Key, b.Entity.Key) })
		scope := "fanout"
		var files, code int
		known := true // every map says how much code it carries (older workspaces do not)
		for _, r := range rows {
			if r.Scope == "target" {
				scope = "target"
			}
			m, ok := read[r.Entity.Key]
			if !ok || m.code == nil {
				known = false
			} else {
				code += *m.code
			}
			files += m.files
		}
		c := h.get("URL", rows[0].Entity.Key, scope)
		c.origin = origin
		for _, r := range rows {
			c.instances = append(c.instances, r.Entity.Key)
			if r.Entity.FirstSeen.After(h.cut) {
				c.fresh = true
			}
		}
		what := fmt.Sprintf("%s read on this host, naming %s of the app's own", plural(len(rows), "source map"), plural(files, "source file"))
		w := weights["sourcemap"]
		switch {
		case !known:
			what += "; whether they carry the code was not recorded"
		case code > 0:
			what += fmt.Sprintf(", %d with their code (sourcesContent)", code)
		default:
			what += ", names only: no code"
			w = mapNamesOnly
		}
		c.addW("sourcemap", w, what)
	}
}

// mapNamesOnly weighs source maps that name the app's files but carry none
// of their code: below a secret, above a bare path word.
const mapNamesOnly = 20

type mapRead struct {
	files int
	code  *int
}

// mapsRead is what azhaq-js read of each source map, by URL.
func mapsRead(obs []types.StoredObservation) map[string]mapRead {
	out := map[string]mapRead{}
	for _, o := range obs {
		if o.Collector != "azhaq-js" || o.Kind != "url" {
			continue
		}
		var p struct {
			URL   string   `json:"url"`
			Role  string   `json:"role"`
			Files []string `json:"files"`
			Code  *int     `json:"with_code"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Role != "sourcemap" {
			continue
		}
		k, err := engine.FoundKey(p.URL, p.Role)
		if err != nil {
			continue
		}
		out[k] = mapRead{files: len(p.Files), code: p.Code}
	}
	return out
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
