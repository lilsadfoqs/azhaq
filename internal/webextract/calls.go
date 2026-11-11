package webextract

import (
	"regexp"
	"sort"
	"strings"
)

// Call is a request a script makes: the method of the client call, the
// path it builds, and the names of what it sends.
//
//	this.http.post(this.hostServer+`/rest/2fa/verify`,{tmpToken:t,totpToken:e})
//	→ POST /rest/2fa/verify, body tmpToken totpToken
//
// Paths keep the parts known only at run time as {name} placeholders:
// `${this.host}/${e.id}` in a service whose host is …+`/api/Cards` is
// /api/Cards/{id}.
//
// A request made inside a function that takes the URL as a parameter is
// read where the function is called, one level deep:
//
//	async function logQuery(url,params){await fetch(url,{method:"post",…})}
//	logQuery('/logger',config.params) → POST /logger
type Call struct {
	Method string   // "" when only a value known at run time says
	Path   string   // starts with / (the app's origin), or an absolute URL
	Query  []string // query parameter names
	Body   []string // field names of an object literal body
	At     int      // where the call starts in the script
	End    int      // and where it ends
	// Client: made through an HTTP client, which joins a path onto its
	// base; Recv is the object it is called on (this.http, o).
	Client bool
	Recv   string
	// Base is the base the script declares for the client, and Route the
	// path the call names: Path is Route joined onto Base.
	Base  string
	Route string
	// Value: a URL built on a page global where the script holds it as a
	// value (uploadUrl: Cfg.server + "/api/upload"), not where it asks it.
	Value bool
}

var (
	// clientCall: .get( .post( … on any object (an HTTP client, axios, $).
	clientCall = lazyRE(`\.(get|post|put|patch|delete|head)\s*\(`)
	fetchCall  = lazyRE(`(?:^|[^\w$.])fetch\s*\(`)
	xhrOpen    = lazyRE(`\.open\s*\(\s*["'\x60](GET|POST|PUT|PATCH|DELETE|HEAD)["'\x60]\s*,`)
	// ajaxCall: $.ajax({url,type,data}), axios({url,method,data}),
	// axios.request(…), and their (url, settings) forms.
	ajaxCall   = lazyRE(`(?:^|[^\w$.])(?:(?:\$|jQuery)\s*\.\s*ajax|axios(?:\s*\.\s*request)?)\s*\(`)
	methodOpt  = lazyRE(`(?i)\bmethod\s*:\s*["'\x60](get|post|put|patch|delete|head)["'\x60]`)
	identChain = lazyRE(`^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$`)
	// originName: a variable that holds a scheme and host, not a path.
	originName = lazyRE(`(?i)(host|server|base|origin|domain|backend|endpoint|apiurl|api_url|baseurl|root|url)`)
	pathChars  = lazyRE(`^(?:https?://[\w.:-]+)?/[\w.~%{}@!$&'*+,;=:/?-]*$`)
	keyRE      = lazyRE(`^\s*(?:["'\x60]?)([A-Za-z_$][\w$-]*)(?:["'\x60]?)\s*(?::|$)`)
)

var (
	// clientHolder: the object an axios instance keeps its settings on.
	clientHolder = lazyRE(`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.(?:interceptors|defaults)\b`)
	// clientAlias: u = axios, u = _.a, u = axios.create(…).
	clientAlias = lazyRE(`(?:\b(?:var|let|const)\s+|[,;(]\s*)([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*(\.create\s*\(|[,;)]|$)`)
)

// clientAliases are the names a script gives an axios client it calls as
// a function (u({url, method, data})), with the client each stands for:
// the object whose .interceptors or .defaults the script uses, or axios.
func clientAliases(script string) map[string]string {
	if !strings.Contains(script, "interceptors") && !strings.Contains(script, ".defaults") && !strings.Contains(script, "axios") {
		return nil
	}
	roots := map[string]bool{"axios": true}
	for _, m := range clientHolder.get().FindAllStringSubmatch(script, 64) {
		if m[1] != "this" && !strings.HasPrefix(m[1], "this.") {
			roots[m[1]] = true
		}
	}
	var out map[string]string
	for _, m := range clientAlias.get().FindAllStringSubmatch(script, -1) {
		if !roots[m[2]] || len(m[1]) < 1 || roots[m[1]] {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		if len(out) < 16 {
			out[m[1]] = m[2]
		}
	}
	return out
}

// maxCalls caps the calls read from one script.
const maxCalls = 4000

// Calls returns the requests script makes through an HTTP client, fetch
// or XMLHttpRequest whose URL it can work out.
func Calls(script string) []Call { return calls(script, false, nil) }

// CallsWith is Calls for a script of a page whose inline scripts set g.
func CallsWith(script string, g Globals) []Call { return calls(script, false, g) }

// PageCalls is Calls for a script inline in a page: a path without a
// leading slash given to fetch or XMLHttpRequest (xhr.open("GET",
// "util/status.jsp?host=" + h)) is relative to the page, and is kept as
// written for the caller to resolve.
func PageCalls(script string) []Call { return calls(script, true, nil) }

// PageCallsWith is PageCalls with the page's globals.
func PageCallsWith(script string, g Globals) []Call { return calls(script, true, g) }

// relPath: a page-relative path that names a resource (a directory or a
// file with an extension), not a bare word.
var relPath = lazyRE(`^[\w~-][\w.~%{}@!$&'*+,;=:-]*(?:/[\w.~%{}@!$&'*+,;=:-]*)+$|^[\w~-][\w~-]*\.(?:jsp|jspx|php|asp|aspx|ashx|do|action|cgi|pl|json|xml|html?)$`)

func calls(script string, relative bool, g Globals) []Call {
	var out []Call
	var wraps []wrapper
	partial := map[int][]int{}                                               // wrapper → the calls read inside it
	names := wrapNames{trusted: map[string]bool{}, stored: map[int]string{}} // function name → worth following
	tries := 0
	add := func(c Call, ok bool, at, end int) int {
		if !ok || len(out) >= maxCalls {
			return -1
		}
		c.At, c.End = at, end
		out = append(out, c)
		return len(out) - 1
	}
	// wrap remembers the function around a request when the request's URL
	// ends with one of the function's parameters. direct is the call read
	// from the request alone, if any: fetch(API+path) is POST /api/v2 for
	// lack of the path, while fetch("/api/accounts/"+id) is a route of its
	// own, /api/accounts/{id}, whatever the callers pass.
	wrap := func(pos int, url string, sh shape, direct int) {
		if _, _, ok := urlParam(url); !ok || len(wraps) >= maxWrappers || tries >= maxWrapperTries {
			return
		}
		tries++
		w, ok := wrapperOf(script, g, pos, url, sh, names)
		if !ok {
			return
		}
		i := len(wraps)
		for j, x := range wraps {
			if x.same(w) {
				i = j // two requests alike in one helper: its calls are read once
				break
			}
		}
		if i == len(wraps) {
			wraps = append(wraps, w)
		}
		if direct >= 0 && truncated(script, g, pos, url) {
			partial[i] = append(partial[i], direct)
		}
	}
	for _, m := range clientCall.FindAllStringSubmatchIndex(script, -1) {
		method := strings.ToUpper(script[m[2]:m[3]])
		args := callArgs(script, m[1]-1)
		if len(args) == 0 {
			continue
		}
		at, end := receiverStart(script, m[0]), closeParen(script, m[1]-1)+1
		// An HTTP client may have a base URL of its own: only fetch and
		// XMLHttpRequest resolve a relative path against the page.
		c, ok := callOf(script, g, m[0], method, args[0], false)
		c.Client, c.Recv = true, script[at:m[0]]
		if ok && len(args) > 1 {
			opts := strings.TrimSpace(args[1])
			switch method {
			case "POST", "PUT", "PATCH":
				c.Body = objectKeys(opts)
				if c.Body == nil {
					// post(r,n) with n set before to an object (or a FormData).
					c.Body = evaluator{src: script, globals: g}.bodyNames(opts, m[0], 0)
				}
				if strings.HasPrefix(opts, "{") && len(args) > 2 {
					c.Query = append(c.Query, paramsOption(args[2])...)
				}
			default:
				c.Query = append(c.Query, paramsOption(opts)...)
			}
		}
		direct := add(c, ok, at, end)
		sh := shape{method: method}
		if len(args) > 1 {
			switch method {
			case "POST", "PUT", "PATCH":
				sh.bodyEx = args[1]
			}
		}
		wrap(m[0], args[0], sh, direct)
	}
	for _, m := range fetchCall.FindAllStringIndex(script, -1) {
		args := callArgs(script, m[1]-1)
		if len(args) == 0 {
			continue
		}
		at := m[0] + strings.Index(script[m[0]:m[1]], "fetch")
		end := closeParen(script, m[1]-1) + 1
		method := "GET"
		var body []string
		ev := evaluator{src: script, globals: g}
		opts := ""
		if len(args) > 1 {
			opts = strings.TrimSpace(args[1])
			if identChain.MatchString(opts) {
				// fetch(url, opts) with opts set to an object just before.
				if rhs, ok := ev.assignedRHS(opts, m[0]); ok && strings.HasPrefix(rhs, "{") {
					opts = rhs
				}
			}
			if mm := methodOpt.FindStringSubmatch(opts); mm != nil {
				method = strings.ToUpper(mm[1])
			} else if !strings.HasPrefix(opts, "{") {
				method = "" // fetch(url, opts): the options say, at run time
			}
			if body = bodyOption(opts); body == nil {
				body = ev.bodyNames(optionExpr(opts, "body"), m[0], 0)
			}
		}
		c, ok := callOf(script, g, m[0], method, args[0], relative)
		c.Body = body
		direct := add(c, ok, at, end)
		sh := shape{method: "GET", bodyKey: "body"}
		if len(args) > 1 {
			sh = settingsShape(opts, "body")
		}
		sh.pageRel = true
		wrap(m[0], args[0], sh, direct)
	}
	for _, m := range xhrOpen.FindAllStringSubmatchIndex(script, -1) {
		rest := topExpr(script[m[1]:])
		at := receiverStart(script, m[0])
		end := m[1] + len(rest)
		if e := closeParen(script, strings.IndexByte(script[m[0]:], '(')+m[0]); e > 0 {
			end = e + 1
		}
		c, ok := callOf(script, g, m[0], script[m[2]:m[3]], rest, relative)
		if ok {
			c.Body = evaluator{src: script, globals: g}.xhrBody(m[0], m[1])
		}
		wrap(m[0], rest, shape{method: script[m[2]:m[3]], pageRel: true}, add(c, ok, at, end))
	}
	type ajaxHit struct {
		m     []int
		recv  string // the client a call is made on: axios, or the one an alias stands for
		alias bool
	}
	var ajax []ajaxHit
	if strings.Contains(script, "ajax") || strings.Contains(script, "axios") {
		for _, m := range ajaxCall.FindAllStringIndex(script, -1) { // most bundles have neither
			recv := ""
			if strings.Contains(script[m[0]:m[1]], "axios") {
				recv = "axios"
			}
			ajax = append(ajax, ajaxHit{m: m, recv: recv})
		}
	}
	for name, root := range clientAliases(script) {
		re, err := regexp.Compile(`(?:^|[^\w$.])(` + regexp.QuoteMeta(name) + `)\s*\(`)
		if err != nil {
			continue
		}
		for _, m := range re.FindAllStringSubmatchIndex(script, -1) {
			ajax = append(ajax, ajaxHit{m: []int{m[2], m[1]}, recv: root, alias: true})
		}
	}
	sort.SliceStable(ajax, func(i, j int) bool { return ajax[i].m[0] < ajax[j].m[0] })
	for _, h := range ajax {
		m := h.m
		args := callArgs(script, m[1]-1)
		if len(args) == 0 {
			continue
		}
		at := m[0]
		if c := script[at]; !h.alias && c != '$' && c != 'j' && c != 'a' {
			at++ // the character before the call
		}
		end := closeParen(script, m[1]-1) + 1
		url, settings := strings.TrimSpace(args[0]), ""
		if identChain.MatchString(url) {
			// axios(config) with config set to an object just before.
			if rhs, ok := (evaluator{src: script, globals: g}).assignedRHS(url, m[0]); ok && strings.HasPrefix(rhs, "{") {
				url, settings = optionExpr(rhs, "url"), rhs
			}
		}
		if strings.HasPrefix(url, "{") {
			url, settings = optionExpr(url, "url"), url
		} else if settings == "" && len(args) > 1 {
			settings = args[1]
		}
		if h.alias && !strings.HasPrefix(strings.TrimSpace(settings), "{") || h.alias && len(args) != 1 {
			continue // a short name is a client only where it is given a config
		}
		if url == "" {
			continue
		}
		sh := shape{method: "GET", bodyKey: "data"}
		if strings.TrimSpace(settings) != "" {
			sh = settingsShape(settings, "data")
		}
		// jQuery sends a GET's data as its query string; axios sends data
		// as the body and params as the query.
		sh.dataQuery = strings.Contains(script[m[0]:m[1]], "ajax")
		sh.pageRel = true
		if sh.body == nil && sh.bodyEx != "" {
			sh.body = evaluator{src: script, globals: g}.bodyNames(sh.bodyEx, m[0], 0)
		}
		c, ok := callOf(script, g, m[0], sh.method, url, relative)
		if h.recv != "" {
			c.Client, c.Recv = true, h.recv
		}
		c.Body, c.Query = sh.body, append(c.Query, sh.query...)
		if sh.dataQuery && (c.Method == "GET" || c.Method == "HEAD") {
			c.Query, c.Body = append(c.Query, c.Body...), nil
		}
		wrap(m[0], url, sh, add(c, ok, at, end))
	}
	drop := map[int]bool{}
	for i, w := range wraps {
		found := w.calls(script, relative, g)
		if len(found) > 0 {
			for _, d := range partial[i] {
				drop[d] = true // the callers say what the helper alone could not
			}
		}
		for _, c := range found {
			add(c, true, c.At, c.End)
		}
	}
	if len(drop) > 0 {
		kept := out[:0]
		for i, c := range out {
			if !drop[i] {
				kept = append(kept, c)
			}
		}
		out = kept
	}
	out = append(out, valueCalls(script, g, out)...)
	return withBases(script, out, g)
}

// valueCalls are the URLs the script builds on a page global anywhere but
// in a call it reads already: Cfg.server + "/api/upload" held in a field
// or a variable. They have no method.
func valueCalls(script string, g Globals, have []Call) []Call {
	if len(g) == 0 {
		return nil
	}
	names := make([]string, 0, len(g))
	for n, v := range g {
		if !bareOrigin(v) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	ev := evaluator{src: script, globals: g}
	var out []Call
	for _, name := range names {
		for from := 0; ; {
			i := strings.Index(script[from:], name)
			if i < 0 {
				break
			}
			i += from
			from = i + len(name)
			if !ev.usable(name) || from >= len(script) || isIdentByte(script[from]) {
				continue
			}
			start := i
			if strings.HasSuffix(script[:i], "window.") {
				start -= len("window.")
			}
			if start > 0 && (isIdentByte(script[start-1]) || script[start-1] == '.') {
				continue
			}
			if p := skipSpaceBack(script, start); p >= 0 && !strings.ContainsRune("=:(,?[{;&|", rune(script[p])) {
				if w, _ := wordBefore(script, start); w != "return" {
					continue // x + Cfg.server + "/a": not the start of the URL
				}
			}
			j := skipSpace(script, from)
			if j >= len(script) || script[j] != '+' {
				continue
			}
			if k := skipSpace(script, j+1); k >= len(script) || !strings.ContainsRune("\"'`", rune(script[k])) {
				continue
			}
			expr := concatExpr(script[start:])
			covered := false
			for _, c := range have {
				covered = covered || c.At <= start && start < c.End
			}
			path, ok := ev.eval(expr, start, 0)
			if covered || !ok {
				continue
			}
			c, hit, ok := ev.onBase(path, "")
			if !hit || !ok {
				continue
			}
			c.Value, c.At, c.End = true, start, start+len(expr)
			if out = append(out, c); len(out) >= maxCalls/4 {
				return out
			}
		}
	}
	return out
}

// concatExpr is the string concatenation s starts with: it ends where
// anything else does, a ternary, an assignment, a comparison, a list.
func concatExpr(s string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(s) && i < 4096; i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(' || c == '{' || c == '[':
			depth++
		case c == ')' || c == '}' || c == ']':
			if depth == 0 {
				return strings.TrimSpace(s[:i])
			}
			depth--
		case depth == 0 && strings.ContainsRune(",;:?=&|<>!\n", rune(c)):
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

// truncated: the URL argument at pos evaluates to what comes before an
// unknown part with no placeholder for it, "/api" for "/api"+path, not
// "/api/accounts/{id}" for "/api/accounts/"+id.
func truncated(script string, g Globals, pos int, arg string) bool {
	ev := evaluator{src: script, globals: g}
	v, ok := ev.eval(arg, pos, 0)
	return ok && !strings.HasSuffix(v, "}")
}

// callOf evaluates the URL argument of a call at pos; relative allows a
// page-relative path.
func callOf(script string, g Globals, pos int, method, arg string, relative bool) (Call, bool) {
	ev := evaluator{src: script, globals: g}
	path, ok := ev.eval(arg, pos, 0)
	if !ok {
		return Call{}, false
	}
	if c, hit, ok := ev.onBase(path, method); hit {
		return c, ok
	}
	return callFrom(path, method, relative)
}

// onBase is the call whose URL starts with a global the page's inline
// scripts set (DocConfig.server + "/api/x", also through a variable that
// holds it): the global is its base, kept apart from the route as a
// client's baseURL is, so that a base with a query of its own
// (…/index.php?s=) stays whole. hit says the URL is built on a global; ok
// that the rest of it is a route. A base with a query and no route after
// it (DocConfig.server + t) is no call: its query is the route.
func (ev evaluator) onBase(path, method string) (c Call, hit, ok bool) {
	base := ""
	for _, v := range ev.globals {
		if len(v) > len(base) && strings.HasPrefix(path, v) && !bareOrigin(v) {
			base = v
		}
	}
	if base == "" {
		return Call{}, false, false
	}
	rest := path[len(base):]
	if !strings.HasPrefix(rest, "/") {
		return Call{}, strings.Contains(base, "?"), false
	}
	c, ok = callFrom(rest, method, false)
	if !ok {
		return Call{}, strings.Contains(base, "?"), false
	}
	c.Route, c.Base = c.Path, base
	c.Path = base + c.Path
	return c, true, true
}

// bareOrigin: a scheme and host with no path or query of their own.
func bareOrigin(v string) bool {
	i := strings.Index(v, "://")
	if i < 0 {
		return strings.Trim(v, "/") == ""
	}
	return !strings.ContainsAny(strings.TrimRight(v[i+3:], "/"), "/?")
}

// usable: a bare name of a minified local, or one a function takes as a
// parameter, is not the page's global.
func (ev evaluator) usable(name string) bool {
	if !strings.Contains(name, ".") {
		if len(name) <= 2 || shadowed(ev.src, name) {
			return false
		}
	}
	return true
}

// shadowed: name is a parameter of some function in src.
func shadowed(src, name string) bool {
	if !strings.Contains(src, name) {
		return false
	}
	q := regexp.QuoteMeta(name)
	re, err := regexp.Compile(`function\s*[\w$]*\s*\([^)]*\b` + q + `\b[^)]*\)|\([^()]*\b` + q + `\b[^()]*\)\s*=>|\b` + q + `\s*=>`)
	return err == nil && re.MatchString(src)
}

// callFrom is the call to a URL worked out from a script.
func callFrom(path, method string, relative bool) (Call, bool) {
	path, query := splitQuery(path)
	if relative && relPath.MatchString(path) && !strings.HasPrefix(path, "{") {
		return Call{Method: method, Path: path, Query: query}, true
	}
	if !pathChars.MatchString(path) || path == "/" && len(query) == 0 || strings.Contains(path, "//{") {
		return Call{}, false
	}
	return Call{Method: method, Path: path, Query: query}, true
}

// splitQuery separates a built path from its query and keeps the names.
func splitQuery(p string) (string, []string) {
	path, q, ok := strings.Cut(p, "?")
	if !ok {
		return p, nil
	}
	var names []string
	for _, kv := range strings.Split(q, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k = strings.TrimSpace(k); k != "" && !strings.ContainsAny(k, "{}") {
			names = append(names, k)
		}
	}
	return path, names
}

// evaluator works out the string an expression builds, from the literals
// in it and the variables the script assigns once.
type evaluator struct {
	src     string
	globals Globals // what the page's inline scripts set from its location
}

const maxDepth = 4

func (ev evaluator) eval(expr string, pos, depth int) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || depth > maxDepth {
		return "", false
	}
	var b strings.Builder
	for _, term := range splitTop(expr, "+") {
		term = strings.TrimSpace(term)
		if term == "" {
			return "", false
		}
		v, known, name := ev.term(term, pos, depth)
		switch {
		case known:
			b.WriteString(v)
		case b.Len() == 0:
			// What a URL starts with but the script does not spell out
			// is its scheme and host: hostServer, baseUrl, environment.api.
			if name == "" || !originName.MatchString(name) && !strings.HasPrefix(name, "this.") {
				return "", false
			}
		case endsPart(b.String()):
			b.WriteString(placeholderFor(name))
		default:
			// "/whoami"+t: what follows is not a segment of its own (a
			// query string, a suffix); the path is what is known.
			return b.String(), true
		}
	}
	return b.String(), b.Len() > 0
}

// endsPart: the next part of a path or query starts here.
func endsPart(s string) bool {
	return strings.HasSuffix(s, "/") || strings.HasSuffix(s, "=")
}

// term is the value of one operand of a concatenation: known, or unknown
// with the name of the variable that holds it.
func (ev evaluator) term(t string, pos, depth int) (string, bool, string) {
	switch t[0] {
	case '"', '\'':
		if s, ok := unquote(t); ok {
			return s, true, ""
		}
		return "", false, ""
	case '`':
		return ev.template(t, pos, depth)
	case '(':
		if strings.HasSuffix(t, ")") {
			v, ok := ev.eval(t[1:len(t)-1], pos, depth+1)
			return v, ok, ""
		}
	}
	if !identChain.MatchString(t) {
		return "", false, lastName(t)
	}
	name := strings.Join(strings.Fields(t), "")
	if v, ok := ev.binding(name, pos, depth); ok {
		return v, true, name
	}
	if g := strings.TrimPrefix(name, "window."); ev.globals != nil && ev.usable(g) {
		if v, ok := ev.globals[g]; ok {
			return v, true, name // set by the page's own script, from its location
		}
	}
	return "", false, name
}

// template evaluates a template literal; each ${…} is evaluated or kept
// as a placeholder.
func (ev evaluator) template(t string, pos, depth int) (string, bool, string) {
	if len(t) < 2 || t[len(t)-1] != '`' {
		return "", false, ""
	}
	body := t[1 : len(t)-1]
	var b strings.Builder
	for len(body) > 0 {
		i := strings.Index(body, "${")
		if i < 0 {
			b.WriteString(body)
			break
		}
		b.WriteString(body[:i])
		end := closeBrace(body, i+2)
		if end < 0 {
			return "", false, ""
		}
		inner := body[i+2 : end]
		v, ok := ev.eval(inner, pos, depth+1)
		switch {
		case ok:
			b.WriteString(v)
		case b.Len() == 0 && (originName.MatchString(inner) || strings.HasPrefix(strings.TrimSpace(inner), "this.")):
			// ${this.hostServer}/rest/…: the origin.
		case b.Len() == 0:
			return "", false, ""
		case endsPart(b.String()):
			b.WriteString(placeholderFor(lastName(inner)))
		default:
			return b.String(), true, ""
		}
		body = body[end+1:]
	}
	return b.String(), true, ""
}

// binding finds the last assignment to name before pos and evaluates it:
// this.host=…, a class field host=…, a variable r=….
func (ev evaluator) binding(name string, pos, depth int) (string, bool) {
	field := strings.TrimPrefix(name, "this.")
	if strings.Contains(field, ".") {
		return "", false // a property of another object: environment.apiUrl
	}
	if field == name && len(field) <= 2 {
		// A minified local: its name is reused everywhere, so only a
		// declaration just before, in the same function, is trusted:
		// let r=this.host+`/submitKey`,n={…};return this.http.post(r,n)
		rhs, at, ok := ev.declared(field, pos)
		if !ok {
			return "", false
		}
		return ev.eval(rhs, at, depth+1)
	}
	window := 3000
	if field != name || len(field) > 2 {
		window = 30000 // a field or a real name, not a minified local
	}
	start := max(0, pos-window)
	re, err := regexp.Compile(`(?:^|[^\w$.]|this\.)` + regexp.QuoteMeta(field) + `\s*=([^=>])`)
	if err != nil {
		return "", false
	}
	locs := re.FindAllStringSubmatchIndex(ev.src[start:pos], -1)
	if len(locs) == 0 {
		return "", false
	}
	at := start + locs[len(locs)-1][2]
	rhs := topExpr(ev.src[at:])
	if rhs == "" {
		return "", false
	}
	return ev.eval(rhs, at, depth+1)
}

// declared finds `let NAME=…`, `const NAME=…` or `, NAME=…` of a
// declaration list in the 300 bytes before pos, and returns what it is
// set to and where.
func (ev evaluator) declared(name string, pos int) (string, int, bool) {
	return ev.declaredWithin(name, pos, 300)
}

// declaredWithin is declared with the reach in bytes before pos.
func (ev evaluator) declaredWithin(name string, pos, reach int) (string, int, bool) {
	start := max(0, pos-reach)
	re := regexp.MustCompile(`(?:\b(?:let|const|var)\s+|,\s*)` + regexp.QuoteMeta(name) + `\s*=([^=>])`)
	locs := re.FindAllStringSubmatchIndex(ev.src[start:pos], -1)
	if len(locs) == 0 {
		return "", 0, false
	}
	at := start + locs[len(locs)-1][2]
	rhs := topExpr(ev.src[at:])
	return rhs, at, rhs != ""
}

// placeholderFor names a run-time part of a path after the variable that
// holds it when the name says something (e.username → {username}).
func placeholderFor(name string) string {
	n := lastName(name)
	if len(n) < 3 || strings.ContainsAny(n, "$") {
		return "{id}"
	}
	return "{" + n + "}"
}

func lastName(expr string) string {
	expr = strings.TrimSpace(expr)
	if i := strings.LastIndexAny(expr, ".("); i >= 0 && i+1 < len(expr) && identChain.MatchString(expr[i+1:]) {
		return expr[i+1:]
	}
	if identChain.MatchString(expr) {
		return expr
	}
	return ""
}

// callArgs splits the arguments of the call whose "(" is at open.
func callArgs(s string, open int) []string {
	end := closeParen(s, open)
	if end < 0 {
		return nil
	}
	return splitTop(s[open+1:end], ",")
}

// closeParen finds the ")" that closes the "(" at open, within 4 KB.
func closeParen(s string, open int) int {
	depth := 0
	var quote byte
	limit := min(len(s), open+4096)
	for i := open; i < limit; i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(' || c == '{' || c == '[':
			depth++
		case c == ')' || c == '}' || c == ']':
			depth--
			if depth == 0 {
				if c != ')' {
					return -1
				}
				return i
			}
		}
	}
	return -1
}

// closeBrace finds the "}" that ends a ${…} opened before i.
func closeBrace(s string, i int) int {
	depth := 0
	var quote byte
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

func unquote(t string) (string, bool) {
	if len(t) < 2 || t[len(t)-1] != t[0] {
		return "", false
	}
	inner := t[1 : len(t)-1]
	if strings.ContainsRune(inner, rune(t[0])) && !strings.Contains(inner, `\`) {
		return "", false // two strings, not one
	}
	return strings.ReplaceAll(inner, `\/`, `/`), true
}

// objectKeys lists the top-level keys of an object literal.
func objectKeys(obj string) []string {
	obj = strings.TrimSpace(obj)
	if !strings.HasPrefix(obj, "{") || !strings.HasSuffix(obj, "}") {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range splitTop(obj[1:len(obj)-1], ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "...") || part == "" {
			continue
		}
		m := keyRE.FindStringSubmatch(part)
		if m == nil || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

// paramsOption reads {params:{a:…,b:…}} from a client call's options.
func paramsOption(opts string) []string {
	return optionKeys(opts, "params")
}

// bodyOption reads body:JSON.stringify({…}) or body:{…} from fetch options.
func bodyOption(opts string) []string {
	for _, part := range splitTop(strings.Trim(strings.TrimSpace(opts), "{}"), ",") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || strings.TrimSpace(k) != "body" {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.TrimSuffix(strings.TrimPrefix(v, "JSON.stringify("), ")")
		return objectKeys(v)
	}
	return nil
}

func optionKeys(opts, key string) []string {
	opts = strings.TrimSpace(opts)
	if !strings.HasPrefix(opts, "{") {
		return nil
	}
	for _, part := range splitTop(opts[1:len(opts)-1], ",") {
		k, v, ok := strings.Cut(part, ":")
		if ok && strings.Trim(strings.TrimSpace(k), `"'`) == key {
			return objectKeys(v)
		}
	}
	return nil
}

// MergeCalls folds calls to the same method and path together, names
// sorted, in a stable order.
func MergeCalls(calls []Call) []Call {
	idx := map[string]int{}
	var out []Call
	for _, c := range calls {
		k := c.Method + " " + c.Path
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, Call{Method: c.Method, Path: c.Path, Base: c.Base, Route: c.Route, Value: true})
			i = len(out) - 1
		}
		out[i].Value = out[i].Value && c.Value
		out[i].Query = union(out[i].Query, c.Query)
		out[i].Body = union(out[i].Body, c.Body)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range append(append([]string(nil), a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
