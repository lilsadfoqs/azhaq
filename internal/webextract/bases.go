package webextract

import (
	"strings"
)

// Base is the base URL a script gives an HTTP client: the client joins
// every path it is asked for onto it.
//
//	const api = axios.create({baseURL: "server/index.php?s="})
//	api.get("/item/list")  → server/index.php?s=/item/list
type Base struct {
	Value  string // as the client joins it: "/api/v2", "server/index.php?s="
	Client string // the name of the instance it was given to; "" for a config or an anonymous client
	At     int    // where the declaration starts in the script
	End    int
}

var (
	// baseKey: axios {baseURL}, ky {prefixUrl}, and the camel-case twin.
	baseKey = lazyRE(`(?:^|[^\w$.])(?:baseURL|baseUrl|prefixUrl)\s*:\s*`)
	// baseSet: axios.defaults.baseURL = "…" and instance.defaults.baseURL = "…".
	baseSet = lazyRE(`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.defaults\.(?:baseURL|baseUrl)\s*=`)
	// baseValue: what a client can take as a base: an origin and a path,
	// or a path, relative to the page or not, with a query of its own
	// (server/index.php?s=). Never an expression, never a placeholder.
	baseValue = lazyRE(`^(?:https?://[\w.:-]+)?[\w.~%@!$&'*+,;=:/?-]*$`)
)

// Bases returns the bases script declares for its HTTP clients.
func Bases(script string) []Base { return bases(script, nil) }

func bases(script string, g Globals) []Base {
	if !strings.Contains(script, "aseURL") && !strings.Contains(script, "aseUrl") && !strings.Contains(script, "prefixUrl") {
		return nil
	}
	ev := evaluator{src: script, globals: g}
	var out []Base
	add := func(expr string, at, end, pos int, client string) {
		if len(out) >= 64 {
			return
		}
		v, ok := ev.eval(expr, pos, 0)
		if !ok {
			return
		}
		if v = strings.TrimSpace(v); v == "" || strings.Trim(v, "/") == "" || strings.HasPrefix(v, "//") || !baseValue.get().MatchString(v) {
			return // the origin's own root joins nothing
		}
		out = append(out, Base{Value: v, Client: client, At: at, End: end})
	}
	for _, m := range baseKey.FindAllStringSubmatchIndex(script, -1) {
		key := m[0] + strings.IndexAny(script[m[0]:m[1]], "bp")
		expr := topExpr(script[m[1]:])
		add(expr, key, m[1]+len(expr), m[1], instanceOf(script, key))
	}
	for _, m := range baseSet.FindAllStringSubmatchIndex(script, -1) {
		if m[1] < len(script) && script[m[1]] == '=' {
			continue // ==
		}
		expr := topExpr(script[m[1]:])
		add(expr, m[0], m[1]+len(expr), m[1], script[m[2]:m[3]])
	}
	return out
}

// instanceOf is the name a client created around the object at key is
// kept under: o in `const o = axios.create({baseURL: …})`; or, for a
// config object of its own (`const cfg = {baseURL: …}`), the name of the
// config, which a later `axios.create(cfg)` hands on.
func instanceOf(script string, key int) string {
	ob := openBrace(script, key)
	if ob < 0 {
		return ""
	}
	open := skipSpaceBack(script, ob)
	if open < 0 {
		return ""
	}
	if script[open] == '=' {
		return assignedName(script, open+1)
	}
	if script[open] != '(' {
		return ""
	}
	word, ws := wordBefore(script, open)
	if word != "create" && word != "extend" {
		return ""
	}
	// The assignment: name = recv.create(
	at := ws
	if at > 0 && script[at-1] == '.' {
		at = receiverStart(script, at-1)
	}
	return assignedName(script, at)
}

// assignedName is the name on the left of the = that comes just before
// at: o in `o = `, this.http in `this.http = `.
func assignedName(script string, at int) string {
	eq := skipSpaceBack(script, at)
	if eq < 1 || script[eq] != '=' || script[eq-1] == '=' || script[eq-1] == '!' || script[eq-1] == '<' || script[eq-1] == '>' {
		return ""
	}
	end := skipSpaceBack(script, eq) + 1
	start := end
	for start > 0 && (isIdentByte(script[start-1]) || script[start-1] == '.') {
		start--
	}
	if start == end || script[start] >= '0' && script[start] <= '9' {
		return ""
	}
	return script[start:end]
}

// JoinBase is the path a client with base asks for when given path, as
// axios joins them: one slash between, whatever the two bring.
func JoinBase(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

// aliasRE: a name given another's value: `const o = k`, `this.$http = k`,
// `const o = axios.create(cfg)` (a client made of a config object).
var aliasRE = lazyRE(`(?:^|[^\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*=\s*(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.(?:create|extend)\(\s*)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)

// withBases joins the paths of the calls an HTTP client makes onto the
// base the script declares for it. A call is joined only onto the base
// given to the object it is made on: the name the base was bound to, or a
// name that is given that one's value. A call on any other object keeps
// its path, as does one whose receiver is unknown: which base such a
// client has is not told by the script. A call to an absolute URL keeps
// it, as the client does; a path that already begins with the base's own
// path (/api/x under /api) is taken as based and not joined twice.
func withBases(script string, calls []Call, g Globals) []Call {
	declared := bases(script, g)
	if len(declared) == 0 {
		return calls
	}
	byClient := map[string]map[string]bool{}
	add := func(name, v string) {
		if byClient[name] == nil {
			byClient[name] = map[string]bool{}
		}
		byClient[name][v] = true
	}
	for _, b := range declared {
		if b.Client != "" {
			add(b.Client, b.Value)
		}
	}
	// Names given a client's value, as far as a few hops follow.
	for round := 0; round < 4; round++ {
		grew := false
		for _, m := range aliasRE.get().FindAllStringSubmatchIndex(script, -1) {
			if !endsValue(script, m[1]) {
				continue // o = k.x, o = k + 1
			}
			name, from := script[m[2]:m[3]], script[m[4]:m[5]]
			for v := range byClient[from] {
				if !byClient[name][v] {
					add(name, v)
					grew = true
				}
			}
		}
		if !grew {
			break
		}
	}
	for i := range calls {
		c := &calls[i]
		if !c.Client || c.Base != "" || c.Recv == "" || strings.HasPrefix(c.Path, "http") || strings.HasPrefix(c.Path, "//") {
			continue
		}
		vs := byClient[c.Recv]
		if len(vs) != 1 {
			continue // no base given to this object, or several
		}
		base := ""
		for v := range vs {
			base = v
		}
		if hasBasePath(base, c.Path) {
			if o := originOf(base); o != "" {
				c.Route, c.Base, c.Path = c.Path, base, o+c.Path
			}
			continue
		}
		c.Route, c.Base = c.Path, base
		c.Path = JoinBase(base, c.Path)
	}
	return calls
}

// endsValue: the expression that ends at i goes no further (; , ) } or a
// new line follows).
func endsValue(script string, i int) bool {
	for ; i < len(script); i++ {
		switch script[i] {
		case ' ', '\t', '\r':
		case ';', ',', ')', '}', '\n':
			return true
		default:
			return false
		}
	}
	return true
}

// originOf is the scheme and host of an absolute base, or "".
func originOf(base string) string {
	i := strings.Index(base, "://")
	if i < 0 {
		return ""
	}
	if j := strings.IndexAny(base[i+3:], "/?"); j >= 0 {
		return base[:i+3+j]
	}
	return base
}

// hasBasePath: path already begins with the path of base, whole segments
// (/api/x under /api, not /apis/x). A base with a query has no such path.
func hasBasePath(base, path string) bool {
	if strings.Contains(base, "?") || !strings.HasPrefix(path, "/") {
		return false
	}
	bp := strings.Trim(strings.TrimPrefix(base, originOf(base)), "/")
	if bp == "" {
		return false
	}
	p := strings.TrimLeft(path, "/")
	return p == bp || strings.HasPrefix(p, bp+"/") || strings.HasPrefix(p, bp+"?")
}
