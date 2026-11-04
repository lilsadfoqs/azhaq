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
func Bases(script string) []Base {
	if !strings.Contains(script, "aseURL") && !strings.Contains(script, "aseUrl") && !strings.Contains(script, "prefixUrl") {
		return nil
	}
	ev := evaluator{src: script}
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
// kept under: o in `const o = axios.create({baseURL: …})`.
func instanceOf(script string, key int) string {
	ob := openBrace(script, key)
	if ob < 0 {
		return ""
	}
	open := skipSpaceBack(script, ob)
	if open < 0 || script[open] != '(' {
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

// withBases joins the paths of the calls an HTTP client makes onto the
// base the script declares for it. A call is joined onto the base given
// to the instance it is made on; one made on a client the script gives
// no base by name is joined onto the only base the script declares, and
// onto none when it declares several. A call to an absolute URL keeps
// it, as the client does.
func withBases(script string, calls []Call) []Call {
	bases := Bases(script)
	if len(bases) == 0 {
		return calls
	}
	byClient := map[string]map[string]bool{}
	all := map[string]bool{}
	for _, b := range bases {
		all[b.Value] = true
		if b.Client != "" {
			if byClient[b.Client] == nil {
				byClient[b.Client] = map[string]bool{}
			}
			byClient[b.Client][b.Value] = true
		}
	}
	only := ""
	if len(all) == 1 {
		for v := range all {
			only = v
		}
	}
	for i := range calls {
		c := &calls[i]
		if !c.Client || strings.HasPrefix(c.Path, "http") || strings.HasPrefix(c.Path, "//") {
			continue
		}
		base := only
		if vs, named := byClient[c.Recv]; named {
			base = ""
			if len(vs) == 1 {
				for v := range vs {
					base = v
				}
			}
		} else if c.Recv == "axios" {
			base = "" // the default instance has no base unless axios.defaults gives it one
		}
		if base == "" {
			continue
		}
		c.Route, c.Base = c.Path, base
		c.Path = JoinBase(base, c.Path)
	}
	return calls
}
