package webextract

import (
	"net/url"
	"path"
	"strings"
)

// Globals holds what the inline scripts of a page assign to globals from
// the page's own location: window.DocConfig = {server: location.origin +
// "/api"} gives "DocConfig.server". The values are worked out for that
// page, as its browser would; the scripts the page loads see them.
type Globals map[string]string

var (
	// globalSet: NAME = …, var NAME = …, window.A.B = …
	globalSet  = lazyRE(`(?:^|[^\w$.])(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*=[^=>]`)
	locationRE = lazyRE(`^(?:(?:window|self|top)\s*\.\s*)?(?:document\s*\.\s*)?location\s*\.\s*(protocol|host|hostname|port|pathname|origin)$`)
)

// maxInline caps the inline script read for globals.
const maxInline = 256 << 10

// PageGlobals evaluates the globals the inline scripts set from the
// location parts of page (protocol, host, hostname, port, pathname,
// origin) and string literals. A value with anything else in it, or none
// of the location, is not one; a comment is not code.
func PageGlobals(inline []string, page *url.URL) Globals {
	if page == nil {
		return nil
	}
	g := Globals{}
	for _, src := range inline {
		if len(src) > maxInline || !strings.Contains(src, "location") {
			continue
		}
		src = stripComments(src)
		depths := braceDepths(src)
		for _, m := range globalSet.get().FindAllStringSubmatchIndex(src, -1) {
			name := strings.Join(strings.Fields(src[m[2]:m[3]]), "")
			win := strings.HasPrefix(name, "window.") || strings.HasPrefix(name, "self.") || strings.HasPrefix(name, "top.")
			if !win && depths[m[2]] != 0 {
				continue // inside a function or a block: not a global
			}
			name = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(name, "window."), "self."), "top.")
			if name == "" || name == "location" || strings.HasPrefix(name, "location.") {
				continue
			}
			g.assign(name, valueExpr(src[m[1]-1:]), page, 0)
			if len(g) >= 64 {
				return g
			}
		}
	}
	if len(g) == 0 {
		return nil
	}
	return g
}

// assign records name as expr, or its keys when expr is an object.
func (g Globals) assign(name, expr string, page *url.URL, depth int) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "{") && strings.HasSuffix(expr, "}") {
		if depth > 2 {
			return
		}
		for _, part := range splitTop(expr[1:len(expr)-1], ",") {
			k, v, ok := strings.Cut(part, ":")
			k = strings.Trim(strings.TrimSpace(k), `"'`)
			if !ok || !identChain.MatchString(k) || strings.Contains(k, ".") {
				continue
			}
			g.assign(name+"."+k, v, page, depth+1)
		}
		return
	}
	if v, ok := g.eval(expr, page, 0); ok {
		g[name] = v
	}
}

// eval works out a concatenation of location parts, earlier globals and
// literals; ok only when at least one part is from the location.
func (g Globals) eval(expr string, page *url.URL, depth int) (string, bool) {
	v, loc, ok := g.concat(expr, page, depth)
	if !ok || !loc {
		return "", false
	}
	return cleanDots(v), true
}

func (g Globals) concat(expr string, page *url.URL, depth int) (string, bool, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || depth > maxDepth {
		return "", false, false
	}
	var b strings.Builder
	loc := false
	for _, term := range splitTop(expr, "+") {
		term = strings.TrimSpace(term)
		if term == "" {
			return "", false, false
		}
		switch term[0] {
		case '"', '\'':
			s, ok := unquote(term)
			if !ok {
				return "", false, false
			}
			b.WriteString(s)
			continue
		case '(':
			if !strings.HasSuffix(term, ")") {
				return "", false, false
			}
			v, l, ok := g.concat(term[1:len(term)-1], page, depth+1)
			if !ok {
				return "", false, false
			}
			b.WriteString(v)
			loc = loc || l
			continue
		case '`':
			v, l, ok := g.template(term, page, depth)
			if !ok {
				return "", false, false
			}
			b.WriteString(v)
			loc = loc || l
			continue
		}
		if v, ok := locationPart(term, page); ok {
			b.WriteString(v)
			loc = true
		} else if v, ok := g[strings.TrimPrefix(strings.Join(strings.Fields(term), ""), "window.")]; ok {
			b.WriteString(v)
			loc = true
		} else {
			return "", false, false
		}
	}
	return b.String(), loc, true
}

func (g Globals) template(t string, page *url.URL, depth int) (string, bool, bool) {
	if len(t) < 2 || t[len(t)-1] != '`' {
		return "", false, false
	}
	body := t[1 : len(t)-1]
	var b strings.Builder
	loc := false
	for len(body) > 0 {
		i := strings.Index(body, "${")
		if i < 0 {
			b.WriteString(body)
			break
		}
		b.WriteString(body[:i])
		end := closeBrace(body, i+2)
		if end < 0 {
			return "", false, false
		}
		v, l, ok := g.concat(body[i+2:end], page, depth+1)
		if !ok {
			return "", false, false
		}
		b.WriteString(v)
		loc = loc || l
		body = body[end+1:]
	}
	return b.String(), loc, true
}

// locationPart is a part of the page's URL as location gives it.
func locationPart(term string, page *url.URL) (string, bool) {
	m := locationRE.get().FindStringSubmatch(strings.Join(strings.Fields(term), ""))
	if m == nil {
		return "", false
	}
	host, port := page.Hostname(), page.Port()
	if port == "80" && page.Scheme == "http" || port == "443" && page.Scheme == "https" {
		port = ""
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port != "" {
		hostport += ":" + port
	}
	switch m[1] {
	case "protocol":
		return page.Scheme + ":", true
	case "host":
		return hostport, true
	case "hostname":
		return host, true
	case "port":
		return port, true
	case "pathname":
		if p := page.EscapedPath(); p != "" {
			return p, true
		}
		return "/", true
	case "origin":
		return page.Scheme + "://" + hostport, true
	}
	return "", false
}

// cleanDots resolves the "." and ".." segments of a URL or a path the way
// a browser does when it requests it; the query stays as written.
func cleanDots(v string) string {
	if !strings.Contains(v, "/./") && !strings.Contains(v, "/../") && !strings.HasSuffix(v, "/..") && !strings.HasSuffix(v, "/.") {
		return v
	}
	rest, q, hasQ := strings.Cut(v, "?")
	head, p := "", rest
	if i := strings.Index(rest, "://"); i >= 0 {
		j := strings.IndexByte(rest[i+3:], '/')
		if j < 0 {
			return v
		}
		head, p = rest[:i+3+j], rest[i+3+j:]
	} else if !strings.HasPrefix(rest, "/") {
		return v
	}
	trail := strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..")
	p = path.Clean(p)
	if trail && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	if hasQ {
		return head + p + "?" + q
	}
	return head + p
}

// valueExpr is the expression at the start of s, which ends at a ","
// or ";" outside brackets, or at a line end the expression does not
// continue over.
func valueExpr(s string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(s) && i < 64<<10; i++ {
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
		case (c == ',' || c == ';') && depth == 0:
			return strings.TrimSpace(s[:i])
		case c == '\n' && depth == 0:
			prev := strings.TrimSpace(s[:i])
			next := strings.TrimLeft(s[i:], " \t\r\n")
			if prev != "" && !strings.ContainsAny(prev[len(prev)-1:], "+(?:=") && !strings.HasPrefix(next, "+") {
				return prev
			}
		}
	}
	return strings.TrimSpace(s)
}

// braceDepths is the {} depth at each byte of src.
func braceDepths(src string) []int8 {
	out := make([]int8, len(src))
	depth := 0
	var quote byte
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case quote != 0:
			if c == '\\' {
				if i+1 < len(src) {
					out[i+1] = int8(min(depth, 100))
				}
				out[i] = int8(min(depth, 100))
				i++
				continue
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			depth = max(0, depth-1)
		}
		out[i] = int8(min(depth, 100))
	}
	return out
}

// stripComments blanks the comments of a script, leaving strings alone.
func stripComments(src string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case quote != 0:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				i++
				b.WriteByte(src[i])
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
			b.WriteByte(c)
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 3
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
