package detect

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The DSL is the subset of nuclei's expression language that detection
// templates use. Anything outside it is rejected when the data is generated,
// so evaluation never meets an unknown construct.

type nodeKind uint8

const (
	nNum nodeKind = iota
	nStr
	nIdent
	nCall
	nUnary
	nBinary
)

type node struct {
	kind nodeKind
	op   string
	num  float64
	str  string
	args []*node
	re   *regexp.Regexp // regex(pattern literal, ...) compiled at parse
	memo string         // cache key of a pure call over response text
}

// dslIdents are the variables a template can read. Header-valued ones map to
// the header named by replacing "_" with "-".
var dslIdents = map[string]string{
	"body": "", "header": "", "all_headers": "", "status_code": "", "content_length": "",
	"server": "Server", "content_type": "Content-Type", "set_cookie": "Set-Cookie",
	"x_powered_by": "X-Powered-By", "location": "Location", "www_authenticate": "Www-Authenticate",
	"etag": "Etag", "last_modified": "Last-Modified", "x_cache": "X-Cache",
	"cf_ray": "Cf-Ray", "cf_cache_status": "Cf-Cache-Status", "via": "Via",
	"x_aspnet_version": "X-Aspnet-Version", "x_generator": "X-Generator",
	"x_frame_options": "X-Frame-Options", "refresh": "Refresh",
}

// dslFuncs maps a function name to its canonical name.
var dslFuncs = map[string]string{
	"contains": "contains", "contains_any": "contains_any", "contains_all": "contains_all",
	"regex": "regex", "to_lower": "to_lower", "tolower": "to_lower",
	"to_upper": "to_upper", "toupper": "to_upper", "len": "len", "concat": "concat",
	"mmh3": "mmh3", "base64_py": "base64_py", "md5": "md5", "sha1": "sha1",
}

// pureFuncs have one string argument and no side effects, so their result over
// the response text can be cached for one match.
var pureFuncs = map[string]bool{
	"mmh3": true, "base64_py": true, "md5": true, "sha1": true,
	"to_lower": true, "to_upper": true, "len": true,
}

// ParseDSL checks that expr only uses supported constructs.
func ParseDSL(expr string) error {
	_, err := parseDSL(expr)
	return err
}

type token struct {
	kind byte // n number, s string, i ident, o operator, e end
	text string
	num  float64
}

func lexDSL(src string) ([]token, error) {
	var out []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"' || c == '\'':
			s, n, err := lexString(src[i:])
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: 's', text: s})
			i += n
		case c >= '0' && c <= '9' || c == '.' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9':
			j := i
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.') {
				j++
			}
			v, err := strconv.ParseFloat(src[i:j], 64)
			if err != nil {
				return nil, fmt.Errorf("bad number %q", src[i:j])
			}
			out = append(out, token{kind: 'n', num: v, text: src[i:j]})
			i = j
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(src) && (src[j] == '_' || src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9') {
				j++
			}
			out = append(out, token{kind: 'i', text: src[i:j]})
			i = j
		default:
			op := ""
			if i+1 < len(src) {
				switch two := src[i : i+2]; two {
				case "==", "!=", "<=", ">=", "&&", "||":
					op = two
				}
			}
			if op == "" {
				switch c {
				case '<', '>', '!', '(', ')', ',', '+', '-', '*', '/':
					op = string(c)
				default:
					return nil, fmt.Errorf("unsupported character %q", c)
				}
			}
			out = append(out, token{kind: 'o', text: op})
			i += len(op)
		}
	}
	return append(out, token{kind: 'e'}), nil
}

// lexString reads a quoted string and returns its value and the bytes used.
// An escaped quote, backslash, n, r or t is decoded; any other escape keeps
// the backslash so regex classes like \d survive.
func lexString(src string) (string, int, error) {
	quote := src[0]
	var b strings.Builder
	for i := 1; i < len(src); i++ {
		c := src[i]
		switch {
		case c == quote:
			return b.String(), i + 1, nil
		case c == '\\' && i+1 < len(src):
			i++
			switch e := src[i]; e {
			case '"', '\'', '\\':
				b.WriteByte(e)
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte('\\')
				b.WriteByte(e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, fmt.Errorf("unterminated string")
}

type parser struct {
	toks []token
	pos  int
}

func parseDSL(expr string) (*node, error) {
	toks, err := lexDSL(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.expr(0)
	if err != nil {
		return nil, err
	}
	if p.peek().kind != 'e' {
		return nil, fmt.Errorf("unexpected %q", p.peek().text)
	}
	switch n.kind {
	case nNum, nStr, nIdent:
		return nil, fmt.Errorf("expression is not boolean")
	}
	return n, nil
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != 'e' {
		p.pos++
	}
	return t
}

func binPrec(op string) int {
	switch op {
	case "||":
		return 1
	case "&&":
		return 2
	case "==", "!=":
		return 3
	case "<", "<=", ">", ">=":
		return 4
	case "+", "-":
		return 5
	case "*", "/":
		return 6
	}
	return 0
}

func (p *parser) expr(minPrec int) (*node, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		prec := 0
		if t.kind == 'o' {
			prec = binPrec(t.text)
		}
		if prec == 0 || prec < minPrec {
			return left, nil
		}
		p.next()
		right, err := p.expr(prec + 1)
		if err != nil {
			return nil, err
		}
		left = &node{kind: nBinary, op: t.text, args: []*node{left, right}}
	}
}

func (p *parser) unary() (*node, error) {
	t := p.next()
	switch t.kind {
	case 'n':
		return &node{kind: nNum, num: t.num}, nil
	case 's':
		return &node{kind: nStr, str: t.text}, nil
	case 'i':
		if p.peek().kind == 'o' && p.peek().text == "(" {
			return p.call(t.text)
		}
		if _, ok := dslIdents[t.text]; !ok {
			return nil, fmt.Errorf("identifier %s", t.text)
		}
		return &node{kind: nIdent, str: t.text}, nil
	case 'o':
		switch t.text {
		case "(":
			n, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			if c := p.next(); c.kind != 'o' || c.text != ")" {
				return nil, fmt.Errorf("missing )")
			}
			return n, nil
		case "!", "-":
			n, err := p.unary()
			if err != nil {
				return nil, err
			}
			return &node{kind: nUnary, op: t.text, args: []*node{n}}, nil
		}
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

func (p *parser) call(name string) (*node, error) {
	canon, ok := dslFuncs[name]
	if !ok {
		return nil, fmt.Errorf("function %s", name)
	}
	p.next() // (
	var args []*node
	if t := p.peek(); !(t.kind == 'o' && t.text == ")") {
		for {
			a, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			args = append(args, a)
			t := p.next()
			if t.kind == 'o' && t.text == ")" {
				break
			}
			if t.kind != 'o' || t.text != "," {
				return nil, fmt.Errorf("bad call to %s", name)
			}
		}
	} else {
		p.next()
	}
	n := &node{kind: nCall, op: canon, args: args}
	if err := checkArity(n); err != nil {
		return nil, err
	}
	if canon == "regex" && args[0].kind == nStr {
		re, err := regexp.Compile(args[0].str)
		if err != nil {
			return nil, fmt.Errorf("regex does not compile")
		}
		n.re = re
	}
	if pureFuncs[canon] {
		n.memo = memoKey(n)
	}
	return n, nil
}

func checkArity(n *node) error {
	want := map[string]int{"contains": 2, "regex": 2, "to_lower": 1, "to_upper": 1, "len": 1,
		"mmh3": 1, "base64_py": 1, "md5": 1, "sha1": 1}
	if w, ok := want[n.op]; ok && len(n.args) != w {
		return fmt.Errorf("%s takes %d arguments", n.op, w)
	}
	if (n.op == "contains_any" || n.op == "contains_all") && len(n.args) < 2 {
		return fmt.Errorf("%s needs arguments", n.op)
	}
	return nil
}

// memoKey names a pure call whose whole argument tree reads only response
// identifiers, so equal keys mean equal results. Otherwise it is empty.
func memoKey(n *node) string {
	switch n.kind {
	case nIdent:
		switch n.str {
		case "body", "header", "all_headers":
			return n.str
		}
	case nCall:
		if pureFuncs[n.op] && len(n.args) == 1 {
			if k := memoKey(n.args[0]); k != "" {
				return n.op + "(" + k + ")"
			}
		}
	}
	return ""
}

// evalCtx is the data an expression reads, taken from one response.
type evalCtx interface {
	ident(name string) value
	memoGet(key string) (value, bool)
	memoSet(key string, v value)
}

// value holds a string, a number or a boolean.
type value struct {
	kind byte // s, n, b
	s    string
	n    float64
	b    bool
}

func vStr(s string) value    { return value{kind: 's', s: s} }
func vNum(n float64) value   { return value{kind: 'n', n: n} }
func vBool(b bool) value     { return value{kind: 'b', b: b} }
func (v value) truthy() bool { return v.kind == 'b' && v.b }

func (v value) text() string {
	switch v.kind {
	case 's':
		return v.s
	case 'n':
		return strconv.FormatFloat(v.n, 'f', -1, 64)
	}
	return strconv.FormatBool(v.b)
}

func (v value) number() (float64, bool) {
	switch v.kind {
	case 'n':
		return v.n, true
	case 's':
		f, err := strconv.ParseFloat(strings.TrimSpace(v.s), 64)
		return f, err == nil
	}
	return 0, false
}

func evalNode(n *node, c evalCtx) value {
	switch n.kind {
	case nNum:
		return vNum(n.num)
	case nStr:
		return vStr(n.str)
	case nIdent:
		return c.ident(n.str)
	case nUnary:
		v := evalNode(n.args[0], c)
		if n.op == "!" {
			return vBool(!v.truthy())
		}
		f, _ := v.number()
		return vNum(-f)
	case nBinary:
		return evalBinary(n, c)
	}
	return evalCall(n, c)
}

func evalBinary(n *node, c evalCtx) value {
	switch n.op {
	case "&&":
		return vBool(evalNode(n.args[0], c).truthy() && evalNode(n.args[1], c).truthy())
	case "||":
		return vBool(evalNode(n.args[0], c).truthy() || evalNode(n.args[1], c).truthy())
	}
	l, r := evalNode(n.args[0], c), evalNode(n.args[1], c)
	switch n.op {
	case "==", "!=", "<", "<=", ">", ">=":
		order, ok := compare(l, r)
		var res bool
		switch n.op {
		case "==":
			res = ok && order == 0
		case "!=":
			res = !ok || order != 0
		case "<":
			res = ok && order < 0
		case "<=":
			res = ok && order <= 0
		case ">":
			res = ok && order > 0
		default:
			res = ok && order >= 0
		}
		return vBool(res)
	case "+":
		if l.kind == 'n' && r.kind == 'n' {
			return vNum(l.n + r.n)
		}
		return vStr(l.text() + r.text())
	}
	a, _ := l.number()
	b, _ := r.number()
	if n.op == "-" {
		return vNum(a - b)
	}
	if n.op == "*" {
		return vNum(a * b)
	}
	if b == 0 {
		return vNum(0)
	}
	return vNum(a / b)
}

// compare orders two values; ok is false when they have no order, such as a
// boolean against a string or text against a number.
func compare(l, r value) (order int, ok bool) {
	if l.kind == 'b' || r.kind == 'b' {
		if l.kind == r.kind && l.b == r.b {
			return 0, true
		}
		return 0, false
	}
	if l.kind == 'n' || r.kind == 'n' {
		a, aok := l.number()
		b, bok := r.number()
		if !aok || !bok {
			return 0, false
		}
		switch {
		case a < b:
			return -1, true
		case a > b:
			return 1, true
		}
		return 0, true
	}
	return strings.Compare(l.s, r.s), true
}

func evalCall(n *node, c evalCtx) value {
	if n.memo != "" {
		if v, ok := c.memoGet(n.memo); ok {
			return v
		}
		v := callFunc(n, c)
		c.memoSet(n.memo, v)
		return v
	}
	return callFunc(n, c)
}

func callFunc(n *node, c evalCtx) value {
	arg := func(i int) string { return evalNode(n.args[i], c).text() }
	switch n.op {
	case "contains":
		return vBool(strings.Contains(arg(0), arg(1)))
	case "contains_any", "contains_all":
		s := arg(0)
		all := n.op == "contains_all"
		for i := 1; i < len(n.args); i++ {
			has := strings.Contains(s, arg(i))
			if all && !has {
				return vBool(false)
			}
			if !all && has {
				return vBool(true)
			}
		}
		return vBool(all)
	case "regex":
		re := n.re
		if re == nil {
			var err error
			if re, err = regexp.Compile(arg(0)); err != nil {
				return vBool(false)
			}
		}
		return vBool(re.MatchString(arg(1)))
	case "to_lower":
		return vStr(strings.ToLower(arg(0)))
	case "to_upper":
		return vStr(strings.ToUpper(arg(0)))
	case "len":
		return vNum(float64(len(arg(0))))
	case "concat":
		var b strings.Builder
		for i := range n.args {
			b.WriteString(arg(i))
		}
		return vStr(b.String())
	case "mmh3":
		return vStr(Mmh3String(arg(0)))
	case "base64_py":
		return vStr(base64Py([]byte(arg(0))))
	case "md5":
		sum := md5.Sum([]byte(arg(0)))
		return vStr(hex.EncodeToString(sum[:]))
	case "sha1":
		sum := sha1.Sum([]byte(arg(0)))
		return vStr(hex.EncodeToString(sum[:]))
	}
	return vBool(false)
}

// base64Py is Python's base64.encodebytes: a newline after every 76
// characters and a closing newline, even for empty input, like the favicon
// hash azhaq already computes.
func base64Py(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/76 + 1)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteByte('\n')
	return b.String()
}
