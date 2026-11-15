package detect

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

//go:embed templates.json.gz
var embedded []byte

// Response is the page a template is matched against.
type Response struct {
	Path   string // request path, "/" for the root
	Status int
	Header http.Header
	Body   []byte
}

// Hit is one template that matched.
type Hit struct {
	Product, Version, Template, Matcher, Extracted string
	// Many: the template names many products, this one by its matcher
	// (tech-detect, fingerprinthub): a library or a CDN as well as an app.
	Many bool
}

// Stats describes the loaded data.
type Stats struct {
	Compiled, Skipped int
	Reasons           map[string]int
}

var (
	loadOnce sync.Once
	engine   *index
	stats    Stats
	paths    []string
)

// Load decodes the embedded data once. Match and Paths call it as needed.
func Load() Stats {
	loadOnce.Do(func() {
		var d Data
		decode(&d)
		engine = build(&d)
		paths = engine.paths()
		stats = Stats{Compiled: len(d.Units), Reasons: map[string]int{}}
		for r, n := range d.Skipped {
			stats.Reasons[r] = n
			stats.Skipped += n
		}
	})
	s := stats
	s.Reasons = make(map[string]int, len(stats.Reasons))
	for r, n := range stats.Reasons {
		s.Reasons[r] = n
	}
	return s
}

func decode(d *Data) {
	zr, err := gzip.NewReader(bytes.NewReader(embedded))
	if err != nil {
		return
	}
	if raw, err := io.ReadAll(zr); err == nil {
		_ = json.Unmarshal(raw, d)
	}
}

// Paths lists the request paths of the compiled units other than "/".
func Paths() []string {
	Load()
	return append([]string(nil), paths...)
}

// Match returns every unit whose path list holds r.Path and whose matchers
// match, in template order.
func Match(r Response) []Hit {
	Load()
	return engine.match(r)
}

// index holds the compiled units grouped by request path.
type index struct {
	groups map[string]*group
}

// requestPath is what a template's path asks of the server: a fragment
// ("/#/login", a single-page app's route) is not sent, so it asks the root.
func requestPath(p string) string {
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	return p
}

// group is the units that share one request path, with one literal index
// over all their prefilterable matchers.
type group struct {
	units   []*gunit
	ac      *ac
	groupOf [][]int32 // needle -> cover group ids
	gSize   []int32   // needles per cover group
	gCand   []int32   // cover group -> candidate id
	refs    []ref     // candidate id -> matcher
	pool    sync.Pool
}

// gunit is a unit as seen from one group.
type gunit struct {
	u    *cunit
	cand []int32 // matcher -> candidate id, or -1 when it is not indexed
	free []int32 // matchers evaluated every time
}

type ref struct{ unit, matcher int32 }

// cunit is a unit with its lazily compiled parts.
type cunit struct {
	spec *Unit
	ms   []*cmatcher
	xs   []*cextractor
}

type cmatcher struct {
	spec  *Matcher
	once  sync.Once
	words []string
	res   []*regexp.Regexp
	exprs []*node
}

type cextractor struct {
	spec *Extractor
	once sync.Once
	res  []*regexp.Regexp
}

func build(d *Data) *index {
	idx := &index{groups: map[string]*group{}}
	byPath := map[string][]*cunit{}
	for i := range d.Units {
		u := &d.Units[i]
		cu := &cunit{spec: u}
		for j := range u.Matchers {
			cu.ms = append(cu.ms, &cmatcher{spec: &u.Matchers[j]})
		}
		for j := range u.Extractors {
			cu.xs = append(cu.xs, &cextractor{spec: &u.Extractors[j]})
		}
		seen := map[string]bool{}
		for _, p := range u.Paths {
			if p = requestPath(p); !seen[p] {
				seen[p] = true
				byPath[p] = append(byPath[p], cu)
			}
		}
	}
	for p, units := range byPath {
		idx.groups[p] = buildGroup(units)
	}
	return idx
}

func buildGroup(units []*cunit) *group {
	g := &group{}
	needle := map[string]int32{}
	b := newACBuilder()
	var needleGroups [][]int32
	for ui, cu := range units {
		gu := &gunit{u: cu}
		for mi, cm := range cu.ms {
			lits := cm.spec.Lits
			if len(lits) == 0 {
				gu.cand = append(gu.cand, -1)
				gu.free = append(gu.free, int32(mi))
				continue
			}
			cid := int32(len(g.refs))
			g.refs = append(g.refs, ref{unit: int32(ui), matcher: int32(mi)})
			gu.cand = append(gu.cand, cid)
			for _, grp := range lits {
				gid := int32(len(g.gSize))
				g.gSize = append(g.gSize, int32(len(grp)))
				g.gCand = append(g.gCand, cid)
				for _, lit := range grp {
					nid, ok := needle[lit]
					if !ok {
						nid = int32(len(needle))
						needle[lit] = nid
						b.add(lit, nid)
						needleGroups = append(needleGroups, nil)
					}
					needleGroups[nid] = append(needleGroups[nid], gid)
				}
			}
		}
		g.units = append(g.units, gu)
	}
	if len(g.refs) > 0 {
		g.ac = b.build()
		g.groupOf = needleGroups
	}
	g.pool.New = func() any {
		return &scratch{
			seen: make([]bool, len(g.groupOf)),
			cnt:  make([]int32, len(g.gSize)),
			cand: make([]bool, len(g.refs)),
		}
	}
	return g
}

func (idx *index) paths() []string {
	var out []string
	for p := range idx.groups {
		if p != "/" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// scratch is per-call state, recycled so a match allocates little.
type scratch struct {
	seen   []bool
	seenL  []int32
	cnt    []int32
	cntL   []int32
	cand   []bool
	candL  []int32
	picked []pick
}

type pick struct{ unit, matcher int32 }

func (s *scratch) reset() {
	for _, n := range s.seenL {
		s.seen[n] = false
	}
	for _, n := range s.cntL {
		s.cnt[n] = 0
	}
	for _, c := range s.candL {
		s.cand[c] = false
	}
	s.seenL, s.cntL, s.candL, s.picked = s.seenL[:0], s.cntL[:0], s.candL[:0], s.picked[:0]
}

func (idx *index) match(r Response) []Hit {
	path := r.Path
	if path == "" {
		path = "/"
	}
	g := idx.groups[path]
	if g == nil {
		return nil
	}
	c := newCtx(r)
	s := g.pool.Get().(*scratch)
	defer func() { s.reset(); g.pool.Put(s) }()

	if g.ac != nil {
		g.ac.scan(strings.ToLower(c.response()), func(n int32) {
			if s.seen[n] {
				return
			}
			s.seen[n] = true
			s.seenL = append(s.seenL, n)
			for _, gid := range g.groupOf[n] {
				if s.cnt[gid] == 0 {
					s.cntL = append(s.cntL, gid)
				}
				s.cnt[gid]++
				if s.cnt[gid] == g.gSize[gid] {
					if cid := g.gCand[gid]; !s.cand[cid] {
						s.cand[cid] = true
						s.candL = append(s.candL, cid)
					}
				}
			}
		})
	}

	var hits []Hit
	extracted := map[int]string{}
	emit := func(ui int32, name string) {
		u := g.units[ui].u
		x, ok := extracted[int(ui)]
		if !ok {
			x = u.extract(c)
			extracted[int(ui)] = x
		}
		prod, many := u.spec.Product, false
		if u.spec.Multi && name != "" {
			prod, many = Humanise(name), true
		}
		hits = append(hits, Hit{
			Product: prod, Version: versionOf(x), Template: u.spec.ID,
			Matcher: name, Extracted: x, Many: many,
		})
	}

	// Units are visited in order; matched matchers of or-units are gathered
	// first so hits come out sorted by unit and matcher.
	for ui, gu := range g.units {
		u := gu.u
		if u.spec.And {
			ok := true
			for mi := range u.ms {
				if id := gu.cand[mi]; id >= 0 && !s.cand[id] {
					ok = false
					break
				}
			}
			for mi := 0; ok && mi < len(u.ms); mi++ {
				ok = u.ms[mi].eval(c)
			}
			if ok {
				s.picked = append(s.picked, pick{int32(ui), -1})
			}
			continue
		}
		for _, mi := range gu.free {
			if u.ms[mi].eval(c) {
				s.picked = append(s.picked, pick{int32(ui), mi})
			}
		}
	}
	for _, cid := range s.candL {
		rf := g.refs[cid]
		u := g.units[rf.unit].u
		if !u.spec.And && u.ms[rf.matcher].eval(c) {
			s.picked = append(s.picked, pick{rf.unit, rf.matcher})
		}
	}
	sort.Slice(s.picked, func(i, j int) bool {
		a, b := s.picked[i], s.picked[j]
		if a.unit != b.unit {
			return a.unit < b.unit
		}
		return a.matcher < b.matcher
	})
	done := map[string]bool{}
	lastUnit := int32(-1)
	for _, p := range s.picked {
		u := g.units[p.unit].u
		if p.unit != lastUnit {
			lastUnit = p.unit
			done = map[string]bool{}
		}
		if p.matcher < 0 { // and-unit: one hit, named by its first named matcher
			name := ""
			for _, m := range u.ms {
				if m.spec.Name != "" {
					name = m.spec.Name
					break
				}
			}
			emit(p.unit, name)
			continue
		}
		name := u.ms[p.matcher].spec.Name
		key := name
		if !u.spec.Multi {
			key = "" // one hit per template unless names are products
		}
		if done[key] {
			continue
		}
		done[key] = true
		emit(p.unit, name)
	}
	return hits
}

var versionRe = lazyre.New(`\d+(?:\.\d+)+[0-9A-Za-z.\-_]*`)

func versionOf(extracted string) string { return versionRe.FindString(extracted) }

// ctx is one response with its derived strings built on first use.
type ctx struct {
	r    Response
	body *string
	hdr  *string
	resp *string
	low  map[string]string
	memo map[string]value
}

func newCtx(r Response) *ctx { return &ctx{r: r} }

func (c *ctx) bodyStr() string {
	if c.body == nil {
		s := string(c.r.Body)
		c.body = &s
	}
	return *c.body
}

func (c *ctx) headers() string {
	if c.hdr == nil {
		s := headerText(c.r.Header)
		c.hdr = &s
	}
	return *c.hdr
}

func (c *ctx) response() string {
	if c.resp == nil {
		s := c.headers() + "\r\n\r\n" + c.bodyStr()
		c.resp = &s
	}
	return *c.resp
}

// part returns the text a matcher or extractor part reads.
func (c *ctx) part(p string) string {
	switch {
	case p == partBody:
		return c.bodyStr()
	case p == partHeaders:
		return c.headers()
	case p == partResponse:
		return c.response()
	case strings.HasPrefix(p, partHeader):
		return strings.Join(c.r.Header.Values(p[len(partHeader):]), ", ")
	}
	return ""
}

func (c *ctx) lower(p string) string {
	if s, ok := c.low[p]; ok {
		return s
	}
	if c.low == nil {
		c.low = map[string]string{}
	}
	s := strings.ToLower(c.part(p))
	c.low[p] = s
	return s
}

func (c *ctx) ident(name string) value {
	switch name {
	case "body":
		return vStr(c.bodyStr())
	case "header", "all_headers":
		return vStr(c.headers())
	case "status_code":
		return vNum(float64(c.r.Status))
	case "content_length":
		if v := c.r.Header.Get("Content-Length"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return vNum(float64(n))
			}
		}
		return vNum(float64(len(c.r.Body)))
	}
	return vStr(strings.Join(c.r.Header.Values(dslIdents[name]), ", "))
}

func (c *ctx) memoGet(key string) (value, bool) { v, ok := c.memo[key]; return v, ok }

func (c *ctx) memoSet(key string, v value) {
	if c.memo == nil {
		c.memo = map[string]value{}
	}
	c.memo[key] = v
}

func (m *cmatcher) compile() {
	s := m.spec
	switch s.Type {
	case "word":
		m.words = s.Vals
		if s.CI {
			m.words = make([]string, len(s.Vals))
			for i, w := range s.Vals {
				m.words[i] = strings.ToLower(w)
			}
		}
	case "regex":
		for _, v := range s.Vals {
			if re, err := regexp.Compile(regexSource(v, s.CI)); err == nil {
				m.res = append(m.res, re)
			} else {
				m.res = append(m.res, nil)
			}
		}
	case "dsl":
		for _, v := range s.Vals {
			n, _ := parseDSL(v)
			m.exprs = append(m.exprs, n)
		}
	}
}

func (m *cmatcher) eval(c *ctx) bool {
	m.once.Do(m.compile)
	s := m.spec
	var ok bool
	switch s.Type {
	case "status":
		for _, st := range s.Status {
			if st == c.r.Status {
				ok = true
				break
			}
		}
	case "word":
		text := c.part(s.Part)
		if s.CI {
			text = c.lower(s.Part)
		}
		ok = anyAll(len(m.words), s.And, func(i int) bool { return strings.Contains(text, m.words[i]) })
	case "regex":
		text := c.part(s.Part)
		ok = anyAll(len(m.res), s.And, func(i int) bool { return m.res[i] != nil && m.res[i].MatchString(text) })
	case "dsl":
		ok = anyAll(len(m.exprs), s.And, func(i int) bool { return m.exprs[i] != nil && evalNode(m.exprs[i], c).truthy() })
	}
	return ok != s.Neg
}

// anyAll folds n checks by a matcher's condition.
func anyAll(n int, and bool, check func(i int) bool) bool {
	for i := 0; i < n; i++ {
		if ok := check(i); ok != and {
			return ok
		}
	}
	return and && n > 0
}

// extract runs the unit's extractors and returns the first non-empty result.
func (u *cunit) extract(c *ctx) string {
	for _, x := range u.xs {
		x.once.Do(x.compile)
		switch x.spec.Type {
		case "kval":
			for _, name := range x.spec.Vals {
				if v := kval(c.r.Header, name); v != "" {
					return v
				}
			}
		case "regex":
			text := c.part(x.spec.Part)
			for _, re := range x.res {
				if re == nil {
					continue
				}
				sm := re.FindStringSubmatch(text)
				if x.spec.Group < len(sm) && sm[x.spec.Group] != "" {
					return sm[x.spec.Group]
				}
			}
		}
	}
	return ""
}

func (x *cextractor) compile() {
	if x.spec.Type != "regex" {
		return
	}
	for _, v := range x.spec.Vals {
		re, err := regexp.Compile(v)
		if err != nil {
			re = nil
		}
		x.res = append(x.res, re)
	}
}

// kval reads a header by a template's key: case-insensitive, "_" for "-".
func kval(h http.Header, key string) string {
	want := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	for k, vs := range h {
		if strings.ToLower(k) == want && len(vs) > 0 {
			return strings.Join(vs, ", ")
		}
	}
	return ""
}
