package webextract

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode/utf8"
)

// lazyRegexp compiles its pattern on first use: a command that never reads
// a page does not pay for the hundred patterns of this package (2.6 MB
// allocated at start).
//
// A pattern that needs a literal in every match (fetch, socket.io, _live_) is
// not run over a text that has none of its literals: the answer is the same
// (no match) and a script of megabytes is read once with strings.Contains, at
// memory speed, instead of once through the regexp's automaton.
type lazyRegexp struct {
	src  string
	once sync.Once
	re   *regexp.Regexp
	must []string // any of these is in every match; nil: none is known
	lead int      // a match starts at most this many bytes before one of them; -1: no bound
	// anchored and anchoredAfter match l at one place, with nothing and with
	// the character before it (see findAll); built when first needed.
	windows                 sync.Once
	anchored, anchoredAfter *regexp.Regexp
}

var (
	lazyMu  sync.Mutex
	lazyAll []*lazyRegexp
)

func lazyRE(src string) *lazyRegexp {
	l := &lazyRegexp{src: src}
	lazyMu.Lock()
	lazyAll = append(lazyAll, l)
	lazyMu.Unlock()
	return l
}

func (l *lazyRegexp) get() *regexp.Regexp {
	l.once.Do(func() {
		l.re = regexp.MustCompile(l.src)
		l.lead = -1
		if sx, err := syntax.Parse(l.src, syntax.Perl); err == nil {
			sx = sx.Simplify()
			l.must = requiredLiterals(sx)
			if len(l.must) > 0 {
				if lead, ok := leadOf(sx); ok {
					l.lead = lead
				}
			}
		}
	})
	return l.re
}

// absent says s holds none of the literals every match of l has, so none is
// there. It compiles l if it has not been.
func (l *lazyRegexp) absent(s string) bool {
	l.get()
	if len(l.must) == 0 {
		return false
	}
	for _, m := range l.must {
		if strings.Contains(s, m) {
			return false
		}
	}
	return true
}

// requiredLiterals are literals of which every match of re holds at least
// one (case-sensitive ones only); nil when it knows none.
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 || len(re.Rune) == 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture:
		return requiredLiterals(re.Sub[0])
	case syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
	case syntax.OpConcat:
		var best []string
		for _, sub := range re.Sub {
			if got := requiredLiterals(sub); shortest(got) > shortest(best) {
				best = got
			}
		}
		return best
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			got := requiredLiterals(sub)
			if len(got) == 0 {
				return nil
			}
			all = append(all, got...)
		}
		return all
	}
	return nil
}

// shortest is the length of the shortest of ls: how much it tells; 0 for none.
func shortest(ls []string) int {
	if len(ls) == 0 {
		return 0
	}
	n := len(ls[0])
	for _, l := range ls {
		n = min(n, len(l))
	}
	return n
}

func (l *lazyRegexp) FindAllString(s string, n int) []string {
	all := l.findAll(s, n)
	if all == nil {
		return nil
	}
	out := make([]string, len(all))
	for i, m := range all {
		out[i] = s[m[0]:m[1]]
	}
	return out
}
func (l *lazyRegexp) FindAllStringIndex(s string, n int) [][]int {
	all := l.findAll(s, n)
	for i, m := range all {
		all[i] = m[:2]
	}
	return all
}
func (l *lazyRegexp) FindAllStringSubmatch(s string, n int) [][]string {
	all := l.findAll(s, n)
	if all == nil {
		return nil
	}
	out := make([][]string, len(all))
	for i, m := range all {
		out[i] = make([]string, len(m)/2)
		for j := range out[i] {
			if m[2*j] >= 0 {
				out[i][j] = s[m[2*j]:m[2*j+1]]
			}
		}
	}
	return out
}
func (l *lazyRegexp) FindAllStringSubmatchIndex(s string, n int) [][]int { return l.findAll(s, n) }
func (l *lazyRegexp) FindStringIndex(s string) []int {
	if l.absent(s) {
		return nil
	}
	return l.get().FindStringIndex(s)
}
func (l *lazyRegexp) FindStringSubmatch(s string) []string {
	if l.absent(s) {
		return nil
	}
	return l.get().FindStringSubmatch(s)
}
func (l *lazyRegexp) FindStringSubmatchIndex(s string) []int {
	if l.absent(s) {
		return nil
	}
	return l.get().FindStringSubmatchIndex(s)
}
func (l *lazyRegexp) FindSubmatch(b []byte) [][]byte { return l.get().FindSubmatch(b) }
func (l *lazyRegexp) MatchString(s string) bool {
	return !l.absent(s) && l.get().MatchString(s)
}
func (l *lazyRegexp) ReplaceAllString(s, repl string) string {
	return l.get().ReplaceAllString(s, repl)
}
func (l *lazyRegexp) ReplaceAllStringFunc(s string, f func(string) string) string {
	return l.get().ReplaceAllStringFunc(s, f)
}

// maxWidth is the most bytes re can match; false when it has no bound.
func maxWidth(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				n += 4 // a letter and its other case may differ in width
			} else {
				n += utf8.RuneLen(r)
			}
		}
		return n, true
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax, true
	case syntax.OpStar, syntax.OpPlus:
		return 0, false
	case syntax.OpQuest, syntax.OpCapture:
		return maxWidth(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return 0, false
		}
		n, ok := maxWidth(re.Sub[0])
		return n * re.Max, ok
	case syntax.OpConcat:
		sum := 0
		for _, sub := range re.Sub {
			n, ok := maxWidth(sub)
			if !ok {
				return 0, false
			}
			sum += n
		}
		return sum, true
	case syntax.OpAlternate:
		most := 0
		for _, sub := range re.Sub {
			n, ok := maxWidth(sub)
			if !ok {
				return 0, false
			}
			most = max(most, n)
		}
		return most, true
	}
	return 0, true // anchors, word boundaries, the empty match
}

// leadOf is how many bytes of a match may come before the literal that
// requiredLiterals chose; false when there is no bound.
func leadOf(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return 0, true
	case syntax.OpCapture, syntax.OpPlus:
		return leadOf(re.Sub[0])
	case syntax.OpRepeat:
		return leadOf(re.Sub[0])
	case syntax.OpConcat:
		var best []string
		at := -1
		for i, sub := range re.Sub {
			if got := requiredLiterals(sub); shortest(got) > shortest(best) {
				best, at = got, i
			}
		}
		lead := 0
		for _, sub := range re.Sub[:at] {
			n, ok := maxWidth(sub)
			if !ok {
				return 0, false
			}
			lead += n
		}
		inner, ok := leadOf(re.Sub[at])
		return lead + inner, ok
	case syntax.OpAlternate:
		most := 0
		for _, sub := range re.Sub {
			n, ok := leadOf(sub)
			if !ok {
				return 0, false
			}
			most = max(most, n)
		}
		return most, true
	}
	return 0, false
}

// windowMin is the size of a text under which a pattern is just run: the
// literals are not worth looking for.
var windowMin = 32 << 10

// windowCost is how many bytes of a text one place to try is worth: about
// what a step of the automaton costs against a try.
var windowCost = 64

// findAll is FindAllStringSubmatchIndex. In a large text, a pattern with a
// literal in every match is tried only where one is: at each place a match
// could start, as long as the places are few, which costs steps of the
// automaton at each instead of one for every byte. A match is found where the
// whole pattern, run from the cursor, would find it: the character before a
// place is given to the pattern, so a \b or a ^ at the start of a match
// sees what it would see in the whole text. A text that is not valid UTF-8
// (where a place is not known to be one the pattern would try) is run whole.
func (l *lazyRegexp) findAll(s string, n int) [][]int {
	re := l.get()
	if n == 0 || l.absent(s) {
		return nil
	}
	if len(s) < windowMin || l.lead < 0 || !utf8.ValidString(s) {
		return re.FindAllStringSubmatchIndex(s, n)
	}
	// The places to try: if there are many, the whole text is cheaper.
	places := 0
	for _, m := range l.must {
		places += strings.Count(s, m)
	}
	if places*(l.lead+1)*windowCost > len(s) {
		return re.FindAllStringSubmatchIndex(s, n)
	}
	l.windows.Do(func() {
		l.anchored = regexp.MustCompile(`^(?:` + l.src + `)`)
		l.anchoredAfter = regexp.MustCompile(`^(?s:.)(?:` + l.src + `)`)
	})
	var out [][]int
	cursor, tried := 0, 0 // where the next match may start, and the first place not tried
	next := make([]int, len(l.must))
	for i := range next {
		next[i] = -2 // not looked for yet
	}
	for n < 0 || len(out) < n {
		// The first literal at or after the cursor.
		p := -1
		for i, m := range l.must {
			if next[i] != -1 && next[i] < cursor {
				next[i] = -2
			}
			if next[i] == -2 {
				if j := strings.Index(s[cursor:], m); j >= 0 {
					next[i] = cursor + j
				} else {
					next[i] = -1
				}
			}
			if next[i] >= 0 && (p < 0 || next[i] < p) {
				p = next[i]
			}
		}
		if p < 0 {
			break
		}
		var hit []int
		for q := max(cursor, tried, p-l.lead); q <= p; q++ {
			if !utf8.RuneStart(s[q]) {
				continue
			}
			tried = q + 1
			if hit = l.matchAt(s, q); hit != nil {
				break
			}
		}
		if hit == nil {
			// None starts in this literal's reach: go on to the next one.
			cursor = max(cursor, p+1)
			continue
		}
		out = append(out, hit)
		cursor = hit[1]
		tried = cursor
	}
	return out
}

// matchAt is the match of l that starts at q, in the indices of s; nil if
// none does.
func (l *lazyRegexp) matchAt(s string, q int) []int {
	if q == 0 {
		return l.anchored.FindStringSubmatchIndex(s)
	}
	_, w := utf8.DecodeLastRuneInString(s[:q])
	at := q - w
	got := l.anchoredAfter.FindStringSubmatchIndex(s[at:])
	if got == nil {
		return nil
	}
	for i := range got {
		if got[i] >= 0 {
			got[i] += at
		}
	}
	got[0] = q
	return got
}
