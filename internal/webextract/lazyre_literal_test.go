package webextract

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"time"
)

func TestRequiredLiterals(t *testing.T) {
	for src, want := range map[string]string{
		`(?:^|[^\w$.])fetch\s*\(`:           "fetch",
		`useHash\s*:|<HashRouter\b`:         "useHash|<HashRouter",
		`["'\x60]/socket\.io/?["'\x60]`:     "/socket.io",
		`\bnew\s+(?:WebSocket|SockJS)\s*\(`: "WebSocket|SockJS",
		`(?i)secret`:                        "",
		`a*b?`:                              "",
		`\d+`:                               "",
		`(x|\d)y`:                           "y",
		`(?:ab){2}`:                         "ab",
		`[a-z]+\.php`:                       ".php",
	} {
		sx, err := syntax.Parse(src, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(requiredLiterals(sx.Simplify()), "|"); got != want {
			t.Errorf("%s: required %q, want %q", src, got, want)
		}
	}
}

// A text without the literals of a pattern has no match of it: whatever a
// pattern finds, absent says false, over every pattern the package holds.
func TestAbsentNeverHidesAMatch(t *testing.T) {
	lazyMu.Lock()
	all := append([]*lazyRegexp(nil), lazyAll...)
	lazyMu.Unlock()
	var tokens []string
	for _, l := range all {
		l.get()
		tokens = append(tokens, l.must...)
		for _, m := range l.must {
			tokens = append(tokens, "  "+m+"(", m+"='", `"`+m+`"`, m+"/x")
		}
	}
	tokens = append(tokens, " ", "\n", "(", ")", "=", "'", `"`, "/", ".", ":", "{", "}", ",", "x", "path", "get", "io", "fetch", "$", "a1", "é")
	rng := rand.New(rand.NewSource(1))
	filtered := 0
	for _, l := range all {
		if len(l.must) > 0 {
			filtered++
		}
	}
	if filtered < 40 {
		t.Fatalf("only %d of %d patterns have a literal to filter by", filtered, len(all))
	}
	plain := make([]*regexp.Regexp, len(all))
	for i, l := range all {
		plain[i] = regexp.MustCompile(l.src)
	}
	for n := 0; n < 300; n++ {
		var b strings.Builder
		for i := rng.Intn(60) + 1; i > 0; i-- {
			b.WriteString(tokens[rng.Intn(len(tokens))])
		}
		s := b.String()
		for i, l := range all {
			if plain[i].FindStringIndex(s) != nil && l.absent(s) {
				t.Fatalf("%s: matches %q, and absent says it cannot", l.src, s)
			}
			if got, want := len(l.FindAllStringIndex(s, -1)), len(plain[i].FindAllStringIndex(s, -1)); got != want {
				t.Fatalf("%s: %d matches, plain %d on %q", l.src, got, want, s)
			}
		}
	}
}

// Looking only where a literal is finds what the whole pattern finds: for every
// pattern the package holds, the same matches and groups as the plain regexp,
// over texts of its own literals mixed with the characters its assertions
// look at, multi-byte ones and invalid UTF-8 among them.
func TestWindowedFindAllIsThePlainOne(t *testing.T) {
	defer func(a, b int) { windowMin, windowCost = a, b }(windowMin, windowCost)
	windowMin, windowCost = 0, 0
	lazyMu.Lock()
	all := append([]*lazyRegexp(nil), lazyAll...)
	lazyMu.Unlock()
	var tokens []string
	for _, l := range all {
		l.get()
		for _, m := range l.must {
			tokens = append(tokens, m, " "+m, "."+m, "$"+m, "'"+m, `"`+m, "\n"+m, "é"+m, m+"(", m+" (", m+"  :  true", m+"/", m+"='x'", m+".get('/a/b')")
		}
	}
	tokens = append(tokens, " ", "\n", "\t", "(", ")", "=", "'", `"`, "`", "/", ".", ":", "{", "}", ",", ";", "x", "path", "get", "io", "fetch", "$", "a1", "é", "日本", "\xff", "\xc3", "0123456789abcdef", "/api/v1/users", "./x/y.js", "http://a.b/c")
	rng := rand.New(rand.NewSource(7))
	windowed := 0
	for n := 0; n < 400; n++ {
		var b strings.Builder
		for i := rng.Intn(80) + 1; i > 0; i-- {
			b.WriteString(tokens[rng.Intn(len(tokens))])
		}
		s := b.String()
		if n%4 == 0 { // valid UTF-8 only: that is where the windows are used
			s = strings.ToValidUTF8(s, "?")
		}
		for _, l := range all {
			plain := l.get().FindAllStringSubmatchIndex(s, -1)
			if got := l.findAll(s, -1); !equalMatches(got, plain) {
				t.Fatalf("%s on %q:\n got  %v\n want %v", l.src, s, got, plain)
			}
			if got, want := l.findAll(s, 2), l.get().FindAllStringSubmatchIndex(s, 2); !equalMatches(got, want) {
				t.Fatalf("%s, 2 matches, on %q:\n got  %v\n want %v", l.src, s, got, want)
			}
			if l.lead >= 0 && len(plain) > 0 {
				windowed++
			}
		}
	}
	if windowed < 100 {
		t.Fatalf("only %d texts found a match through a pattern the windows are used for", windowed)
	}
}

func equalMatches(a, b [][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

// A pattern with a rare literal does not read the text: on a few megabytes
// with three of them, the windows find the same matches in a fraction of what
// the plain pattern takes. Both are timed in one run of the test, so a loaded
// machine slows both; the bound is a quarter, where it is about a fiftieth.
func TestWindowsSkipTheText(t *testing.T) {
	var b strings.Builder
	filler := "var a=b.c(d,e);if(f){g.h=i[j]+k}else{l('m','n')}\n"
	for b.Len() < 4<<20 {
		b.WriteString(filler)
		if b.Len()%(1<<20) < len(filler) {
			b.WriteString("fetch('/api/Products');")
		}
	}
	s := b.String()
	l := lazyRE(`(?:^|[^\w$.])fetch\s*\(`)
	plain := l.get()
	t0 := time.Now()
	want := plain.FindAllStringSubmatchIndex(s, -1)
	tPlain := time.Since(t0)
	t0 = time.Now()
	got := l.FindAllStringSubmatchIndex(s, -1)
	tWindows := time.Since(t0)
	if len(want) < 3 || !equalMatches(got, want) {
		t.Fatalf("%d matches, plain %d", len(got), len(want))
	}
	if tWindows*4 > tPlain {
		t.Errorf("windows %v, plain %v: not a quarter of it", tWindows, tPlain)
	}
}

func BenchmarkFindAllRareLiteral(b *testing.B) {
	s := strings.Repeat("var a=b.c(d,e);if(f){g.h=i[j]+k}else{l('m','n')}\n", 80000) + "fetch('/a');"
	l := lazyRE(`(?:^|[^\w$.])fetch\s*\(`)
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		l.FindAllStringIndex(s, -1)
	}
}

// BenchmarkFindAllRareLiteralPlain is the same text through the plain pattern.
func BenchmarkFindAllRareLiteralPlain(b *testing.B) {
	s := strings.Repeat("var a=b.c(d,e);if(f){g.h=i[j]+k}else{l('m','n')}\n", 80000) + "fetch('/a');"
	re := lazyRE(`(?:^|[^\w$.])fetch\s*\(`).get()
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		re.FindAllStringIndex(s, -1)
	}
}
