package pagesim

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// a page that is a different length each time: random words in rows
func nonce(title string) []byte {
	var b strings.Builder
	b.WriteString("<html><title>" + title + "</title><body>\n")
	for i := 0; i < 30+rand.IntN(60); i++ {
		for j := 0; j < 3+rand.IntN(9); j++ {
			fmt.Fprintf(&b, "w%d ", rand.IntN(100000))
		}
		b.WriteString("\n")
	}
	b.WriteString("</body></html>")
	return []byte(b.String())
}

func TestShapeHoldsAPageThatChangesEachTime(t *testing.T) {
	var calib []Page
	for range 6 {
		calib = append(calib, Of(nonce("Console")))
	}
	s, ok := Learn(calib)
	if !ok {
		t.Fatal("no shape")
	}
	if !s.Like(Of(nonce("Console"))) {
		t.Error("another answer of that page is not like it")
	}
	if s.Like(Of(nonce("Admin panel"))) {
		t.Error("a page with another title is like it")
	}
	if s.Like(Of([]byte("<html><title>Console</title><body><form><input></form><p>login</p></body></html>"))) {
		t.Error("a page with other tags is like it")
	}
}

func TestLearnNeedsSomethingInCommon(t *testing.T) {
	a := Of([]byte("<html><body>alpha beta gamma</body></html>"))
	b := Of([]byte("<html><body>delta epsilon zeta</body></html>"))
	if _, ok := Learn([]Page{a, b}); ok {
		t.Error("no title and no shared words must not make a shape")
	}
	if _, ok := Learn([]Page{a}); ok {
		t.Error("one answer shows nothing varies")
	}
}

func TestOfSkipsScriptsAndReadsTheTitle(t *testing.T) {
	p := Of([]byte("<HTML><Title> My   App </Title><script>var token=1234abc;</script><p>Welcome home</p><!-- hidden words --></HTML>"))
	if p.Title != "my app" || !p.Words["welcome"] || p.Words["token"] || p.Words["hidden"] || !p.Tags["p"] || !p.Tags["script"] {
		t.Errorf("%+v", p)
	}
}
