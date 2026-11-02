package webextract

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Stylesheets are the stylesheets a page loads: the <link rel=stylesheet>
// hrefs, resolved as a browser does, each once.
func Stylesheets(body []byte, base *url.URL) []string {
	if base == nil {
		return nil
	}
	base = docBase(body, base)
	var out []string
	seen := map[string]bool{}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return out
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		if !strings.EqualFold(tok.Data, "link") {
			continue
		}
		isSheet := false
		for _, rel := range strings.Fields(attr(tok.Attr, "rel")) {
			isSheet = isSheet || strings.EqualFold(rel, "stylesheet")
		}
		if !isSheet {
			continue
		}
		if u, ok := resolve(base, attr(tok.Attr, "href")); ok && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
}

// CSSRef is a URL a stylesheet names: Import is true for an @import, which
// loads another stylesheet, and false for a url() (an image, a font).
type CSSRef struct {
	URL    string
	Import bool
}

var (
	cssComment = lazyRE(`(?s)/\*.*?\*/`)
	// One pattern, so an @import url(x) is read once, as an import: groups
	// 1-3 are an @import's string, 4-6 a url()'s.
	cssRef = lazyRE(`(?i)@import\s+(?:url\(\s*)?(?:"([^"]*)"|'([^']*)'|([^)\s"';]+))|url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s"']+))\s*\)`)
)

// CSSRefs are the URLs a stylesheet names with url() and @import, resolved
// against the stylesheet's own address, each once, in the order written.
// Comments are not read: a browser does not load them.
func CSSRefs(css string, base *url.URL) []CSSRef {
	if base == nil {
		return nil
	}
	css = cssComment.get().ReplaceAllString(css, " ")
	var out []CSSRef
	seen := map[string]bool{}
	for _, m := range cssRef.get().FindAllStringSubmatchIndex(css, -1) {
		for g := 1; g <= 6; g++ {
			if m[2*g] < 0 {
				continue
			}
			u, ok := resolve(base, css[m[2*g]:m[2*g+1]])
			if ok && !seen[u] {
				seen[u] = true
				out = append(out, CSSRef{URL: u, Import: g <= 3})
			}
			break
		}
	}
	return out
}
