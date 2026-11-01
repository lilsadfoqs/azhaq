package paramcol

import (
	"bytes"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// maxHarvest caps the names taken from one page.
const maxHarvest = 300

var (
	formTagRE  = lazyre.New(`(?is)<(?:input|textarea|select|button)\b[^>]*>`)
	attrNameRE = lazyre.New(`(?is)\b(?:name|id)\s*=\s*(?:"([^"]{1,60})"|'([^']{1,60})'|([A-Za-z0-9_.\[\]-]{1,60}))`)
	jsEmptyRE  = lazyre.New(`\b(?:var|let|const)\s+([A-Za-z_][A-Za-z0-9_]{1,40})\s*=\s*(?:""|'')`)
	quotedKey  = lazyre.New(`["']([A-Za-z_][A-Za-z0-9_.-]{1,40})["']\s*:`)
	plainWord  = lazyre.New(`[A-Za-z_][A-Za-z0-9_]{2,30}`)
	nameOK     = lazyre.New(`^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,59}$`)
)

// harvest lists names the answer itself holds, which the page is likely
// to read: the name and id of its form fields, the variables its scripts
// set empty, the keys of its objects, the words of a short plain reply.
func (s *search) harvest(a answer) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if len(out) < maxHarvest && nameOK.MatchString(n) && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	body := a.body
	isJSON := strings.Contains(a.ctype, "json")
	isHTML := strings.Contains(a.ctype, "html") || (a.ctype == "" && bytes.Contains(body, []byte("<")))
	switch {
	case isHTML:
		for _, tag := range formTagRE.FindAll(body, -1) {
			for _, m := range attrNameRE.FindAllSubmatch(tag, -1) {
				for _, g := range m[1:] {
					if len(g) > 0 {
						add(string(g))
					}
				}
			}
		}
		for _, m := range jsEmptyRE.FindAllSubmatch(body, -1) {
			add(string(m[1]))
		}
		for _, m := range quotedKey.FindAllSubmatch(body, 5000) {
			add(string(m[1]))
		}
	case isJSON || strings.Contains(a.ctype, "javascript"):
		for _, m := range quotedKey.FindAllSubmatch(body, 5000) {
			add(string(m[1]))
		}
		for _, m := range jsEmptyRE.FindAllSubmatch(body, -1) {
			add(string(m[1]))
		}
	case strings.Contains(a.ctype, "xml"):
		for _, m := range xmlTagRE.FindAllSubmatch(body, 5000) {
			add(string(m[1]))
		}
	case len(body) <= 2000:
		for _, w := range plainWord.FindAll(body, 200) {
			add(string(w))
		}
	}
	return out
}
