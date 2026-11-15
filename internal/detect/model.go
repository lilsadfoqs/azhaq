package detect

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Data is the compiled template set that templates.json.gz holds.
type Data struct {
	Version int            `json:"version"`
	Units   []Unit         `json:"units"`
	Skipped map[string]int `json:"skipped,omitempty"`
}

// Unit is one http block of a template: where to look and what to match.
type Unit struct {
	ID         string      `json:"i"`
	Product    string      `json:"p"`           // from the template title
	Multi      bool        `json:"m,omitempty"` // matcher names are the products
	Paths      []string    `json:"u"`
	And        bool        `json:"a,omitempty"` // matchers-condition: and
	Matchers   []Matcher   `json:"t"`
	Extractors []Extractor `json:"x,omitempty"`
}

// Matcher is one nuclei matcher.
type Matcher struct {
	Type   string     `json:"t"` // word, regex, status, dsl
	Name   string     `json:"n,omitempty"`
	Part   string     `json:"p,omitempty"` // see NormalizePart; empty is the body
	And    bool       `json:"a,omitempty"` // condition: and
	Neg    bool       `json:"g,omitempty"`
	CI     bool       `json:"c,omitempty"`
	Vals   []string   `json:"v,omitempty"` // words, regexes or expressions
	Status []int      `json:"s,omitempty"`
	Lits   [][]string `json:"l,omitempty"` // prefilter, see cover.go
}

// Extractor is one nuclei extractor.
type Extractor struct {
	Type  string   `json:"t"` // regex, kval
	Part  string   `json:"p,omitempty"`
	Group int      `json:"g,omitempty"`
	Vals  []string `json:"v"`
}

// Part names. Header-valued parts hold "header:" and the header name.
const (
	partBody     = ""
	partHeaders  = "headers"
	partResponse = "response"
	partHeader   = "header:"
)

// headerParts maps a template part to the response header it reads.
var headerParts = map[string]string{
	"server": "Server", "content_type": "Content-Type", "set_cookie": "Set-Cookie",
	"x_cache": "X-Cache", "cf_ray": "Cf-Ray", "cf_cache_status": "Cf-Cache-Status",
	"x_powered_by": "X-Powered-By", "location": "Location", "www_authenticate": "Www-Authenticate",
	"etag": "Etag", "last_modified": "Last-Modified", "via": "Via", "content_length": "Content-Length",
}

// NormalizePart maps a template part name to the stored form. It reports
// false for a part the engine cannot read from one response.
func NormalizePart(name string) (string, bool) {
	switch name = strings.ToLower(strings.TrimSpace(name)); name {
	case "", "body":
		return partBody, true
	case "header", "all_headers":
		return partHeaders, true
	case "response", "all", "raw":
		return partResponse, true
	}
	if h, ok := headerParts[name]; ok {
		return partHeader + h, true
	}
	return "", false
}

// Prepare checks a matcher the engine can run and fills its prefilter. The
// error says what is unsupported, in the words the skip reasons use.
func Prepare(m *Matcher) error {
	m.Lits = nil
	switch m.Type {
	case "status":
		if len(m.Status) == 0 {
			return fmt.Errorf("empty status matcher")
		}
		return nil
	case "word", "regex", "dsl":
		if len(m.Vals) == 0 {
			return fmt.Errorf("empty %s matcher", m.Type)
		}
	default:
		return fmt.Errorf("matcher type %s", m.Type)
	}
	covers := make([][][]string, 0, len(m.Vals))
	for _, v := range m.Vals {
		var c [][]string
		switch m.Type {
		case "word":
			c = lowerCover(v)
		case "regex":
			src := regexSource(v, m.CI)
			if _, err := regexp.Compile(src); err != nil {
				return fmt.Errorf("regex does not compile")
			}
			c = regexCover(src)
		case "dsl":
			n, err := parseDSL(v)
			if err != nil {
				return err
			}
			c = dslCover(n)
		}
		covers = append(covers, c)
	}
	if m.Neg {
		return nil
	}
	m.Lits = finishCover(combineCovers(covers, m.And))
	return nil
}

func regexSource(v string, ci bool) string {
	if ci {
		return "(?i)" + v
	}
	return v
}

// combineCovers joins per-item covers by the matcher's condition.
func combineCovers(items [][][]string, and bool) [][]string {
	if !and {
		return orCover(items)
	}
	var acc [][]string
	for _, c := range items {
		acc = andCover(acc, c)
	}
	return acc
}

// PrepareExtractor checks an extractor's regexes.
func PrepareExtractor(e *Extractor) error {
	switch e.Type {
	case "kval":
	case "regex":
		for _, v := range e.Vals {
			if _, err := regexp.Compile(v); err != nil {
				return fmt.Errorf("extractor regex does not compile")
			}
		}
	default:
		return fmt.Errorf("extractor type %s", e.Type)
	}
	if len(e.Vals) == 0 {
		return fmt.Errorf("empty extractor")
	}
	return nil
}

// headerText renders headers as Key: Value lines, sorted by key.
func headerText(h http.Header) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	first := true
	for _, k := range keys {
		for _, v := range h[k] {
			if !first {
				b.WriteString("\r\n")
			}
			first = false
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
		}
	}
	return b.String()
}
