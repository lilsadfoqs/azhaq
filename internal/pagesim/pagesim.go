// Package pagesim says whether an answer is the same page as some others
// when the bytes differ: a nonce, a counter, a build stamp, a list of
// items. A page is read as its title, the tag names it uses and the
// words it shows; the answers to names that cannot exist say which of
// those stay the same, and an answer that keeps them is the page they
// gave. Calibration of fuzz and dirs uses it where no size, word count or
// line count is shared.
package pagesim

import (
	"strconv"
	"strings"
)

// maxRead is how much of a body is read: a page's shape shows in its head.
const maxRead = 256 << 10

// Page is what an answer's body is, apart from its bytes.
type Page struct {
	Title string
	Tags  map[string]bool // tag names, lower case
	Words map[string]bool // words of the text between tags, lower case, 3 letters or more
}

// Of reads a body.
func Of(body []byte) Page {
	if len(body) > maxRead {
		body = body[:maxRead]
	}
	p := Page{Tags: map[string]bool{}, Words: map[string]bool{}}
	s := string(body)
	var skip string // inside <script> or <style>: not text
	for i := 0; i < len(s); {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				j = len(s) - i
			}
			if skip == "" {
				words(s[i:i+j], p.Words)
			}
			i += j
			continue
		}
		// a tag, a closing tag, a comment or a declaration
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			break
		}
		tag := s[i+1 : i+j]
		i += j + 1
		if strings.HasPrefix(tag, "!--") {
			continue
		}
		closing := strings.HasPrefix(tag, "/")
		name := tagName(strings.TrimPrefix(tag, "/"))
		if name == "" {
			continue
		}
		if closing {
			if name == skip {
				skip = ""
			}
			continue
		}
		p.Tags[name] = true
		switch name {
		case "script", "style":
			skip = name
		case "title":
			if end := strings.Index(strings.ToLower(s[i:]), "</title"); end >= 0 {
				p.Title = strings.ToLower(strings.Join(strings.Fields(s[i:i+end]), " "))
			}
		}
	}
	return p
}

func tagName(t string) string {
	n := 0
	for n < len(t) && (t[n] >= 'a' && t[n] <= 'z' || t[n] >= 'A' && t[n] <= 'Z' || t[n] >= '0' && t[n] <= '9' || t[n] == '-' || t[n] == ':') {
		n++
	}
	if n == 0 || !(t[0] >= 'a' && t[0] <= 'z' || t[0] >= 'A' && t[0] <= 'Z') {
		return ""
	}
	return strings.ToLower(t[:n])
}

// words adds the words of text: runs of letters, digits and _ - that start
// with a letter and are at least 3 long, lower case.
func words(text string, into map[string]bool) {
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= 3 {
			into[strings.ToLower(text[start:end])] = true
		}
		start = -1
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
		switch {
		case letter:
			if start < 0 {
				start = i
			}
		case start >= 0 && (c >= '0' && c <= '9' || c == '_' || c == '-'):
		default:
			flush(i)
		}
	}
	flush(len(text))
}

// Shape is what the pages it was learned from have in common.
type Shape struct {
	Title     string          // the title they all have, "" when they differ or have none
	tagsAll   map[string]bool // tags every page has
	tagsAny   map[string]bool // tags some page has
	Stable    map[string]bool // words every page shows
	pages     int
	stableMin int // how many of Stable a page must show, in percent of them
}

// stableShare is the share of the stable words a page must show to be the
// page.
const stableShare = 80

// Learn reads what answers that are the same page have in common. It says
// false when that is too little to tell a page by: no shared title and
// fewer than three shared words.
func Learn(pages []Page) (Shape, bool) {
	if len(pages) < 2 {
		return Shape{}, false
	}
	s := Shape{tagsAll: copySet(pages[0].Tags), tagsAny: copySet(pages[0].Tags), Stable: copySet(pages[0].Words), Title: pages[0].Title, pages: len(pages)}
	for _, p := range pages[1:] {
		for t := range p.Tags {
			s.tagsAny[t] = true
		}
		for t := range s.tagsAll {
			if !p.Tags[t] {
				delete(s.tagsAll, t)
			}
		}
		for w := range s.Stable {
			if !p.Words[w] {
				delete(s.Stable, w)
			}
		}
		if p.Title != s.Title {
			s.Title = ""
		}
	}
	if s.Title == "" && len(s.Stable) < 3 {
		return Shape{}, false
	}
	return s, true
}

// Like says whether p is the page the shape was learned from: the tags of
// the pages and no others, the same title, and most of the shared words.
func (s Shape) Like(p Page) bool {
	if s.pages == 0 {
		return false
	}
	if s.Title != "" && p.Title != s.Title {
		return false
	}
	for t := range s.tagsAll {
		if !p.Tags[t] {
			return false
		}
	}
	for t := range p.Tags {
		if !s.tagsAny[t] {
			return false
		}
	}
	if n := len(s.Stable); n > 0 {
		have := 0
		for w := range s.Stable {
			if p.Words[w] {
				have++
			}
		}
		if have*100 < n*stableShare {
			return false
		}
	}
	return true
}

// Describe is what the shape rests on, for a note.
func (s Shape) Describe() string {
	var parts []string
	if s.Title != "" {
		parts = append(parts, "the title "+quote(s.Title))
	}
	if len(s.tagsAll) > 0 {
		parts = append(parts, "the tags they use")
	}
	if n := len(s.Stable); n > 0 {
		parts = append(parts, plural(n, "word")+" they all show")
	}
	return strings.Join(parts, ", ")
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return strconv.Itoa(n) + " " + w + "s"
}

func quote(s string) string {
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return `"` + s + `"`
}

func copySet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
