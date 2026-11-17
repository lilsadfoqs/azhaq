package build

import (
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// The protocol and feature preconditions a record states in its own words.
// Each need keeps the clause it was read from, so a reader can judge it: the
// vocabulary is of how an advisory says "only when", never of what we think
// a flaw needs.
var (
	needHTTP2   = lazyre.New(`(?i)\bhttp/?2(\.0)?\b`)
	needHTTP3   = lazyre.New(`(?i)\bhttp/?3\b`)
	needQUIC    = lazyre.New(`\bQUIC\b`)
	needHTTP1   = lazyre.New(`(?i)\bhttp/?1(\.[01])?\b`)
	needModule  = lazyre.New(`(?i)\b(mod_[a-z0-9_]+|ngx_[a-z0-9_]+_module)\b`)
	needConfig  = lazyre.New(`(?i)\b(?:when|if|once|only when|only if|provided that)\b[^.;:]{0,80}?\bconfigured\s+(?:with|to|as|for|so)\b[^.;]{0,100}`)
	needEnabled = lazyre.New(`(?i)\b(?:when|if|only when|only if|provided that)\b[^.;:]{0,100}?\b(?:is|are|been)\s+(?:enabled|turned on|activated|loaded|installed|active|in use)\b`)
	needWith    = lazyre.New(`(?i)\bwith\s+[^.;,]{1,60}?\s+(?:enabled|turned on|activated)\b`)
	needNonDef  = lazyre.New(`(?i)\bnon-?default\s+(?:configuration|config|setting|option|mode|build)s?\b`)
	// A clause that says the opposite: no non-default setting is needed, the
	// feature is not enabled.
	needNegated = lazyre.New(`(?i)\b(?:no|without|not|never|isn't|aren't)\b[^.;,]{0,25}\b(?:non-?default|enabled|turned on|activated|loaded|installed|active|in use)\b`)
	// "enabled by default" is no precondition: the record says it is on.
	needDefault = lazyre.New(`(?i)\bby default\b|\bthe default\b|\bdefault (?:configuration|setting)\b`)
	// A sentence about the fix or a workaround names a module to turn off, not
	// one the flaw needs.
	needSkip   = lazyre.New(`(?i)\b(?:workaround|mitigat\w*|disabl\w*|recommend\w*|upgrad\w*|fixed|patch\w*|remediat\w*|users should)\b`)
	needSpace  = lazyre.New(`\s+`)
	needSplit  = lazyre.New(`[.!?]\s+[A-Z"(\[]`)
	needPlugin = lazyre.New(`(?i)\b(?:plugin|extension|add-?on)s?\b`)
	needModTxt = lazyre.New(`(?i)\bmodules?\b`)
)

const (
	maxNeeds  = 3
	quoteSize = 200
)

// needsOf is the preconditions the description states for a flaw of the CPE
// product vendor:product, in the order they are read, one per name, at most
// maxNeeds. A module is a precondition of the product only when the sentence
// names the module before it names the product or its vendor ("mod_rewrite
// in Apache HTTP Server"): a module listed after the product is one of the
// flaw's vectors ("Bash … the mod_cgi module in Apache"), and the product
// itself, as a module of its own name, needs nothing.
func needsOf(desc, vendor, product string) []advisory.Need {
	var out []advisory.Need
	seen := map[string]bool{}
	add := func(name, sentence string, at, end int) {
		if len(out) >= maxNeeds || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, advisory.Need{Name: name, Quote: quote(sentence, at, end)})
	}
	own := squash(product)
	for _, s := range sentences(desc) {
		if needSkip.MatchString(s) {
			continue
		}
		// A sentence that names several protocols alike says none is needed.
		if !needHTTP1.MatchString(s) {
			if m := needHTTP2.FindStringIndex(s); m != nil {
				add(advisory.NeedHTTP2, s, m[0], m[1])
			}
			if m := needHTTP3.FindStringIndex(s); m != nil {
				add("HTTP/3", s, m[0], m[1])
			}
		}
		if m := needQUIC.FindStringIndex(s); m != nil && !needHTTP1.MatchString(s) {
			add("QUIC", s, m[0], m[1])
		}
		for _, m := range needModule.FindAllStringIndex(s, 2) {
			name := strings.ToLower(s[m[0]:m[1]])
			if n := squash(name); n == own || n == "mod"+own {
				continue
			}
			if at := mention(s, vendor, product); at < 0 || at < m[0] {
				continue
			}
			add(name, s, m[0], m[1])
		}
		if m := needConfig.FindStringIndex(s); m != nil {
			add("a configuration", s, m[0], m[1])
		}
		if m := needEnabled.FindStringIndex(s); m != nil && statesNeed(s, m) {
			add(enabledName(s[m[0]:m[1]]), s, m[0], m[1])
		} else if m := needWith.FindStringIndex(s); m != nil && statesNeed(s, m) {
			add(enabledName(s[m[0]:m[1]]), s, m[0], m[1])
		}
		if m := needNonDef.FindStringIndex(s); m != nil && !needNegated.MatchString(s[max(0, m[0]-30):m[1]]) {
			add("a non-default setting", s, m[0], m[1])
		}
	}
	return out
}

// statesNeed says the clause s[m[0]:m[1]] is a precondition: it is not
// negated and not said to be the default.
func statesNeed(s string, m []int) bool {
	tail := s[m[1]:min(len(s), m[1]+16)]
	return !needNegated.MatchString(s[m[0]:m[1]]) && !needDefault.MatchString(s[m[0]:m[1]]+tail)
}

// mention is where the product or its vendor is first named in a sentence
// ("http_server" or "apache" as "http server", "http-server" or "Apache"), -1
// when neither is, or none is known.
func mention(s, vendor, product string) int {
	low := strings.ToLower(s)
	at := -1
	for _, n := range []string{product, vendor} {
		parts := strings.FieldsFunc(strings.ToLower(n), func(r rune) bool { return r == '_' || r == '-' || r == ' ' })
		if len(parts) == 0 {
			continue
		}
		for _, sep := range []string{"", " ", "-", "_"} {
			if i := strings.Index(low, strings.Join(parts, sep)); i >= 0 && (at < 0 || i < at) {
				at = i
			}
		}
	}
	return at
}

// enabledName names what an "if … is enabled" clause is about: a plugin, a
// module, or just a feature.
func enabledName(clause string) string {
	switch {
	case needPlugin.MatchString(clause):
		return "a plugin enabled"
	case needModTxt.MatchString(clause):
		return "a module enabled"
	}
	return "a feature enabled"
}

// sentences is the description cut into sentences, white space folded.
func sentences(desc string) []string {
	var out []string
	for _, para := range strings.Split(desc, "\n\n") {
		para = strings.TrimSpace(needSpace.ReplaceAllString(para, " "))
		for para != "" {
			m := needSplit.FindStringIndex(para)
			if m == nil {
				out = append(out, para)
				break
			}
			out = append(out, strings.TrimSpace(para[:m[0]+1]))
			para = strings.TrimSpace(para[m[0]+1:])
		}
	}
	return out
}

// quote is the sentence, or the part of it around the words matched when it
// is long, marked with … where it was cut.
func quote(s string, at, end int) string {
	if len(s) <= quoteSize {
		return s
	}
	from, to := at-quoteSize/3, at+2*quoteSize/3
	if to < end {
		to = end
	}
	if from < 0 {
		from = 0
	}
	if to > len(s) {
		to = len(s)
	}
	// Whole words: back off to a space, so no rune is cut.
	for from > 0 && s[from-1] != ' ' {
		from--
	}
	for to < len(s) && s[to] != ' ' {
		to++
	}
	out := s[from:to]
	if from > 0 {
		out = "…" + out
	}
	if to < len(s) {
		out += "…"
	}
	return out
}

// squash is a name with only its lower-case letters and digits, to compare a
// module with the product it belongs to.
func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// needKind groups a need's name for the build report: a module, or the name
// itself.
func needKind(name string) string {
	if strings.HasPrefix(name, "mod_") || strings.HasPrefix(name, "ngx_") {
		return "module"
	}
	return name
}
