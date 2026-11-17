// Package productname is how azhaq compares the names it gives products: the
// folding every catalog and advisory lookup shares, the vendor prefix a name
// may or may not carry ("Apache ActiveMQ", "ActiveMQ"), and the product a
// Server or X-Powered-By token names. It reads no data and asks nothing.
package productname

import (
	"strings"
	"unicode"
)

// vendors are the prefixes a product name may carry or leave off. A closed
// list: "Apache" alone is the HTTP server and never a prefix of another
// product, and no word outside this list is dropped from a name.
var vendors = map[string]bool{"apache": true, "microsoft": true, "mikrotik": true}

// generic are words too general to be a product once the vendor is taken off:
// "Apache HTTP Server" is not every vendor's "HTTP Server".
var generic = map[string]bool{
	"server": true, "httpserver": true, "http": true, "web": true, "webserver": true,
	"client": true, "agent": true, "console": true, "manager": true, "portal": true,
	"gateway": true, "proxy": true, "router": true, "api": true, "app": true,
}

// noise are words a template's title adds to a product that its header token
// does not carry ("Boa Web Server" is the "Boa/0.94" token).
var noise = map[string]bool{
	"server": true, "web": true, "http": true, "httpd": true, "file": true,
	"panel": true, "login": true, "console": true, "dashboard": true,
	"software": true, "version": true,
}

// words splits a name into lower-case letter and digit runs.
func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// foldDrops removes what Key folds away. One replacer for all calls: a new
// one built its tables for every template at load.
var foldDrops = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "")

// Key folds a product name for comparison: case, spaces, dashes, underscores
// and dots, and the usual spellings of one product (Apache httpd, OpenSSH).
func Key(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = foldDrops.Replace(s)
	switch s {
	case "apache", "apachehttpserver", "httpd":
		return "apachehttpd"
	case "ssh":
		return "openssh"
	}
	return s
}

// Keys are the keys a name answers to: its own, then the one without a leading
// vendor word when what is left is a product on its own.
func Keys(s string) []string {
	k := Key(s)
	if k == "" {
		return nil
	}
	out := []string{k}
	w := words(s)
	if len(w) > 1 && vendors[w[0]] {
		rest := strings.Join(w[1:], "")
		if !generic[rest] {
			if r := Key(rest); r != k {
				out = append(out, r)
			}
		}
	}
	return out
}

// Same says two names are one product: they share a key. "Apache ActiveMQ"
// is "ActiveMQ", "Apache" is not "Apache ActiveMQ".
func Same(a, b string) bool {
	for _, x := range Keys(a) {
		for _, y := range Keys(b) {
			if x == y {
				return true
			}
		}
	}
	return false
}

// Canon is the one key a name is deduplicated by: the vendor-less one.
func Canon(s string) string {
	k := Keys(s)
	if len(k) == 0 {
		return ""
	}
	return k[len(k)-1]
}

// Token reads the product a Server or X-Powered-By value starts with, in
// "name/version", "name(version)" or "name version" form. The name keeps its
// words: "Apache Traffic Server/9.1.0" is that product, not "Server". The
// version is "" unless it starts with a digit; the name is "" when the value
// does not start with a name.
func Token(s string) (name, version string) {
	s = strings.TrimSpace(s)
	head, rest := s, ""
	cut := strings.IndexAny(s, "/(")
	if cut >= 0 {
		head, rest = s[:cut], s[cut+1:]
	}
	w := strings.Fields(head)
	// "name version": the first word that starts with a digit ends the name.
	if cut < 0 || rest == "" || !startsDigit(strings.TrimLeft(rest, "(vV")) {
		for i := 1; i < len(w); i++ {
			if startsDigit(w[i]) || (len(w[i]) > 1 && (w[i][0] == 'v' || w[i][0] == 'V') && startsDigit(w[i][1:])) {
				version = strings.TrimLeft(w[i], "vV")
				w = w[:i]
				break
			}
		}
	}
	if version == "" {
		if v := strings.TrimLeft(rest, "(vV"); startsDigit(v) {
			if f := strings.Fields(v); len(f) > 0 {
				version = strings.Trim(f[0], "();,")
			}
		}
	}
	var keep []string
	for _, x := range w {
		if !nameWord(x) {
			break
		}
		keep = append(keep, x)
	}
	if len(keep) == 0 {
		return "", ""
	}
	if len(keep) > 4 { // a sentence, not a product name: no version is its own
		return keep[0], ""
	}
	return strings.Join(keep, " "), strings.TrimRight(version, ".")
}

func startsDigit(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

func nameWord(s string) bool {
	if s == "" || !(s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// Names says the product token a header value starts with is product's own:
// the same product (vendor prefix or not), or the product's own words once the
// ones a title adds are left off ("Serv-U" for "SolarWinds Serv-U File
// Server"). A token that adds a word ("Apache-Coyote", "Apache Tomcat" for
// "Apache") or merges one ("ApacheBench") is another product. A value with no
// readable name is not judged.
func Names(value, product string) bool {
	name, _ := Token(value)
	if name == "" {
		return true
	}
	if Same(name, product) {
		return true
	}
	tw, pw := significant(words(name)), significant(words(product))
	if len(tw) == 0 || len(pw) == 0 {
		return false
	}
	allVendor := true
	for _, x := range tw {
		allVendor = allVendor && vendors[x]
	}
	if allVendor {
		return false
	}
	for i := 0; i+len(tw) <= len(pw); i++ {
		match := true
		for j, x := range tw {
			if pw[i+j] != x {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func significant(w []string) []string {
	var out []string
	for _, x := range w {
		if !noise[x] {
			out = append(out, x)
		}
	}
	return out
}
