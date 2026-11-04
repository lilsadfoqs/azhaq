// Package statechange names the GET requests whose own name declares a
// state change: a word such as create, delete, reset, populate or logout
// in the URL's path, or in an API description's operationId or summary
// for that operation.
//
// The match is a whole word of the documented set below, never a
// substring. Only what names the request counts: its path segments (not
// its query), and, for an operation of an API description, its
// operationId and summary. Prose about the application or the service
// (an info description, an operation's long description) is never read:
// "the app was created" says nothing about the request.
//
// A path whose last segment is a static file (logo.png, clear.gif, a
// script or a stylesheet) is not a request that declares anything, so it
// is left out of the match.
//
// The set is the verbs a path or an operation uses to say it changes data
// or ends a session; it is stated here and in the docs so a user can tell
// exactly which requests are named, and held back unless
// -send-state-changing is given.
package statechange

import (
	"net/url"
	"strings"
	"unicode"
)

// Verbs are the words that declare a state change, in their base form.
var Verbs = []string{
	"create", "createdb", "delete", "remove", "reset", "populate",
	"logout", "signout", "clear", "wipe", "drop", "truncate",
	"purge", "destroy", "erase", "seed",
}

var verbSet = func() map[string]bool {
	m := make(map[string]bool, len(Verbs))
	for _, v := range Verbs {
		m[v] = true
	}
	return m
}()

// Word returns the verb a text declares, or "" when none of its words
// is in the set. The first matching word, in the order the texts are
// given, is returned in its base form ("logout" for "logs out").
func Word(texts ...string) string {
	for _, text := range texts {
		words := tokens(text)
		for i, w := range words {
			if w == "log" || w == "logs" || w == "sign" || w == "signs" {
				if i+1 < len(words) && (words[i+1] == "out" || words[i+1] == "off") {
					return "logout"
				}
			}
			if v := stem(w); v != "" {
				return v
			}
		}
	}
	return ""
}

// Declares says whether these texts declare a state change, and the word
// that says so.
func Declares(texts ...string) (string, bool) {
	w := Word(texts...)
	return w, w != ""
}

// stem is w in its base form when w is a form of one of the verbs:
// creates, created and creating are create; populated is populate.
func stem(w string) string {
	if verbSet[w] {
		return w
	}
	for _, cand := range []string{
		strings.TrimSuffix(w, "s"),
		strings.TrimSuffix(w, "es"),
		trimSuffix2(w, "ed"),
		trimSuffix2(w, "d"),
		trimSuffix2(w, "ing"),
	} {
		if cand != w && verbSet[cand] {
			return cand
		}
		if cand != w && verbSet[cand+"e"] {
			return cand + "e"
		}
	}
	return ""
}

// trimSuffix2 is TrimSuffix that keeps at least two letters.
func trimSuffix2(w, suffix string) string {
	if len(w) > len(suffix)+2 {
		return strings.TrimSuffix(w, suffix)
	}
	return w
}

// tokens splits text into lower-case words: on anything that is not a
// letter or digit, and on a lower-to-upper case change, so createDB
// gives create and db, and /api/cache-clear gives api, cache, clear.
func tokens(text string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	var prev rune
	for _, r := range text {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if unicode.IsUpper(r) && unicode.IsLower(prev) {
				flush()
			}
			cur = append(cur, unicode.ToLower(r))
			prev = r
		default:
			flush()
			prev = 0
		}
	}
	flush()
	return out
}

// OfPath is the verb a URL's path declares, or "": the path alone, its
// query and host left out, and nothing for a static file.
func OfPath(path string) string {
	if static(path) {
		return ""
	}
	return Word(path)
}

// OfURL is OfPath of a URL's path ("" for a URL that does not parse).
func OfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return OfPath(u.Path)
}

// OfOperation is the verb an API description's operation declares, and
// where the word is ("path", "operationId" or "summary"): its path, then
// its operationId, then its summary. Its description, and the description
// of the API, are never read.
func OfOperation(path, operationID, summary string) (word, where string) {
	if w := OfPath(path); w != "" {
		return w, "path"
	}
	if w := Word(operationID); w != "" {
		return w, "operationId"
	}
	if w := Word(summary); w != "" {
		return w, "summary"
	}
	return "", ""
}

// staticExt are the extensions of a file served as it is.
var staticExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true, ".avif": true, ".bmp": true,
	".css": true, ".js": true, ".mjs": true, ".map": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
}

// static says the path's last segment is a static file.
func static(path string) bool {
	last := path[strings.LastIndex(path, "/")+1:]
	i := strings.LastIndex(last, ".")
	return i > 0 && staticExt[strings.ToLower(last[i:])]
}
