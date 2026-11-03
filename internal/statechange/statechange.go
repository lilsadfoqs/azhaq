// Package statechange names the GET requests whose own name or
// description declares a state change: a word such as create, delete,
// reset, populate or logout in the URL's path, in an operation's
// summary or description, or in its operationId.
//
// The match is a whole word of the documented set below, never a
// substring, and it decides nothing by itself: azhaq still sends every
// GET in scope, and only a user's -deny-path rule keeps one out. The
// set is the verbs an API description or a path uses to say it changes
// data or ends a session; it is stated here and in the docs so a user
// can tell exactly which requests will be named.
package statechange

import (
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
// is in the set. Texts are the name and description of one request:
// its path, its operation's summary, description and operationId.
// The first matching word, in the order the texts are given, is
// returned in its base form ("logout" for "logs out").
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

// Declares says whether a request with these texts declares a state
// change, and the word that says so.
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
