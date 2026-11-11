// Package statechange names the GET requests whose own name declares a
// state change: a word such as create, delete, reset, populate or logout
// in the URL's path, or in an API description's operationId or summary
// for that operation.
//
// The match is a whole word of the documented set below, never a
// substring. Only what names the request counts: its path segments, the
// query parameters that name an action (ActionParams) with a value that
// is a verb (Verbs and ActionVerbs), and, for an operation of an API
// description, its operationId and summary. Other query parameters are not
// read: ?q=delete searches for a word. Prose about the application or the service
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

// ActionParams are the names of the query parameters that name an action,
// as a whole word of the parameter's name (action, and so ajax_action).
var ActionParams = []string{"action", "act", "cmd", "command", "op", "operation", "do", "task"}

// ActionVerbs are the words a value of an action parameter declares besides
// Verbs: what a process or service control page says in its links
// (?action=stop). They are read in a query's value only, never in a path.
var ActionVerbs = []string{
	"stop", "start", "restart", "kill", "shutdown", "reboot", "halt",
	"terminate", "flush", "disable", "enable",
}

// ReadVerbs are the words an operation opens with when it reads: an
// operationId or summary that starts with one (listRecordingRules, "Lists
// all rules: active or deleted") reads, and its later words say what.
var ReadVerbs = []string{
	"get", "list", "read", "fetch", "find", "search", "show", "return",
	"retrieve", "view", "query", "count", "describe", "export", "download", "lookup", "check",
}

var verbSet = setOf(Verbs)

var readSet = setOf(ReadVerbs)

// actionSet is what an action parameter's value may name.
var actionSet = func() map[string]bool {
	m := setOf(Verbs)
	for _, v := range ActionVerbs {
		m[v] = true
	}
	return m
}()

var paramSet = setOf(ActionParams)

func setOf(words []string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, v := range words {
		m[v] = true
	}
	return m
}

// Word returns the verb a text declares, or "" when none of its words
// is in the set. The first matching word, in the order the texts are
// given, is returned in its base form ("logout" for "logs out").
func Word(texts ...string) string { return wordIn(verbSet, texts...) }

func wordIn(set map[string]bool, texts ...string) string {
	for _, text := range texts {
		words := tokens(text)
		for i, w := range words {
			if w == "log" || w == "logs" || w == "sign" || w == "signs" {
				if i+1 < len(words) && (words[i+1] == "out" || words[i+1] == "off") {
					return "logout"
				}
			}
			if v := stem(w, set); v != "" {
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
// creates, created and creating are create; populated is populate; and
// a verb run into "all", as a control page names it (?action=stopall,
// restartall, deleteall), is that verb.
func stem(w string, set map[string]bool) string {
	if set[w] {
		return w
	}
	for _, cand := range []string{
		trimSuffix2(w, "all"),
		strings.TrimSuffix(w, "s"),
		strings.TrimSuffix(w, "es"),
		trimSuffix2(w, "ed"),
		trimSuffix2(w, "d"),
		trimSuffix2(w, "ing"),
	} {
		if cand != w && set[cand] {
			return cand
		}
		if cand != w && set[cand+"e"] {
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

// OfQuery is the verb a raw query string declares, or "": a parameter whose
// name has one of ActionParams as a word and whose value has a word of Verbs
// or ActionVerbs (?action=stop, ?cmd=delete_user, ?do=restart). A parameter
// of any other name says nothing, whatever its value.
func OfQuery(rawQuery string) string {
	for _, pair := range strings.Split(rawQuery, "&") {
		name, value, _ := strings.Cut(pair, "=")
		if name, err := url.QueryUnescape(name); err == nil && namesAction(name) {
			if v, err := url.QueryUnescape(value); err == nil {
				if w := wordIn(actionSet, v); w != "" {
					return w
				}
			}
		}
	}
	return ""
}

func namesAction(name string) bool {
	for _, w := range tokens(name) {
		if paramSet[w] {
			return true
		}
	}
	return false
}

// OfTarget is the verb a request target (a path with its query, as a
// wordlist word asks it) declares, and where: "path" or "query".
func OfTarget(target string) (word, where string) {
	pathPart, query, _ := strings.Cut(target, "?")
	if w := OfPath(pathPart); w != "" {
		return w, "path"
	}
	if w := OfQuery(query); w != "" {
		return w, "query"
	}
	return "", ""
}

// Of is the verb a URL declares and where ("path" or "query"), or "".
func Of(raw string) (word, where string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	if w := OfPath(u.Path); w != "" {
		return w, "path"
	}
	if w := OfQuery(u.RawQuery); w != "" {
		return w, "query"
	}
	return "", ""
}

// OfURL is the verb a URL's path or query declares ("" for a URL that does
// not parse).
func OfURL(raw string) string {
	w, _ := Of(raw)
	return w
}

// OfOperation is the verb an API description's operation declares, and
// where the word is ("path", "operationId" or "summary"): its path, then
// its operationId, then its summary. An operationId or summary that opens
// with a read verb (ReadVerbs) declares a read, whatever follows. Its
// description, and the description of the API, are never read.
func OfOperation(path, operationID, summary string) (word, where string) {
	if w := OfPath(path); w != "" {
		return w, "path"
	}
	if opensWithRead(operationID) || opensWithRead(summary) {
		return "", ""
	}
	if w := Word(operationID); w != "" {
		return w, "operationId"
	}
	if w := Word(summary); w != "" {
		return w, "summary"
	}
	return "", ""
}

func opensWithRead(text string) bool {
	words := tokens(text)
	return len(words) > 0 && stem(words[0], readSet) != ""
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
