package advisory

import (
	"strconv"
	"strings"
)

// Compare says how version a stands to b (-1, 0, 1) in the forms an
// advisory's range and a banner both use: semver (1.18.0, 1.0.0-rc.1)
// and epoch-version-release (1:2.4.25-3ubuntu1, 9.6p1). ok is false
// when the comparison would be a guess — a version with no number, a
// range ("14 - 17"), a bare word — and the caller then labels the match
// conditional and says so, never affected or not affected on a guess.
func Compare(a, b string) (cmp int, ok bool) {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return 0, false
	}
	if pa.epoch != pb.epoch {
		return sign(pa.epoch - pb.epoch), true
	}
	if c := compareTokens(pa.tokens, pb.tokens); c != 0 {
		return c, true
	}
	return compareTokens(pa.revision, pb.revision), true
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

type parsedVersion struct {
	epoch    int
	tokens   []token // the upstream version, split into runs
	revision []token // after the last -, when it starts with a number (Debian/RPM release)
}

type token struct {
	num   string // a run of digits, "" for a non-number
	alpha string // a run of letters
	tilde bool   // ~ (or a pre-release -): sorts before everything, even the end
	pre   int    // the place of a pre-release word (rc, beta, M), 1 and up: sorts before the end
	end   bool
}

// preWords are the qualifiers that name a build before its release, in
// the order they come (1.0.0.M1 < 1.0.0.RC1 < 1.0.0), and releaseWords
// those that name the release itself (8.0.0.Final and 3.2.1.RELEASE equal
// 8.0.0 and 3.2.1). Any other word after a number is a later patch level
// (9.6p1), and a -word nobody listed is a pre-release, as in semver.
var preWords = map[string]int{
	"dev": 1, "snapshot": 2, "nightly": 3, "canary": 4, "alpha": 5, "beta": 6,
	"preview": 7, "pre": 8, "m": 9, "milestone": 9, "ea": 11, "cr": 12, "rc": 13,
}

var releaseWords = map[string]bool{"final": true, "ga": true, "release": true, "stable": true, "lts": true}

var postWords = map[string]bool{"sp": true, "patch": true, "p": true, "update": true, "u": true, "hotfix": true, "fix": true, "build": true, "rev": true, "r": true}

// dashWord is the letters that open s, lowercased.
func dashWord(s string) string {
	i := 0
	for i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z') {
		i++
	}
	return strings.ToLower(s[:i])
}

func parseVersion(s string) (parsedVersion, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if s == "" || !strings.ContainsAny(s, "0123456789") {
		return parsedVersion{}, false
	}
	if strings.ContainsAny(s, " \t,;/()[]{}") {
		return parsedVersion{}, false
	}
	var p parsedVersion
	if ep, rest, found := strings.Cut(s, ":"); found {
		n, err := strconv.Atoi(ep)
		if err != nil || n < 0 || rest == "" {
			return parsedVersion{}, false
		}
		p.epoch, s = n, rest
	}
	// The release is the part after the last -, when it starts with a
	// number (2.4.25-3, 1.0-1ubuntu1). A -word is a semver pre-release
	// (1.0.0-rc.1): it belongs to the version and sorts before it.
	upstream := s
	if i := strings.LastIndex(s, "-"); i > 0 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
		upstream, p.revision = s[:i], tokenize(s[i+1:])
	} else if i > 0 {
		if w := dashWord(s[i+1:]); preWords[w] > 0 || releaseWords[w] || postWords[w] {
			upstream = s[:i] + "." + s[i+1:]
		} else {
			upstream = s[:i] + "~" + s[i+1:]
		}
	}
	p.tokens = tokenize(upstream)
	if len(p.tokens) == 0 {
		return parsedVersion{}, false
	}
	return p, true
}

// tokenize splits s into runs of digits and of letters; separators
// (. _ +) only split, ~ is a token of its own.
func tokenize(s string) []token {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '~':
			out = append(out, token{tilde: true})
			i++
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			out = append(out, token{num: s[i:j]})
			i = j
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(s) && (s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
				j++
			}
			w := strings.ToLower(s[i:j])
			switch {
			case releaseWords[w]:
				// the release itself: no token
			case preWords[w] > 0:
				out = append(out, token{alpha: w, pre: preWords[w]})
			default:
				out = append(out, token{alpha: w})
			}
			i = j
		default:
			i++
		}
	}
	return out
}

// compareTokens compares token by token: a ~ sorts before the end of
// the version (1.0~rc1 < 1.0), numbers compare by value, a number sorts
// before a word, and words compare as text. Where one side ends, the
// other's next token decides: a trailing word is a later patch level
// (9.6p1 > 9.6), a trailing number a later release (1.0.1 > 1.0).
func compareTokens(a, b []token) int {
	for i := 0; ; i++ {
		ta, tb := tokenAt(a, i), tokenAt(b, i)
		if ta.end && tb.end {
			return 0
		}
		if c := compareToken(ta, tb); c != 0 {
			return c
		}
	}
}

func tokenAt(ts []token, i int) token {
	if i < len(ts) {
		return ts[i]
	}
	return token{end: true}
}

func compareToken(a, b token) int {
	// ~ before everything, then the pre-release words, the end, numbers
	// and words: 1.0~x < 1.0.rc1 < 1.0 < 1.0p1, and 1.0 < 1.0.1 by the
	// next round.
	rank := func(t token) int {
		switch {
		case t.tilde:
			return 0
		case t.pre > 0:
			return 1
		case t.end:
			return 2
		case t.num != "":
			return 3
		default:
			return 4
		}
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		return sign(ra - rb)
	}
	switch {
	case a.pre > 0 && b.pre > 0:
		return sign(a.pre - b.pre)
	case a.num != "" && b.num != "":
		an, bn := strings.TrimLeft(a.num, "0"), strings.TrimLeft(b.num, "0")
		if len(an) != len(bn) {
			return sign(len(an) - len(bn))
		}
		return strings.Compare(an, bn)
	case a.alpha != "" && b.alpha != "":
		return strings.Compare(a.alpha, b.alpha)
	}
	return 0
}
