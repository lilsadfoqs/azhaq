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
	end   bool
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
		upstream = s[:i] + "~" + s[i+1:]
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
			out = append(out, token{alpha: strings.ToLower(s[i:j])})
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
	// ~ before everything, the end next, then numbers, then words:
	// 1.0~rc1 < 1.0 < 1.0p1, and 1.0 < 1.0.1 by the next round.
	rank := func(t token) int {
		switch {
		case t.tilde:
			return 0
		case t.end:
			return 1
		case t.num != "":
			return 2
		default:
			return 3
		}
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		return sign(ra - rb)
	}
	switch {
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
