package detect

import (
	"regexp/syntax"
	"sort"
	"strings"
)

// A cover is a necessary condition on a text, as a disjunction of groups:
// the text can match only if, for some group, every literal of the group
// occurs in it (compared lower-cased). A nil cover proves nothing.

const (
	minLiteral = 3  // shorter needles match too often to help
	maxGroups  = 32 // wider conditions cost more than they save
)

func lowerCover(s string) [][]string {
	if s == "" {
		return nil
	}
	return [][]string{{strings.ToLower(s)}}
}

// regexCover returns the cover of a Go regex source.
func regexCover(pattern string) [][]string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	return cover(re)
}

// The regex cover walk follows internal/wappalyzer/patterns.go, which derives
// the same condition for its own fingerprints.
func cover(re *syntax.Regexp) [][]string {
	switch re.Op {
	case syntax.OpLiteral:
		return lowerCover(string(re.Rune))
	case syntax.OpCapture, syntax.OpPlus:
		if len(re.Sub) == 0 {
			return nil
		}
		return cover(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) == 0 {
			return nil
		}
		return coverConcat(flattenConcat(re, nil))
	case syntax.OpConcat:
		return coverConcat(flattenConcat(re, nil))
	case syntax.OpAlternate:
		return orCover(coverAll(re.Sub))
	}
	return nil
}

func coverAll(subs []*syntax.Regexp) [][][]string {
	out := make([][][]string, len(subs))
	for i, s := range subs {
		out[i] = cover(s)
	}
	return out
}

// optional stands for the tail of a bounded repeat: it proves nothing.
var optional = &syntax.Regexp{Op: syntax.OpQuest}

// flattenConcat lists the parts of a concatenation, writing out a repeat that
// must happen Min times.
func flattenConcat(re *syntax.Regexp, dst []*syntax.Regexp) []*syntax.Regexp {
	switch {
	case re.Op == syntax.OpConcat:
		for _, sub := range re.Sub {
			dst = flattenConcat(sub, dst)
		}
		return dst
	case re.Op == syntax.OpRepeat && re.Min > 0 && len(re.Sub) == 1:
		for i := 0; i < re.Min && i < 8; i++ {
			dst = flattenConcat(re.Sub[0], dst)
		}
		if re.Max != re.Min && re.Max != -1 || re.Min > 8 {
			dst = append(dst, optional)
		}
		return dst
	}
	return append(dst, re)
}

// coverConcat ANDs the required pieces. Adjacent single literals are glued
// into one needle; a gap keeps both sides.
func coverConcat(parts []*syntax.Regexp) [][]string {
	var acc [][]string
	adjacent := false
	for _, part := range parts {
		next := cover(part)
		if len(next) == 0 {
			adjacent = false
			continue
		}
		if acc == nil {
			acc = next
			adjacent = true
			continue
		}
		if adjacent {
			if glued, ok := glueLiterals(acc, next); ok {
				acc = glued
				continue
			}
		}
		acc = andCover(acc, next)
		adjacent = true
	}
	return acc
}

func glueLiterals(left, right [][]string) ([][]string, bool) {
	l, lok := singles(left)
	r, rok := singles(right)
	if !lok || !rok || len(l)*len(r) > maxGroups {
		return nil, false
	}
	out := make([][]string, 0, len(l)*len(r))
	for _, a := range l {
		for _, b := range r {
			out = append(out, []string{a + b})
		}
	}
	return out, true
}

func singles(groups [][]string) ([]string, bool) {
	out := make([]string, len(groups))
	for i, g := range groups {
		if len(g) != 1 {
			return nil, false
		}
		out[i] = g[0]
	}
	return out, true
}

// andCover is the cover of two conditions that must both hold. A nil side
// proves nothing, so the other side stands alone.
func andCover(left, right [][]string) [][]string {
	if len(left) == 0 {
		return right
	}
	if len(right) == 0 {
		return left
	}
	if len(left)*len(right) > maxGroups {
		if coverScore(left) >= coverScore(right) {
			return left
		}
		return right
	}
	out := make([][]string, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			g := make([]string, 0, len(a)+len(b))
			g = append(g, a...)
			g = append(g, b...)
			out = append(out, g)
		}
	}
	return out
}

// orCover is the cover of alternatives: nil if any alternative proves nothing.
func orCover(alts [][][]string) [][]string {
	var out [][]string
	for _, a := range alts {
		if len(a) == 0 {
			return nil
		}
		out = append(out, a...)
	}
	return out
}

// coverScore is the length of the weakest group's best needle.
func coverScore(groups [][]string) int {
	score := int(^uint(0) >> 1)
	for _, g := range groups {
		best := 0
		for _, l := range g {
			if len(l) > best {
				best = len(l)
			}
		}
		if best < score {
			score = best
		}
	}
	return score
}

// finishCover drops needles that are too short and normalises groups. A group
// left empty makes the whole cover useless.
func finishCover(groups [][]string) [][]string {
	if len(groups) == 0 || len(groups) > maxGroups {
		return nil
	}
	var out [][]string
	seenGroup := map[string]bool{}
	for _, g := range groups {
		var keep []string
		seen := map[string]bool{}
		for _, l := range g {
			if len(l) < minLiteral || seen[l] {
				continue
			}
			seen[l] = true
			keep = append(keep, l)
		}
		if len(keep) == 0 {
			return nil
		}
		sort.Strings(keep)
		key := strings.Join(keep, "\x00")
		if seenGroup[key] {
			continue
		}
		seenGroup[key] = true
		out = append(out, keep)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Join(out[i], "\x00") < strings.Join(out[j], "\x00") })
	return out
}

// dslCover derives a cover of the response text from an expression. Only
// calls over body, header or all_headers (optionally lower-cased) count.
func dslCover(n *node) [][]string {
	switch n.kind {
	case nBinary:
		switch n.op {
		case "&&":
			return andCover(dslCover(n.args[0]), dslCover(n.args[1]))
		case "||":
			return orCover([][][]string{dslCover(n.args[0]), dslCover(n.args[1])})
		}
	case nCall:
		return callCover(n)
	}
	return nil
}

func callCover(n *node) [][]string {
	switch n.op {
	case "contains", "contains_any", "contains_all":
		if !isResponseText(n.args[0]) {
			return nil
		}
		var lits []string
		for _, a := range n.args[1:] {
			if a.kind != nStr {
				if n.op == "contains_all" {
					continue // an unknown needle only loosens an AND
				}
				return nil
			}
			lits = append(lits, strings.ToLower(a.str))
		}
		switch {
		case len(lits) == 0:
			return nil
		case n.op == "contains_all":
			return [][]string{lits}
		}
		groups := make([][]string, len(lits))
		for i, l := range lits {
			groups[i] = []string{l}
		}
		return groups
	case "regex":
		if n.args[0].kind != nStr || !isResponseText(n.args[1]) {
			return nil
		}
		return regexCover(n.args[0].str)
	}
	return nil
}

func isResponseText(n *node) bool {
	switch n.kind {
	case nIdent:
		return n.str == "body" || n.str == "header" || n.str == "all_headers"
	case nCall:
		return (n.op == "to_lower" || n.op == "to_upper") && isResponseText(n.args[0])
	}
	return false
}
