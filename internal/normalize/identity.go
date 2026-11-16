package normalize

import (
	"net/url"
	"sort"
	"strings"
)

// TokenShaped says a value is a random token, by its shape alone: a hex
// string of 16 characters or more, or one of 16 or more characters from the
// base64 alphabets (standard or URL-safe) that mixes digits, lower and upper
// case. A word, a number or a short id is not one.
func TokenShaped(v string) bool {
	if len(v) < 16 {
		return false
	}
	hex, digit, lower, upper := true, false, false, false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
			hex = hex && c <= 'f'
		case c >= 'A' && c <= 'Z':
			upper = true
			hex = hex && c <= 'F'
		case c == '-' || c == '_' || c == '+' || c == '/' || c == '=':
			hex = false
		default:
			return false
		}
	}
	return hex || digit && lower && upper
}

// Number says v is a run of digits.
func Number(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// Param is one name=value pair of a query as it was written; HasValue is
// false for a bare name.
type Param struct {
	Name, Value string
	HasValue    bool
}

// SplitURL cuts a URL into what comes before its query and its query pairs,
// in the order written; a fragment is dropped.
func SplitURL(raw string) (base string, params []Param) {
	raw, _, _ = strings.Cut(raw, "#")
	base, q, _ := strings.Cut(raw, "?")
	for _, kv := range strings.Split(q, "&") {
		if kv == "" {
			continue
		}
		n, v, has := strings.Cut(kv, "=")
		params = append(params, Param{n, v, has})
	}
	return base, params
}

// Parts is a URL as runs are compared: what comes before its query, without
// the servlet session path parameter, and the query pairs ordered by name (a
// name written twice keeps its values' order).
func Parts(raw string) (base string, params []Param) {
	base, params = SplitURL(raw)
	if strings.Contains(strings.ToLower(base), ";jsessionid") {
		if i := strings.Index(base, "://"); i >= 0 {
			if j := strings.Index(base[i+3:], "/"); j >= 0 {
				base = base[:i+3+j] + dropSessionParam(base[i+3+j:])
			}
		}
	}
	sort.SliceStable(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	return base, params
}

// Identity is what two spellings of one URL have in common for comparing runs:
// Parts with the values that are tokens, and those of the names in perVisit,
// written as {}. It is a key, not a URL to send: what a request carries stays
// as asked.
func Identity(raw string, perVisit map[string]bool) string {
	base, params := Parts(raw)
	if len(params) == 0 {
		return base
	}
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = p.Name
		if !p.HasValue {
			continue
		}
		v, err := url.QueryUnescape(p.Value)
		if perVisit[p.Name] || err == nil && TokenShaped(v) {
			parts[i] += "={}"
		} else {
			parts[i] += "=" + p.Value
		}
	}
	return base + "?" + strings.Join(parts, "&")
}
