package cdnranges

import (
	"encoding/json"
	"errors"
	"strings"
)

// The data is read with this small scanner rather than json.Unmarshal: it
// walks the embedded text and hands out pieces of it, where Unmarshal copies
// every one of the 120,000 strings into the heap for a caller that needs a
// few thousand.

var errJSON = errors.New("not the JSON of provider lists")

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	return i
}

// readString reads the string starting at s[i] (a quote): its text, and the
// index after it. A string with an escape is decoded; one without is a piece
// of s.
func readString(s string, i int) (string, int, error) {
	if i >= len(s) || s[i] != '"' {
		return "", 0, errJSON
	}
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '"':
			if !strings.Contains(s[i:j], `\`) {
				return s[i+1 : j], j + 1, nil
			}
			var out string
			if err := json.Unmarshal([]byte(s[i:j+1]), &out); err != nil {
				return "", 0, err
			}
			return out, j + 1, nil
		case '\\':
			j++
		}
	}
	return "", 0, errJSON
}

// skipValue returns the index after the value starting at s[i].
func skipValue(s string, i int) (int, error) {
	if i >= len(s) {
		return 0, errJSON
	}
	if s[i] == '"' {
		_, j, err := readString(s, i)
		return j, err
	}
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '"':
			_, k, err := readString(s, j)
			if err != nil {
				return 0, err
			}
			j = k - 1
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return j, nil // the end of the enclosing value, after a scalar
			}
			if depth--; depth == 0 {
				return j + 1, nil
			}
		case ',':
			if depth == 0 {
				return j, nil
			}
		}
	}
	return len(s), nil
}

// members calls f with each key of the JSON object s and its value as JSON.
func members(s string, f func(key, val string)) error {
	i := skipSpace(s, 0)
	if i >= len(s) || s[i] != '{' {
		return errJSON
	}
	i = skipSpace(s, i+1)
	for i < len(s) && s[i] != '}' {
		key, j, err := readString(s, i)
		if err != nil {
			return err
		}
		if j = skipSpace(s, j); j >= len(s) || s[j] != ':' {
			return errJSON
		}
		j = skipSpace(s, j+1)
		end, err := skipValue(s, j)
		if err != nil {
			return err
		}
		f(key, s[j:end])
		i = skipSpace(s, end)
		if i < len(s) && s[i] == ',' {
			i = skipSpace(s, i+1)
		}
	}
	if i >= len(s) {
		return errJSON // no closing brace
	}
	return nil
}

// strs calls f with each string of the JSON array s.
func strs(s string, f func(string)) error {
	i := skipSpace(s, 0)
	if i >= len(s) || s[i] != '[' {
		return errJSON
	}
	i = skipSpace(s, i+1)
	for i < len(s) && s[i] != ']' {
		v, j, err := readString(s, i)
		if err != nil {
			return err
		}
		f(v)
		i = skipSpace(s, j)
		if i < len(s) && s[i] == ',' {
			i = skipSpace(s, i+1)
		}
	}
	if i >= len(s) {
		return errJSON // no closing bracket
	}
	return nil
}
