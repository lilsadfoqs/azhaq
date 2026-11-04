package fetch

import "strings"

// canonical is the spelling an answer is kept under: the URLs that name one
// resource by RFC 3986 section 6.2 are one, so a page already asked under
// another spelling is not sent again. It folds what the standard says does
// not change the resource (case of the scheme, the host and the hex digits
// of an escape, an escaped unreserved character such as %61 for a, the
// default port, an empty path, a fragment, which is never sent) and nothing
// else: an empty query, the order of the parameters, a trailing slash and dot
// segments are other requests and stay as they are.
func canonical(raw string) string {
	rest, _, _ := strings.Cut(raw, "#")
	scheme, rest, ok := strings.Cut(rest, "://")
	if !ok || scheme == "" || strings.ContainsAny(scheme, "/?") {
		return raw
	}
	scheme = strings.ToLower(scheme)
	auth, rest := rest, ""
	if i := strings.IndexAny(auth, "/?"); i >= 0 {
		auth, rest = auth[:i], auth[i:]
	}
	if strings.Contains(auth, "@") {
		return raw // a user's name or password is kept as it was written
	}
	auth = strings.ToLower(auth)
	if scheme == "http" {
		auth = strings.TrimSuffix(auth, ":80")
	} else if scheme == "https" {
		auth = strings.TrimSuffix(auth, ":443")
	}
	if auth == "" || strings.HasSuffix(auth, ":") {
		return raw
	}
	path, query, hasQuery := strings.Cut(rest, "?")
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + auth + foldEscapes(path)
	if hasQuery {
		out += "?" + foldEscapes(query)
	}
	return out
}

// foldEscapes writes the hex digits of every escape in upper case and
// decodes an escaped unreserved character (letters, digits, - . _ ~).
func foldEscapes(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			c := unhex(s[i+1])<<4 | unhex(s[i+2])
			if unreserved(c) {
				b.WriteByte(c)
			} else {
				b.WriteByte('%')
				b.WriteString(strings.ToUpper(s[i+1 : i+3]))
			}
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}
