// Package proof is what a finding carries to be checked without azhaq: the
// request that was sent, an excerpt of the answer that shows the thing, the
// stage that found it and one shell command that shows the same. It holds
// what was received, cut to a bounded size; it never asks again.
//
// It also judges the answers to the built-in path checks (paths.go): a path
// that names a file or a panel is a finding only when its answer holds what
// the path names and is not one of the host's own baselines.
package proof

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The three tiers every row of the findings output is in.
const (
	TierFinding        = "finding"        // proven: the answer shows the thing named
	TierIdentification = "identification" // a product and version, with the advisory match where there is one
	TierLead           = "lead"           // inferred from a name, a path or a guess
)

// MaxExcerpt bounds the excerpt of an answer a proof keeps, in characters.
const MaxExcerpt = 240

// Proof is the proof fields of a record, as they are written in the findings
// output. Every field is what was received or sent when the row was found.
type Proof struct {
	ObservedAt   string `json:"observed_at"`
	Method       string `json:"method"` // GET, HEAD, connect, a protocol's request
	Target       string `json:"target"` // the URL, or host:port
	RequestBytes string `json:"request_bytes,omitempty"`
	Status       int    `json:"status,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	Excerpt      string `json:"excerpt"`
	// ExcerptPart is where in the answer the excerpt is from: body, header (the
	// status line and headers), banner (what a service said on its own),
	// response (what a service answered to the request sent) or dns.
	// ExcerptOffset is the byte offset of the excerpt in the answer, when its
	// bytes were at hand to count it.
	ExcerptPart   string `json:"excerpt_part"`
	ExcerptOffset *int   `json:"excerpt_offset,omitempty"`
	How           string `json:"how"`
	Reproduce     string `json:"reproduce"`
}

// Complete says every field a finding must have is set.
func (p *Proof) Complete() bool {
	return p != nil && p.ObservedAt != "" && p.Method != "" && p.Target != "" && p.Excerpt != "" &&
		p.ExcerptPart != "" && p.How != "" && p.Reproduce != ""
}

// Offset returns a pointer for ExcerptOffset.
func Offset(n int) *int { return &n }

// Printable is b as one line of at most max characters: tabs and line breaks
// as \t, \r and \n, any byte that is not text as \xNN, so what is shown is
// exactly what came.
func Printable(b []byte, max int) string {
	var sb strings.Builder
	n := 0
	for len(b) > 0 && n < max {
		c, size := utf8.DecodeRune(b)
		var piece string
		switch {
		case c == '\n':
			piece = `\n`
		case c == '\r':
			piece = `\r`
		case c == '\t':
			piece = `\t`
		case c == utf8.RuneError && size <= 1, !unicode.IsPrint(c):
			for _, x := range b[:size] {
				piece += fmt.Sprintf(`\x%02x`, x)
			}
		default:
			piece = string(c)
		}
		sb.WriteString(piece)
		n += utf8.RuneCountInString(piece)
		b = b[size:]
	}
	return sb.String()
}

// Window is the excerpt of body from at, at most MaxExcerpt characters, and
// the offset it starts at.
func Window(body []byte, at int) (string, *int) {
	if at < 0 || at > len(body) {
		at = 0
	}
	return Printable(body[at:], MaxExcerpt), Offset(at)
}

// Quote is s as one POSIX shell word, in single quotes.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Curl is the curl command that sends method to rawURL and prints the answer
// with its headers. A GET is the default and is not named.
func Curl(method, rawURL string) string {
	args := []string{"curl", "-sS"}
	switch method {
	case "", "GET":
		args = append(args, "-i")
	case "HEAD":
		args = append(args, "-I")
	default:
		args = append(args, "-i", "-X", method)
	}
	args = append(args, "--max-time", "10")
	if strings.HasPrefix(rawURL, "https://") {
		args = append(args, "-k")
	}
	return strings.Join(append(args, Quote(rawURL)), " ")
}

// EscapeBytes is b written for printf's %b: printable ASCII as it is, the
// rest (and the backslash) as \xNN.
func EscapeBytes(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f && c != '\\' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteString(`\x` + hex2(c))
	}
	return sb.String()
}

func hex2(c byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[c>>4], digits[c&15]})
}

// NC is the command that sends req to host:port over TCP and prints what
// comes back: printf piped to nc. An empty req waits for the service to speak
// first, as the services that greet do.
func NC(host string, port int, req []byte) string {
	p := strconv.Itoa(port)
	if len(req) == 0 {
		return "nc -w 3 " + host + " " + p + " < /dev/null"
	}
	return "printf '%b' " + Quote(EscapeBytes(req)) + " | nc -w 3 " + host + " " + p
}

// OpenSSL is the command that opens a TLS session with host:port and, when req
// is not empty, sends it inside.
func OpenSSL(host string, port int, req []byte) string {
	target := host + ":" + strconv.Itoa(port)
	if len(req) == 0 {
		return "openssl s_client -connect " + target + " -servername " + host + " < /dev/null"
	}
	return "printf '%b' " + Quote(EscapeBytes(req)) + " | openssl s_client -quiet -connect " + target + " -servername " + host
}
