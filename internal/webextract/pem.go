package webextract

import (
	"encoding/base64"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// maxPEM is how far past a begin line the end line is looked for: a 16 Kbit
// RSA key is 12 KB, a PGP block a little more.
const maxPEM = 64 << 10

var (
	pemBody   = lazyre.New(`^[A-Za-z0-9+/]+={0,2}$`)
	pemJoined = lazyre.New(`["'` + "`" + `]\s*\+\s*["'` + "`" + `]`)
	pemEscape = strings.NewReplacer(`\r\n`, "\n", `\n`, "\n", `\r`, "\n", `\/`, "/")
)

// pemBlock says whether the begin line at script[start:end] opens a whole key:
// an end line of the same type, a body of base64 lines that decodes, and, for
// the formats that have one, the structure a key has (DER, or OpenSSH's magic).
// Text that only names the marker (help text, a regular expression, a begin
// line joined to a variable) is not a key.
func pemBlock(script string, start, end int) bool {
	label := strings.TrimSuffix(strings.TrimPrefix(script[start:end], "-----BEGIN "), "-----")
	tail := script[end:min(len(script), end+maxPEM)]
	stop := strings.Index(tail, "-----END "+label+"-----")
	if stop < 0 {
		return false
	}
	body := pemEscape.Replace(pemJoined.ReplaceAllString(tail[:stop], ""))
	var rows []string
	encrypted := false
	for i, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case len(rows) == 0 && strings.Contains(line, ": "): // Proc-Type, DEK-Info, Version
			encrypted = encrypted || strings.HasPrefix(line, "Proc-Type") && strings.Contains(line, "ENCRYPTED")
		case strings.Contains(label, "PGP") && strings.HasPrefix(line, "=") && i > 0: // the armor's checksum
		default:
			rows = append(rows, line)
		}
	}
	for _, r := range rows {
		if !pemBody.MatchString(r) {
			return false
		}
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(rows, ""))
	if err != nil || len(der) < 16 {
		return false
	}
	switch {
	case strings.Contains(label, "OPENSSH"):
		return strings.HasPrefix(string(der), "openssh-key-v1\x00")
	case strings.Contains(label, "PGP"):
		return der[0]&0x80 != 0 // an OpenPGP packet tag
	case encrypted:
		return true // legacy encryption: the body is ciphertext
	}
	return isDER(der)
}

// isDER says whether b is one DER SEQUENCE that fills it.
func isDER(b []byte) bool {
	if len(b) < 2 || b[0] != 0x30 {
		return false
	}
	n, off := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return false
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		off += k
	}
	return off+n == len(b)
}
