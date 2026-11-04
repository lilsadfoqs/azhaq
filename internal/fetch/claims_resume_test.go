package fetch

import (
	"strings"
	"testing"
)

// What a workspace keeps of an answer's request has no header that sounds
// like a credential and no body.
func TestScrubbedRequestKeepsNoCredentialHeaderAndNoBody(t *testing.T) {
	wire := "POST /login HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer SECRET\r\nCookie: s=SECRET\r\nX-Api-Token: SECRET\r\nX-Api-Key: SECRET\r\n" +
		"X-Session-Id: SECRET\r\nX-Client-Secret: SECRET\r\nX-Csrf: SECRET\r\nX-Xsrf-Token: SECRET\r\nX-Trace: 1\r\nContent-Length: 6\r\n\r\nSECRET"
	r := (&Raw{Request: []byte(wire), Chain: []RawHop{{Request: wire}}}).Scrubbed()
	for _, got := range []string{string(r.Request), r.Chain[0].Request} {
		if strings.Contains(got, "SECRET") {
			t.Errorf("a secret is kept:\n%s", got)
		}
		if got != "POST /login HTTP/1.1\r\nHost: a.test\r\nX-Trace: 1\r\nContent-Length: 6\r\n\r\n" {
			t.Errorf("kept %q", got)
		}
	}
	if (*Raw)(nil).Scrubbed() != nil {
		t.Error("a nil Raw is not nil when scrubbed")
	}
}
