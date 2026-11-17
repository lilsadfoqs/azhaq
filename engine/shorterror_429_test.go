package engine

import "testing"

// A 429 in the URL an error quotes (a port, a query value) is not a rate limit.
func TestShortErrorDoesNotReadA429OutOfAQuotedURL(t *testing.T) {
	for in, want := range map[string]string{
		`Get "http://127.0.0.1:42901/lost?name150=a429b": EOF`:     "connection closed (EOF)",
		`Get "http://127.0.0.1:80/x?v=429": unexpected status 429`: "HTTP 429 (rate limited)",
		`HTTP 429 from the target: it limits requests`:             "HTTP 429 (rate limited)",
	} {
		if got := ShortError(in); got != want {
			t.Errorf("ShortError(%q) = %q, want %q", in, got, want)
		}
	}
}

// A body that ended early keeps its own words, whatever status it had, and is
// retryable; it is not read as the HTTP 500 its text names.
func TestShortErrorKeepsACutBody(t *testing.T) {
	for _, in := range []string{
		"closed after 234 of 4096 bytes (HTTP 200, text/html)",
		"closed after 16 bytes (HTTP 500, application/json)",
	} {
		if got := ShortError(in); got != in {
			t.Errorf("ShortError(%q) = %q", in, got)
		}
		if !Retryable(in) {
			t.Errorf("%q is not retryable", in)
		}
	}
}

// The TLS hint on a plain request's failure is text for the reader: the failure
// is classified, grouped and retried as it was without it.
func TestTLSHintDoesNotChangeTheFailure(t *testing.T) {
	for raw, want := range map[string]string{
		`Get "http://127.0.0.1:34117/": EOF; this port may speak TLS; try https://127.0.0.1:34117`:                                "connection closed (EOF)",
		`Get "http://h:80/": read tcp 1.2.3.4:5->6.7.8.9:80: connection reset by peer; this port may speak TLS; try https://h:80`: "connection reset",
	} {
		if got := ShortError(raw); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
		if !Retryable(raw) {
			t.Errorf("%s: not retryable", raw)
		}
	}
	if Retryable(`Get "http://h:80/": malformed HTTP response "\x15\x03\x01"; this port speaks TLS; try https://h:80`) {
		t.Error("an alert answer became retryable")
	}
}
