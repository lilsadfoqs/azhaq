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
