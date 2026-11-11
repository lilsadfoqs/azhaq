package egress

import (
	"context"
	"errors"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/scope"
)

// With no rule, a URL target holds its host to its port at the HTTP client and
// the raw dial, and says why; a host the targets do not name is not held, and
// the run has no scope.
func TestTargetPortsHoldTheHost(t *testing.T) {
	Reset()
	defer Reset()
	good, goodHits := counting(t)
	bad, badHits := counting(t)
	SetTargetPorts(scope.TargetPorts([]string{good.URL + "/"}, nil))
	if HasScope() {
		t.Fatal("target ports made a scope")
	}

	c := TargetClient(TargetOptions{})
	if err := get(c, good.URL+"/"); err != nil || goodHits.Load() != 1 {
		t.Fatalf("the target's port: %v, %d hits", err, goodHits.Load())
	}
	err := get(c, bad.URL+"/")
	if !errors.Is(err, neterr.ErrOutOfTargetPort) || !errors.Is(err, neterr.ErrOutOfPort) || !errors.Is(err, neterr.ErrOutOfScope) || badHits.Load() != 0 {
		t.Fatalf("another port of the host: %v, %d hits", err, badHits.Load())
	}
	if _, err := DialTarget(context.Background(), "tcp", bad.Listener.Addr().String()); !errors.Is(err, neterr.ErrOutOfTargetPort) {
		t.Fatalf("a dial to another port: %v", err)
	}
	if AllowsURL(bad.URL+"/") || !AllowsURL("http://other.test:9/") || !AllowsURL(good.URL+"/") {
		t.Fatal("AllowsURL does not follow the targets' ports")
	}

	var got string
	Current().SetOnPortSkip(func(raw, reason string) { got = reason })
	NotePortSkip(bad.URL + "/")
	if got != neterr.OutOfTargetPortReason {
		t.Fatalf("reason %q", got)
	}
}

// A URL on its scheme's default port holds its host to 80 and 443, so a move
// from http to https stays in; several URLs on a host allow each port; a bare
// target keeps every port.
func TestTargetPortsOfURLs(t *testing.T) {
	Reset()
	defer Reset()
	SetTargetPorts(scope.TargetPorts([]string{"http://web.test/", "https://tls.test/", "http://two.test:81/", "http://two.test:82/", "https://alt.test:8443/", "http://covered.test:9/"}, []string{"covered.test"}))
	for _, c := range []struct {
		url string
		ok  bool
	}{
		{"http://web.test/", true}, {"https://web.test/", true}, {"http://web.test:8080/", false},
		{"https://tls.test/", true}, {"http://tls.test/", true}, {"https://tls.test:444/", false},
		{"http://two.test:81/", true}, {"http://two.test:82/", true}, {"http://two.test/", false},
		{"https://alt.test:8443/", true}, {"https://alt.test/", false}, {"http://alt.test/", false},
		{"http://covered.test:7/", true}, {"http://elsewhere.test:7/", true},
	} {
		if got := AllowsURL(c.url); got != c.ok {
			t.Errorf("AllowsURL(%s) = %v, want %v", c.url, got, c.ok)
		}
	}
}
