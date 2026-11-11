package contract

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// A write is a request with a method other than GET, HEAD or OPTIONS. Each
// way azhaq can send one has its own flag: without it, only reads reach the
// site; with it, the write does.

// graphQLServer answers a GET as a GraphQL endpoint does and a POST with an
// error, and counts what it gets.
func graphQLServer(t *testing.T) (*httptest.Server, *Wire) {
	t.Helper()
	w := newWire()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.addHTTP(r.Method, "http://"+r.Host+r.RequestURI)
		rw.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			rw.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(rw, `{"errors":[{"message":"Must provide query string."}]}`)
			return
		}
		fmt.Fprint(rw, `{"errors":[{"message":"introspection is disabled"}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv, w
}

// writesIn are the requests a wire saw that are not reads, as "METHOD /path".
func writesIn(w *Wire) []string {
	var out []string
	for k := range w.HTTP() {
		method, rest, _ := strings.Cut(k, " ")
		if slices.Contains([]string{"GET", "HEAD", "OPTIONS"}, method) {
			continue
		}
		path := rest[strings.Index(rest[len("http://"):], "/")+len("http://"):]
		out = append(out, method+" "+path)
	}
	slices.Sort(out)
	return out
}

func TestEveryWriteWaitsForItsFlag(t *testing.T) {
	for _, c := range []struct {
		name, flag string
		// run sends the command with the flag when on, and returns the wire the write would land on.
		run  func(t *testing.T, on bool) *Wire
		want string // the write the flag lets through
	}{
		{"crawl -submit-forms", "-submit-forms", func(t *testing.T, on bool) *Wire {
			l := newLabs(t)
			a := []string{"crawl", "-u", l.Site.URL, "-d", "3"}
			if on {
				a = append(a, "-submit-forms")
			}
			RunRaw(t, l.Dir, nil, withJSON(a)...)
			return l.Site.Wire
		}, "POST /contact"},
		{"run -graphql", "-graphql", func(t *testing.T, on bool) *Wire {
			l := newLabs(t)
			srv, w := graphQLServer(t)
			a := []string{"run", "-url", srv.URL + "/graphql", "-allow", strings.TrimPrefix(srv.URL, "http://"), "-sources", "none", "-db", "w.db"}
			if on {
				a = append(a, "-graphql")
			}
			RunRaw(t, l.Dir, nil, withJSON(a)...)
			return w
		}, "POST /graphql"},
		{"roles -replay-writes", "-replay-writes", func(t *testing.T, on bool) *Wire {
			l := newLabs(t)
			h := l.File("alice.har", har(l.Site, [2]string{"GET", "/api/v1/items/1"}, [2]string{"POST", "/api/v1/items"}))
			a := []string{"roles", "-role", "anon", "-role", "bob=Authorization: Bearer t-bob", "-har", "alice=" + h, "-replay"}
			if on {
				a = append(a, "-replay-writes", "post")
			}
			a = append(a, "-dir", "rd", "--", "-url", l.Site.URL, "-allow", l.Allow())
			RunRaw(t, l.Dir, nil, withJSON(a)...)
			return l.Site.Wire
		}, "POST /api/v1/items"},
		{"run -params-writes", "-params-writes", func(t *testing.T, on bool) *Wire {
			l := newLabs(t)
			a := []string{"run", "-url", l.Site.URL + "/products", "-allow", l.Allow(), "-sources", "none", "-db", "w.db", "-params", "small", "-params-method", "POST"}
			if on {
				a = append(a, "-params-writes")
			}
			RunRaw(t, l.Dir, nil, withJSON(a)...)
			return l.Site.Wire
		}, "POST /products"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := writesIn(c.run(t, false)); len(got) != 0 {
				t.Errorf("without %s the site got writes: %v", c.flag, got)
			}
			if got := writesIn(c.run(t, true)); !slices.Contains(got, c.want) {
				t.Errorf("with %s the site got %v, want %s", c.flag, got, c.want)
			}
		})
	}
}

// withJSON puts -json where the command takes it: before the run options of roles.
func withJSON(args []string) []string {
	if i := slices.Index(args, "--"); i >= 0 {
		return slices.Insert(slices.Clone(args), i, "-json")
	}
	return append(slices.Clone(args), "-json")
}

// Guesses, ports, UDP and wordlists go out only when you ask: a run without
// their flag sends none, and with it sends them.
func TestGuessesAndProbesGoOutOnlyWhenAsked(t *testing.T) {
	for _, c := range []struct {
		name string
		// run sends the command with the flags when on, and says what reached the labs.
		run func(t *testing.T, on bool) (seen int)
	}{
		{"a wordlist (-dirs)", func(t *testing.T, on bool) int {
			l := newLabs(t)
			w := l.File("w.txt", "zzguessone\nzzguesstwo\n")
			a := []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db"}
			if on {
				a = append(a, "-dirs", w)
			}
			RunRaw(t, l.Dir, nil, withJSON(a)...)
			n := 0
			for k := range l.Site.Wire.HTTP() {
				if strings.Contains(k, "/zzguess") {
					n++
				}
			}
			return n
		}},
		{"a port (-ports)", func(t *testing.T, on bool) int {
			l := newLabs(t)
			l.Ports = newPortLab(t)
			// A URL target starts no port scan; -ports asks the port. (A range or an address
			// among the targets is asked its ports without the flag: -ports default.)
			a := []string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db"}
			if on {
				a = []string{"run", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db", "-ports", portOf(l.Ports.Banner)}
			}
			RunRaw(t, l.Dir, nil, withJSON(a)...)
			return l.Ports.Wire.TCP()[l.Ports.Banner]
		}},
		{"a UDP port (-ports-udp)", func(t *testing.T, on bool) int {
			l := newLabs(t)
			wire := newWire()
			udp := listenUDP(t, wire)
			a := []string{"run", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-sources", "none", "-db", "w.db", "-ports", "none"}
			if on {
				a = append(a, "-ports-udp", portOf(udp))
			}
			RunRaw(t, l.Dir, nil, withJSON(a)...)
			time.Sleep(200 * time.Millisecond)
			return wire.UDP()[udp]
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if n := c.run(t, false); n != 0 {
				t.Errorf("without its flag, %d requests went out", n)
			}
			if n := c.run(t, true); n == 0 {
				t.Errorf("with its flag, none went out")
			}
		})
	}
}
