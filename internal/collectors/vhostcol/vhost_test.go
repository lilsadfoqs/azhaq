package vhostcol

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/types"
)

// site is a web server that routes by Host: the names of apps get a page of
// their own, every other Host the default page.
type site struct {
	port  string
	mu    sync.Mutex
	hosts []string
	n     atomic.Int64
}

func (s *site) seen(host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.hosts {
		if h == host {
			n++
		}
	}
	return n
}

func newSite(t *testing.T, apps map[string]string, nonce bool) *site {
	t.Helper()
	s := &site{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hosts = append(s.hosts, r.Host)
		s.mu.Unlock()
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html")
		if title, ok := apps[host]; ok {
			fmt.Fprintf(w, "<html><head><title>%s</title></head><body><h1>%s</h1><p>the %s application</p></body></html>", title, title, title)
			return
		}
		extra := ""
		if nonce {
			extra = fmt.Sprintf("<p>request %s</p>", strings.Repeat("7", int(s.n.Add(1))))
		}
		fmt.Fprintf(w, "<html><head><title>It works</title></head><body><h1>Default</h1><p>the default site of the server</p>%s</body></html>", extra)
	}))
	t.Cleanup(srv.Close)
	_, s.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return s
}

func resolving(t *testing.T, m map[string][]string) {
	t.Helper()
	egress.Reset()
	egress.SetResolver(func(_ context.Context, host string) []string { return m[host] })
	t.Cleanup(egress.Reset)
}

func hostSeed(n string) types.Seed {
	return types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}}
}

func urlSeed(u string) types.Seed {
	return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}}
}

// feed runs the seeds in order and gathers what they found.
func feed(t *testing.T, c *Collector, seeds ...types.Seed) (obs []types.Observation, hints []types.Seed) {
	t.Helper()
	for _, s := range seeds {
		meta, err := c.Run(context.Background(), s, func(o types.Observation) error { obs = append(obs, o); return nil })
		if err != nil {
			t.Fatalf("%v: %v", s, err)
		}
		hints = append(hints, meta.NextHints...)
	}
	return obs, hints
}

// A name whose answer differs from the service's answer to a name that cannot
// exist is a site of its own, whichever of the name and the service is found
// first; the others are not. The default answer costs two requests, and each
// name one.
func TestANameAnsweredDifferentlyIsASiteOfItsOwn(t *testing.T) {
	for _, order := range []string{"names first", "service first"} {
		t.Run(order, func(t *testing.T) {
			resolving(t, nil)
			s := newSite(t, map[string]string{"wiki.lab.zz": "Team wiki"}, false)
			svc := urlSeed("http://127.0.0.1:" + s.port + "/")
			seeds := []types.Seed{hostSeed("wiki.lab.zz"), hostSeed("plain.lab.zz"), svc}
			if order == "service first" {
				seeds = []types.Seed{svc, hostSeed("wiki.lab.zz"), hostSeed("plain.lab.zz")}
			}
			obs, hints := feed(t, &Collector{}, seeds...)
			if len(obs) != 1 || obs[0].Kind != Kind || !strings.Contains(string(obs[0].Payload), `"name":"wiki.lab.zz"`) {
				t.Fatalf("observations %v, want the wiki only", obs)
			}
			want := "http://wiki.lab.zz:" + s.port + "/"
			if len(hints) != 1 || hints[0].Keys["url"] != want {
				t.Errorf("hints %v, want %s to be mapped by name", hints, want)
			}
			if got := egress.Resolve(context.Background(), "wiki.lab.zz"); len(got) != 1 || got[0] != "127.0.0.1" {
				t.Errorf("a name no DNS answers is not connected to the address that served it: %v", got)
			}
			if n := s.seen("wiki.lab.zz:"+s.port) + s.seen("plain.lab.zz:"+s.port); n != 2 {
				t.Errorf("%d requests for the two names, want one each", n)
			}
			if len(s.hosts) != 4 {
				t.Errorf("the service was asked %d times, want 2 names and 2 for its default answer: %v", len(s.hosts), s.hosts)
			}
		})
	}
}

// A default page that changes in numbers on every request is still the
// default: its shape is what the made-up names' pages share.
func TestADefaultPageThatChangesIsNotASite(t *testing.T) {
	resolving(t, nil)
	s := newSite(t, nil, true)
	obs, _ := feed(t, &Collector{}, urlSeed("http://127.0.0.1:"+s.port+"/"), hostSeed("a.lab.zz"), hostSeed("b.lab.zz"), hostSeed("c.lab.zz"))
	if len(obs) != 0 {
		t.Errorf("%d names taken for sites of their own: %s", len(obs), obs[0].Payload)
	}
}

// A name that resolves to the address and is asked there by name (a web port
// of the run) is not asked again; on a port nobody asks it, it is.
func TestANameAskedByNameIsNotAskedTwice(t *testing.T) {
	s := newSite(t, map[string]string{"wiki.lab.zz": "Team wiki"}, false)
	resolving(t, map[string][]string{"wiki.lab.zz": {"127.0.0.1"}})
	port := 0
	fmt.Sscan(s.port, &port)
	svc := urlSeed("http://127.0.0.1:" + s.port + "/")

	feed(t, &Collector{Ports: []int{port}}, hostSeed("wiki.lab.zz"), svc)
	if n := s.seen("wiki.lab.zz:" + s.port); n != 0 {
		t.Errorf("asked %d times as a virtual host on a port it is asked by name", n)
	}

	s2 := newSite(t, map[string]string{"wiki.lab.zz": "Team wiki"}, false)
	obs, hints := feed(t, &Collector{}, hostSeed("wiki.lab.zz"), urlSeed("http://127.0.0.1:"+s2.port+"/"))
	if s2.seen("wiki.lab.zz:"+s2.port) != 1 || len(obs) != 1 {
		t.Errorf("on a port the name is not asked on: %d requests, %d findings", s2.seen("wiki.lab.zz:"+s2.port), len(obs))
	}
	if len(hints) != 1 || !strings.Contains(string(obs[0].Payload), `"mapped":"resolves"`) {
		t.Errorf("a name that resolves to the address is mapped by name: %v %s", hints, obs[0].Payload)
	}
}

// A Host the scope does not allow is never sent, not even for the made-up
// names the default answer is learned with.
func TestAHostOutsideTheScopeIsNeverSent(t *testing.T) {
	resolving(t, nil)
	egress.SetScope(func(h string) bool { return h == "wiki.lab.zz" || h == "127.0.0.1" })
	s := newSite(t, map[string]string{"wiki.lab.zz": "Team wiki"}, false)
	obs, _ := feed(t, &Collector{}, hostSeed("wiki.lab.zz"), hostSeed("other.lab.zz"), urlSeed("http://127.0.0.1:"+s.port+"/"))
	if len(obs) != 1 {
		t.Errorf("findings %d, want the wiki", len(obs))
	}
	for _, h := range s.hosts {
		if h != "wiki.lab.zz:"+s.port && h != "127.0.0.1:"+s.port {
			t.Errorf("the service was sent Host %q, outside the scope", h)
		}
	}
}

// A name that resolves only to other addresses is recorded and not mapped:
// a request by its name would go to those addresses, not to the service.
func TestANameThatResolvesElsewhereIsRecordedNotMapped(t *testing.T) {
	resolving(t, map[string][]string{"wiki.lab.zz": {"127.0.0.5"}})
	s := newSite(t, map[string]string{"wiki.lab.zz": "Team wiki"}, false)
	obs, hints := feed(t, &Collector{}, hostSeed("wiki.lab.zz"), urlSeed("http://127.0.0.1:"+s.port+"/"))
	if len(obs) != 1 || !strings.Contains(string(obs[0].Payload), `"resolves_elsewhere":["127.0.0.5"]`) {
		t.Fatalf("observations %v", obs)
	}
	if len(hints) != 0 {
		t.Errorf("a name that resolves elsewhere is crawled: %v", hints)
	}
}

// A port the run scans is one the names are asked on: a name that resolves to
// the address is not asked there again as a virtual host.
func TestANameOnAScannedPortIsNotAskedTwice(t *testing.T) {
	s := newSite(t, map[string]string{"wiki.lab.zz": "Team wiki"}, false)
	resolving(t, map[string][]string{"wiki.lab.zz": {"127.0.0.1"}})
	port := 0
	fmt.Sscan(s.port, &port)
	feed(t, &Collector{Scanned: []int{port}}, hostSeed("wiki.lab.zz"), urlSeed("http://127.0.0.1:"+s.port+"/"))
	if n := s.seen("wiki.lab.zz:" + s.port); n != 0 {
		t.Errorf("asked %d times as a virtual host on a port the run scans", n)
	}
}
