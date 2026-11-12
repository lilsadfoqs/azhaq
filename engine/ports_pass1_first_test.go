package engine_test

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// Under a request cap below pass 1 plus pass 2, every address is asked the
// ports of pass 1 before any address is asked pass 2: four addresses with one
// listener each, one task for each and one worker. An address that answered
// early must not spend the cap on the other ports of its own before the later
// addresses have had their first.
func TestCapSpendsPassOneOnEveryAddressBeforePassTwo(t *testing.T) {
	for name, seedOf := range map[string]func(ip string) types.Seed{
		"a block of one address": func(ip string) types.Seed {
			return types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": ip + "/32"}}
		},
		"an address": func(ip string) types.Seed {
			return types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": ip}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fetch.Reset()
			egress.Reset()
			ips := []string{"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"}
			var port int
			for _, ip := range ips {
				l, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
				if err != nil {
					t.Skip(err)
				}
				t.Cleanup(func() { _ = l.Close() })
				go func() {
					for {
						c, err := l.Accept()
						if err != nil {
							return
						}
						_ = c.Close()
					}
				}()
				port = l.Addr().(*net.TCPAddr).Port
			}
			first := []int{port - 1, port, port + 1} // pass 1: the listener and two ports beside it
			var mu sync.Mutex
			asked := map[string]bool{}
			pc := portcol.New(nil, first, 0)
			pc.Apply(portcol.Config{Escalate: true})
			pc.Scanner.Banner = 20 * time.Millisecond
			pc.Scanner.Opened = func(ip string, p int) {
				if p == port {
					mu.Lock()
					asked[ip] = true
					mu.Unlock()
				}
			}
			cat := catalog.New()
			cat.MustRegister(pc)
			st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			// 4 addresses × 3 ports is pass 1; the cap leaves 8 connects for pass 2.
			egress.SetMaxRequests(int64(len(ips)*len(first) + 8))
			eng := &engine.Engine{Cat: cat, Store: st}
			rules := scope.Rules{Allow: []string{"127.0.0.0/24"}}.Compile()
			var seeds []types.Seed
			for _, ip := range ips {
				seeds = append(seeds, seedOf(ip))
			}
			done := make(chan error, 1)
			go func() {
				done <- eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 2, Parallel: 1, Scope: rules, Active: map[string]bool{"ports": true}})
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the run did not end: a second pass waited for a worker it held")
			}
			mu.Lock()
			defer mu.Unlock()
			for _, ip := range ips {
				if !asked[ip] {
					t.Errorf("%s was not asked its pass-1 ports: pass 2 of another address spent the cap first (%d connects sent of %d)", ip, egress.Sent(), egress.MaxRequests())
				}
			}
			if got := egress.Sent(); got != egress.MaxRequests() {
				t.Errorf("%d connects sent, want the cap of %d spent: pass 2 uses what pass 1 left", got, egress.MaxRequests())
			}
		})
	}
}
