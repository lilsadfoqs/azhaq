package engine_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// A request budget smaller than the sweep still maps the web service the
// sweep found: the connects of the sweep leave the requests that service's
// mapping needs (its page and two path checks here, and the guesses at the address's own 443 and 80), though the web requests
// are paced and the sweep is not.
func TestBudgetKeepsTheMappingOfAWebPortTheSweepFound(t *testing.T) {
	fetch.Reset()
	egress.Reset()
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip(err)
	}
	var served atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>lab</title>"))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { _ = srv.Close() })
	web := l.Addr().(*net.TCPAddr).Port
	// Ten closed ports, the web port, then a long tail the budget cannot cover.
	var ports []int
	for p := web + 1; len(ports) < 10; p++ {
		ports = append(ports, p)
	}
	ports = append(ports, web)
	for p := web + 100; len(ports) < 400; p++ {
		ports = append(ports, p)
	}

	cat := catalog.New()
	pc := portcol.New(nil, ports, 400) // paced, as a sweep is: the web port is found early in it
	pc.Scanner.Detect = portscan.DetectAll
	pc.Scanner.Banner = 50 * time.Millisecond
	pc.Apply(portcol.Config{WebCost: 8, Detect: portscan.DetectAll})
	cat.MustRegister(pc)
	cat.MustRegister(&pathscol.Collector{Client: http.DefaultClient, Wordlist: []string{"a", "b"}})
	httpcol.Register(cat, http.DefaultClient)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_ = st.BeginRun("r", 3, 0)
	egress.SetMaxRequests(60)
	egress.SetRate(5)
	eng := &engine.Engine{Cat: cat, Store: st}
	rules := scope.Rules{Allow: []string{"127.0.0.0/24"}}.Compile()
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.2/32"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 3, Scope: rules, Active: map[string]bool{"ports": true}}); err != nil {
		t.Fatal(err)
	}
	// The probe that named the port is the first request; the address's own 443 and 80 are asked too.
	if got := served.Load(); got < 4 {
		t.Errorf("the web service the sweep found was sent %d requests, want the probe, its page and its 2 paths; %d of 60 were spent", got, egress.Sent())
	}
	if egress.Sent() > 60 {
		t.Errorf("%d requests sent, the budget was 60", egress.Sent())
	}
}
