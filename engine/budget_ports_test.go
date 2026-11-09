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

// A row a collector marks Keep reaches the workspace as it is emitted, also
// under a request budget, which holds the other rows of a task until it
// ends: a task killed in the middle leaves what it kept.
type keeper struct {
	kept, held chan struct{}
}

func (keeper) Name() string             { return "keeper" }
func (keeper) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }
func (keeper) Outputs() []string        { return nil }
func (k keeper) Run(ctx context.Context, _ types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	_ = emit(types.Observation{Collector: "keeper", Source: "s", Kind: "plain", Payload: []byte(`{}`), ObservedAt: time.Now().UTC()})
	_ = emit(types.Observation{Collector: "keeper", Source: "s", Kind: "kept", Payload: []byte(`{}`), ObservedAt: time.Now().UTC(), Keep: true})
	close(k.kept)
	<-k.held // the process is killed here
	return types.RunMeta{Status: types.StatusOK}, nil
}

func TestKeptRowIsWrittenAtOnceUnderABudget(t *testing.T) {
	egress.Reset()
	k := keeper{kept: make(chan struct{}), held: make(chan struct{})}
	cat := catalog.New()
	cat.MustRegister(k)
	st, err := store.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_ = st.BeginRun("r", 1, 0)
	egress.SetMaxRequests(100)
	eng := &engine.Engine{Cat: cat, Store: st}
	done := make(chan error, 1)
	go func() {
		done <- eng.RunLocal(context.Background(), []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "a.test"}}}, engine.Budgets{MaxDepth: 1})
	}()
	select {
	case <-k.kept:
	case <-time.After(5 * time.Second):
		t.Fatal("the collector did not run")
	}
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, o := range obs {
		kinds = append(kinds, o.Kind)
	}
	if len(kinds) != 1 || kinds[0] != "kept" {
		t.Errorf("while the task runs the workspace holds %v, want only the kept row", kinds)
	}
	close(k.held)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if obs, _ = st.Observations(); len(obs) != 2 {
		t.Errorf("after the task the workspace holds %d rows, want both", len(obs))
	}
}

// The reserve a sweep holds for each web service it finds goes back to the
// sweep once that service is mapped: two services that reserved 2 x 30 and
// used a handful of requests leave nothing held, and the sweep spends the rest
// of the budget.
func TestBudgetGivesBackTheReserveOfAMappedService(t *testing.T) {
	fetch.Reset()
	egress.Reset()
	t.Cleanup(egress.Reset)
	var webs []int
	for i := 0; i < 2; i++ {
		l, err := net.Listen("tcp", "127.0.0.2:0")
		if err != nil {
			t.Skip(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<title>lab</title>"))
		})}
		go srv.Serve(l)
		t.Cleanup(func() { _ = srv.Close() })
		webs = append(webs, l.Addr().(*net.TCPAddr).Port)
	}
	// Closed ports first, then the two web ports, then a long tail.
	var ports []int
	for p := 20000; len(ports) < 10; p++ {
		ports = append(ports, p)
	}
	ports = append(ports, webs...)
	for p := 30000; len(ports) < 600; p++ {
		ports = append(ports, p)
	}

	cat := catalog.New()
	pc := portcol.New(nil, ports, 300)
	pc.Scanner.Detect = portscan.DetectAll
	pc.Scanner.Banner = 50 * time.Millisecond
	pc.Apply(portcol.Config{WebCost: 30, Detect: portscan.DetectAll})
	cat.MustRegister(pc)
	cat.MustRegister(&pathscol.Collector{Client: http.DefaultClient, Wordlist: []string{"a", "b"}})
	httpcol.Register(cat, http.DefaultClient)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_ = st.BeginRun("r", 3, 0)
	const budget = 300
	egress.SetMaxRequests(budget)
	eng := &engine.Engine{Cat: cat, Store: st}
	rules := scope.Rules{Allow: []string{"127.0.0.0/24"}}.Compile()
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.2/32"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 3, Scope: rules, Active: map[string]bool{"ports": true}}); err != nil {
		t.Fatal(err)
	}
	if egress.Reserved() != 0 {
		t.Errorf("%d requests are still held for 2 services that were mapped", egress.Reserved())
	}
	// Held back for the services, the sweep would stop 60 short of the budget.
	if egress.Sent() < budget-10 {
		t.Errorf("%d of %d requests were sent: the reserve of the mapped services was not given back to the sweep", egress.Sent(), budget)
	}
}
