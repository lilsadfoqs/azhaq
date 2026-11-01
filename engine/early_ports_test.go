package engine_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// A web port of a range is probed when it is found, not when the sweep of
// the whole range ends: two addresses, one with a web service on the first
// port asked, and a sweep of 150 slow connects each. The page is requested
// while most of the connects are still to be made.
func TestRangeWebPortIsProbedWhileTheSweepRuns(t *testing.T) {
	fetch.Reset()
	egress.Reset()
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip(err)
	}
	var takes, atHit atomic.Int64
	var once sync.Once
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>lab</title>"))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { _ = srv.Close() })
	first := l.Addr().(*net.TCPAddr).Port
	const sweep = 150
	var ports []int
	for p := first; p < first+sweep; p++ {
		ports = append(ports, p)
	}

	pc := portcol.New(nil, ports, 0)
	pc.Scanner.Banner = 50 * time.Millisecond
	pc.Scanner.Take = func() error { takes.Add(1); time.Sleep(10 * time.Millisecond); return nil }
	cat := catalog.New()
	cat.MustRegister(pc)
	httpcol.Register(cat, &http.Client{Transport: noteFirst(func() { once.Do(func() { atHit.Store(takes.Load()) }) })})
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := &engine.Engine{Cat: cat, Store: st}
	rules := scope.Rules{Allow: []string{"127.0.0.0/24"}}.Compile()
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.2/31"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 3, MaxItems: 64, Scope: rules, Active: map[string]bool{"ports": true}}); err != nil {
		t.Fatal(err)
	}
	t.Logf("web probe sent after %d of %d connects", atHit.Load(), 2*sweep)
	if got := atHit.Load(); got == 0 || got > 2*sweep/3 {
		t.Errorf("the web port was probed after %d of %d connects: it waited for the sweep", got, 2*sweep)
	}
}

// noteFirst calls note before each request the web collector sends.
type noteFirst func()

func (f noteFirst) RoundTrip(r *http.Request) (*http.Response, error) {
	f()
	return http.DefaultTransport.RoundTrip(r)
}
