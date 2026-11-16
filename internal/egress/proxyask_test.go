package egress

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// sendAll is a proxy that forwards every request it gets, the one addressed
// to it included, to one upstream, and notes when each arrived.
type sendAll struct {
	*httptest.Server
	mu sync.Mutex
	at []time.Time
	to []string
}

func newSendAll(t *testing.T) *sendAll {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "page") }))
	t.Cleanup(up.Close)
	p := &sendAll{}
	tr := &http.Transport{Proxy: nil}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.at, p.to = append(p.at, time.Now()), append(p.to, r.URL.Host)
		p.mu.Unlock()
		out, _ := http.NewRequestWithContext(r.Context(), r.Method, up.URL+r.URL.RequestURI(), nil)
		resp, err := tr.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *sendAll) seen() (at []time.Time, to []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Time(nil), p.at...), append([]string(nil), p.to...)
}

// sendOne counts a request as a sender does (Spend), then sends it through
// -proxy.
func sendOne(t *testing.T, c *http.Client) error {
	t.Helper()
	if err := Spend(t.Context()); err != nil {
		return err
	}
	resp, err := c.Get("http://target.test/x")
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// The ask is one more request: it spends from the budget, so the proxy's
// count is the run's.
func TestTheProxyAskSpendsFromTheBudget(t *testing.T) {
	Reset()
	defer Reset()
	px := newSendAll(t)
	pu, _ := url.Parse(px.URL)
	SetTargetProxy(pu)
	SetMaxRequests(3)
	c := TargetClient(TargetOptions{Timeout: 5 * time.Second})
	for i := 0; i < 2; i++ {
		if err := sendOne(t, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := sendOne(t, c); !errors.Is(err, neterr.ErrBudget) {
		t.Errorf("a third target request after the ask: %v, want the budget refusal", err)
	}
	if _, to := px.seen(); len(to) != 3 || Sent() != 3 {
		t.Errorf("the proxy forwarded %d requests and the run counts %d: want 3 (the ask and two) each", len(to), Sent())
	}
	if ProxyUnasked() {
		t.Error("the proxy was asked")
	}
	if n := ProxyAskNote(); n == "" {
		t.Error("the ask is not named")
	}
}

// With the budget spent by the request itself, the proxy is not asked: it
// counts as one that could not be asked.
func TestTheProxyIsNotAskedWithTheBudgetSpent(t *testing.T) {
	Reset()
	defer Reset()
	px := newSendAll(t)
	pu, _ := url.Parse(px.URL)
	SetTargetProxy(pu)
	SetMaxRequests(1)
	if err := sendOne(t, TargetClient(TargetOptions{Timeout: 5 * time.Second})); err != nil {
		t.Fatal(err)
	}
	if _, to := px.seen(); len(to) != 1 || Sent() != 1 {
		t.Errorf("the proxy forwarded %d requests and the run counts %d: want 1 each", len(to), Sent())
	}
	if !ProxyUnasked() || ProxyAskNote() != "" {
		t.Errorf("unasked %v, ask note %q: want a proxy marked as not asked and no ask named", ProxyUnasked(), ProxyAskNote())
	}
}

// The ask waits for the pace like a request, and the first target request
// waits after it.
func TestTheProxyAskIsPaced(t *testing.T) {
	Reset()
	defer Reset()
	px := newSendAll(t)
	pu, _ := url.Parse(px.URL)
	SetTargetProxy(pu)
	SetRate(5)
	c := TargetClient(TargetOptions{Timeout: 5 * time.Second})
	for i := 0; i < 2; i++ {
		if err := sendOne(t, c); err != nil {
			t.Fatal(err)
		}
	}
	at, to := px.seen()
	if len(at) != 3 || to[0] != "" {
		t.Fatalf("the proxy saw %q: want its own ask first, then two requests", to)
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < 150*time.Millisecond {
			t.Errorf("request %d came %v after the one before at 5 a second", i, gap)
		}
	}
}

// Commands that run others in turn ask once: a reset between the runs keeps
// the answer for the same proxy, and a different proxy is asked.
func TestAnAskSharedBetweenRunsIsMadeOnce(t *testing.T) {
	Reset()
	defer Reset()
	ShareProxyAsk(true)
	defer ShareProxyAsk(false)
	px := newSendAll(t)
	pu, _ := url.Parse(px.URL)
	for i := 0; i < 3; i++ {
		Reset()
		SetTargetProxy(pu)
		if err := sendOne(t, TargetClient(TargetOptions{Timeout: 5 * time.Second})); err != nil {
			t.Fatal(err)
		}
	}
	other := newSendAll(t)
	ou, _ := url.Parse(other.URL)
	SetTargetProxy(ou)
	if err := sendOne(t, TargetClient(TargetOptions{Timeout: 5 * time.Second})); err != nil {
		t.Fatal(err)
	}
	if _, to := px.seen(); len(to) != 4 || to[0] != "" {
		t.Errorf("the proxy saw %q: want one ask and three requests", to)
	}
	if _, to := other.seen(); len(to) != 2 || to[0] != "" {
		t.Errorf("the other proxy saw %q: want its own ask and the request", to)
	}
}
