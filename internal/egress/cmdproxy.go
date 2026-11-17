package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/scope"
)

// CmdScope is what a command's proxy holds its requests to while it runs.
// Its fields replace the policy's own for that time (a sign-in sent before
// any run has set them) and are put back when the proxy closes.
type CmdScope struct {
	Allow       func(host string) bool
	AllowAddr   func(host, port string) bool
	DenyPath    func(raw string) string
	TargetPorts map[string]map[string]bool
	// Capped says the command's requests have a budget of their own, Left
	// requests: zero left refuses every one.
	Capped bool
	Left   int64
}

// CmdProxy is a forward proxy on loopback that a helper command (a
// -role-cmd) sends through, so that what it requests is azhaq's: the scope,
// the budget, the pace and the ledger hold it as they hold the run's own.
// A plain HTTP request goes through a target client, as the run's own do,
// and is listed with its method and URL; HTTPS is a CONNECT, held to the
// scope by host and port and listed as CONNECT host:port, then a byte
// tunnel nothing reads. A request that skips the proxy variables skips all
// of it.
type CmdProxy struct {
	role      string
	collector string
	pol       *Policy
	ln        net.Listener
	srv       *http.Server
	client    *http.Client
	ctx       context.Context
	stop      context.CancelFunc
	restore   func()
	before    int64
	spent     bool
	wg        sync.WaitGroup

	mu      sync.Mutex
	refused []error
	n       int64
	closed  bool
}

// StartCmdProxy starts the proxy of role's command; Close ends it. The
// caller sends nothing else to targets until then.
func StartCmdProxy(role string, s CmdScope) (*CmdProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := Current()
	cp := &CmdProxy{role: role, collector: "role-cmd:" + role, pol: p, ln: ln, spent: s.Capped && s.Left <= 0}
	cp.ctx, cp.stop = context.WithCancel(context.Background())
	cp.client = TargetClient(TargetOptions{})
	cp.restore = p.holdFor(s)
	cp.before = p.Total()
	cp.srv = &http.Server{Handler: cp, ReadHeaderTimeout: 15 * time.Second}
	cp.wg.Add(1)
	go func() {
		defer cp.wg.Done()
		_ = cp.srv.Serve(ln)
	}()
	return cp, nil
}

// holdFor sets the scope, the -deny-path rule and, when the command is
// capped, a cap of Left more requests; the func it returns puts back what was.
func (p *Policy) holdFor(s CmdScope) (restore func()) {
	p.mu.Lock()
	allow, allowAddr, open, deny, ports := p.allow, p.allowAddr, p.openHeaders, p.denyPath, p.targetPorts
	p.allow, p.allowAddr, p.openHeaders, p.denyPath, p.targetPorts = s.Allow, s.AllowAddr, nil, s.DenyPath, s.TargetPorts
	p.mu.Unlock()
	oldMax := p.maxReq.Load()
	if s.Capped && s.Left > 0 {
		if cap := p.sent.Load() + s.Left; oldMax <= 0 || cap < oldMax {
			p.maxReq.Store(cap)
		}
	}
	return func() {
		p.mu.Lock()
		p.allow, p.allowAddr, p.openHeaders, p.denyPath, p.targetPorts = allow, allowAddr, open, deny, ports
		p.mu.Unlock()
		p.maxReq.Store(oldMax)
	}
}

// Addr is the proxy's address, host:port.
func (cp *CmdProxy) Addr() string { return cp.ln.Addr().String() }

// proxyVars are the variables that send a program through a proxy, and the
// ones that exempt hosts from it.
var proxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

// Env is env with the proxy variables pointing at this proxy, upper and
// lower case, and NO_PROXY emptied: the command's own exemptions would send
// a request round it, and a program that skips the proxy for loopback by its
// own rule (Go's) still does.
func (cp *CmdProxy) Env(env []string) []string {
	out := make([]string, 0, len(env)+8)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, v := range proxyVars {
			if strings.EqualFold(k, v) {
				drop = true
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	u := "http://" + cp.Addr()
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		out = append(out, v+"="+u, strings.ToLower(v)+"="+u)
	}
	return append(out, "NO_PROXY=", "no_proxy=")
}

// Close ends the proxy and the tunnels it relays, waits for them, and puts
// the policy's scope back.
func (cp *CmdProxy) Close() {
	cp.mu.Lock()
	if cp.closed {
		cp.mu.Unlock()
		return
	}
	cp.closed = true
	cp.mu.Unlock()
	cp.stop()
	_ = cp.srv.Close()
	_ = cp.ln.Close()
	cp.wg.Wait()
	cp.n = cp.pol.Total() - cp.before
	cp.restore()
	cp.client.CloseIdleConnections()
}

// Requests is how many requests and tunnels the command's proxy sent and
// counted, once it is closed: what the summary's requests hold of them.
func (cp *CmdProxy) Requests() int64 {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.n
}

// Refused is why the proxy refused the first request it did, nil when it
// refused none: the command asked for something the run holds back, and its
// sign-in is not to be taken for done. errors.Is sees the reason (the scope,
// the budget, the kill file).
func (cp *CmdProxy) Refused() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.refused) == 0 {
		return nil
	}
	err := cp.refused[0]
	if n := len(cp.refused); n > 1 {
		return fmt.Errorf("%w (and %d more refused)", err, n-1)
	}
	return err
}

func (cp *CmdProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cp.mu.Lock()
	if cp.closed {
		cp.mu.Unlock()
		http.Error(w, "azhaq: the proxy of this command has ended", http.StatusServiceUnavailable)
		return
	}
	cp.wg.Add(1)
	cp.mu.Unlock()
	defer cp.wg.Done()
	if r.Method == http.MethodConnect {
		cp.connect(w, r)
		return
	}
	cp.forward(w, r)
}

// isRefusal says err is the run's controls holding a request back, not a
// network failure.
func isRefusal(err error) bool {
	for _, e := range []error{neterr.ErrOutOfScope, neterr.ErrDenied, neterr.ErrBudget, neterr.ErrKilled, neterr.ErrNotRepeated} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// refuse answers a request the controls hold back: 403 for the scope and
// -deny-path, 429 for the budget, 503 for the kill file, with the reason in
// the body, and keeps it for the command's sign-in to fail with.
func (cp *CmdProxy) refuse(w http.ResponseWriter, what string, err error) {
	cp.mu.Lock()
	cp.refused = append(cp.refused, fmt.Errorf("%s: %w", what, err))
	cp.mu.Unlock()
	code, note := http.StatusForbidden, ""
	switch {
	case errors.Is(err, neterr.ErrKilled):
		code = http.StatusServiceUnavailable
	case errors.Is(err, neterr.ErrBudget):
		code = http.StatusTooManyRequests
	case errors.Is(err, neterr.ErrOutOfScope):
		note = " (a -role-cmd command may reach what the run's scope names, hosts and ports)"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, "azhaq refused %s: %v%s\n", what, err, note)
}

func (cp *CmdProxy) fail(w http.ResponseWriter, what string, err error) {
	http.Error(w, "azhaq could not send "+what+": "+err.Error(), http.StatusBadGateway)
}

// hopHeaders are the headers that belong to one connection, not to the
// request or the answer.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func dropHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// maxCmdBody caps a request body the proxy keeps to hash for the ledger.
const maxCmdBody = 8 << 20

func (cp *CmdProxy) ctxFor(r *http.Request) context.Context {
	return ledger.WithCollector(Unwatched(r.Context()), cp.collector)
}

// forward sends a plain request through the run's target client: the scope
// (host, port, Host header, headers naming a host), -deny-path, the budget,
// the pace, -proxy and the ledger are those of the run's own requests.
func (cp *CmdProxy) forward(w http.ResponseWriter, r *http.Request) {
	u := r.URL
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "azhaq: this is the forward proxy of a -role-cmd command: it takes absolute URLs and CONNECT", http.StatusBadRequest)
		return
	}
	what := r.Method + " " + u.Redacted()
	if cp.spent {
		cp.refuse(w, what, neterr.ErrBudget)
		return
	}
	if err := cp.pol.CheckAddr(u.Hostname(), scope.URLPort(u)); err != nil {
		cp.refuse(w, what, err)
		return
	}
	ctx := cp.ctxFor(r)
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		if body, err = io.ReadAll(io.LimitReader(r.Body, maxCmdBody+1)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > maxCmdBody {
			http.Error(w, "azhaq: a request body over 8 MiB is not sent for a -role-cmd command", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if err := cp.pol.SpendCounted(ctx, true); err != nil {
		cp.refuse(w, what, err)
		return
	}
	var rd io.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	out, err := http.NewRequestWithContext(ctx, r.Method, u.String(), rd)
	if err != nil {
		cp.pol.Refund() // never sent
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out.Header = r.Header.Clone()
	dropHop(out.Header)
	out.Host = r.Host
	resp, err := cp.client.Do(out)
	if err != nil {
		if isRefusal(err) {
			cp.refuse(w, what, err)
		} else {
			cp.fail(w, what, err)
		}
		return
	}
	defer resp.Body.Close()
	dropHop(resp.Header)
	h := w.Header()
	for k, vs := range resp.Header {
		h[k] = vs
	}
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// connect opens a tunnel: held to the scope by host and port, counted and
// paced, listed as CONNECT host:port, then the bytes go both ways unread.
// It goes through -proxy as the run's own HTTPS requests do.
func (cp *CmdProxy) connect(w http.ResponseWriter, r *http.Request) {
	addr := r.Host
	if addr == "" {
		addr = r.URL.Host
	}
	what := "CONNECT " + addr
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		http.Error(w, "azhaq: CONNECT takes host:port", http.StatusBadRequest)
		return
	}
	if cp.spent {
		cp.refuse(w, what, neterr.ErrBudget)
		return
	}
	if err := cp.pol.CheckAddr(host, port); err != nil {
		cp.refuse(w, what, err)
		return
	}
	ctx := cp.ctxFor(r)
	if err := cp.pol.SpendCounted(ctx, true); err != nil {
		cp.refuse(w, what, err)
		return
	}
	ledger.Connect(ctx, host, port)
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	via, err := upstream("https", addr, nil)
	var up net.Conn
	if err == nil {
		up, err = dialOut(dctx, via, addr)
	}
	cancel()
	if err != nil {
		if isRefusal(err) {
			cp.refuse(w, what, err)
		} else {
			cp.fail(w, what, err)
		}
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "azhaq: cannot tunnel on this connection", http.StatusInternalServerError)
		return
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	defer c.Close()
	defer up.Close()
	stop := context.AfterFunc(cp.ctx, func() { _ = c.Close(); _ = up.Close() })
	defer stop()
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		var src io.Reader = c
		if n := brw.Reader.Buffered(); n > 0 { // bytes the client sent behind the CONNECT
			src = io.MultiReader(io.LimitReader(brw.Reader, int64(n)), c)
		}
		_, _ = io.Copy(up, src)
		closeWrite(up)
		close(done)
	}()
	_, _ = io.Copy(c, up)
	closeWrite(c)
	<-done
}
