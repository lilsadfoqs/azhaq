package egress

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/scope"
)

// Class is what a request or connection is sent to.
type Class string

const (
	// Target: a host the run was pointed at. Held to the scope, -deny-path,
	// the budget, the pace and -proxy.
	Target Class = ledger.ClassTarget
	// Source: a third party asked about the targets (archives, RDAP,
	// search, a notification). Not held to the target scope; held to the
	// kill file and its own proxy, and recorded.
	Source Class = ledger.ClassSource
	// DNS: a resolver.
	DNS Class = ledger.ClassDNS
	// Own: an endpoint of the user's own (a replay proxy, a worker's link to
	// its run, where -seal-to posts). Not a target and not recorded: the
	// ledger holds what was sent about targets.
	Own Class = ledger.ClassOwn
)

// Policy is the controls of one run. There is one in use at a time
// (Current); the CLI builds it from the flags before anything is sent.
type Policy struct {
	mu          sync.RWMutex
	allow       func(host string) bool
	allowAddr   func(host, port string) bool // allow for a connection to a port; nil: allow's answer for the host
	targetPorts map[string]map[string]bool   // no rule: a URL target's host and the ports the targets give it; others unheld
	openHeaders map[string]bool
	denyPath    func(raw string) string
	word        func(raw string) string // the word a URL's own name declares as a state change; nil: none is looked for
	holding     bool                    // the GETs word names are held back
	asked       func(raw string) bool   // the user gave raw as a target: never held
	declared    sync.Map                // normalized URL -> the word an API description's operation declares for it
	nDeclared   atomic.Int64
	sentKeys    sync.Map // the keys of watched URLs that were sent
	onDenied    func(raw, rule string)
	onPort      func(raw, reason string) // hears of a URL kept out for its port
	proxy       *url.URL
	resolver    func(ctx context.Context, host string) []string
	only        bool // the resolver is the only one: a name it cannot answer is not looked up elsewhere

	maxReq atomic.Int64
	sent   atomic.Int64
	dnsq   atomic.Int64 // DNS queries sent to resolvers: the dns lines the ledger records
	dnsAll atomic.Int64 // what dnsq held when Reset last put it back to zero, summed
	// reserve is the requests set aside for web work already known (Reserve):
	// a port sweep does not spend them, and the web requests sent use them up.
	reserve atomic.Int64
	resv    reserves     // what each service holds of it (ReserveFor)
	gone    atomic.Int64 // what sent held when Reset last put it back to zero, summed
	held    atomic.Int64 // counted, and not yet known to have left (waiting for the pace, let go in Chrome)

	paceMu sync.Mutex
	pace   *rate.Limiter
	paceR  float64

	kill
}

// Config is what a Policy is built from. A zero Config holds nothing back.
type Config struct {
	// Allow says whether a target host is in scope; nil: every host is.
	Allow func(host string) bool
	// OpenHeaders are host-naming headers (lower case) that are not held to
	// Allow: the user typed what they name.
	OpenHeaders map[string]bool
	// DenyPath returns the -deny-path rule a URL matches, or "".
	DenyPath func(raw string) string
	// OnDenied hears of each request DenyPath kept out.
	OnDenied func(raw, rule string)
	// MaxRequests caps the requests to targets; zero is no cap.
	MaxRequests int64
	// Rate paces the requests to targets, per second over all hosts.
	Rate float64
	// TargetProxy is where every request to a target goes (-proxy); nil: the
	// environment's.
	TargetProxy *url.URL
	// Resolver gives the addresses to connect to for a name; nil: the system's.
	Resolver func(ctx context.Context, host string) []string
	// ResolverOnly: a name Resolver has no address for is not connected to;
	// the system's resolver is not asked in its place.
	ResolverOnly bool
}

// New is a Policy holding what cfg says.
func New(cfg Config) *Policy {
	p := &Policy{}
	p.allow, p.openHeaders, p.denyPath, p.onDenied = cfg.Allow, cfg.OpenHeaders, cfg.DenyPath, cfg.OnDenied
	p.proxy, p.resolver, p.only = cfg.TargetProxy, cfg.Resolver, cfg.ResolverOnly
	p.maxReq.Store(cfg.MaxRequests)
	p.SetRate(cfg.Rate)
	return p
}

var current atomic.Pointer[Policy]

func init() {
	current.Store(New(Config{}))
	ledger.Unsent = Refund
	ledger.Deny = CheckDenied
	ledger.Hold = func(req *http.Request) error { return CheckHeld(req.Context(), req.Method, req.URL.String()) }
	ledger.OnSent = func(method, raw string) { Current().noteSent(method, raw) }
}

// Use makes p the policy of the run.
func Use(p *Policy) { current.Store(p) }

// Current is the policy in use: never nil.
func Current() *Policy { return current.Load() }

// Reset puts the policy in use back to holding nothing back, as a new run
// (or a test) starts. A kill file being watched stays watched.
func Reset() { Current().Reset() }

// Reset is Reset for p.
func (p *Policy) Reset() {
	p.mu.Lock()
	p.allow, p.allowAddr, p.openHeaders, p.denyPath, p.onDenied, p.onPort, p.proxy, p.resolver, p.only = nil, nil, nil, nil, nil, nil, nil, nil, false
	p.targetPorts = nil
	p.word, p.asked, p.holding = nil, nil, false
	p.sentKeys.Clear()
	p.declared.Clear()
	p.nDeclared.Store(0)
	p.mu.Unlock()
	p.resv.clear()
	p.maxReq.Store(0)
	p.gone.Add(p.sent.Swap(0))
	p.dnsAll.Add(p.dnsq.Swap(0))
	p.held.Store(0)
	p.reserve.Store(0)
	p.SetRate(0)
}

// SetScope sets which target hosts are in scope; nil lifts the scope.
func (p *Policy) SetScope(allow func(host string) bool, open map[string]bool) {
	p.mu.Lock()
	p.allow, p.allowAddr, p.openHeaders = allow, nil, open
	p.mu.Unlock()
}

// SetScopeAddr makes the scope hold a connection to its port as well: an
// -allow entry written HOST:PORT allows that port only. Call it after SetScope,
// which clears it.
func (p *Policy) SetScopeAddr(allow func(host, port string) bool) {
	p.mu.Lock()
	p.allowAddr = allow
	p.mu.Unlock()
}

// SetTargetPorts holds the hosts it names to the ports it gives them, as the
// URL targets of a run with no rule do (scope.TargetPorts). It is not a scope:
// a host it does not name, and any host with no rule, is judged as before.
func (p *Policy) SetTargetPorts(m map[string]map[string]bool) {
	p.mu.Lock()
	p.targetPorts = m
	p.mu.Unlock()
}

// heldByTargets says the targets name host with other ports than port.
func (p *Policy) heldByTargets(host, port string) bool {
	p.mu.RLock()
	m := p.targetPorts
	p.mu.RUnlock()
	if len(m) == 0 || port == "" {
		return false
	}
	ports, ok := m[normalize.Hostname(host)]
	return ok && !ports[port]
}

// namedByTargets says the targets hold host to ports.
func (p *Policy) namedByTargets(host string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.targetPorts[normalize.Hostname(host)] != nil
}

// PortReason is why a URL on a host in scope is left out for its port, and the
// error to refuse it with.
func (p *Policy) PortReason(host, port string) (string, error) {
	if p.heldByTargets(host, port) {
		return neterr.OutOfTargetPortReason, neterr.ErrOutOfTargetPort
	}
	return neterr.OutOfPortReason, neterr.ErrOutOfPort
}

// SetDenyPath sets the user's -deny-path rules; nil lifts them.
func (p *Policy) SetDenyPath(f func(raw string) string) {
	p.mu.Lock()
	p.denyPath = f
	p.mu.Unlock()
}

// SetOnDenied sets who hears of a request -deny-path kept out; nil: the run's notes.
func (p *Policy) SetOnDenied(f func(raw, rule string)) {
	p.mu.Lock()
	p.onDenied = f
	p.mu.Unlock()
}

// SetOnPortSkip sets who hears of a URL found on a host that is in scope on
// another port only (-allow HOST:PORT), and so left out; nil: the run's notes.
func (p *Policy) SetOnPortSkip(f func(raw, reason string)) {
	p.mu.Lock()
	p.onPort = f
	p.mu.Unlock()
}

// NotePortSkip tells the run about a URL it leaves out because -allow lists
// its host with another port only, when that is why. A URL outside the scope
// by its host is left out as before, without a word.
func (p *Policy) NotePortSkip(raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || p.AllowsAddr(u.Hostname(), scope.URLPort(u)) || !p.Allows(u.Hostname()) {
		return
	}
	reason, _ := p.PortReason(u.Hostname(), scope.URLPort(u))
	p.mu.RLock()
	f := p.onPort
	p.mu.RUnlock()
	switch {
	case f != nil:
		f(raw, reason)
	case Noter != nil:
		Noter(raw + " was not requested: " + reason)
	}
}

// SetTargetProxy sets the proxy for every request to a target (-proxy).
func (p *Policy) SetTargetProxy(u *url.URL) {
	p.mu.Lock()
	p.proxy = u
	p.mu.Unlock()
}

// SetResolver sets the run's resolver; nil goes back to the system's. It
// is swapped whole: a request a finished run left behind may still dial
// while the next run sets it.
func (p *Policy) SetResolver(f func(ctx context.Context, host string) []string) {
	p.mu.Lock()
	p.resolver = f
	p.mu.Unlock()
}

// SetResolverOnly says the run's resolver is the only one (the user named
// resolvers): a name it has no address for fails to connect instead of
// going to the system's resolver.
func (p *Policy) SetResolverOnly(on bool) {
	p.mu.Lock()
	p.only = on
	p.mu.Unlock()
}

func (p *Policy) resolverOnly() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.only
}

func (p *Policy) scope() (func(string) bool, map[string]bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.allow, p.openHeaders
}

// Scope is the run's scope, nil when it has none.
func (p *Policy) Scope() func(host string) bool {
	a, _ := p.scope()
	return a
}

// ScopeAddr is the run's scope for a connection to a port, nil when it has
// none; a scope that names no ports judges the host alone.
func (p *Policy) ScopeAddr() func(host, port string) bool {
	p.mu.RLock()
	a, f, t := p.allow, p.allowAddr, len(p.targetPorts) > 0
	p.mu.RUnlock()
	switch {
	case a == nil && !t:
		return nil
	case a == nil:
		return func(host, port string) bool { return !p.heldByTargets(host, port) }
	case f != nil:
		return func(host, port string) bool {
			if port == "" {
				return a(host)
			}
			return f(host, port) && !p.heldByTargets(host, port)
		}
	}
	return func(host, port string) bool { return a(host) && !p.heldByTargets(host, port) }
}

// Allows says whether a target host is in scope: always without a scope.
func (p *Policy) Allows(host string) bool {
	a, _ := p.scope()
	return a == nil || a(host)
}

// AllowsAddr says whether a connection to host on port is in scope: the host
// is, and the -allow entry for it names no other port. A port "" is
// unknown, and the host alone is judged.
func (p *Policy) AllowsAddr(host, port string) bool {
	p.mu.RLock()
	a, f := p.allow, p.allowAddr
	p.mu.RUnlock()
	if p.heldByTargets(host, port) {
		return false
	}
	switch {
	case a == nil:
		return true
	case f != nil && port != "":
		return f(host, port)
	}
	return a(host)
}

// CheckAddr is nil for a connection to host on port the scope allows, else
// the error to refuse it with: neterr.ErrOutOfPort when the host is in scope
// on another port, neterr.ErrOutOfScope otherwise.
func (p *Policy) CheckAddr(host, port string) error {
	if p.AllowsAddr(host, port) {
		return nil
	}
	if p.Allows(host) {
		_, err := p.PortReason(host, port)
		return err
	}
	return neterr.ErrOutOfScope
}

// TargetProxy is the proxy for requests to targets, nil for none.
func (p *Policy) TargetProxy() *url.URL {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.proxy
}

// ProxyFor sends a request to a target through -proxy, else as the
// environment says.
func (p *Policy) ProxyFor(r *http.Request) (*url.URL, error) {
	if u := p.TargetProxy(); u != nil {
		return u, nil
	}
	return http.ProxyFromEnvironment(r)
}

// Resolve is the run's answer for host, nil without a resolver.
func (p *Policy) Resolve(ctx context.Context, host string) []string {
	p.mu.RLock()
	f := p.resolver
	p.mu.RUnlock()
	if f != nil {
		return f(ctx, host)
	}
	return nil
}

// DeniedBy is the -deny-path rule that keeps raw out, or "".
func (p *Policy) DeniedBy(raw string) string {
	p.mu.RLock()
	f := p.denyPath
	p.mu.RUnlock()
	if f == nil {
		return ""
	}
	return f(raw)
}

// Noter, when set, takes a line for the run's summary: what -deny-path
// kept out when nothing is listening for it.
var Noter func(text string)

// CheckDenied is nil for a URL no -deny-path rule keeps out, else the error
// to refuse it with; it tells OnDenied. Nothing has been spent or sent.
func (p *Policy) CheckDenied(raw string) error {
	rule := p.DeniedBy(raw)
	if rule == "" {
		return nil
	}
	p.mu.RLock()
	f := p.onDenied
	p.mu.RUnlock()
	switch {
	case f != nil:
		f(raw, rule)
	case Noter != nil:
		Noter(raw + " was not requested: " + DenyReason(rule))
	}
	return &neterr.Denied{Rule: rule}
}

// DenyReason is how a rule is named in a list of what was not requested.
func DenyReason(rule string) string {
	if w, ok := neterr.HeldWord(rule); ok {
		return neterr.HeldReason(w)
	}
	return "-deny-path " + rule
}

// IsHeldReason says a reason from DenyReason names a held GET, not a rule.
func IsHeldReason(reason string) bool {
	// The older wording is read too: a workspace kept it in its skipped list.
	return strings.HasPrefix(reason, "a GET whose own name declares a state change") ||
		strings.HasPrefix(reason, "a GET found on the way whose own name declares a state change")
}

type askedKey struct{}

// WithAsked marks ctx: the caller has already decided which of the requests
// made with it are held back for what their own name declares (a wordlist
// sweep lists its held words), so the transport does not hold them again.
func WithAsked(ctx context.Context) context.Context {
	return context.WithValue(ctx, askedKey{}, true)
}

// SetStateWords has the policy look for the GETs and HEADs whose own name
// declares a state change: word returns the verb a URL's name declares, or
// "". Those sent are remembered (WasSent). With hold, they are also held
// back, unless the user gave the URL (asked) or the request is made with a
// WithAsked context. A nil word lifts all of it.
func (p *Policy) SetStateWords(word func(raw string) string, asked func(raw string) bool, hold bool) {
	p.mu.Lock()
	p.word, p.asked, p.holding = word, asked, hold
	p.mu.Unlock()
	p.sentKeys.Clear()
}

// Holding says the run holds back the GETs whose own name declares a state
// change (without -send-state-changing).
func (p *Policy) Holding() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.holding
}

// Declares is the word a GET of raw declares as a state change, by its path
// or by an API description's operation, or "".
func (p *Policy) Declares(raw string) string {
	p.mu.RLock()
	word := p.word
	p.mu.RUnlock()
	if word == nil {
		return ""
	}
	if w := word(raw); w != "" {
		return w
	}
	if p.nDeclared.Load() > 0 {
		if n, err := normalize.URL(raw); err == nil {
			if v, ok := p.declared.Load(n); ok {
				return v.(string)
			}
		}
	}
	return ""
}

// DeclareStateChange records that an API description's operation names this
// GET as one that changes state (by its operationId or summary: the path
// alone is read from the URL). raw is a normalized URL.
func (p *Policy) DeclareStateChange(raw, word string) {
	if _, dup := p.declared.LoadOrStore(raw, word); !dup {
		p.nDeclared.Add(1)
	}
}

// HeldWord is the word that makes a GET of raw held back, or "": what
// CheckHeld would refuse it for, without the context.
func (p *Policy) HeldWord(raw string) string {
	p.mu.RLock()
	hold, asked := p.holding, p.asked
	p.mu.RUnlock()
	if !hold {
		return ""
	}
	w := p.Declares(raw)
	if w == "" || asked != nil && asked(raw) {
		return ""
	}
	return w
}

// CheckHeld is nil for a request that is not held back, else the error to
// refuse it with; it tells OnDenied. Nothing has been spent or sent.
func (p *Policy) CheckHeld(ctx context.Context, method, raw string) error {
	if method != "" && method != http.MethodGet && method != http.MethodHead {
		return nil
	}
	if ctx != nil {
		if ok, _ := ctx.Value(askedKey{}).(bool); ok {
			return nil
		}
	}
	w := p.HeldWord(raw)
	if w == "" {
		return nil
	}
	rule := neterr.HeldRule(w)
	p.mu.RLock()
	f := p.onDenied
	p.mu.RUnlock()
	switch {
	case f != nil:
		f(raw, rule)
	case Noter != nil:
		Noter(raw + " was not requested: " + DenyReason(rule))
	}
	return &neterr.Denied{Rule: rule}
}

// noteSent remembers a GET to a target whose name declares a state change:
// the requests heard are the ones the ledger records, so WasSent says what
// the ledger holds.
func (p *Policy) noteSent(method, raw string) {
	if method != "" && method != http.MethodGet {
		return
	}
	if p.Declares(raw) == "" {
		return
	}
	if n, err := normalize.URL(raw); err == nil {
		p.sentKeys.Store(n, true)
	}
}

// WasSent says a GET of the normalized URL was recorded as sent, among the
// URLs whose names declare a state change.
func (p *Policy) WasSent(key string) bool {
	_, ok := p.sentKeys.Load(key)
	return ok
}

// Package-level forms for the policy in use.

// SetScope is Current().SetScope with no open headers.
func SetScope(allow func(host string) bool) { Current().SetScope(allow, nil) }

// HasScope says the run has a scope.
func HasScope() bool { return Current().Scope() != nil }

// Allows is Current().Allows.
func Allows(host string) bool { return Current().Allows(host) }

// SetTargetPorts is Current().SetTargetPorts.
func SetTargetPorts(m map[string]map[string]bool) { Current().SetTargetPorts(m) }

// SetScopeAddr is Current().SetScopeAddr.
func SetScopeAddr(allow func(host, port string) bool) { Current().SetScopeAddr(allow) }

// AllowsAddr is Current().AllowsAddr.
func AllowsAddr(host, port string) bool { return Current().AllowsAddr(host, port) }

// AllowsURL says whether a request to raw is in scope, its port included: the
// one it names, else its scheme's. A URL with no host is not held back.
func AllowsURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return true
	}
	return Current().AllowsAddr(u.Hostname(), scope.URLPort(u))
}

// DeniedBy is Current().DeniedBy.
func DeniedBy(raw string) string { return Current().DeniedBy(raw) }

// CheckDenied is Current().CheckDenied.
func CheckDenied(raw string) error { return Current().CheckDenied(raw) }

// NotePortSkip is Current().NotePortSkip.
func NotePortSkip(raw string) { Current().NotePortSkip(raw) }

// SetOnPortSkip is Current().SetOnPortSkip.
func SetOnPortSkip(f func(raw, reason string)) { Current().SetOnPortSkip(f) }

// SetOnDenied is Current().SetOnDenied.
func SetOnDenied(f func(raw, rule string)) { Current().SetOnDenied(f) }

// SetStateWords is Current().SetStateWords.
func SetStateWords(word func(raw string) string, asked func(raw string) bool, hold bool) {
	Current().SetStateWords(word, asked, hold)
}

// Declares is Current().Declares.
func Declares(raw string) string { return Current().Declares(raw) }

// DeclareStateChange is Current().DeclareStateChange.
func DeclareStateChange(raw, word string) { Current().DeclareStateChange(raw, word) }

// HeldWord is Current().HeldWord.
func HeldWord(raw string) string { return Current().HeldWord(raw) }

// CheckHeld is Current().CheckHeld.
func CheckHeld(ctx context.Context, method, raw string) error {
	return Current().CheckHeld(ctx, method, raw)
}

// WasSent is Current().WasSent.
func WasSent(key string) bool { return Current().WasSent(key) }

// SetDenyPath is Current().SetDenyPath.
func SetDenyPath(f func(raw string) string) { Current().SetDenyPath(f) }

// SetTargetProxy is Current().SetTargetProxy.
func SetTargetProxy(u *url.URL) { Current().SetTargetProxy(u) }

// TargetProxy is Current().TargetProxy.
func TargetProxy() *url.URL { return Current().TargetProxy() }

// ProxyFor is Current().ProxyFor.
func ProxyFor(r *http.Request) (*url.URL, error) { return Current().ProxyFor(r) }

// SetResolver is Current().SetResolver.
func SetResolver(f func(ctx context.Context, host string) []string) { Current().SetResolver(f) }

// SetResolverOnly is Current().SetResolverOnly.
func SetResolverOnly(on bool) { Current().SetResolverOnly(on) }

// Resolve is Current().Resolve.
func Resolve(ctx context.Context, host string) []string { return Current().Resolve(ctx, host) }
