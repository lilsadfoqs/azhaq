// Package dnsr resolves names through a pool of recursive resolvers, with a
// rate limit per resolver, retries on another resolver, and wildcard
// detection per zone.
package dnsr

import (
	"context"
	"errors"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/limit"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
)

// DefaultResolvers are used when none are configured: three operators,
// two addresses each, in pairs (pick asks half the list away for a
// second opinion, so it lands on another operator).
var DefaultResolvers = []string{
	"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
}

// Status values of an Answer.
const (
	StatusOK       = "ok"       // A or AAAA records
	StatusCNAME    = "cname"    // a CNAME chain that ends without an address
	StatusNoData   = "nodata"   // the name exists but has no address
	StatusNXDomain = "nxdomain" // the name does not exist
	StatusReserved = "reserved" // special-use name (.test, .local, …); not queried
	StatusFailed   = "failed"   // every resolver tried failed or timed out
	// StatusBroken: every attempt, on two passes, was answered SERVFAIL,
	// by two resolvers or more. They answered alike: the name's own DNS
	// is broken (a lame delegation, dead name servers) for everyone. A
	// REFUSED is the resolver refusing this machine, and one resolver
	// alone may be the broken one: both stay failures.
	StatusBroken = "servfail"
)

// errBroken: every attempt was answered SERVFAIL, by two resolvers or
// more.
var errBroken = errors.New("SERVFAIL from every resolver asked")

// queryError is the last resolver's failure, naming it; its text is the
// failure's own.
type queryError struct {
	server string
	err    error
}

func (e *queryError) Error() string { return e.err.Error() }
func (e *queryError) Unwrap() error { return e.err }

// FailedResolver names the resolver whose failure err is, or "".
func FailedResolver(err error) string {
	var q *queryError
	if errors.As(err, &q) {
		return q.server
	}
	return ""
}

// IsBroken says whether err is the SERVFAIL of every attempt, by two
// resolvers or more: the name's own DNS is broken, for everyone.
func IsBroken(err error) bool { return errors.Is(err, errBroken) }

// Answer is what a name resolved to.
type Answer struct {
	Name   string
	A      []string
	AAAA   []string
	CNAME  []string // the chain, first hop first
	Status string
	Err    string
	// Resolver is the one that failed last, when Status is failed: the
	// resolver a reader looks at (a timeout, a REFUSED for this machine).
	Resolver string
}

// Live is true when the name has an address.
func (a Answer) Live() bool { return len(a.A)+len(a.AAAA) > 0 }

// IPs are the A and AAAA addresses.
func (a Answer) IPs() []string { return append(append([]string(nil), a.A...), a.AAAA...) }

// Pool resolves names. It is safe for concurrent use and caches each name
// for the life of the pool.
type Pool struct {
	servers []string
	health  map[string]*health // fixed at New: read without p.mu
	limit   *limit.Limiter
	timeout time.Duration
	retries int
	fixed   bool                 // the retries were asked for (-retry): generated names keep them
	paced   bool                 // PerSecond is set: the user's rate bounds the queries sent
	rate    float64              // PerSecond, for Window
	x       *egress.DNSExchanger // sends the queries: the only code here that opens a connection
	rtt     rtts                 // how long answers took, for when a query is late
	proto   map[string]Server    // by key
	named   bool                 // the resolvers were given, not the defaults
	next    atomic.Uint64

	// TraceRoots and TracePort replace RootServers and port 53 for Trace
	// (tests, a lab).
	TraceRoots []string
	TracePort  string

	// Outside says whether a domain is outside the run's scope; nil: the egress
	// scope's. Registered counts the questions it asks about such domains.
	Outside func(domain string) bool

	askMu   sync.Mutex
	asked   int      // registration questions about domains outside the scope
	askedAt []string // the first few of those domains

	mu    sync.Mutex
	cache map[string]*entry
	six   map[string]*entry // AAAA asked for names that have A records
	wild  map[string]bool   // zones that answer for any label (Wildcards)

	// Exchange replaces the network call (tests).
	Exchange func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error)
}

// health counts a resolver's recent attempts and the ones that got no
// answer, halved as they grow so it can recover.
type health struct {
	mu                  sync.Mutex
	tries, fails, skips int
	// nxAgree is how many NXDOMAIN answers in a row a second resolver
	// confirmed: a resolver that has been right so many times is asked for a
	// second opinion on one in auditEvery only, to catch it going wrong.
	nxAgree, nxSkips int
}

const (
	trustedAfter = 64 // confirmed NXDOMAINs in a row before the audit sampling starts
	auditEvery   = 16
)

// confirmNX says whether an NXDOMAIN this resolver gave needs a second
// opinion: always until it has been confirmed trustedAfter times in a row,
// then one in auditEvery; a disagreement starts the count again.
func (h *health) confirmNX() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nxAgree < trustedAfter {
		return true
	}
	h.nxSkips++
	return h.nxSkips%auditEvery == 0
}

func (h *health) nxResult(agreed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if agreed {
		h.nxAgree++
	} else {
		h.nxAgree = 0
	}
}

func (h *health) note(failed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tries++; failed {
		h.fails++
	}
	if h.tries >= 200 {
		h.tries, h.fails = h.tries/2, h.fails/2
	}
}

// sick: a third of its recent queries went unanswered. Quad9 drops about
// half the queries for names a CDN zone serves (2026-10-29), each costing a
// full timeout; the pool stops leaning on it.
func (h *health) sick() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tries >= 20 && h.fails*3 > h.tries
}

// pass says whether to pass a resolver over: it is sick, and this is not
// the one time in sixteen it is asked anyway, to show it is back.
func (h *health) pass() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tries < 20 || h.fails*3 <= h.tries {
		return false
	}
	h.skips++
	return h.skips%16 != 0
}

type entry struct {
	once sync.Once
	ans  Answer
}

// Options configure a Pool. Zero values take the defaults.
type Options struct {
	Resolvers []string      // as ParseResolvers gives them; default DefaultResolvers
	PerSecond float64       // queries per second per resolver; 0 is no pace but the callers' workers
	Burst     int           // queries a resolver may be sent at once after a pause; default a fifth of PerSecond, at least 1
	Timeout   time.Duration // per query; default 2s
	Retries   int           // extra attempts on other resolvers; default 2
	Attempts  int           // when set, attempts in all per query (Retries+1), as dnsx -retry
	Proxy     string        // socks5://host:port: every query goes through it, over TCP
}

// New returns a Pool.
func New(o Options) *Pool {
	servers := o.Resolvers
	named := len(servers) > 0
	if !named {
		servers = DefaultResolvers
	}
	var norm []string
	proto := map[string]Server{}
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		srv, err := ParseResolver(s)
		if err != nil {
			// Not a form ParseResolvers gives: a plain address, as before.
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			srv = Server{Key: s, Net: NetUDP, Addr: s}
		}
		if _, dup := proto[srv.Key]; !dup {
			norm = append(norm, srv.Key)
			proto[srv.Key] = srv
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	fixed := o.Retries != 0 || o.Attempts > 0
	if o.Retries == 0 {
		o.Retries = 2
	}
	if o.Attempts > 0 {
		o.Retries = o.Attempts - 1
	}
	hs := map[string]*health{}
	for _, s := range norm {
		hs[s] = &health{}
	}
	p := &Pool{
		servers: norm,
		health:  hs,
		proto:   proto,
		named:   named,
		limit:   limit.New(o.PerSecond, cmpBurst(o)),
		timeout: o.Timeout,
		retries: o.Retries,
		fixed:   fixed,
		paced:   o.PerSecond > 0,
		rate:    o.PerSecond,
		x:       egress.NewDNSExchanger(o.Timeout, o.Proxy),
		cache:   map[string]*entry{},
		six:     map[string]*entry{},
		wild:    map[string]bool{},
	}
	return p
}

// WindowSeconds is how many seconds of its rate a lookup that is not in a
// hurry holds in flight (see Window).
const WindowSeconds = 4

// Window is how many lookups a bulk caller that is not in a hurry (the
// guesses of subs -live) keeps in flight: up to most, and with a -dns-rate
// WindowSeconds of the pool's whole rate, at least 8, which keeps the rate
// used while answers take up to that long. A query that arrives meanwhile
// (a name a source gave) waits behind at most that many, not behind every
// guess of the batch, which would otherwise be queued at once.
func (p *Pool) Window(most int) int {
	if !p.paced {
		return most
	}
	w := int(math.Ceil(p.rate * float64(len(p.servers)) * WindowSeconds))
	return min(most, max(w, 8))
}

func cmpBurst(o Options) int {
	if o.Burst > 0 {
		return o.Burst
	}
	return max(1, int(o.PerSecond/5))
}

// ProxyError says whether proxy is a URL New can use for DNS.
func ProxyError(raw string) error { return egress.CheckDNSProxy(raw) }

// Reserved says whether name is one the pool does not send to its resolvers:
// a special-use name (localhost, *.test, *.local) or a single label, when the
// resolvers are the default public ones. The system's resolver answers
// those, so /etc/hosts and local DNS work and nothing local is asked of a
// public resolver. Resolvers the user named are asked for everything, as
// dnsx does.
func (p *Pool) Reserved(name string) bool {
	name = normalize.Hostname(name)
	return !p.named && net.ParseIP(name) == nil && (normalize.SpecialUse(name) || !strings.Contains(name, "."))
}

// System asks the system's resolver for the addresses of name.
func (p *Pool) System(ctx context.Context, name string) (a, aaaa []string) {
	r := p.system(ctx, normalize.Hostname(name))
	return r.A, r.AAAA
}

// Resolvers lists the servers in use.
func (p *Pool) Resolvers() []string { return append([]string(nil), p.servers...) }

// Resolve returns A, AAAA and the CNAME chain of name. AAAA is asked only
// when there is no A record.
func (p *Pool) Resolve(ctx context.Context, name string) Answer {
	name = normalize.Hostname(name)
	p.mu.Lock()
	e, ok := p.cache[name]
	if !ok {
		e = &entry{}
		p.cache[name] = e
	}
	p.mu.Unlock()
	e.once.Do(func() { e.ans = p.resolve(ctx, name) })
	return e.ans
}

// ResolveBoth is Resolve with the AAAA records of names that also have
// A records: what a connection needs on a network that prefers IPv6.
func (p *Pool) ResolveBoth(ctx context.Context, name string) Answer {
	a := p.Resolve(ctx, name)
	if len(a.A) == 0 || len(a.AAAA) > 0 || a.Status != StatusOK {
		return a
	}
	name = normalize.Hostname(name)
	p.mu.Lock()
	e, ok := p.six[name]
	if !ok {
		e = &entry{}
		p.six[name] = e
	}
	p.mu.Unlock()
	e.once.Do(func() {
		if m, err := p.Query(ctx, name, dns.TypeAAAA); err == nil && m.Rcode == dns.RcodeSuccess {
			e.ans.AAAA, _ = records(m, dns.TypeAAAA)
		}
	})
	a.AAAA = e.ans.AAAA
	return a
}

// minForPass is how many names a batch needs before a first pass with no
// answer at all is taken for dead resolvers.
const minForPass = 16

// retryProbe is how many of the names that failed the first pass the second
// pass asks first: when none of them is answered the rest are not asked.
const retryProbe = 16

// ResolveMany resolves names with up to workers queries in flight and
// returns answers in the same order. Names whose every attempt failed
// (timeouts, SERVFAIL under load) get a second pass at a quarter of the
// concurrency, so a burst of dropped queries does not lose names.
func (p *Pool) ResolveMany(ctx context.Context, names []string, workers int) []Answer {
	if workers <= 0 {
		workers = 64
	}
	out := p.resolveMany(ctx, names, workers)
	var again []string
	var at []int
	for i, a := range out {
		if (a.Status == StatusFailed || a.Status == StatusBroken) && ctx.Err() == nil {
			again = append(again, names[i])
			at = append(at, i)
		}
	}
	// When no name got an answer the resolvers are down, not loaded: a
	// second pass at a quarter of the speed would cost minutes and fail
	// alike. A resolver that answered some and dropped the rest is loaded
	// (public resolvers limit a busy client), and the slower pass is what
	// gets the rest.
	if len(names) >= minForPass && len(again) == len(names) {
		again, at = nil, nil
	}
	p.askAgain(ctx, again, at, out, max(workers/4, 4))
	return out
}

// askAgain is ResolveMany's second pass over the names at out[at[i]]. It
// asks retryProbe of them first, spread over the list and once each: when
// none of those is answered either, the zone's servers are not answering (a
// lame delegation, a dead name server) and the rest would fail alike, each
// at the cost of every attempt again; they keep the failure of the first
// pass. When one is answered, every name still failed is asked in full.
func (p *Pool) askAgain(ctx context.Context, names []string, at []int, out []Answer, workers int) {
	ask := func(ctx context.Context, idx []int) (answered int, failed []int) {
		batch := make([]string, len(idx))
		for j, i := range idx {
			batch[j] = names[i]
			p.forget(names[i])
		}
		for j, a := range p.resolveMany(ctx, batch, workers) {
			out[at[idx[j]]] = a
			if a.Status != StatusFailed && a.Status != StatusBroken {
				answered++
			} else {
				failed = append(failed, idx[j])
			}
		}
		return answered, failed
	}
	idx := make([]int, len(names))
	for i := range idx {
		idx[i] = i
	}
	if len(idx) <= retryProbe {
		ask(ctx, idx)
		return
	}
	inProbe := map[int]bool{}
	var probe, rest []int
	for k := 0; k < retryProbe; k++ {
		i := k * len(idx) / retryProbe
		inProbe[i] = true
		probe = append(probe, i)
	}
	for _, i := range idx {
		if !inProbe[i] {
			rest = append(rest, i)
		}
	}
	answered, failed := ask(once(ctx), probe)
	if answered > 0 {
		ask(ctx, append(rest, failed...))
	}
}

type onceKey struct{}

// once marks ctx for one attempt a query.
func once(ctx context.Context) context.Context { return context.WithValue(ctx, onceKey{}, true) }

// Registered says whether a registrable domain exists in DNS: its SOA is
// answered, or anything but NXDOMAIN is (a failure is taken as existing,
// so nothing is called free that may not be).
func (p *Pool) Registered(ctx context.Context, domain string) bool {
	p.noteAsk(domain)
	m, err := p.Query(ctx, domain, dns.TypeSOA)
	return err != nil || m.Rcode != dns.RcodeNameError
}

// noteAsk counts a question about a domain outside the scope.
func (p *Pool) noteAsk(domain string) {
	out := p.Outside
	if out == nil {
		out = func(d string) bool { return egress.HasScope() && !egress.Allows(d) }
	}
	if !out(domain) {
		return
	}
	p.askMu.Lock()
	defer p.askMu.Unlock()
	p.asked++
	if len(p.askedAt) < 3 && !slices.Contains(p.askedAt, domain) {
		p.askedAt = append(p.askedAt, domain)
	}
}

// TakeoverNote says how many questions the takeover check put to the
// resolvers about CNAME targets outside the scope, "" when none: asking the
// resolver is how the check tells a free domain from a taken one, and the
// user should be told it left the scope. off is the flag that turns the
// check off.
func (p *Pool) TakeoverNote(off string) string {
	p.askMu.Lock()
	defer p.askMu.Unlock()
	if p.asked == 0 {
		return ""
	}
	s := "s"
	if p.asked == 1 {
		s = ""
	}
	return fmt.Sprintf("asked the resolver about %d CNAME target%s outside the scope for the takeover check (%s): %s turns the check off",
		p.asked, s, strings.Join(p.askedAt, ", "), off)
}

// forget drops a cached answer so the next Resolve asks again.
func (p *Pool) forget(name string) {
	p.mu.Lock()
	delete(p.cache, normalize.Hostname(name))
	p.mu.Unlock()
}

func (p *Pool) resolveMany(ctx context.Context, names []string, workers int) []Answer {
	out := make([]Answer, len(names))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer guard.Recover(ctx)
			defer wg.Done()
			select {
			case <-ctx.Done():
				out[i] = Answer{Name: n, Status: StatusFailed, Err: ctx.Err().Error()}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			out[i] = p.Resolve(ctx, n)
			if fn, ok := ctx.Value(eachKey{}).(func(Answer)); ok {
				fn(out[i])
			}
		}(i, n)
	}
	wg.Wait()
	return out
}

func (p *Pool) resolve(ctx context.Context, name string) Answer {
	a := Answer{Name: name}
	if !p.named && (normalize.SpecialUse(name) || !strings.Contains(name, ".")) {
		// localhost, *.test, *.local, single labels: public resolvers do not
		// know them, but /etc/hosts or the local resolver may. Resolvers the
		// user named are asked for everything: the system's is never used.
		return p.system(ctx, name)
	}
	q := question(name, dns.TypeA)
	m, from, err := p.query(ctx, q, "")
	if err != nil {
		a.Status, a.Err, a.Resolver = StatusFailed, err.Error(), FailedResolver(err)
		if errors.Is(err, errBroken) {
			a.Status = StatusBroken
		}
		return a
	}
	// One resolver's NXDOMAIN or empty answer is not the name dead: a
	// public resolver answers NODATA now and then for a name every other
	// one resolves (a stale negative cache, an edge that lost the zone).
	// A second resolver is asked once before the name is called dead, and
	// its addresses win. Names under a wildcard zone and wildcard probes
	// are not worth the query: they answer alike everywhere.
	asked := false
	second := func() bool {
		if !p.confirms(name) {
			return false
		}
		asked = true
		m2, _, err := p.query(ctx, q, from)
		if err != nil || m2.Rcode != dns.RcodeSuccess {
			return false
		}
		if addrs, chain := records(m2, dns.TypeA); len(addrs) > 0 {
			a.A, a.CNAME = addrs, chain
			return true
		}
		return false
	}
	if m.Rcode == dns.RcodeNameError {
		// A generated name (DNS brute force, permutations) that one good
		// resolver says does not exist almost never exists, and confirming
		// every miss would double a wordlist's queries; a NODATA or a
		// dangling CNAME below is still confirmed.
		// A name that is no CNAME's target and that a resolver has been right
		// about trustedAfter times running is asked about once in auditEvery.
		_, chain := records(m, dns.TypeA)
		h := p.health[from]
		if !bulk(ctx) && (len(chain) > 0 || h == nil || h.confirmNX()) {
			found := second()
			if h != nil && asked {
				h.nxResult(!found)
			}
			if found {
				a.Status = StatusOK
				return a
			}
		}
		// A CNAME chain the resolver followed to a name that does not exist
		// says where the name points: a dangling one.
		a.CNAME = chain
		a.Status = StatusNXDomain
		return a
	}
	a.A, a.CNAME = records(m, dns.TypeA)
	if len(a.A) == 0 {
		if m6, err := p.Query(ctx, name, dns.TypeAAAA); err == nil && m6.Rcode == dns.RcodeSuccess {
			var chain []string
			a.AAAA, chain = records(m6, dns.TypeAAAA)
			if len(a.CNAME) == 0 {
				a.CNAME = chain
			}
		}
	}
	// A generated name that answers NOERROR with no address and no CNAME is
	// an empty non-terminal or a name with other records: as with its
	// NXDOMAIN above, a bulk resolve does not ask a second resolver.
	if !a.Live() && !(bulk(ctx) && len(a.CNAME) == 0) {
		second()
	}
	switch {
	case a.Live():
		a.Status = StatusOK
	case len(a.CNAME) > 0:
		a.Status = StatusCNAME
	default:
		a.Status = StatusNoData
	}
	return a
}

func (p *Pool) system(ctx context.Context, name string) Answer {
	a := Answer{Name: name, Status: StatusReserved}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	ips, err := egress.SystemLookup(ctx, name)
	if err != nil || len(ips) == 0 {
		return a
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			a.A = append(a.A, v4.String())
		} else {
			a.AAAA = append(a.AAAA, ip.IP.String())
		}
	}
	a.Status = StatusOK
	return a
}

// Query sends one question, moving to another resolver on a timeout,
// SERVFAIL or REFUSED, and retrying over TCP when the answer is truncated.
func (p *Pool) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m, _, err := p.query(ctx, question(name, qtype), "")
	return m, err
}

// question asks for qtype with EDNS0 and a 4,096-byte buffer, so a long
// answer (a CNAME chain, a long TXT) arrives over UDP; one larger still is
// read again over TCP.
func question(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	q.SetEdns0(4096, false) // as dnsx (retryabledns) asks
	return q
}

// reply is what one attempt of a query came back with.
type reply struct {
	attempt int
	server  string
	in      *dns.Msg
	err     error
	paced   bool // err is the pace's wait cut short, not the resolver's
}

// query is Query naming the resolver that answered; avoid, when the pool
// has another, is one that is not asked (a second opinion). An attempt that
// is late (see hedgeDelay) is not waited out: the next one is sent beside it
// and the first answer wins, so a dropped datagram costs a fraction of the
// timeout (not under a pace: see below); an attempt that fails sends the
// next at once.
func (p *Pool) query(ctx context.Context, q *dns.Msg, avoid string) (*dns.Msg, string, error) {
	if len(p.servers) == 0 {
		return nil, "", errors.New("no resolvers")
	}
	retries := p.retriesFor(ctx)
	qctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var last error
	var lastServer string
	var lastMsg *dns.Msg         // the last SERVFAIL or REFUSED, returned with the error
	servfail := map[string]int{} // resolver → attempts it answered SERVFAIL
	ch := make(chan reply, retries+1)
	waiting := map[int]string{}       // attempts sent and not answered, by number
	sent := make(chan int, retries+1) // attempts that left the pace
	shift := 0                        // how many times the latest attempt's hedge delay doubles
	launched := 0
	launch := func(doubled int) {
		n, server := launched, p.pick(launched, avoid)
		launched++
		shift = doubled
		waiting[n] = server
		m := q.Copy() // packing writes the message: no two attempts share one
		go func() {
			defer guard.Recover(ctx)
			r := reply{attempt: n, server: server}
			if err := p.limit.Wait(qctx, server); err != nil {
				r.err, r.paced = err, true
			} else {
				sent <- n
				t0 := time.Now()
				r.in, r.err = p.exchange(qctx, m, server)
				if r.err == nil {
					p.rtt.add(time.Since(t0))
				}
			}
			ch <- r
		}()
	}
	// A query is late from when it is sent: time spent waiting for the pace
	// is not, and a hedge sent then would only take another paced slot.
	hedge := time.NewTimer(time.Hour)
	hedge.Stop()
	defer hedge.Stop()
	launch(0)
	for len(waiting) > 0 {
		select {
		case n := <-sent:
			// Under a pace no attempt is hedged: a slow answer would be
			// asked for two or three times, each a slot of the rate the user
			// set, and a retry waits for the timeout as dnsx's does.
			if n == launched-1 && launched <= retries && !p.paced {
				hedge.Reset(p.hedgeDelay() << shift)
			}
			continue
		case <-hedge.C:
			if launched <= retries {
				launch(launched) // each later one waits longer: losses come in bursts
			}
			continue
		case r := <-ch:
			delete(waiting, r.attempt)
			if r.paced {
				return nil, "", r.err
			}
			if h := p.health[r.server]; h != nil && ctx.Err() == nil {
				h.note(r.err != nil)
			}
			switch {
			case r.err != nil:
				last, lastServer = r.err, r.server
			case r.in.Rcode == dns.RcodeServerFailure || r.in.Rcode == dns.RcodeRefused:
				if r.in.Rcode == dns.RcodeServerFailure {
					servfail[r.server]++
				}
				last, lastMsg, lastServer = errors.New(r.server+": "+dns.RcodeToString[r.in.Rcode]), r.in, r.server
			default:
				// An attempt sent before this one and still unanswered lost
				// the race: its resolver was too slow for the one that won.
				for n, s := range waiting {
					if h := p.health[s]; h != nil && n < r.attempt {
						h.note(true)
					}
				}
				return r.in, r.server, nil
			}
		}
		if len(waiting) == 0 && launched <= retries {
			hedge.Stop()
			launch(0)
		}
	}
	n := 0
	for _, c := range servfail {
		n += c
	}
	if n == retries+1 && len(servfail) >= 2 {
		return lastMsg, "", fmt.Errorf("%w (last %v)", errBroken, last)
	}
	if last != nil && lastServer != "" {
		last = &queryError{server: lastServer, err: last}
	}
	return lastMsg, "", last
}

// pick is the resolver for an attempt: round robin, or, first, for a
// second opinion on what avoid answered, the resolver half the list away
// from it. The list pairs an operator's addresses (1.1.1.1 and 1.0.0.1
// share a cache), so the next one would often answer alike.
func (p *Pool) pick(attempt int, avoid string) string {
	n := len(p.servers)
	if avoid != "" && n > 1 && attempt == 0 {
		for i, s := range p.servers {
			if s == avoid {
				if o := p.servers[(i+n/2)%n]; p.health[o] == nil || !p.health[o].sick() {
					return o
				}
				break
			}
		}
	}
	// One step of the round robin a call, however many resolvers it passes
	// over: when every one is sick the first is the next in turn, not always
	// the same one (which would halve the pace the user set).
	start := int(p.next.Add(1) - 1)
	var first string
	for k := range n {
		s := p.servers[(start+k)%n]
		if s == avoid && n > 1 {
			continue
		}
		if first == "" {
			first = s
		}
		if h := p.health[s]; h == nil || !h.pass() {
			return s
		}
	}
	if first == "" {
		first = p.servers[0]
	}
	return first
}

// bulkAttempts is how many times a generated name (DNS brute force,
// permutations, a source's guesses, the name history) is asked unless -retry
// says otherwise: dnsx's default of 2. Made-up names mostly do not exist, a
// name the resolvers never answer costs every attempt, and each is a paced
// query (-dns-rate), so a third attempt is 50% more time on a zone whose
// servers are silent, for names that are rarely there.
const bulkAttempts = 2

// retriesFor is how many extra attempts a query under ctx gets.
func (p *Pool) retriesFor(ctx context.Context) int {
	if v, _ := ctx.Value(onceKey{}).(bool); v {
		return 0
	}
	if bulk(ctx) && !p.fixed {
		return min(p.retries, bulkAttempts-1)
	}
	return p.retries
}

type bulkKey struct{}

type eachKey struct{}

// WithEach makes ResolveMany on ctx call fn for each answer as it arrives
// (from the goroutines asking, so fn is safe for concurrent use): work that
// needs the run live, such as judging a wildcard, is done before a stop can
// cut it off.
func WithEach(ctx context.Context, fn func(Answer)) context.Context {
	return context.WithValue(ctx, eachKey{}, fn)
}

// Bulk marks ctx as a bulk resolve (DNS brute force, permutations), where
// a plain NXDOMAIN, or a NODATA with no CNAME, is taken at its word: see
// resolve. A dangling CNAME is confirmed either way.
func Bulk(ctx context.Context) context.Context {
	return context.WithValue(ctx, bulkKey{}, true)
}

func bulk(ctx context.Context) bool {
	v, _ := ctx.Value(bulkKey{}).(bool)
	return v
}

// confirms says whether a dead-looking answer for name is worth a second
// resolver's opinion: the pool has one, and the name is neither a
// wildcard probe nor under a zone known to answer for any label.
func (p *Pool) confirms(name string) bool {
	if len(p.servers) < 2 || p.retries < 1 || strings.HasPrefix(name, probePrefix) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for z := parent(name); z != ""; z = parent(z) {
		if p.wild[z] {
			return false
		}
	}
	return true
}

// wildcard records a zone that answers for any label.
func (p *Pool) wildcard(zone string) {
	p.mu.Lock()
	p.wild[zone] = true
	p.mu.Unlock()
}

func (p *Pool) exchange(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
	if p.Exchange != nil {
		ctx, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()
		return p.Exchange(ctx, q, server)
	}
	srv, ok := p.proto[server]
	if !ok {
		srv = Server{Key: server, Net: NetUDP, Addr: server}
	}
	return p.x.Exchange(ctx, q, egress.DNSServer{Key: srv.Key, Net: srv.Net, Addr: srv.Addr, GET: srv.GET})
}

// records returns the addresses of type qtype and the CNAME chain in m.
func records(m *dns.Msg, qtype uint16) (addrs, chain []string) {
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				addrs = append(addrs, r.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				addrs = append(addrs, r.AAAA.String())
			}
		case *dns.CNAME:
			chain = append(chain, normalize.Hostname(r.Target))
		}
	}
	return addrs, chain
}

// rtts keeps the round trips of the last answered queries.
type rtts struct {
	mu   sync.Mutex
	ring [128]time.Duration
	n    int
}

func (r *rtts) add(d time.Duration) {
	r.mu.Lock()
	r.ring[r.n%len(r.ring)] = d
	r.n++
	r.mu.Unlock()
}

// p95 is the round trip 19 in 20 answers beat, 0 before there are enough to say.
func (r *rtts) p95() time.Duration {
	r.mu.Lock()
	n := min(r.n, len(r.ring))
	if n < 32 {
		r.mu.Unlock()
		return 0
	}
	s := append([]time.Duration(nil), r.ring[:n]...)
	r.mu.Unlock()
	slices.Sort(s)
	return s[n*95/100]
}

// hedgeDelay is how long a query waits for its answer before the next
// attempt is sent beside it: past what nearly every answer takes (this run's
// resolvers), within the timeout. A datagram that was lost is then not
// waited out for the whole timeout.
func (p *Pool) hedgeDelay() time.Duration {
	d := p.rtt.p95() * 3 / 2
	if d == 0 {
		d = p.timeout / 4
	}
	return min(max(d, 250*time.Millisecond), p.timeout/2)
}
