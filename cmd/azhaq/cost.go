package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/dirscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/vhostcol"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/types"
)

// What a run costs: counted before it starts (plan, and run's own line) from
// the flags and the targets, and counted again as it sends, by stage. The
// two are printed side by side in the summary.
//
// A stage is the part of a command that sends: the sign-in, the sources it
// asks, the names it resolves, the web map, the port scan, a wordlist sweep.
// roles has its own (see rolesStages). Each stage lists its collectors.

// amount is what a stage sends: requests to targets (HTTP, Chrome), connects
// (TCP connections) and datagrams (UDP) to them, DNS queries to resolvers, and
// questions to third-party sources. The first three add up to the summary's
// requests.
type amount struct {
	Requests  int64 `json:"requests,omitempty"`
	Connects  int64 `json:"connects,omitempty"`
	Datagrams int64 `json:"datagrams,omitempty"`
	DNS       int64 `json:"dns_queries,omitempty"`
	Sources   int64 `json:"source_queries,omitempty"`
}

func (a amount) zero() bool { return a == amount{} }

// contacts is everything that goes to a target or a resolver, the number the
// size of a run is judged by.
func (a amount) contacts() int64 { return a.Requests + a.Connects + a.Datagrams + a.DNS }

func (a *amount) add(b amount) {
	a.Requests += b.Requests
	a.Connects += b.Connects
	a.Datagrams += b.Datagrams
	a.DNS += b.DNS
	a.Sources += b.Sources
}

func (a amount) String() string {
	var parts []string
	for _, p := range []struct {
		n         int64
		one, many string
	}{{a.Requests, "request", "requests"}, {a.Connects, "connect", "connects"}, {a.Datagrams, "datagram", "datagrams"}, {a.DNS, "DNS query", "DNS queries"}, {a.Sources, "source query", "source queries"}} {
		if p.n > 0 {
			parts = append(parts, nOf(int(p.n), p.one, p.many))
		}
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

// costStage is one stage of a command: what it was estimated to send before
// it started and what it sent.
type costStage struct {
	Stage      string          `json:"stage"`
	Estimate   *amount         `json:"estimate,omitempty"`
	AtLeast    bool            `json:"estimate_at_least,omitempty"` // the estimate leaves out what the answers lead to (see NotCounted)
	NotCounted string          `json:"not_counted,omitempty"`
	Actual     *amount         `json:"actual,omitempty"`
	Collectors []costCollector `json:"collectors,omitempty"`
	// AtMost is the most the stage sends to the targets and the resolvers
	// (requests, connects, datagrams and DNS queries) whatever the answers are,
	// from the flags that bound it. It is absent when nothing does: NoCeiling
	// says what is open, and AtMostBy names the option that gives it when
	// that is -max-requests, not the stage's own flags.
	AtMost    *int64 `json:"at_most,omitempty"`
	AtMostBy  string `json:"at_most_by,omitempty"`
	AtMostOwn *int64 `json:"at_most_without_cap,omitempty"` // with AtMostBy: the stage's own ceiling, above the cap
	NoCeiling string `json:"no_ceiling,omitempty"`
	ceil      ceiling
}

// costCollector is the same for one collector of a stage.
type costCollector struct {
	Collector string  `json:"collector"`
	Estimate  *amount `json:"estimate,omitempty"`
	Actual    *amount `json:"actual,omitempty"`
	ceil      ceiling
}

// costEstimate is what a run would send, by stage, from its flags and targets.
type costEstimate struct {
	Total  amount      `json:"total"`
	Stages []costStage `json:"stages"`
	// AtLeast: some stage leaves out what its answers lead to (the links of
	// a page, the names a source gives), so a run may send more than Total.
	AtLeast bool `json:"at_least,omitempty"`
	// AtMost, NoCeiling and AtMostBy are the total's, as a stage's are.
	AtMost    *int64 `json:"at_most,omitempty"`
	AtMostBy  string `json:"at_most_by,omitempty"`
	AtMostOwn *int64 `json:"at_most_without_cap,omitempty"`
	NoCeiling string `json:"no_ceiling,omitempty"`
	Basis     string `json:"basis"`
	ceil      ceiling
	cap       int64 // -max-requests: the most requests, connects and datagrams a run sends to its targets
}

// ceiling is the most a part of an estimate sends, from the flags that bound
// it: contacts with the targets (requests, connects, datagrams) and queries to
// resolvers. A part with reasons in tOpen or dOpen has no ceiling of its own;
// -max-requests bounds the first, which the DNS queries are not part of.
type ceiling struct {
	target, dns  int64
	tOpen, dOpen []string
}

// dnsAgain is why the queries of a lookup have no ceiling: a lookup that gets
// no answer is asked again on another resolver, and an answer leads to more.
const dnsAgain = "a lookup that gets no answer is asked again on another resolver (-retry), and a name that answers is asked for its other records"

func (c *ceiling) add(o ceiling) {
	c.target += o.target
	c.dns += o.dns
	c.tOpen = mergeReasons(c.tOpen, o.tOpen)
	c.dOpen = mergeReasons(c.dOpen, o.dOpen)
}

func (c ceiling) times(n int64) ceiling {
	return ceiling{target: c.target * n, dns: c.dns * n, tOpen: c.tOpen, dOpen: c.dOpen}
}

func mergeReasons(a, b []string) []string {
	for _, r := range b {
		if !slices.Contains(a, r) {
			a = append(a, r)
		}
	}
	return a
}

// ceilingOf is the ceiling of what a floor leaves nothing out of (open is
// empty): as much as it counts; with something left out, no flag bounds it
// unless the caller says so. The sources stage asks third parties, which no
// flag of the targets bounds and no ceiling covers.
func ceilingOf(stage string, a amount, open string) ceiling {
	if stage == "sources" {
		return ceiling{}
	}
	c := ceiling{target: a.Requests + a.Connects + a.Datagrams, dns: a.DNS}
	switch {
	case open == "" && a.DNS > 0:
		c.dOpen = []string{dnsAgain}
	case open == "":
	case stage == "names":
		c.dOpen = []string{open}
	default:
		c.tOpen = []string{open}
	}
	return c
}

// atMost is what the flags bound: the most sent, which option sets it when
// that is -max-requests, or what leaves it open. Nothing at all to bound is
// no ceiling and no reason.
func (c ceiling) atMost(cap int64) (at *int64, by, open string, own *int64) {
	t := c.target
	var why []string
	switch {
	case len(c.tOpen) > 0 && cap > 0:
		t, by = cap, "-max-requests"
	case len(c.tOpen) > 0:
		why = append(why, c.tOpen...)
	case cap > 0 && t > cap:
		// The cap is printed with the ceiling it hides.
		o := c.target + c.dns
		t, by, own = cap, "-max-requests", &o
	}
	why = append(why, c.dOpen...)
	if len(why) > 0 {
		sort.Strings(why)
		return nil, "", strings.Join(why, "; "), nil
	}
	if c.target == 0 && c.dns == 0 {
		return nil, "", "", nil
	}
	v := t + c.dns
	return &v, by, "", own
}

// seal sets the ceilings printed, stage by stage and for the whole, from what
// each was counted with.
func (e *costEstimate) seal() {
	e.ceil = ceiling{}
	for i := range e.Stages {
		st := &e.Stages[i]
		e.ceil.add(st.ceil)
		st.AtMost, st.AtMostBy, st.NoCeiling, st.AtMostOwn = st.ceil.atMost(e.cap)
	}
	e.AtMost, e.AtMostBy, e.NoCeiling, e.AtMostOwn = e.ceil.atMost(e.cap)
}

const rolesBasis = "from the roles, their histories and the run options: each stage counts what they fix, as if each target answers, and says what it leaves out"

const estimateBasis = "from the flags and the targets given, as if each target answers: the same wordlists, port lists and built-in checks the run sends; what a page, a script or a source's answer leads to is not known before it is read, and each stage says what it leaves out"

// trivialRun is the size under which run does not print its estimate before it
// sends: requests, connects, datagrams and DNS queries together.
const trivialRun = 1000

// signInStage is the name Chrome's sign-ins send under: a stage of their own.
const signInStage = ledger.SignIn

// The stages of roles, in the order it goes through them.
const (
	stageRoleMaps = "role maps" // each role's run: its map of the target
	stageHistory  = "history reads"
	stageReplay   = "replay"
	stageControls = "controls"
	stageWrites   = "write replay"
	stageVerify   = "verification" // the owner's object read before and after a replayed write
)

var rolesStages = []string{signInStage, stageRoleMaps, stageHistory, stageReplay, stageControls, stageWrites, stageVerify}

// stageOfCollector groups a collector into the stage of a run that it works
// in. The stages carry the names of azhaq's capabilities (sources, names,
// web, ports, fuzz, shots, verify), so the summary, the plan and the ui
// say the same words.
func stageOfCollector(name string) string {
	switch strings.TrimPrefix(name, "azhaq-") {
	case "subdomains", "urls", "rdap", "search":
		return "sources"
	case "dns", "dns-brute", "permute", "asn", "prefix", "ptr":
		return "names"
	case "http", "paths", "crawl", "js", "tls", "openapi", "graphql", "graphql-schema", "render", "vhost":
		return "web"
	case "ports":
		return "ports"
	case "dirs", "params":
		return "fuzz"
	case "shots":
		return "shots"
	case "advisories", "verify":
		return "verify"
	case "notify":
		return "notify"
	case signInStage:
		return signInStage
	}
	return "other"
}

// stageOrder is how stages are listed: the order a run goes through them.
var stageOrder = []string{signInStage, "sources", "names", "web", "ports", "fuzz", "shots", "verify", "notify",
	stageRoleMaps, stageHistory, stageReplay, stageControls, stageWrites, stageVerify, "other"}

func stageRank(s string) int {
	for i, n := range stageOrder {
		if n == s {
			return i
		}
	}
	return len(stageOrder)
}

// costEnv is what the estimate of a run needs besides its targets: how big
// each wordlist and port list is, from the same values the run sends.
type costEnv struct {
	sendLimits
	// What the floors are counted against.
	rules    scope.Rules
	pathList []string // the built-in path checks and -paths ones; none when azhaq-paths does not run
}

// estimator accumulates the estimate: stage → collector → amount.
type estimator struct {
	stages  map[string]*costStage
	notes   map[string]map[string]bool
	coll    map[string]map[string]*amount
	collCap map[string]map[string]*ceiling
	atLeast bool
	cap     int64 // -max-requests
}

func newEstimator() *estimator {
	return &estimator{stages: map[string]*costStage{}, notes: map[string]map[string]bool{}, coll: map[string]map[string]*amount{}, collCap: map[string]map[string]*ceiling{}}
}

// add puts a into the stage of collector, with what it leaves out (open).
func (e *estimator) add(collector string, a amount, open string) {
	st := stageOfCollector(collector)
	e.put(st, collector, a, open)
}

// has says whether a stage has an entry.
func (e *estimator) has(stage string) bool { return e.stages[stage] != nil }

// addBound is add with the ceiling the flags give it.
func (e *estimator) addBound(collector string, a amount, open string, cl ceiling) {
	e.putBound(stageOfCollector(collector), collector, a, open, cl)
}

// growsBeyond says why a ceiling counted from the seeds may be passed: a
// seed that names more than itself (a domain, an organisation, an AS number),
// or a scope that allows hosts that are not seeds, finds targets on the way.
func growsBeyond(seeds []types.Seed, rules scope.Rules) string {
	own := map[string]bool{}
	var spans []netip.Prefix
	for _, s := range seeds {
		switch s.Type {
		case types.TypeURL:
			own[normalize.HostFromURL(s.Key())] = true
		case types.TypeHostname, types.TypeIPAddress:
			own[strings.ToLower(s.Key())] = true
		case types.TypePrefix:
			if pf, err := netip.ParsePrefix(s.Key()); err == nil {
				spans = append(spans, pf.Masked())
			}
		default:
			return "names, addresses and web services found under the domains, organisations and AS numbers given are asked too"
		}
	}
	inSpans := func(a string) bool {
		if pf, err := netip.ParsePrefix(a); err == nil {
			for _, sp := range spans {
				if sp.Bits() <= pf.Bits() && sp.Contains(pf.Addr()) {
					return true
				}
			}
		} else if ip, err := netip.ParseAddr(a); err == nil {
			for _, sp := range spans {
				if sp.Contains(ip.Unmap()) {
					return true
				}
			}
		}
		return false
	}
	for _, a := range rules.Allow {
		host := normalize.Hostname(a)
		if h, _, err := net.SplitHostPort(a); err == nil {
			host = normalize.Hostname(h)
		}
		if !own[host] && !own[strings.ToLower(a)] && !inSpans(a) && !inSpans(host) {
			return "-allow or -scope names hosts that are not targets: the ones a page links to there are asked too"
		}
	}
	return ""
}

// paramsPerPage is what searching one page asks at least: the questions that
// tell how the page answers, and the groups of 500 names (see planGuesses).
func paramsPerPage(names int) int64 { return int64(3 + (names+499)/500) }

// paramsPages is how many pages azhaq-params is sure to search: the pages the
// user gave, one for each path, up to -params-per-host of a host, when a body
// is not what it sends or writes were asked for.
func paramsPages(seeds []types.Seed, planned [][]string, env costEnv) int64 {
	if env.paramsBody != "" && !env.paramsWrites {
		return 0
	}
	perHost := map[string]int{}
	paths := map[string]bool{}
	var n int64
	for i, s := range seeds {
		if s.Type != types.TypeURL || !slices.Contains(planned[i], "azhaq-params") || !env.rules.AllowsURL(s.Key()) || env.rules.DeniedPath(s.Key()) != "" {
			continue
		}
		raw, err := normalize.URL(s.Key())
		if err != nil {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		page := u.Scheme + "://" + u.Host + u.Path
		if paths[page] || (env.paramsPages > 0 && perHost[u.Host] >= env.paramsPages) {
			continue
		}
		paths[page] = true
		perHost[u.Host]++
		n++
	}
	return n
}

func (e *estimator) put(stage, collector string, a amount, open string) {
	e.putBound(stage, collector, a, open, ceilingOf(stage, a, open))
}

// putBound is put with the ceiling the flags give it.
func (e *estimator) putBound(stage, collector string, a amount, open string, cl ceiling) {
	if e.stages[stage] == nil {
		e.stages[stage] = &costStage{Stage: stage, Estimate: &amount{}}
		e.coll[stage] = map[string]*amount{}
		e.collCap[stage] = map[string]*ceiling{}
		e.notes[stage] = map[string]bool{}
	}
	e.stages[stage].Estimate.add(a)
	e.stages[stage].ceil.add(cl)
	if e.coll[stage][collector] == nil {
		e.coll[stage][collector] = &amount{}
		e.collCap[stage][collector] = &ceiling{}
	}
	e.coll[stage][collector].add(a)
	e.collCap[stage][collector].add(cl)
	if open != "" {
		e.notes[stage][open] = true
		e.stages[stage].AtLeast = true
		e.atLeast = true
	}
}

func (e *estimator) result() costEstimate {
	out := costEstimate{AtLeast: e.atLeast, Basis: estimateBasis, cap: e.cap}
	var names []string
	for n := range e.stages {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if a, b := stageRank(names[i]), stageRank(names[j]); a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		st := *e.stages[n]
		var notes []string
		for note := range e.notes[n] {
			notes = append(notes, note)
		}
		sort.Strings(notes)
		st.NotCounted = strings.Join(notes, "; ")
		var cols []string
		for c := range e.coll[n] {
			cols = append(cols, c)
		}
		sort.Strings(cols)
		if len(cols) > 1 || (len(cols) == 1 && cols[0] != "") {
			for _, c := range cols {
				a := *e.coll[n][c]
				st.Collectors = append(st.Collectors, costCollector{Collector: c, Estimate: &a, ceil: *e.collCap[n][c]})
			}
		}
		out.Total.add(*st.Estimate)
		out.Stages = append(out.Stages, st)
	}
	out.seal()
	return out
}

// An estimate is a floor: each stage counts what the run sends whatever the
// answers are, and says what it leaves out. Work an answer can skip is not
// in it: an API description found ends the guesses of one, a URL that was
// asked already is not asked again, a request the scope or -deny-path holds
// back is not sent. A request is counted once however many collectors would
// make it.

// estimateCost is what a run of seeds would send, for the collectors planned
// on each. planned[i] are the collectors planFor found for seeds[i]; runs says
// whether a collector would run on a web service found.
func estimateCost(seeds []types.Seed, planned [][]string, runs func(string) bool, active map[string]bool, env costEnv, asks func(collector string, s types.Seed) int) costEstimate {
	e := newEstimator()
	e.cap = env.max
	grows := growsBeyond(seeds, env.rules)
	has := func(i int, c string) bool {
		for _, n := range planned[i] {
			if n == c {
				return true
			}
		}
		return false
	}
	permuteNoted := false
	guessLeft := env.guessBudget // -max-names holds the guesses of -dns-brute and -permute together
	guess := func(n int) int64 {
		if env.guessBudget > 0 {
			n = min(n, guessLeft)
			guessLeft -= n
		}
		return int64(n)
	}
	ports := newPortModel(env.rules, env)
	var ranges []netip.Prefix // the ranges that are scanned: an address in one is scanned there
	for i, s := range seeds {
		if pf, err := netip.ParsePrefix(s.Key()); err == nil && s.Type == types.TypePrefix && has(i, "azhaq-ports") {
			ranges = append(ranges, pf.Masked())
		}
	}
	pageHosts := map[string]bool{} // hosts of the URLs asked
	for i, s := range seeds {
		if s.Type == types.TypeURL && has(i, "azhaq-http") {
			pageHosts[normalize.HostFromURL(s.Key())] = true
		}
	}
	portsOpen := "banner and protocol probes of each open port"
	if env.portEscalate {
		for _, s := range seeds {
			if pf, err := netip.ParsePrefix(s.Key()); err == nil && s.Type == types.TypePrefix && !pf.IsSingleIP() {
				portsOpen = fmt.Sprintf("pass 2 of -ports default on each address of a range that answers pass 1 (%d connects each), and the banner and protocol probes of each open port", secondPortsOf(len(env.portList), env.portSkip))
				break
			}
		}
	}
	if len(env.portUDPList) > 0 {
		// The floor counts one datagram a UDP port; a silent one gets the rest.
		portsOpen += fmt.Sprintf("; up to %d more datagrams to each UDP port that does not answer (each protocol's own request)", portscan.MaxUDPAsks-1)
	}
	nameScanned := false // a name is scanned: whether it is behind a CDN or WAF is not known
	var (
		pages     = map[string]bool{} // the URLs of the web map the run asks whatever the answers are
		sweepSeen = map[string]bool{} // origins whose path sweep is planned
		sweeps    []string            // the URLs the sweeps ask
		descs     int                 // the guesses of an API description they leave out
		hostPages int                 // names asked for their page: its URL is not known before
		dirsBases = map[string]bool{}
		dirsReqs  int64
		dirsMax   int64               // the most the sweeps send at depth 1
		names     = map[string]bool{} // the names looked up
	)
	for i, s := range seeds {
		for _, c := range planned[i] {
			switch c {
			case "azhaq-subdomains", "azhaq-urls", "azhaq-rdap", "azhaq-search":
				if n := asks(c, s); n > 0 {
					e.add(c, amount{Sources: int64(n)}, "names and archived URLs found are asked about too")
				}
			case "azhaq-dns":
				names[s.Key()] = true
			case "azhaq-dns-brute":
				e.add(c, amount{DNS: guess(brutecol.BruteCount(env.bruteList, s.Key()))}, "")
			case "azhaq-permute":
				// The variations of a name given are known; the names a source or
				// a lookup gives later bring variations of their own.
				e.add(c, amount{DNS: guess(brutecol.PermuteCount(s.Key()))}, permuteOpen)
				permuteNoted = true
			case "azhaq-tls":
				if env.rules.AllowsAddr(s.Key(), "443") {
					e.add(c, amount{Connects: 1}, "")
				}
			case "azhaq-ports":
				cl := ports.ceilOf(s, ranges)
				if grows != "" {
					cl.tOpen = mergeReasons(cl.tOpen, []string{grows})
				}
				e.addBound(c, portsOf(ports, s, ranges), portsOpen, cl)
				nameScanned = nameScanned || s.Type == types.TypeHostname && net.ParseIP(s.Key()) == nil
			case "azhaq-http":
				switch {
				case s.Type == types.TypeURL && env.rules.AllowsURL(s.Key()):
					pages[s.Key()] = true
				case s.Type == types.TypeHostname && !pageHosts[s.Key()] && env.rules.Allows(s.Key()):
					hostPages++
				}
			case "azhaq-paths":
				if s.Type != types.TypeURL || !env.rules.AllowsURL(s.Key()) {
					continue
				}
				origin := originOf(s.Key())
				if sweepSeen[origin] {
					continue // an API base of the origin: its guesses are all of a description
				}
				sweepSeen[origin] = true
				locs, guesses := pathscol.Sweep(s.Key(), env.pathList)
				for _, u := range locs {
					if env.rules.DeniedPath(u) == "" {
						sweeps = append(sweeps, u)
					}
				}
				descs += len(guesses)
			case "azhaq-dirs":
				if s.Type != types.TypeURL || !env.rules.AllowsURL(s.Key()) {
					continue
				}
				if base := dirscol.Base(s.Key()); base != "" && !dirsBases[base] {
					dirsBases[base] = true
					dirsReqs += int64(dirscol.Requests(s.Key(), env.dirsWordList, env.dirsExtList, !env.dirsNoCal, env.dirsHold, env.rules.DeniedPath))
					dirsMax += int64(dirscol.MaxRequests(s.Key(), env.dirsWordList, env.dirsExtList, !env.dirsNoCal, env.dirsHold, env.rules.DeniedPath))
				}
			}
		}
	}
	if n := dnsFloor(names); n > 0 {
		e.add("azhaq-dns", amount{DNS: n}, "wildcard checks past the first of a zone, CNAME chains, and a second resolver asked about a name that does not answer")
	}
	if runs("azhaq-vhost") && vhostPossible(seeds) {
		e.add("azhaq-vhost", amount{}, vhostOpen)
	}
	if active["permute"] && !permuteNoted {
		for _, s := range seeds {
			if s.Type == types.TypeDomain || s.Type == types.TypeHostname {
				e.add("azhaq-permute", amount{}, permuteOpen)
				break
			}
		}
	}
	if grows != "" {
		// Targets found on the way are asked by these stages too, whether or
		// not a seed has them yet: a stage with no seed says so.
		if active["ports"] && !e.has("ports") {
			e.addBound("azhaq-ports", amount{}, grows, ceiling{tOpen: []string{grows}})
		}
		if active["dirs"] && len(env.dirsWordList) > 0 && !e.has("fuzz") {
			e.addBound("azhaq-dirs", amount{}, grows, ceiling{tOpen: []string{grows}})
		}
	}
	if active["ports"] {
		for _, s := range seeds {
			if s.Type == types.TypeASN {
				e.add("azhaq-ports", amount{}, "the addresses of the ranges an AS number holds, known when RIPEstat answers")
				break
			}
		}
		// The ceiling counts the ports of every address and every datagram.
		if len(ranges) > 0 && env.portDiscover == portcol.DiscoverFirst {
			e.addBound("azhaq-ports", amount{}, "the ports of the addresses of a range that answer the connects to 80 and 443 (-port-discover first)", ceiling{})
		}
		if len(env.portUDPList) > 0 && nameScanned {
			e.addBound("azhaq-ports", amount{}, "UDP datagrams to a name, which may be behind a CDN or WAF: none go to those addresses", ceiling{})
		}
	}
	// The page of each URL, then each path the sweeps ask; one that is both is
	// one request, and the favicon is /favicon.ico, one of the paths, or an
	// icon the page names, which only the answer tells.
	if runs("azhaq-http") && len(pages)+hostPages > 0 {
		e.add("azhaq-http", amount{Requests: int64(len(pages) + hostPages)}, "what its pages, scripts and archived URLs lead to, and the control requests that tell a catch-all answer from a page")
	}
	if runs("azhaq-paths") && len(sweeps) > 0 {
		own := 0
		seen := map[string]bool{}
		for _, u := range sweeps {
			if !seen[u] && !pages[u] {
				own++
			}
			seen[u] = true
		}
		note := "the documentation paths under each API prefix the pages name"
		if descs > 0 {
			note += "; the " + nOf(descs, "guess", "guesses") + " of an API description, which stop at the first found"
		}
		e.add("azhaq-paths", amount{Requests: int64(own)}, note)
	}
	if dirsReqs > 0 {
		cl := ceiling{target: dirsMax}
		switch {
		case env.dirsDepth > 1:
			cl.tOpen = []string{"each directory found is swept too (-dirs-depth " + fmt.Sprint(env.dirsDepth) + ")"}
		case grows != "":
			cl.tOpen = []string{grows}
		}
		e.addBound("azhaq-dirs", amount{Requests: dirsReqs}, "each directory found is swept and calibrated too, and a directory two hits are found in (words with a slash) gets one more request", cl)
	}
	if active["params"] && len(pages) > 0 && env.paramsN > 0 {
		// A page the user gave is searched whatever it answers (up to
		// -params-per-host of a host): its first questions are the floor, and
		// a group that changes the answer is narrowed down, which no flag bounds.
		if n := paramsPages(seeds, planned, env); n > 0 {
			e.add("azhaq-params", amount{Requests: n * paramsPerPage(env.paramsN)}, "groups that change the answer are narrowed down, and pages the run finds are searched too, up to -params-per-host a host")
		} else {
			e.add("azhaq-params", amount{}, "pages searched, up to -params-per-host a host, each asked in batches of the wordlist")
		}
	}
	if env.login != "" {
		e.put("sign-in", "chrome", amount{Requests: 3}, "the sign-in page's scripts, styles and images, which Chrome asks for as the page names them")
	}
	return e.result()
}

// dnsFloor is the queries the lookup of names sends if each answers: one
// for each name, one for each zone above a name that a wildcard is looked for
// in (a random label of it, once for the run), and for a registrable domain
// its MX, TXT and NS.
func dnsFloor(names map[string]bool) int64 {
	var n int64
	zones := map[string]bool{}
	for h := range names {
		n++
		apex := normalize.RegistrableDomain(h)
		switch {
		case apex == "":
		case h == apex:
			n += 3
		default:
			for p := parentName(h); p == apex || strings.HasSuffix(p, "."+apex); p = parentName(p) {
				zones[p] = true
			}
		}
	}
	return n + int64(len(zones))
}

// parentName is a name without its first label.
func parentName(h string) string {
	_, rest, _ := strings.Cut(h, ".")
	return rest
}

// portsOf is what the port scan costs at least on one target: a range is every
// address of it the scope allows; an address inside a range that is scanned is
// scanned there, and not again.
func portsOf(m portModel, s types.Seed, ranges []netip.Prefix) amount {
	switch s.Type {
	case types.TypePrefix:
		if pf, err := netip.ParsePrefix(s.Key()); err == nil {
			return m.span(pf)
		}
	case types.TypeIPAddress, types.TypeHostname:
		if a, err := netip.ParseAddr(s.Key()); err == nil {
			for _, pf := range ranges {
				if pf.Contains(a.Unmap()) {
					return amount{}
				}
			}
		}
		return m.host(s.Key())
	}
	return amount{}
}

// vhostPossible says whether the targets can bring a name and a web service
// together: not a run of addresses alone, which names nothing.
func vhostPossible(seeds []types.Seed) bool {
	for _, s := range seeds {
		switch s.Type {
		case types.TypeIPAddress:
		case types.TypeURL:
			if net.ParseIP(normalize.HostFromURL(s.Key())) == nil {
				return true
			}
		case types.TypeHostname:
			if net.ParseIP(s.Key()) == nil {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// vhostOpen is what the virtual host requests leave out of the estimate: the
// names and the web services they are asked of are found as the run goes.
var vhostOpen = fmt.Sprintf("virtual host requests: one for each name found in scope and web service of the addresses in scope (a name asked there by name is not asked twice), and %d for each service to learn its default answer (-no-vhost turns them off)", vhostcol.Calibrations)

// permuteOpen is what -permute's estimate leaves out: the names the sources
// and the lookups give are not known before they answer.
const permuteOpen = "variations of the names the sources and lookups find (-permute)"

// printEstimate says the estimate in plain text, one line a stage.
func printEstimate(w io.Writer, lead string, est costEstimate) {
	fmt.Fprintln(w, lead+atLeastPrefix(est.AtLeast)+est.Total.String()+atLeastWord(est.AtLeast)+ceilingWord(est.AtMost, est.AtMostBy, est.AtMostOwn, est.NoCeiling, "", est.cap))
	for _, st := range est.Stages {
		line := fmt.Sprintf("  %-12s %s%s", st.Stage, atLeastPrefix(st.AtLeast), st.Estimate)
		var by []string
		for _, c := range st.Collectors {
			if len(st.Collectors) > 1 && c.Estimate != nil && !c.Estimate.zero() {
				by = append(by, fmt.Sprintf("%s %d", strings.TrimPrefix(c.Collector, "azhaq-"), c.Estimate.contacts()+c.Estimate.Sources))
			}
		}
		if len(by) > 0 {
			line += " (" + strings.Join(by, ", ") + ")"
		}
		line += ceilingWord(st.AtMost, st.AtMostBy, st.AtMostOwn, st.NoCeiling, st.NotCounted, est.cap)
		if st.NotCounted != "" {
			line += "; not counted: " + st.NotCounted
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "  "+est.Basis)
}

// ceilingWord says what bounds an estimate beside its floor: "; at most N"
// (and the option that gives it when that is the budget), or "; no ceiling"
// with what is open. A reason a stage lists under not counted is not said twice.
func ceilingWord(at *int64, by string, own *int64, no, counted string, cap int64) string {
	return ceilingWordIn(at, by, own, no, counted, cap, false)
}

// ceilingWordIn is ceilingWord; short leaves the reasons out, for a line that
// has no room for them (the summary's: they are in the plan).
func ceilingWordIn(at *int64, by string, own *int64, no, counted string, cap int64, short bool) string {
	switch {
	case at != nil && by != "" && own != nil:
		return fmt.Sprintf("; at most %s by %s (%s by the run itself)", commas(*at), by, commas(*own))
	case at != nil && by != "":
		return fmt.Sprintf("; at most %s (%s)", commas(*at), by)
	case at != nil:
		return "; at most " + commas(*at)
	case no == "":
		return ""
	}
	hint := ""
	if cap == 0 {
		hint = " (-max-requests sets one)"
	}
	if no == counted || short {
		return "; no ceiling" + hint
	}
	return "; no ceiling: " + no + hint
}

// commas writes n with a comma between each three digits.
func commas(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// atLeastPrefix says a floor is one: what the answers lead to is not in it.
func atLeastPrefix(atLeast bool) string {
	if atLeast {
		return "at least "
	}
	return ""
}

func atLeastWord(atLeast bool) string {
	if atLeast {
		return ", and what the answers lead to"
	}
	return ""
}

// spentAmount is what an account (ledger.Account, as a difference) holds for
// one stage and collector: the requests, connects, datagrams, DNS queries and source
// queries its keys add up to.
func spentAmount(acc map[ledger.SpentKey]int64, keep func(ledger.SpentKey) bool) amount {
	var a amount
	for k, n := range acc {
		if n == 0 || !keep(k) {
			continue
		}
		switch {
		case k.Class == ledger.ClassDNS:
			a.DNS += n
		case k.Class == ledger.ClassSource:
			a.Sources += n
		case k.Class == ledger.ClassOwn:
		case k.Kind == "tcp":
			a.Connects += n
		case k.Kind == "udp":
			a.Datagrams += n
		default:
			a.Requests += n
		}
	}
	return a
}

// purposesOf is what the requests and connections an account holds to
// targets were for, by purpose; a line with none names "other".
func purposesOf(acc map[ledger.SpentKey]int64) map[string]int {
	out := map[string]int{}
	for k, n := range acc {
		if n > 0 && k.Class == ledger.ClassTarget {
			p := k.Purpose
			if p == "" {
				p = ledger.PurposeOther
			}
			out[p] += int(n)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sumOf(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// purposeLine says the purposes in a line, the most requests first.
func purposeLine(m map[string]int) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if m[names[i]] != m[names[j]] {
			return m[names[i]] > m[names[j]]
		}
		return names[i] < names[j]
	})
	parts := make([]string, len(names))
	for i, k := range names {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	return strings.Join(parts, ", ")
}

// accountSince is the account of what a command sent: now less then.
func accountSince(then map[ledger.SpentKey]int64) map[ledger.SpentKey]int64 {
	out := map[ledger.SpentKey]int64{}
	for k, n := range ledger.Account() {
		if d := n - then[k]; d > 0 {
			out[k] = d
		}
	}
	return out
}

// stageOfKey is the stage an entry of the account belongs to: the stage the
// command named (SetStage), else the stage of its collector.
func stageOfKey(k ledger.SpentKey) string {
	if k.Collector == signInStage {
		return signInStage
	}
	if k.Stage != "" {
		return k.Stage
	}
	if k.Class == ledger.ClassDNS {
		// Any query to a resolver is the names stage's: the resolver's cache
		// gives an answer to whichever collector asked first, so the collector
		// that sent a query says nothing of the stage that needed it.
		return "names"
	}
	return stageOfCollector(k.Collector)
}

// costReport is the summary's account of the cost: what each stage was
// estimated to send, and what it sent.
type costReport struct {
	cap      int64
	Estimate *amount `json:"estimate,omitempty"` // the total, when the command estimated
	AtLeast  bool    `json:"estimate_at_least,omitempty"`
	// AtMost: the most the command was bounded to send, as the estimate has it.
	AtMost    *int64      `json:"at_most,omitempty"`
	AtMostBy  string      `json:"at_most_by,omitempty"`
	AtMostOwn *int64      `json:"at_most_without_cap,omitempty"`
	NoCeiling string      `json:"no_ceiling,omitempty"`
	Actual    amount      `json:"actual"`
	Stages    []costStage `json:"stages"`
}

// accountCost builds the cost account of a command from the estimate it made
// (nil: none) and what it sent since then. order lists the stages in the
// order the command goes through them; the rest follow in run order.
func accountCost(est *costEstimate, then map[ledger.SpentKey]int64, order []string) *costReport {
	return accountCostBy(est, then, order, false)
}

// accountCostBy is accountCost; byCollector groups by collector alone, as a run's stages are, and not by the stage a caller named.
func accountCostBy(est *costEstimate, then map[ledger.SpentKey]int64, order []string, byCollector bool) *costReport {
	acc := accountSince(then)
	if byCollector {
		flat := map[ledger.SpentKey]int64{}
		for k, n := range acc {
			k.Stage = ""
			flat[k] += n
		}
		acc = flat
	}
	out := &costReport{}
	byStage := map[string]*costStage{}
	get := func(name string) *costStage {
		if byStage[name] == nil {
			byStage[name] = &costStage{Stage: name}
		}
		return byStage[name]
	}
	if est != nil {
		out.Estimate, out.AtLeast = &amount{}, est.AtLeast
		*out.Estimate = est.Total
		out.AtMost, out.AtMostBy, out.AtMostOwn, out.NoCeiling, out.cap = est.AtMost, est.AtMostBy, est.AtMostOwn, est.NoCeiling, est.cap
		for _, st := range est.Stages {
			c := st
			byStage[st.Stage] = &c
		}
	}
	stages := map[string]bool{}
	for k := range acc {
		stages[stageOfKey(k)] = true
	}
	for s := range stages {
		st := get(s)
		a := spentAmount(acc, func(k ledger.SpentKey) bool { return stageOfKey(k) == s })
		st.Actual = &a
		cols := map[string]bool{}
		for k := range acc {
			if stageOfKey(k) == s {
				cols[k.Collector] = true
			}
		}
		if len(cols) == 1 && (cols[""] || cols[s]) && len(st.Collectors) == 0 {
			continue // one sender with no name: the stage says all there is
		}
		for _, c := range st.Collectors {
			cols[c.Collector] = true
		}
		var names []string
		for c := range cols {
			names = append(names, c)
		}
		sort.Strings(names)
		var merged []costCollector
		for _, c := range names {
			a := spentAmount(acc, func(k ledger.SpentKey) bool { return stageOfKey(k) == s && k.Collector == c })
			cc := costCollector{Collector: c, Actual: &a}
			for _, old := range st.Collectors {
				if old.Collector == c {
					cc.Estimate = old.Estimate
				}
			}
			if c == "" {
				cc.Collector = "other"
			}
			merged = append(merged, cc)
		}
		st.Collectors = merged
	}
	rank := func(s string) int {
		for i, n := range order {
			if n == s {
				return i
			}
		}
		return len(order) + stageRank(s)
	}
	for _, st := range byStage {
		out.Stages = append(out.Stages, *st)
		if st.Actual != nil {
			out.Actual.add(*st.Actual)
		}
	}
	sort.Slice(out.Stages, func(i, j int) bool {
		a, b := rank(out.Stages[i].Stage), rank(out.Stages[j].Stage)
		if a != b {
			return a < b
		}
		return out.Stages[i].Stage < out.Stages[j].Stage
	})
	return out
}

// line says the account in one line for the text summary: each stage's
// estimate beside what it sent.
func (c *costReport) lines() []string {
	var out []string
	for _, st := range c.Stages {
		if st.Actual == nil && st.Estimate == nil {
			continue
		}
		act := amount{}
		if st.Actual != nil {
			act = *st.Actual
		}
		line := fmt.Sprintf("%s: sent %s", st.Stage, act)
		if st.Estimate != nil {
			line += fmt.Sprintf(" (estimated %s%s%s%s)", atLeastPrefix(st.AtLeast), st.Estimate, map[bool]string{true: " and what the answers lead to"}[st.AtLeast], ceilingWordIn(st.AtMost, st.AtMostBy, st.AtMostOwn, st.NoCeiling, st.NotCounted, c.cap, true))
		}
		out = append(out, line)
	}
	return out
}

// stopDetail says what a limit stop knew of where it was reached: the
// collector that sent the last request of the budget, the first the budget
// refused when that is another, and what each stage had sent.
func stopDetail(last string, refused []string, c *costReport) string {
	var parts []string
	if last != "" {
		parts = append(parts, "last sent by "+strings.TrimPrefix(last, "azhaq-"))
	}
	if len(refused) > 0 && refused[0] != last {
		parts = append(parts, "first refused: "+strings.TrimPrefix(refused[0], "azhaq-"))
	}
	if by := spentBy(c); by != "" {
		parts = append(parts, "sent"+strings.TrimPrefix(by, ","))
	}
	return strings.Join(parts, "; ")
}

// stoppedIn says where the request budget of a run was reached, for its
// stopped line: ", reached in the ports stage (last sent by ports; sent by
// stage: map 29, ports 11)". "" when nothing says.
func stoppedIn(refused []string, c *costReport) string {
	k := ledger.LastSender()
	stage := stageOfCollector(k.Collector)
	if k.Collector == "" && len(refused) > 0 {
		k.Collector, stage = refused[0], stageOfCollector(refused[0])
	}
	d := stopDetail(k.Collector, refused, c)
	switch {
	case k.Collector != "":
		return fmt.Sprintf(", reached in the %s stage (%s)", stage, d)
	case d != "":
		return " (" + d + ")"
	}
	return ""
}

// spentBy says what each stage sent, for a note on a budget: ": sign-in 3,
// role maps 31" with the lead given.
func spentBy(c *costReport) string {
	if c == nil {
		return ""
	}
	var by []string
	for _, st := range c.Stages {
		if st.Actual != nil && st.Actual.contacts() > 0 {
			by = append(by, fmt.Sprintf("%s %d", st.Stage, st.Actual.contacts()))
		}
	}
	if len(by) == 0 {
		return ""
	}
	return ", by stage: " + strings.Join(by, ", ")
}

// roleStage is the stage of roles a request was sent in.
func roleStage(k ledger.SpentKey) string {
	if st := stageOfKey(k); st != "" && st != "other" {
		return st
	}
	return stageRoleMaps
}
