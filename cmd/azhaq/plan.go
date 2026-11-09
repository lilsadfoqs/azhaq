package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/gqlcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// cmdPlan is a run that stops before sending anything: what it would
// take, leave out, run and send.
func cmdPlan(args []string) error {
	if len(args) > 0 && args[0] == "roles" {
		// What azhaq roles would send, by stage.
		return cmdRoles(append([]string{"-plan"}, args[1:]...))
	}
	fs := newFlags("plan")
	var names []string
	runFlags().VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Usage, "internal:") {
			names = append(names, f.Name)
		}
	})
	given := inherit(fs, names...)
	axfr := fs.Bool("axfr", false, "also plan the zone transfers azhaq dns -axfr would try for the domain and host targets: the name servers' lookups, and which name servers the scope would let it ask")
	if err := parse(fs, args); err != nil {
		return err
	}
	rep := newReport("plan")
	out := runOut{embedded: true, plan: true, axfr: *axfr}
	if err := mapTarget(given(), rep, &out); err != nil {
		return err
	}
	return rep.finish(out.json, false)
}

// runPlan is what a run would do, as plan prints it.
type runPlan struct {
	Targets    []planTarget      `json:"targets"`
	Skipped    []engine.Skip     `json:"skipped,omitempty"`
	Collectors map[string]string `json:"collectors"` // name → what it does to whom
	Active     []string          `json:"active"`
	Paths      []string          `json:"builtin_paths,omitempty"`
	Limits     map[string]string `json:"limits"`
	Sends      []string          `json:"sends"`
	Requests   planRequests      `json:"requests"`
	Estimate   costEstimate      `json:"estimate"`       // what the run would send, by stage
	AXFR       []planAXFR        `json:"axfr,omitempty"` // -axfr: the zone transfers dns -axfr would try
	// StateChanging are the in-scope GET requests among the targets
	// whose own name declares a state change, each with the -deny-path
	// rule that would keep it out. They are still sent: the list
	// informs, the user decides. Requests a crawl would only find by
	// reading an API description are not known to a plan, which sends
	// nothing; a run names those in its summary as it finds them.
	StateChanging []stateChangeEntry `json:"state_changing,omitempty"`
}

// planAXFR is the zone transfer of one name, as dns -axfr would go about it.
// The name servers' addresses are not known before they are looked up, so the
// plan says how they are chosen; the resolvers named are known.
type planAXFR struct {
	Zone      string   `json:"zone"`
	Lookups   string   `json:"lookups"`             // the DNS queries that find the name servers
	Transfer  string   `json:"transfer"`            // the connections it makes, and the ones it does not
	Resolvers []string `json:"resolvers,omitempty"` // the resolvers named: each is asked for the zone as well
}

type planTarget struct {
	Type       types.SeedType `json:"type"`
	Key        string         `json:"key"`
	Collectors []string       `json:"collectors"`
}

// planRequests is what is known of a run's requests before it sends any.
// The queries to third-party sources about the targets listed are known
// exactly. The requests to the targets are not: they follow from the
// names that resolve and what their pages lead to, so the plan gives
// what each web service costs before that, and the cap on them all.
type planRequests struct {
	Sources    map[string]int `json:"source_queries"` // collector → queries about the targets listed
	Total      int            `json:"source_queries_total"`
	NotCounted []string       `json:"source_queries_not_counted,omitempty"` // passive collectors that cannot say before they run
	Found      bool           `json:"found_domains_asked"`                  // domains found on the way are asked about too
	Passive    bool           `json:"passive,omitempty"`                    // none go to the targets
	PerService int            `json:"per_web_service,omitempty"`            // about: its page, the favicon, the built-in paths
	// Guesses are the requests for names nobody gave, on each host, by
	// technique, and the cap on them (-host-guesses; 0: none).
	Guesses  []string `json:"guesses_per_host,omitempty"`
	GuessCap int64    `json:"host_guesses"`
	MaxNames int      `json:"max_names,omitempty"` // names found under the domains looked up at most
	Cap      int64    `json:"cap"`                 // requests to the targets at most; 0: no cap
	CapBy    string   `json:"cap_by,omitempty"`
	scoped   bool
}

// sendLimits are the options that bound or change what a run sends to its
// targets.
type sendLimits struct {
	max          int64  // requests at most; 0: no cap
	by           string // the option that set max
	noFavicon    bool
	chrome       bool   // -browser or -screenshots
	shots        string // -screenshots: the directory the pictures go to
	render       bool   // -browser
	chromeWrites bool   // -browser-writes
	interact     bool   // -interact
	login        string
	loginUser    string
	graphql      bool
	hostGuesses  int64 // -host-guesses; 0: none
	dirsWords    int   // -dirs: words, and extensions besides the bare word
	dirsExts     int
	paramsWords  int // -params: names, and pages searched at most on each host
	paramsPages  int
	submitForms  bool
	dirs         bool
	params       bool
	noThirdParty bool   // -sources none
	paramsBody   string // POST, JSON or XML when -params sends names in a body
	tcpPorts     int    // ports asked on each address (-ports)
	udpPorts     int    // UDP ports asked on each address (-ports-udp)
	portsOn      bool   // some hosts have ports of their own
	portDetect   portscan.Detect
	portPayload  bool
	portDiscover portcol.Discovery
	axfr         bool     // -axfr: plan the zone transfers of dns -axfr too
	verify       bool     // -verify: the enumerated read-only verification checks
	resolvers    []string // the resolvers named (-resolvers)
	paramsN      int      // names of -params
	dirsNoCal    bool     // -dirs-calibrate=false
	// What the cost estimate counts from: the lists themselves, not their sizes.
	portList, portUDPList     []int
	portsFor                  map[string][]int // -ports-on
	portExcludeCDN            bool
	portThreshold             int
	dirsWordList, dirsExtList []string
	guessBudget               int      // -max-names: the most names -dns-brute and -permute ask, 0: no cap
	bruteList                 []string // the words of -dns-brute
	// sendState is -send-state-changing: GETs found on the way whose own name
	// declares a state change are sent, not held back. dirsHeld is how many of
	// the -dirs requests the built-in list makes are held back for it.
	sendState bool
	dirsHeld  int
	dirsHold  bool // the built-in -dirs words that declare a state change are held back
	// What the ceilings are counted with.
	portPasses    int  // the most times a port is asked: 1, and one more for each pass over the silent ones
	portNameAddrs int  // the most addresses of a name that are scanned; 0: every one it has
	dirsDepth     int  // -dirs-depth
	paramsWrites  bool // -params-writes
}

// planSends are the lines on what a run sends besides the GET requests for
// pages, each true of the options given. gets are the techniques that send
// GET requests too; others send something else: a port scan's connects and
// the probes of what answers, UDP datagrams, POST bodies, a sign-in, DNS
// guesses.
func planSends(b engine.Budgets, send sendLimits) (gets, others []string) {
	out := &others
	if send.dirs {
		gets = append(gets, "GET requests for each word of the -dirs wordlist (and each -dirs-ext extension) under each web service")
	}
	if send.params && send.paramsBody == "" {
		gets = append(gets, "GET requests with batches of the -params wordlist as query names")
	}
	if b.Active["ports"] && send.tcpPorts > 0 {
		ports := plural(send.tcpPorts, "port") + " of each address"
		if send.portsOn {
			ports += " (a host given with a port: that port only)"
		}
		line := "TCP connects (full handshakes) to " + ports + " (-ports)"
		switch send.portDiscover {
		case portcol.DiscoverFirst:
			line += ", after a connect to 80 and 443 to tell whether the address is up (-port-discover)"
		case portcol.DiscoverOnly:
			line = "TCP connects to ports 80 and 443 of each address, to tell whether it is up (-port-discover only), and no other port"
		}
		*out = append(*out, line)
		if send.portDiscover != portcol.DiscoverOnly {
			switch send.portDetect {
			case portscan.DetectAll:
				*out = append(*out, "each open port is asked what it is, on connections of their own (-port-detect all): its banner, and for a port that says nothing its protocol's own request on its usual number, one HEAD /, a TLS handshake and one request of each of the other protocols until one answers, then one GET / if nothing named it (at most 25 more connects per port; a GET / for a web page whose head names no product)")
			case portscan.DetectBanner:
				*out = append(*out, "an open port is read for what it says first, and nothing is sent on it (-port-detect banner)")
			default:
				*out = append(*out, "an open port is closed at once (-port-detect none)")
			}
			if send.portPayload {
				*out = append(*out, "the -port-payload text is sent to each open port before it is read")
			}
		}
	}
	if b.Active["ports"] && send.udpPorts > 0 {
		*out = append(*out, fmt.Sprintf("UDP datagrams to %s of each address (-ports-udp): the harmless request of the protocol the port usually carries, and, for a port that stays silent, each other request its protocol has (a port with no known protocol: a DNS query, an SNMP get with community public, memcached's version, an empty datagram)", plural(send.udpPorts, "port")))
	}
	if send.verify {
		for _, c := range verify.Checks() {
			*out = append(*out, fmt.Sprintf("one verification read to each %s service confirmed (-verify %s): sends %s and no credential; precondition: %s", c.Service, c.ID, c.Request, c.Precondition))
		}
		*out = append(*out, "with -advisories, each advisory lead is labelled proved, version-only or conditional from its confirmation read (-verify): the one GET the advisory names, or of /, held to -deny-path like any GET; a data-store read is a TCP connect with no path, held to the scope, the budget, the kill file and the ledger")
	}
	if send.shots != "" {
		*out = append(*out, fmt.Sprintf("Chrome loads the front page of each web service and saves a screenshot in %s (-screenshots, azhaq-shots): it also requests the page's scripts, styles and images, so a page costs more than one GET", send.shots))
	}
	if send.render {
		*out = append(*out, "Chrome loads each page found and reads the links its scripts draw (-browser, azhaq-render): every page costs a GET and the requests its scripts, styles and images make")
	}
	if send.graphql {
		*out = append(*out, fmt.Sprintf("POST requests with a GraphQL introspection query to the GraphQL endpoints found (-graphql): they read the schema and change nothing; at most 2 per endpoint (a page that refuses both the same way is dropped there), and up to %d more when it refuses introspection in words of its own, validation queries with a field no schema has that never run (a GraphiQL page is not asked once another URL of its origin gave the schema whole)", gqlcol.MaxRecoveryPOSTs))
	}
	if send.paramsBody != "" {
		*out = append(*out, fmt.Sprintf("%s requests whose body holds the parameter names guessed (-params-method %s, -params-writes): a body may change data on the target", send.paramsBody, send.paramsBody))
	}
	if send.submitForms {
		*out = append(*out, "POST requests that submit the forms the crawl finds with neutral values (-submit-forms): this changes data on the target")
	}
	if send.login != "" {
		*out = append(*out, fmt.Sprintf("Chrome signs in at %s as %s (-login): the sign-in's POST goes to the target, and the session it gets goes with every request", send.login, send.loginUser))
	}
	if send.chrome && send.interact {
		line := "Chrome clicks the buttons, links and menus of each page (-interact): every click is made, a log out link included, and the GETs it sends are requested like any other"
		if !send.chromeWrites {
			line += "; the writes it would send are refused by their method and mapped, not sent"
		}
		*out = append(*out, line)
	}
	if b.Active["dns-brute"] || b.Active["permute"] {
		var what []string
		if b.Active["dns-brute"] {
			what = append(what, "WORD.domain for each word (-dns-brute)")
		}
		if b.Active["permute"] {
			what = append(what, "variations of the names found (-permute)")
		}
		*out = append(*out, "DNS queries for "+strings.Join(what, " and ")+", to the resolvers: not requests to the targets")
	}
	return gets, others
}

func buildPlan(cat *catalog.Catalog, seeds []types.Seed, b engine.Budgets, paths []string, limits map[string]string, send sendLimits, rep *report) runPlan {
	p := planFor(cat, seeds, b, paths, limits, send, rep)
	if send.axfr {
		p.AXFR, p.Sends = planTransfers(seeds, b, send.resolvers), append(p.Sends, "-axfr (azhaq dns): "+axfrSummary(b))
	}
	if send.noThirdParty {
		p.Sends = append([]string{"-sources none: no third party is asked (no subdomain source, archive, RDAP, RIPEstat or search engine); only the resolvers and the targets get requests"}, p.Sends...)
	}
	return p
}

// axfrSummary says, for a plan's sends, which connections a zone transfer makes.
func axfrSummary(b engine.Budgets) string {
	const asks = "a zone transfer over TCP port 53 to the address of each name server of a domain or host target and to each resolver named; the name servers are found by NS and A queries to the resolvers"
	if b.Scope.Empty() {
		return asks + ". No -allow or -scope is given: a name server is asked when its name is under the target's"
	}
	return asks + ". A name server whose address the scope does not allow (-allow, -scope, -deny; the address, not its name) is not contacted: the summary names it, and adding the address to -allow allows the transfer"
}

// planTransfers lists the zone transfers dns -axfr would try for the names
// among the targets, in the order given.
func planTransfers(seeds []types.Seed, b engine.Budgets, resolvers []string) []planAXFR {
	via := "the resolvers given"
	if len(resolvers) == 0 {
		via = "the default public resolvers"
	}
	transfer := "TCP port 53 of each name server's address, if the scope allows it (that name server is listed in the summary, not contacted)"
	if b.Scope.Empty() {
		transfer = "TCP port 53 of each name server whose name is under the zone's"
	}
	seen := map[string]bool{}
	var out []planAXFR
	for _, s := range engine.ExpandSeeds(seeds) {
		if s.Type != types.TypeDomain && s.Type != types.TypeHostname {
			continue
		}
		name := s.Key()
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, planAXFR{
			Zone:      name,
			Lookups:   "NS of " + name + ", then A of each name server, asked of " + via,
			Transfer:  transfer,
			Resolvers: append([]string(nil), resolvers...),
		})
	}
	return out
}

func planFor(cat *catalog.Catalog, seeds []types.Seed, b engine.Budgets, paths []string, limits map[string]string, send sendLimits, rep *report) runPlan {
	p := runPlan{Collectors: map[string]string{}, Limits: limits, Skipped: slices.Clone(rep.Skipped)}
	p.StateChanging = stateChangesOfSeeds(seeds, b.Scope)
	p.Requests = planRequests{Sources: map[string]int{}, Cap: send.max, scoped: !b.Scope.Empty()}
	if send.max > 0 {
		p.Requests.CapBy = send.by
	}
	notCounted := map[string]bool{}
	eng := &engine.Engine{Cat: cat}
	var kept []types.Seed // the seeds a run would take, with the collectors planned on each
	var planned [][]string
	for _, s := range engine.ExpandSeeds(seeds) {
		if s.Type == types.TypeURL {
			if rule := b.Scope.DeniedPath(s.Key()); rule != "" {
				// A run never requests it: it is left out, with the rule, as run lists it.
				p.Skipped = append(p.Skipped, engine.Skip{Target: s.Key(), Reason: egress.DenyReason(rule)})
				continue
			}
		}
		t := planTarget{Type: s.Type, Key: s.Key()}
		for _, item := range eng.Plan([]types.Seed{s}) {
			col, ok := cat.Get(item.Collector)
			if !ok || !b.Allows(col, s) {
				continue
			}
			if sk, ok := col.(interface{ Skip(types.Seed) bool }); ok && sk.Skip(s) {
				continue
			}
			t.Collectors = append(t.Collectors, item.Collector)
			kind := catalog.InfoOf(col).Kind
			p.Collectors[item.Collector] = collectorRole(kind)
			if kind != catalog.Passive {
				continue
			}
			if a, ok := col.(catalog.Asker); ok {
				if n := len(a.Asks(s)); n > 0 {
					p.Requests.Sources[item.Collector] += n
					p.Requests.Total += n
				}
			} else {
				notCounted[item.Collector] = true
			}
			if s.Type == types.TypeDomain {
				// Names found under another domain (a CNAME's target, a
				// link) bring their domain: the scope decides whether it
				// is asked about, and -depth how far.
				p.Requests.Found = true
				if p.Requests.MaxNames = b.MaxNames; b.MaxNames <= 0 {
					p.Requests.MaxNames = engine.DefaultBudgets().MaxNames
				}
			}
		}
		p.Targets = append(p.Targets, t)
		kept, planned = append(kept, s), append(planned, t.Collectors)
	}
	p.Requests.NotCounted = sortedKeys(notCounted)
	for f, on := range b.Active {
		if on {
			p.Active = append(p.Active, "-"+f)
		}
	}
	sort.Strings(p.Active)
	// What runs on each web service, given or found under a domain.
	service := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://service.invalid/"}}
	runs := func(name string) bool {
		col, ok := cat.Get(name)
		return ok && b.Allows(col, service)
	}
	if runs("azhaq-paths") {
		p.Paths = paths
	}
	asks := func(name string, s types.Seed) int {
		if col, ok := cat.Get(name); ok {
			if a, ok := col.(catalog.Asker); ok {
				return len(a.Asks(s))
			}
		}
		return 0
	}
	env := costEnv{sendLimits: send, rules: b.Scope}
	if runs("azhaq-paths") {
		env.pathList = p.Paths
	}
	p.Estimate = estimateCost(kept, planned, runs, b.Active, env, asks)
	gets, others := planSends(b, send)
	switch {
	case b.Passive && len(others) == 0:
		p.Sends = []string{"nothing to the targets (-passive): third-party sources and DNS only"}
		p.Requests.Passive = true
		return p
	case b.Passive:
		// The techniques below still go to the targets: -passive leaves out the pages.
		p.Sends = append([]string{"no pages are requested (-passive); only what the active techniques send goes to the targets"}, append(gets, others...)...)
		return p
	default:
		p.Sends = []string{"GET requests to the targets and what they lead to inside the scope"}
	}
	if send.sendState {
		p.Sends = append(p.Sends, "azhaq cannot know what a GET does on the server: every URL found in scope is requested, those whose own name declares a state change too (-send-state-changing), and writes (POST, PUT, PATCH, DELETE) only with their flags")
	} else {
		p.Sends = append(p.Sends, "azhaq cannot know what a GET does on the server: every URL found in scope is requested, except a GET whose own path, query or API operation declares a state change (create, delete, reset, logout, action=stop, ...), found on the way or a word of a wordlist you give: it is held back and listed as skipped ("+neterr.SendFlag+" sends it), and writes (POST, PUT, PATCH, DELETE) only with their flags")
	}
	for _, rule := range b.Scope.DenyPath {
		p.Sends = append(p.Sends, "never requested, by any collector or Chrome: a URL whose path or query matches -deny-path "+rule)
	}
	switch {
	case send.chrome && send.chromeWrites:
		p.Sends = append(p.Sends, "Chrome lets pages send their writes (-browser-writes): the POST, PUT and DELETE their scripts send change data on the target")
	case send.chrome:
		p.Sends = append(p.Sends, "Chrome sends GET, HEAD and OPTIONS only, except signing in: the writes pages would send are mapped and listed, not sent (-browser-writes to send them)")
	}
	p.Sends = append(append(p.Sends, gets...), others...)
	p.Requests.GuessCap = send.hostGuesses
	p.Requests.Guesses = planGuesses(p.Paths, send)
	if runs("azhaq-http") {
		p.Requests.PerService = 1 + len(p.Paths)
		if !send.noFavicon {
			p.Requests.PerService++
		}
	}
	return p
}

// planGuesses says what each technique that guesses names sends to one host,
// before any answer shortens it.
func planGuesses(paths []string, send sendLimits) []string {
	var out []string
	if len(paths) > 0 {
		out = append(out, fmt.Sprintf("%s, one each, on each web service (-no-paths turns them off)", plural(len(paths), "built-in path check")))
	}
	if send.dirs {
		line := fmt.Sprintf("-dirs: %s on each web service (every word, and each of %s)", plural(send.dirsWords*(1+send.dirsExts)-send.dirsHeld, "request"), plural(send.dirsExts, "extension"))
		if send.dirsHeld > 0 {
			line += fmt.Sprintf("; %d more of the wordlist name a state change and are held back (%s sends them)", send.dirsHeld, neterr.SendFlag)
		}
		out = append(out, line)
	}
	if send.params {
		per := 3 + (send.paramsWords+499)/500
		out = append(out, fmt.Sprintf("-params: on at most %s of a host, each at least %d requests for its %s (groups of 500 names; a group that changes the answer is narrowed down, so more); pages beyond are listed as not searched (-params-per-host), and pages a request of the run showed to read no name are not searched at all (-params-all)", plural(send.paramsPages, "page"), per, plural(send.paramsWords, "name")))
	}
	if send.graphql {
		out = append(out, fmt.Sprintf("-graphql: at most 2 per endpoint; one that refuses both queries the same way gets no more and is named in the summary; one whose introspection is off gets up to %d more", gqlcol.MaxRecoveryPOSTs))
	}
	if send.hostGuesses > 0 {
		out = append(out, fmt.Sprintf("-host-guesses %d: no host is sent more than that of them together; the rest are not asked, the summary lists them, and the run exits 4 (azhaq resume asks them with a larger value)", send.hostGuesses))
	} else if len(out) > 0 {
		out = append(out, "no cap on them (-host-guesses sets one for each host)")
	}
	return out
}

func collectorRole(k catalog.Kind) string {
	switch k {
	case catalog.Passive:
		return "asks third parties or DNS resolvers, not the target"
	case catalog.Active:
		return "active: sends many requests to the target"
	default:
		return "sends requests to the target"
	}
}

func printPlan(p runPlan, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	printPlanText(os.Stdout, p)
	return nil
}

// printPlanText is the plan in plain text on w.
func printPlanText(w io.Writer, p runPlan) {
	if len(p.Targets) == 0 {
		fmt.Fprintln(w, "targets (0): nothing to do")
	}
	fmt.Fprintf(w, "targets (%d)\n", len(p.Targets))
	for _, t := range p.Targets {
		fmt.Fprintf(w, "  %s %s: %s\n", t.Type, t.Key, strings.Join(t.Collectors, " "))
	}
	if len(p.AXFR) > 0 {
		fmt.Fprintf(w, "zone transfers (%d, -axfr)\n", len(p.AXFR))
		for _, x := range p.AXFR {
			fmt.Fprintf(w, "  %s: %s; then %s", x.Zone, x.Lookups, x.Transfer)
			if len(x.Resolvers) > 0 {
				fmt.Fprintf(w, "; also each resolver named: %s", strings.Join(x.Resolvers, ", "))
			}
			fmt.Fprintln(w)
		}
	}
	if len(p.Skipped) > 0 {
		fmt.Fprintf(w, "left out (%d)\n", len(p.Skipped))
		for _, s := range p.Skipped {
			fmt.Fprintf(w, "  %s: %s\n", s.Target, s.Reason)
		}
	}
	if len(p.StateChanging) > 0 {
		fmt.Printf("requests that may change state (%d; named by their own path, and sent because you gave them as targets)\n", len(p.StateChanging))
		for _, e := range p.StateChanging {
			fmt.Printf("  %s\n", e.line())
		}
	}
	names := make([]string, 0, len(p.Collectors))
	for n := range p.Collectors {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintln(w, "collectors")
	for _, n := range names {
		fmt.Fprintf(w, "  %-18s %s\n", n, p.Collectors[n])
	}
	if len(p.Paths) > 0 {
		fmt.Fprintf(w, "built-in path checks on each web service (%d; -no-paths turns them off): %s\n", len(p.Paths), strings.Join(p.Paths, " "))
	}
	active := "none"
	if len(p.Active) > 0 {
		active = strings.Join(p.Active, " ")
	}
	fmt.Fprintf(w, "active techniques (wordlists, ports, introspection; besides the built-in path checks): %s\n", active)
	var lim []string
	for _, k := range []string{"depth", "max-items", "max-requests", "rate", "timeout", "daily-requests"} {
		lim = append(lim, k+" "+p.Limits[k])
	}
	fmt.Fprintf(w, "limits: %s\n", strings.Join(lim, ", "))
	for _, s := range p.Sends {
		fmt.Fprintf(w, "sends: %s\n", s)
	}
	printRequests(w, p)
	printEstimate(w, "estimate: ", p.Estimate)
}

// printRequests says what is known of the requests before any is sent:
// the source queries exactly, the requests to the targets as a bound.
func printRequests(w io.Writer, p runPlan) {
	r := p.Requests
	var by []string
	for _, n := range slices.Sorted(maps.Keys(r.Sources)) {
		by = append(by, fmt.Sprintf("%s %d", n, r.Sources[n]))
	}
	switch {
	case len(by) > 0:
		fmt.Fprintf(w, "source queries: %d about the targets above (%s)\n", r.Total, strings.Join(by, ", "))
	case len(r.NotCounted) > 0:
		fmt.Fprintln(w, "source queries:")
	default:
		fmt.Fprintln(w, "source queries: none")
	}
	for _, n := range r.NotCounted {
		fmt.Fprintf(w, "  %s: not counted; it does not say which sources it asks before it runs\n", n)
	}
	switch {
	case r.Found && r.scoped:
		fmt.Fprintln(w, "  domains found on the way are asked about too, inside the scope")
	case r.Found:
		fmt.Fprintln(w, "  domains found on the way are asked about too (no scope: -depth bounds how far, and -allow keeps them to yours)")
	}
	if r.Passive {
		fmt.Fprintln(w, "requests to the targets: none (-passive)")
		return
	}
	if r.Cap > 0 {
		fmt.Fprintf(w, "requests to the targets: at most %d (%s)\n", r.Cap, r.CapBy)
	} else {
		fmt.Fprintln(w, "requests to the targets: no cap (-max-requests sets one)")
	}
	if r.PerService > 0 {
		names := "the names that resolve and answer"
		if r.MaxNames > 0 {
			names = fmt.Sprintf("how many names resolve and answer (up to %d are looked up, -max-names)", r.MaxNames)
		}
		what := fmt.Sprintf("its page, %d built-in paths", len(p.Paths))
		if r.PerService > 1+len(p.Paths) {
			what = fmt.Sprintf("its page, the favicon, %d built-in paths", len(p.Paths))
		}
		fmt.Fprintf(w, "  how many depends on %s: about %d per web service (%s), then what its pages, scripts and archived URLs lead to\n", names, r.PerService, what)
	}
	if len(p.Active) > 0 {
		fmt.Fprintf(w, "  %s add their own\n", strings.Join(p.Active, " "))
	}
	if len(r.Guesses) > 0 {
		fmt.Fprintln(w, "guesses sent to each host (requests for names nobody gave):")
		for _, g := range r.Guesses {
			fmt.Fprintf(w, "  %s\n", g)
		}
	}
}

func limitsOf(b engine.Budgets, maxRequests int64, rate float64, timeout time.Duration, daily int64) map[string]string {
	none := func(ok bool, s string) string {
		if !ok {
			return "none"
		}
		return s
	}
	return map[string]string{
		"depth":          fmt.Sprint(b.MaxDepth),
		"max-items":      none(b.MaxItems > 0, fmt.Sprint(b.MaxItems)),
		"max-requests":   none(maxRequests > 0, fmt.Sprint(maxRequests)),
		"rate":           none(rate > 0, fmt.Sprintf("%g/s", rate)),
		"timeout":        none(timeout > 0, timeout.String()),
		"daily-requests": none(daily > 0, fmt.Sprint(daily)),
	}
}
