package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/dirscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
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
// (TCP connections and UDP datagrams) to them, DNS queries to resolvers, and
// questions to third-party sources. The first two add up to the summary's
// requests.
type amount struct {
	Requests int64 `json:"requests,omitempty"`
	Connects int64 `json:"connects,omitempty"`
	DNS      int64 `json:"dns_queries,omitempty"`
	Sources  int64 `json:"source_queries,omitempty"`
}

func (a amount) zero() bool { return a == amount{} }

// contacts is everything that goes to a target or a resolver, the number the
// size of a run is judged by.
func (a amount) contacts() int64 { return a.Requests + a.Connects + a.DNS }

func (a *amount) add(b amount) {
	a.Requests += b.Requests
	a.Connects += b.Connects
	a.DNS += b.DNS
	a.Sources += b.Sources
}

func (a amount) String() string {
	var parts []string
	for _, p := range []struct {
		n         int64
		one, many string
	}{{a.Requests, "request", "requests"}, {a.Connects, "connect", "connects"}, {a.DNS, "DNS query", "DNS queries"}, {a.Sources, "source query", "source queries"}} {
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
}

// costCollector is the same for one collector of a stage.
type costCollector struct {
	Collector string  `json:"collector"`
	Estimate  *amount `json:"estimate,omitempty"`
	Actual    *amount `json:"actual,omitempty"`
}

// costEstimate is what a run would send, by stage, from its flags and targets.
type costEstimate struct {
	Total  amount      `json:"total"`
	Stages []costStage `json:"stages"`
	// AtLeast: some stage leaves out what its answers lead to (the links of
	// a page, the names a source gives), so a run may send more than Total.
	AtLeast bool   `json:"at_least,omitempty"`
	Basis   string `json:"basis"`
}

const rolesBasis = "from the roles, their histories and the run options: each stage counts what they fix, as if each target answers, and says what it leaves out"

const estimateBasis = "from the flags and the targets given, as if each target answers: the same wordlists, port lists and built-in checks the run sends; what a page, a script or a source's answer leads to is not known before it is read, and each stage says what it leaves out"

// trivialRun is the size under which run does not print its estimate before it
// sends: requests, connects and DNS queries together.
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

// stageOfCollector groups a collector into the stage of a run that it works in.
func stageOfCollector(name string) string {
	switch strings.TrimPrefix(name, "azhaq-") {
	case "subdomains", "urls", "rdap", "search":
		return "sources"
	case "dns", "dns-brute", "permute", "asn", "prefix", "ptr":
		return "names"
	case "http", "paths", "crawl", "js", "tls", "openapi", "graphql", "graphql-schema", "render":
		return "map"
	case "ports":
		return "ports"
	case "dirs":
		return "dirs"
	case "params":
		return "params"
	case "shots":
		return "screenshots"
	case "advisories":
		return "advisories"
	case "notify":
		return "notify"
	case signInStage:
		return signInStage
	}
	return "other"
}

// stageOrder is how stages are listed: the order a run goes through them.
var stageOrder = []string{signInStage, "sources", "names", "map", "ports", "dirs", "params", "screenshots", "advisories", "notify",
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
	paths     int // built-in path checks on each web service; 0 when azhaq-paths does not run
	favicon   bool
	dirsWords int // words of -dirs
	dirsExts  int // -dirs-ext extensions
	paramsN   int // names of -params
	bruteN    int // words of -dns-brute
}

// estimator accumulates the estimate: stage → collector → amount.
type estimator struct {
	stages  map[string]*costStage
	notes   map[string]map[string]bool
	coll    map[string]map[string]*amount
	atLeast bool
}

func newEstimator() *estimator {
	return &estimator{stages: map[string]*costStage{}, notes: map[string]map[string]bool{}, coll: map[string]map[string]*amount{}}
}

// add puts a into the stage of collector, with what it leaves out (open).
func (e *estimator) add(collector string, a amount, open string) {
	st := stageOfCollector(collector)
	e.put(st, collector, a, open)
}

func (e *estimator) put(stage, collector string, a amount, open string) {
	if e.stages[stage] == nil {
		e.stages[stage] = &costStage{Stage: stage, Estimate: &amount{}}
		e.coll[stage] = map[string]*amount{}
		e.notes[stage] = map[string]bool{}
	}
	e.stages[stage].Estimate.add(a)
	if e.coll[stage][collector] == nil {
		e.coll[stage][collector] = &amount{}
	}
	e.coll[stage][collector].add(a)
	if open != "" {
		e.notes[stage][open] = true
		e.stages[stage].AtLeast = true
		e.atLeast = true
	}
}

func (e *estimator) result() costEstimate {
	out := costEstimate{AtLeast: e.atLeast, Basis: estimateBasis}
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
				st.Collectors = append(st.Collectors, costCollector{Collector: c, Estimate: &a})
			}
		}
		out.Total.add(*st.Estimate)
		out.Stages = append(out.Stages, st)
	}
	return out
}

// estimateCost is what a run of seeds would send, for the collectors planned
// on each. planned[i] are the collectors planFor found for seeds[i]; runs says
// whether a collector would run on a web service found.
func estimateCost(seeds []types.Seed, planned [][]string, runs func(string) bool, active map[string]bool, env costEnv, asks func(collector string, s types.Seed) int) costEstimate {
	e := newEstimator()
	has := func(i int, c string) bool {
		for _, n := range planned[i] {
			if n == c {
				return true
			}
		}
		return false
	}
	permuteNoted := false
	services := 0 // web services known: the URLs given, and the names given, which are asked to answer
	for i, s := range seeds {
		for _, c := range planned[i] {
			switch c {
			case "azhaq-subdomains", "azhaq-urls", "azhaq-rdap", "azhaq-search":
				if n := asks(c, s); n > 0 {
					e.add(c, amount{Sources: int64(n)}, "names and archived URLs found are asked about too")
				}
			case "azhaq-dns":
				e.add(c, amount{DNS: 2}, "wildcard checks and CNAME chains")
			case "azhaq-dns-brute":
				e.add(c, amount{DNS: int64(env.bruteN)}, "")
			case "azhaq-permute":
				// The variations of a name given are known; the names a source or
				// a lookup gives later bring variations of their own.
				e.add(c, amount{DNS: int64(brutecol.PermuteCount(s.Key()))}, permuteOpen)
				permuteNoted = true
			case "azhaq-tls":
				e.add(c, amount{Connects: 1}, "")
			case "azhaq-ports":
				e.add(c, portCost(env), "banner and protocol probes of each open port")
			}
		}
		switch s.Type {
		case types.TypeURL:
			services++
		case types.TypeHostname:
			if has(i, "azhaq-http") {
				services++
			}
		}
	}
	if active["permute"] && !permuteNoted {
		for _, s := range seeds {
			if s.Type == types.TypeDomain || s.Type == types.TypeHostname {
				e.add("azhaq-permute", amount{}, permuteOpen)
				break
			}
		}
	}
	if runs("azhaq-http") && services > 0 {
		n := int64(services)
		per := int64(1)
		if env.favicon {
			per++
		}
		e.add("azhaq-http", amount{Requests: n * per}, "what its pages, scripts and archived URLs lead to")
	}
	if runs("azhaq-paths") && services > 0 && env.paths > 0 {
		e.add("azhaq-paths", amount{Requests: int64(services) * int64(env.paths)}, "the documentation paths under each API prefix the pages name")
	}
	if active["dirs"] && services > 0 && env.dirsWords > 0 {
		per := int64(env.dirsWords) * int64(1+env.dirsExts)
		if !env.dirsNoCal {
			per += int64(dirscol.CalibrationProbes(env.dirsExts))
		}
		e.add("azhaq-dirs", amount{Requests: int64(services) * per}, "each directory found is swept and calibrated too")
	}
	if active["params"] && services > 0 && env.paramsN > 0 {
		e.add("azhaq-params", amount{}, "pages searched, up to -params-per-host a host, each asked in batches of the wordlist")
	}
	if env.login != "" {
		e.put("sign-in", "chrome", amount{Requests: 3}, "the sign-in page's scripts, styles and images")
	}
	return e.result()
}

// permuteOpen is what -permute's estimate leaves out: the names the sources
// and the lookups give are not known before they answer.
const permuteOpen = "variations of the names the sources and lookups find (-permute)"

// portCost is what one address costs the port scan: a connect for each port,
// the two that tell whether it is up first, the datagrams of -ports-udp.
func portCost(env costEnv) amount {
	n := int64(env.tcpPorts)
	switch env.portDiscover {
	case portcol.DiscoverFirst:
		n += 2
	case portcol.DiscoverOnly:
		n = 2
	}
	return amount{Connects: n + int64(env.udpPorts)}
}

// printEstimate says the estimate in plain text, one line a stage.
func printEstimate(w io.Writer, lead string, est costEstimate) {
	fmt.Fprintln(w, lead+est.Total.String()+atLeastWord(est.AtLeast))
	for _, st := range est.Stages {
		line := fmt.Sprintf("  %-12s %s", st.Stage, st.Estimate)
		var by []string
		for _, c := range st.Collectors {
			if len(st.Collectors) > 1 && c.Estimate != nil && !c.Estimate.zero() {
				by = append(by, fmt.Sprintf("%s %d", strings.TrimPrefix(c.Collector, "azhaq-"), c.Estimate.contacts()+c.Estimate.Sources))
			}
		}
		if len(by) > 0 {
			line += " (" + strings.Join(by, ", ") + ")"
		}
		if st.NotCounted != "" {
			line += "; not counted: " + st.NotCounted
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "  "+est.Basis)
}

func atLeastWord(atLeast bool) string {
	if atLeast {
		return ", and what the answers lead to"
	}
	return ""
}

// spentAmount is what an account (ledger.Account, as a difference) holds for
// one stage and collector: the requests, connects, DNS queries and source
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
		case k.Kind == "tcp" || k.Kind == "udp":
			a.Connects += n
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
	return stageOfCollector(k.Collector)
}

// costReport is the summary's account of the cost: what each stage was
// estimated to send, and what it sent.
type costReport struct {
	Estimate *amount     `json:"estimate,omitempty"` // the total, when the command estimated
	AtLeast  bool        `json:"estimate_at_least,omitempty"`
	Actual   amount      `json:"actual"`
	Stages   []costStage `json:"stages"`
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
			line += fmt.Sprintf(" (estimated %s%s)", st.Estimate, map[bool]string{true: " and what the answers lead to"}[st.AtLeast])
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
