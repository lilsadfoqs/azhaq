package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// subsMode is what subs tells the run it starts.
var subsMode struct {
	NoCheck bool // names only guessed or only remembered are listed unverified, not looked up
	// GuessSamples is -guess-samples: the most samples of guesses taken, with no time budget.
	GuessSamples int
	Recursive    bool // only the sources that handle subdomains of subdomains
	// NoGuessCheck is -live -guesses=false: subdomain.center's guesses are not looked up.
	NoGuessCheck bool
}

// subsOut writes the names subs prints: text, subfinder's host,[sources] and
// host,ip,source forms, or JSON; with -oD also a file per domain.
type subsOut struct {
	w        *writer
	cs, oI   bool
	dir      string
	perInput map[string]*bytes.Buffer
	live     bool
	// takeover is the candidates DNS found, by name: -json rows carry them.
	takeover map[string]takeoverRow
}

func (o *subsOut) put(input, name string, row map[string]any, ips, by []string) {
	if t, ok := o.takeover[name]; ok && o.w.json {
		row["takeover"] = t.Finding
	}
	var line string
	switch {
	case o.w.json:
		raw, _ := json.Marshal(row)
		line = string(raw)
	case o.oI:
		ip := ""
		if len(ips) > 0 {
			ip = ips[0]
		}
		src := ""
		if len(by) > 0 {
			src = by[0]
		}
		line = name + "," + ip + "," + src
	case o.cs:
		line = name + ",[" + strings.Join(by, ",") + "]"
	default:
		line = name
	}
	if o.w.json {
		o.w.obj(row)
	} else {
		o.w.line(line)
	}
	if o.dir != "" {
		b := o.perInput[input]
		if b == nil {
			b = &bytes.Buffer{}
			o.perInput[input] = b
		}
		b.WriteString(line + "\n")
	}
}

// files writes the -oD files: one per domain, even when it has no names.
func (o *subsOut) files(domains []string, ext string) error {
	if o.dir == "" {
		return nil
	}
	if err := os.MkdirAll(o.dir, 0o755); err != nil {
		return err
	}
	for _, d := range domains {
		b := o.perInput[d]
		if b == nil {
			b = &bytes.Buffer{}
		}
		if err := os.WriteFile(filepath.Join(o.dir, d+ext), b.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// printSources is -ls: the sources, with subfinder's marks (* needs a key,
// ~ takes one), or one JSON object each.
func printSources(asJSON bool) {
	list := subcol.Sources()
	for _, s := range list {
		switch {
		case asJSON:
			raw, _ := json.Marshal(s)
			fmt.Println(string(raw))
		case s.KeyRequirement == "required":
			fmt.Println(s.Name + " *")
		case s.KeyRequirement == "optional":
			fmt.Println(s.Name + " ~")
		default:
			fmt.Println(s.Name)
		}
	}
}

// cmdSubs is subfinder (and subfinder | dnsx with -live; with -w and
// -permute, puredns and alterx too).
func cmdSubs(args []string) error {
	fs := newFlags("subs")
	var c common
	c.register(fs)
	var domains stringsFlag
	fs.Var(&domains, "d", "domain (repeatable; a comma list, a URL or a name with a trailing dot is cleaned, as subfinder does)")
	list := onceString(fs, "dL", "file of domains (- for stdin)")
	live := fs.Bool("live", false, "only names that resolve (wildcard answers left out, tier \"dns\"); without it nothing is looked up and every name the sources gave is printed as a candidate (-json: \"tier\": \"candidate\"), the ones no source asserted (subdomain.center's guesses, the name history's) marked \"unverified\": true")
	guesses := fs.Bool("guesses", true, "print the names only subdomain.center guessed, which no source asserted and no lookup checked, as candidates marked \"unverified\": true; -guesses=false holds them back and counts them, and with -live leaves them unlooked (no query is sent for them); an explicit -guesses cannot go with -live, which looks them up by default")
	nW := fs.Bool("nW", false, "same as -live (subfinder's name)")
	httpTier := fs.Bool("http", false, "also ask each live name's web service one request (GET /, as azhaq probe does) and mark the names that answered \"tier\": \"http\"; sends requests to the names, so it is off by default; implies -live (-web-ports names the ports)")
	words := fs.String("w", "", "also resolve WORD.domain for each word in this file, like puredns bruteforce (active DNS; the names found are live)")
	guessSamples := fs.Int("guess-samples", 0, fmt.Sprintf("take up to N samples of subdomain.center's guesses while each has a new name that resolves (with -live) or the names seen are not yet most of its pool, with no time budget (default: the first sample, which is what subfinder | dnsx checks, then with -live more for %s at most, up to %d; without -live one)", subcol.SampleBudget(), subcol.SampleRounds()))
	permute := fs.Bool("permute", false, "also resolve variations of the names found (api → api-dev, api2, dev.api), like alterx | dnsx (active DNS)")
	oJ := fs.Bool("oJ", false, "same as -json (subfinder's name)")
	ls := fs.Bool("ls", false, "list the sources and exit: name, then * if a key is required and ~ if one improves the answer; with -json one object each (name, default, recursive, keyRequirement)")
	cs := fs.Bool("cs", false, "text output: host,[source,source] (subfinder -cs)")
	oI := fs.Bool("oI", false, "text output: host,ip,source, with -live (subfinder -oI); -json rows get an ip field")
	oD := fs.String("oD", "", "write one file per domain into this directory (NAME.txt, NAME.json with -json), as well as stdout")
	var match, filter, matchRe, filterRe stringsFlag
	fs.Var(&match, "m", "only names matching these (comma list or file; * matches anything), as subfinder -m")
	fs.Var(&filter, "f", "leave out names matching these (comma list or file), as subfinder -f")
	fs.Var(&matchRe, "match-regex", "only names matching this regular expression (repeatable)")
	fs.Var(&filterRe, "filter-regex", "leave out names matching this regular expression (repeatable)")
	fresh := fs.Bool("fresh", false, "with -db: start a run of its own and ask the sources again, where the workspace holds a stopped -live run of these domains whose unchecked names the command would otherwise check without asking the sources")
	_ = fs.Bool("ei", false, "accepted for subfinder's sake: an IP address given as a domain is always left out with a note")
	recursive := fs.Bool("recursive", false, "only sources that look for subdomains of subdomains, as subfinder -recursive (see -ls)")
	stats := fs.Bool("stats", false, "after the run, one note per source: requests, names, errors and seconds, as subfinder -stats")
	showVersion := fs.Bool("version", false, "print the version and exit")
	given := inherit(fs, "sources", "exclude-sources", "all-sources", "no-history", "history-dir", "source-timeout", "extra-wait", "providers", "resolvers", "dns-rate", "timeout", "v", "fail-on-errors",
		"source-rate", "source-rates", "max-results", "max-time", "max-body", "proxy=source-proxy", "t=parallel", "ledger", "web-ports", "http-proxy=proxy",
		"scope", "program", "allow", "deny")
	maxNames := fs.Int("max-names", 0, fmt.Sprintf("most names kept per domain, and looked up with -live (default %d); a value you give also caps the names -w and -permute ask, together: the guesses past it are not asked, the run exits 4 and says how many", subcol.DefaultMaxNames))
	if err := parse(fs, args); err != nil {
		return err
	}
	if *oJ {
		c.json = true
	}
	if *showVersion {
		fmt.Println("azhaq " + version)
		return nil
	}
	if *ls {
		printSources(c.json)
		return nil
	}
	if hasFlag(args, "guesses") && *guesses && (*live || *nW) {
		return usagef("-guesses prints names that no lookup checked, and -live looks them up and keeps the ones that resolve: use one of them (-live -guesses=false leaves the guesses out unlooked)")
	}
	if *guessSamples < 0 {
		return usagef("-guess-samples is not negative")
	}
	if *oI && !(*live || *nW) {
		return usagef("-oI prints the address, so it needs -live (or -nW)")
	}
	*live = *live || *nW || *httpTier
	filt, err := compileSubsFilter(listOrFile(match), listOrFile(filter), matchRe, filterRe)
	if err != nil {
		return usagef("%v", err)
	}
	filtering := len(match)+len(filter)+len(matchRe)+len(filterRe) > 0
	raw, err := inputs(domains, *list)
	if err != nil {
		return err
	}
	ds, dnotes := subsDomains(raw)
	if len(raw) == 0 {
		return usagef("give -d DOMAIN, -dL FILE or domains on stdin")
	}
	if len(ds) == 0 {
		return usagef("no domain such as example.com in the input (%s)", strings.Join(dnotes, "; "))
	}
	rep := newReport("subs")
	rep.what = "names"
	rep.Notes = append(rep.Notes, dnotes...)
	keep := []string{"azhaq-subdomains"}
	active := *words != "" || *permute
	if *live || active {
		keep = append(keep, "azhaq-dns")
	}
	if *httpTier {
		keep = append(keep, "azhaq-http")
	}
	if *live {
		rep.what = "live names"
	}
	run := []string{"-passive"}
	if *httpTier {
		run = nil // the requests to the names are asked for
	}
	if *words != "" {
		keep = append(keep, "azhaq-dns-brute")
		run = append(run, "-dns-brute", *words)
	}
	if *permute {
		keep = append(keep, "azhaq-permute")
		run = append(run, "-permute")
	}
	run = append(run, "-skip", skipAllBut(keep...))
	var apexes []string
	userScope := hasFlag(args, "allow", "scope")
	rules, err := flagScope(fs)
	if err != nil {
		return err
	}
	for _, d := range ds {
		apexes = append(apexes, d)
		run = append(run, "-domain", d)
		if active && !userScope {
			// The domains given are the scope of the guesses, unless the user gave one.
			run = append(run, "-allow", d)
		}
	}
	if !*live && !active {
		// The names are known once the sources answer: no DNS to wait for.
		run = append(run, "-depth", "0")
	}
	extra := given()
	if *maxNames > 0 {
		extra = append(extra, "-max-names="+fmt.Sprint(*maxNames))
	}
	// A stopped run of this workspace keeps the names it did not check: the
	// run goes on from them, and the sources, which answered, are not asked.
	if sr, ok := stoppedSubsRun(c.db, apexes, skipAllBut(keep...)); ok && (*live || active) && !*fresh {
		extra = append(extra, "-resume-run", sr.run)
		rep.Notes = append(rep.Notes, sr.note(c.db))
	}
	subsMode.NoCheck, subsMode.Recursive, subsMode.GuessSamples = !*live && !active, *recursive, *guessSamples
	subsMode.NoGuessCheck = (*live || active) && !*guesses
	// The output is opened before anything is sent: a bad -o is not found out
	// after the run. Without -live a domain's names are printed when its
	// sources have answered, as subfinder prints a domain when it ends.
	c.appendOut = true // subfinder's -o appends
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	out := &subsOut{w: w, cs: *cs, oI: *oI, dir: *oD, perInput: map[string]*bytes.Buffer{}, live: *live}
	var alive map[string]map[string]any
	// dangling: names that are a CNAME whose chain ends without an address.
	// They exist in DNS, as dnsx -cname lists them, and are marked "cname_only":
	// a takeover lead when the target is gone.
	var dangling map[string]map[string]any
	cnameOnly, cnameOnlySrc := 0, 0
	seen := map[string]bool{}
	dnsTier := map[string]bool{}     // printed rows a DNS lookup confirmed
	var answeredHTTP map[string]bool // with -http: the names a request got an answer from
	httpTier2 := map[string]bool{}   // printed rows an HTTP answer confirmed
	answered, ran, failedOff := 0, 0, 0
	verbose := hasFlag(extra, "v")
	private := map[string]bool{}
	collected := map[string]bool{} // every passive name, before the -live filter
	bySource := map[string]int{}   // how many each source returned
	var union, dropped, unverified, heldBack, notChecked, filtered, dup, cut, didNot, itself, notAsked, noAnswer, heldOut int
	var poolKept, poolDropped int         // of the names only a padding source or the history held, how many resolved and how many did not
	lookupsFailed := false                // a source says its names were not checked because the lookups failed
	notCheckedWhy := map[string]bool{}    // why names no lookup checked were not (the run's own words)
	var answers map[string]map[string]any // every name DNS was asked: a name missing was not
	noAnswerBy := map[[2]string]int{}
	health := newHealthTally(false)
	var procMu sync.Mutex
	processed := map[string]bool{}
	process := func(p map[string]any) {
		procMu.Lock()
		defer procMu.Unlock()
		input, _ := p["domain"].(string)
		if processed[input] {
			return
		}
		processed[input] = true
		foundBy, _ := p["found_by"].(map[string]any)
		srcs, _ := p["sources"].(map[string]any)
		health.add(input, srcs)
		union += intOf(p["from_sources"])
		dropped += intOf(p["dropped"])
		cut += intOf(p["names_cut"])
		if why, _ := p[subcol.UncheckedWhyKey].(string); why != "" {
			notCheckedWhy[why] = true
		}
		unver := map[string]bool{}
		for _, n := range strs(p["unverified"]) {
			unver[n] = true
		}
		guess := map[string]bool{}
		for _, n := range strs(p["guesses"]) {
			guess[n] = true
		}
		wild := map[string]bool{}
		for _, n := range strs(p["wildcard_certificate"]) {
			wild[n] = true
		}
		for name, v := range srcs {
			row, _ := v.(map[string]any)
			if strings.HasPrefix(fmt.Sprint(row["skipped"]), "not a public domain") && !private[input] {
				private[input] = true
				rep.Notes = append(rep.Notes, input+": not a public domain, so no third-party source was asked (its TLD has no registry); -w or the name history find its names")
			}
			if name == "history" {
				continue // a local file, not a source that was asked
			}
			if row["skipped"] == nil {
				ran++
				if row["error"] == nil || (intOf(row[subcol.NotCheckedKey]) > 0 && allAnswered(answers, strs(p["unverified"]))) {
					// Names it left unchecked, that a continued run has since
					// looked up, are not a failure of the source.
					answered++
				} else if row["default"] == false {
					failedOff++ // -all-sources reaches for flaky ones: counted apart
				}
			}
			if e, _ := row["error"].(string); strings.Contains(e, "the DNS lookups failed") {
				lookupsFailed = true
			}
			if n, _ := row["partial"].(string); n != "" {
				rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %s gave a partial answer: %s", input, name, n))
			}
			if row["rate_limited"] == true {
				rep.Notes = append(rep.Notes, rateLimitNote(input, name, row))
			}
		}
		kept, gone := 0, 0
		for _, v := range srcs {
			if row, _ := v.(map[string]any); row["dropped_unresolved"] != nil {
				kept, gone = max(kept, intOf(row["kept"])), max(gone, intOf(row["dropped_unresolved"])) // one pool, shared by its rows
			}
		}
		poolKept, poolDropped = poolKept+kept, poolDropped+gone
		if verbose {
			rep.Notes = append(rep.Notes, sourceDetail(input, srcs))
		}
		if n := slowSource(input, srcs); n != "" {
			rep.Notes = append(rep.Notes, n)
		}
		if *stats {
			rep.Notes = append(rep.Notes, sourceStats(input, srcs)...)
		}
		if n := guessCheck(input, srcs); n != "" {
			rep.Notes = append(rep.Notes, n)
		}
		if n := samplingNote(input, srcs); n != "" {
			rep.Notes = append(rep.Notes, n)
		}
		for name, by := range foundBy {
			if name == input {
				continue
			}
			for _, s := range strs(by) {
				bySource[s]++ // sources credited with a name Azhaq kept
			}
		}
		for _, name := range strs(p["names"]) {
			if name == input {
				// The domain given is the target, not one of its subdomains
				// (subfinder keeps only names below it); run's map has it.
				itself++
				continue
			}
			collected[name] = true
			switch {
			case !rules.Empty() && !rules.Allows(name):
				heldOut++ // the user's -allow, -deny or -scope: no query, no row
				continue
			case seen[name]:
				dup++
				continue
			case !filt.keep(name):
				filtered++
				continue
			case guess[name] && !*guesses:
				// No source asserted it and nothing looked it up: not printed.
				heldBack++
				continue
			case alive != nil && alive[name] == nil && dangling[name] == nil:
				switch ans := answers[name]; {
				case (unver[name] || guess[name]) && (ans == nil || ans["degraded"] == true):
					// A guess is checked only by a lookup stored in the run: one the guess
					// check saw resolve, that the run stopped before recording, is not.
					notChecked++
				case ans == nil:
					notAsked++ // the run stopped before its answer came
				case ans["degraded"] == true:
					noAnswer++
					resolver, why := dnsAnswerText(ans)
					noAnswerBy[[2]string{resolver, why}]++
				default:
					didNot++
				}
				continue
			}
			seen[name] = true
			// A live row was looked up, whatever the source's own check could not do.
			isUnver := unver[name] && alive == nil
			if isUnver {
				unverified++
			}
			by := strs(foundBy[name])
			row := map[string]any{"host": name, "input": input}
			if len(by) > 0 {
				row["source"], row["sources"] = by[0], by
			}
			if isUnver {
				row["unverified"] = true
			}
			row["tier"] = tierCandidate
			if alive != nil {
				row["tier"] = tierDNS
				dnsTier[name] = true
				if answeredHTTP[name] {
					row["tier"] = tierHTTP
					httpTier2[name] = true
				}
			}
			if wild[name] {
				row["wildcard_certificate"] = true
			}
			var ips []string
			if alive != nil {
				var only bool
				if ips, only = liveRow(row, alive, dangling, name); only {
					cnameOnly++
					cnameOnlySrc++
				}
				if *oI && len(ips) > 0 {
					row["ip"] = ips[0]
				}
			}
			out.put(input, name, row, ips, by)
		}
	}
	var observe func(types.Entity, types.Observation)
	if !*live {
		observe = func(_ types.Entity, o types.Observation) {
			if o.Collector != "azhaq-subdomains" || o.Kind != "subdomains" {
				return
			}
			var p map[string]any
			if json.Unmarshal(o.Payload, &p) == nil {
				process(p)
			}
		}
	}
	st, done, err := runPreset(&c, append(run, extra...), rep, observe)
	subsMode.NoCheck, subsMode.Recursive, subsMode.GuessSamples, subsMode.NoGuessCheck = false, false, 0, false
	if err != nil {
		w.close()
		return err
	}
	defer done()
	out.takeover = map[string]takeoverRow{}
	for _, t := range rep.Takeover {
		out.takeover[t.Host] = t
	}
	if *httpTier {
		answeredHTTP = answeredNames(st)
	}
	if *live {
		// A live name has an address, directly or through its CNAME chain; a
		// chain that ends without one is listed too, marked cname_only.
		alive = liveNames(st)
		answers = dnsAnswers(st)
		dangling = cnameNames(st)
	}
	for _, p := range payloads(st, "azhaq-subdomains") {
		process(p) // the ones not printed yet: every one with -live
	}
	// Names the guesses found.
	guessed, guessTried, guessHeld, guessDead, guessFiltered, guessOut := 0, 0, 0, 0, 0, 0
	for _, g := range []struct{ collector, source string }{{"azhaq-dns-brute", "dns-brute"}, {"azhaq-permute", "permute"}} {
		for _, p := range payloads(st, g.collector) {
			names := strs(p["names"])
			guessOut += intOf(p[brutecol.HeldOutKey])
			// Every guess is accounted for: found and printed, found but
			// already given, left out by a filter or by the -live check, or
			// not found (it did not resolve, or only a wildcard answered).
			guessTried += max(intOf(p["tried"]), len(names))
			guessDead += max(intOf(p["tried"]), len(names)) - len(names)
			for _, name := range names {
				switch {
				case seen[name]:
					guessHeld++
					continue
				case !filt.keep(name):
					guessFiltered++
					continue
				case alive != nil && alive[name] == nil && dangling[name] == nil:
					guessDead++
					continue
				}
				seen[name] = true
				guessed++
				row := map[string]any{"host": name, "input": apexOf(name, apexes), "source": g.source, "sources": []string{g.source}, "tier": tierDNS}
				dnsTier[name] = true // a guess is kept only when it resolved
				var ips []string
				if alive != nil {
					var only bool
					if ips, only = liveRow(row, alive, dangling, name); only {
						cnameOnly++
					}
					if *oI && len(ips) > 0 {
						row["ip"] = ips[0]
					}
				}
				out.put(apexOf(name, apexes), name, row, ips, []string{g.source})
			}
		}
	}
	// Live names under the domains that DNS met as another name's CNAME
	// target: no source gave them, but they are found and in scope.
	viaCNAME := 0
	if alive != nil {
		var extra []string
		for _, set := range []map[string]map[string]any{alive, dangling} {
			for name := range set {
				if !seen[name] && apexOf(name, apexes) != "" && !slices.Contains(apexes, name) && filt.keep(name) {
					extra = append(extra, name)
				}
			}
		}
		sort.Strings(extra)
		for _, name := range slices.Compact(extra) {
			seen[name] = true
			viaCNAME++
			row := map[string]any{"host": name, "input": apexOf(name, apexes), "source": "cname", "sources": []string{"cname"}, "tier": tierDNS}
			dnsTier[name] = true
			ips, only := liveRow(row, alive, dangling, name)
			if only {
				cnameOnly++
			}
			if *oI && len(ips) > 0 {
				row["ip"] = ips[0]
			}
			out.put(apexOf(name, apexes), name, row, ips, []string{"cname"})
		}
	}
	ext := ".txt"
	if c.json {
		ext = ".json"
	}
	if err := out.files(apexes, ext); err != nil {
		return err
	}
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	rep.Sources = health.result()
	rep.Counts = map[string]int{"sources asked": ran, "sources answered": answered, "sources failed": ran - answered - failedOff, "off-by-default failed": failedOff}
	rep.Degraded = rep.Counts["sources failed"] > 0
	if rep.Degraded {
		rep.DegradedBy = health.degradedBy()
	}
	if active {
		rep.Counts["found by guessing"] = guessed
		// A guess a source gave too is one of the source names.
		if n := guessTried - guessHeld; n > 0 {
			rep.Counts["asked by guessing"] = n
		}
	}
	// The names add up: from sources, less what was dropped or left out,
	// plus what DNS and the guesses added, is what was printed.
	rep.Counts["from sources"] = union
	set := func(k string, n int) {
		if n > 0 {
			rep.Counts[k] = n
		}
	}
	// The tiers: what the sources gave, and what a lookup then confirmed.
	// They nest: a name is a candidate before it is DNS-confirmed.
	rep.Counts[countRaw] = max(union-itself, 0)
	if *live || active {
		rep.Counts[countDNS] = len(dnsTier)
	}
	if *httpTier {
		rep.Counts[countHTTP] = len(httpTier2)
	}
	set("the domain itself", itself)
	set("held out by scope", heldOut)
	set("did not resolve", dropped+didNot+guessDead)
	if *live {
		// Show the live/dead split: a raw subdomain count is mostly names
		// that do not resolve (stale certificate logs, wildcard noise). The
		// live set is the one you can act on.
		rep.Counts["collected"] = len(collected)
		rep.Counts["resolved from sources"] = rep.Results - guessed - viaCNAME - cnameOnlySrc
		set("found as CNAME targets", viaCNAME)
	}
	set("CNAME only", cnameOnly)
	set("not checked", notChecked)
	set("no answer", noAnswer)
	set("not asked", notAsked)
	set("unverified", unverified)
	set("guesses held back", heldBack)
	set("left out by -m/-f", filtered+guessFiltered)
	set("listed under another domain", dup)
	if !*live && !active && rep.Results > 0 && !(hasFlag(args, "guesses") && *guesses) { // an explicit -guesses cannot go with -live
		if why, _ := livePass(rep.Results); why != "" {
			rep.hint(livePassCommand(args) + "   (next pass, not run: " + why + ")")
		}
	}
	set("cut by -max-names", cut)
	set("guesses held back by -max-names", guessBudget.Held())
	set("guesses held out by scope", guessOut)
	if cut > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names were cut at -max-names: raise it to keep them", cut))
		rep.warned = true
	}
	if heldBack > 0 {
		then := "-guesses (the default) prints them as unverified candidates, -live looks them up and prints the ones that resolve"
		if *live || active {
			then = "without -guesses=false they are looked up, at -dns-rate, and the ones that resolve are printed"
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names are held back: only subdomain.center guessed them, no source asserted them and no DNS lookup was made; %s", heldBack, then))
	}
	if unverified > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names are listed unverified (-json: \"unverified\": true): only the name history or subdomain.center's guesses held them and no DNS lookup was made; -live checks them", unverified))
	}
	if cnameOnly > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names are listed with a CNAME and no address (-json: \"cname_only\": true): one whose target is gone is a takeover lead", cnameOnly))
	}
	if notChecked > 0 {
		why := "the resolvers failed"
		if len(notCheckedWhy) > 0 {
			why = strings.Join(slices.Sorted(maps.Keys(notCheckedWhy)), "; ")
		} else if rep.Stopped != "" && !lookupsFailed {
			why = "the run stopped first" // -timeout, -max-time, a signal or a budget
		}
		how := "azhaq resume -db " + c.db + " checks them, and azhaq query -db " + c.db + " -type Hostname -role unresolved lists them"
		if c.db == "" {
			how = "this run kept no database: run again with -db FILE to keep them for azhaq resume, or without -live to list them unverified"
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names could not be checked (%s) and are left out of the list; %s", notChecked, why, how))
		if n := poolKept + poolDropped; n > 0 {
			rep.Notes = append(rep.Notes, uncheckedEstimate(notChecked, poolKept, n))
		}
		rep.warned = true
	}
	if noAnswer > 0 {
		rep.Notes = append(rep.Notes, dnsAnswerNote(noAnswerBy)+": those names are left out, neither live nor dead; ask again with other -resolvers or a lower -dns-rate")
		rep.warned = true
	}
	if notAsked > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names were not asked in DNS before the run stopped: azhaq resume asks them", notAsked))
	}
	if s := topSources(bySource, 8); s != "" {
		rep.Notes = append(rep.Notes, "sources: "+s)
	}
	if n := nameSum(rep.Counts, rep.Results, filtering); n != "" {
		rep.Notes = append(rep.Notes, n)
		rep.holds("names from the sources, less what was left out, plus what DNS added, against the names printed", namesFromCounts(rep.Counts), rep.Results)
	}
	tiers := []tierSet{{countRaw, nil}}
	if *live || active {
		tiers = append(tiers, tierSet{countDNS, dnsTier})
	}
	if *httpTier {
		tiers = append(tiers, tierSet{countHTTP, httpTier2})
	}
	rep.Notes = append(rep.Notes, tierNote(rep.Counts, *live || active)...)
	rep.Notes = append(rep.Notes, subsNotes(payloads(st, "azhaq-subdomains"), tiers)...)
	rep.wrote(historyWrote(payloads(st, "azhaq-subdomains"))...)
	if c.db != "" {
		rep.Next = append(rep.Next, "azhaq query -db "+c.db+" -type Hostname")
	}
	if !*permute && rep.Stopped == "" {
		rep.hint(permuteHint(rep.Results, apexes, seen, c.db))
	}
	return rep.finish(c.json, c.silent)
}

// permuteHint is the command that also resolves variations of the names a
// run found, with two of the variations it would ask, or "".
func permuteHint(found int, apexes []string, names map[string]bool, db string) string {
	if found == 0 || len(apexes) == 0 || len(apexes) > 3 {
		return ""
	}
	var host string
	for n := range names {
		if !slices.Contains(apexes, n) && (host == "" || n < host) {
			host = n
		}
	}
	if host == "" {
		return ""
	}
	cmd := "azhaq subs -d " + strings.Join(apexes, ",") + " -permute"
	if db != "" {
		cmd += " -db " + db
	}
	why := fmt.Sprintf("try variations of the %s found", plural(found, "name"))
	if v := brutecol.PermuteSample(host); len(v) == 2 {
		why += ", such as " + v[0] + " and " + v[1] + " for " + host
	}
	return cmd + "   (" + why + ")"
}

// nameSum is the note that lets a reader check the counts: the names the
// sources gave, less what was dropped, plus what DNS added, are the names
// printed.
func nameSum(c map[string]int, results int, filtering bool) string {
	if c["from sources"] == 0 && c["asked by guessing"] == 0 {
		return ""
	}
	parts := []string{fmt.Sprintf("%d from the sources", c["from sources"])}
	if n := c["asked by guessing"]; n > 0 {
		parts = append(parts, fmt.Sprintf("+ %d asked by guessing", n))
	}
	minus := func(k, label string) {
		if c[k] > 0 {
			parts = append(parts, fmt.Sprintf("− %d %s", c[k], label))
		}
	}
	minus("the domain itself", "the domain itself, not a subdomain")
	minus("held out by scope", "held out by scope (-allow, -deny, -scope)")
	minus("did not resolve", "did not resolve")
	minus("guesses held back", "guesses held back (-guesses=false)")
	minus("not checked", "not checked")
	minus("no answer", "no answer from the resolvers")
	minus("not asked", "not asked before the run stopped")
	minus("left out by -m/-f", "left out by -m/-f")
	minus("listed under another domain", "listed under another domain")
	minus("cut by -max-names", "cut by -max-names")
	if n := c["found as CNAME targets"]; n > 0 {
		parts = append(parts, fmt.Sprintf("+ %d found as CNAME targets", n))
	}
	return fmt.Sprintf("count: %s = %d printed", strings.Join(parts, " "), results)
}

// namesFromCounts is the names printed that the counts of a subs run give:
// the sum nameSum writes out.
func namesFromCounts(c map[string]int) int {
	n := c["from sources"] + c["asked by guessing"] + c["found as CNAME targets"]
	for _, k := range []string{"the domain itself", "held out by scope", "did not resolve", "guesses held back", "not checked", "no answer", "not asked",
		"left out by -m/-f", "listed under another domain", "cut by -max-names"} {
		n -= c[k]
	}
	return n
}

// rateLimitNote says what a source's 429 answers cost.
func rateLimitNote(domain, source string, row map[string]any) string {
	n := intOf(row["retried_429"])
	switch {
	case row["gave_up_429"] == true && n == 0:
		return fmt.Sprintf("%s: %s answered 429 and asked for %v s (Retry-After), more than is waited for: its names are missing", domain, source, row["retry_after_seconds"])
	case row["gave_up_429"] == true:
		return fmt.Sprintf("%s: %s kept answering 429 after %d retries and %v s of waiting: its answer may be partial", domain, source, n, row["waited_seconds"])
	}
	return fmt.Sprintf("%s: %s answered 429; it was asked again %d times after %v s of waiting (Retry-After) and answered", domain, source, n, row["waited_seconds"])
}

// sourceStats is -stats: a note per source.
func sourceStats(domain string, srcs map[string]any) []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(srcs)) {
		row, _ := srcs[name].(map[string]any)
		if row["skipped"] != nil || name == "history" {
			continue
		}
		errs := 0
		if row["error"] != nil {
			errs = 1
		}
		out = append(out, fmt.Sprintf("%s stats: %s requests %v, names %v, errors %d, seconds %v", domain, name, row["requests"], row["count"], errs, row["seconds"]))
	}
	return out
}

// topSources renders the n biggest sources as "crtname 32, rapiddns 20, …",
// so a thin result shows which sources answered and which were dark, and a
// raw count is read next to where it came from.
func topSources(by map[string]int, n int) string {
	type kv struct {
		s string
		n int
	}
	var all []kv
	for s, c := range by {
		if c > 0 {
			all = append(all, kv{s, c})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].s < all[j].s
	})
	var parts []string
	for i, x := range all {
		if i >= n {
			parts = append(parts, fmt.Sprintf("+%d more", len(all)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", x.s, x.n))
	}
	return strings.Join(parts, ", ")
}

// liveRow puts a live name's DNS fields in row and returns its addresses. A
// name that is only a CNAME whose chain ends without one is listed too, as
// dnsx -cname lists it, marked "cname_only"; it returns true for it.
func liveRow(row map[string]any, alive, dangling map[string]map[string]any, name string) (ips []string, only bool) {
	p := alive[name]
	if p == nil {
		p, only = dangling[name], true
	}
	dnsFields(row, p)
	if only {
		row["cname_only"] = true
		row["a"] = []string{}
	}
	return strs(p["ips"]), only
}

// cnameNames maps each name azhaq-dns found as a CNAME whose chain ends
// without an address, a wildcard zone's answers left out, to its payload.
func cnameNames(st *store.Store) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, p := range payloads(st, "azhaq-dns") {
		name, _ := p["fqdn"].(string)
		if name != "" && p["wildcard"] == nil && len(strs(p["cnames"])) > 0 && len(strs(p["ips"])) == 0 && out[name] == nil {
			out[name] = p
		}
	}
	return out
}

// allAnswered says whether the resolvers answered every one of names, the
// answers being those of the lookups made (nil: none were).
func allAnswered(answers map[string]map[string]any, names []string) bool {
	if answers == nil {
		return false
	}
	for _, n := range names {
		if a := answers[n]; a == nil || a["degraded"] == true {
			return false
		}
	}
	return true
}

// uncheckedEstimate is the estimate of how many of the names a run left
// unchecked would resolve: of the looked up names that only a source that
// guesses or the name history held, resolved did, in a sample of looked up
// names. It rests on that share holding for the rest, and is labelled so.
func uncheckedEstimate(unchecked, resolved, lookedUp int) string {
	est := (unchecked*resolved + lookedUp/2) / lookedUp
	return fmt.Sprintf("estimate, not a count: of the %d names looked up that only subdomain.center or the name history held, %d resolved; the %d left unchecked are of the same kind, so about %d of them would resolve if that share held (a sample of %d names)",
		lookedUp, resolved, unchecked, est, lookedUp)
}
