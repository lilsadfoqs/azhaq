package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// change set between the last two runs of a workspace, in the terms a
// person watching a target cares about.
type changes struct {
	DB        string        `json:"db"`
	Run       time.Time     `json:"run"`
	Previous  time.Time     `json:"previous,omitempty"`
	Baseline  bool          `json:"baseline,omitempty"` // the first run: everything is new
	Hosts     []string      `json:"hosts,omitempty"`    // new names that resolve: "name (ips): 53/tcp BIND 9.11"
	Services  []string      `json:"services,omitempty"` // new web services, "url [status] title (technologies)"
	URLs      []string      `json:"urls,omitempty"`     // other new URLs, one per identity
	Ports     []string      `json:"ports,omitempty"`    // "host: +9000/tcp php-fpm, -8080/tcp (open: 22,9000)" where the open set changed
	Changed   []string      `json:"changed,omitempty"`  // "url: [200] old title → [403] new title"
	Dangling  []string      `json:"dangling,omitempty"` // new names that point nowhere: "name → target (NXDOMAIN)"
	GoneHosts []string      `json:"gone_hosts,omitempty"`
	GoneSvcs  []string      `json:"gone_services,omitempty"`
	GoneURLs  []string      `json:"gone_urls,omitempty"`
	Routes    []routeChange `json:"routes,omitempty"` // API routes, methods and body names the scripts call that changed
}

func (c changes) any() bool {
	return len(c.Hosts)+len(c.Dangling)+len(c.Services)+len(c.URLs)+len(c.Ports)+len(c.Changed)+len(c.GoneHosts)+len(c.GoneSvcs)+len(c.GoneURLs)+len(c.Routes) > 0
}

// cmdWatch runs the same target into a workspace again and again and
// reports what changed: azhaq watch -db acme.db -every 24h -notify URL -- -scope acme.csv
func cmdWatch(args []string) error {
	fs := newFlags("watch")
	db := fs.String("db", "", "workspace database (required)")
	every := fs.Duration("every", 0, "run again after this long (default: run once, for cron)")
	var hooks stringsFlag
	fs.Var(&hooks, "notify", "webhook for changes: Slack, Discord, Telegram (…/sendMessage?chat_id=…) or any JSON endpoint (repeatable); @FILE reads URLs from a file, one a line, and $AZHAQ_NOTIFY holds more (comma-separated), so a token need not stand on the command line where ps shows it")
	notifyConfig := fs.String("notify-config", "", "notify's provider-config.yaml: send the changes to the providers it lists (Slack, Discord, Telegram, Teams, Google Chat, Pushover, Gotify, SMTP, custom)")
	var notifyProviders, notifyIDs stringsFlag
	fs.Var(&notifyProviders, "notify-provider", "with -notify-config, only these providers (repeatable or comma-separated)")
	fs.Var(&notifyIDs, "notify-id", "with -notify-config, only the entries with these ids (repeatable or comma-separated)")
	notifyFormat := fs.String("notify-format", "", "format of each message: {{data}}, {{date}}, {{time}}, {{datetime}}, {{count}}")
	notifyRate := fs.Float64("notify-rate", 1, "requests per second to the webhooks and providers (0: no limit)")
	notifyProxy := fs.String("notify-proxy", "", "proxy URL for the notification requests (default: the environment's)")
	notifyLines := fs.Int("notify-lines", 100, "lines per kind of change in a message, the rest counted (0: all); a message longer than the service takes is sent in parts")
	notifyCmd := fs.String("notify-cmd", "", "command that gets the change set as JSON on stdin")
	always := fs.Bool("always", false, "notify after every run, the first (the baseline) included, not only when something changed")
	jsonOut := fs.Bool("json", false, "print the change set as JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	runArgs := fs.Args()
	if len(runArgs) > 0 && runArgs[0] == "--" {
		runArgs = runArgs[1:]
	}
	if *db == "" || len(runArgs) == 0 {
		return usagef("usage: azhaq watch -db WORKSPACE.db [-every 24h] [-notify URL] -- RUN OPTIONS")
	}
	urls, err := hooksFrom(hooks, os.Getenv("AZHAQ_NOTIFY"))
	if err != nil {
		return err
	}
	nt, err := newNotifier(urls, *notifyConfig, notifyProviders, notifyIDs, *notifyFormat, *notifyRate, *notifyProxy, *notifyLines)
	if err != nil {
		return err
	}
	ctx, stop := stopContext()
	defer stop()
	for cycle := 1; ; cycle++ {
		rep, err := runEmbeddedAs(append(append([]string(nil), runArgs...), "-db", *db, "-quiet"), *jsonOut)
		if err != nil {
			return err
		}
		if ctx.Err() != nil && strings.HasPrefix(rep.Stopped, "interrupted") {
			// The run is partial: comparing it would call what it did not
			// reach gone, and a notification would say so.
			return watchInterrupted(cycle, "its run was cut ("+rep.Stopped+")", nt.client != nil, *jsonOut)
		}
		ch, err := diffRuns(*db)
		if err != nil {
			return err
		}
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(ch)
		} else {
			fmt.Print(ch.text())
		}
		// The first run is the baseline, not a change: -always sends it too.
		lost, cut, cutSend, cmdFailed := false, 0, 0, false
		var note *report // the notifications' summary, printed last (carry)
		if (ch.any() && !ch.Baseline) || *always {
			nrep, lostMsgs, cutMsgs, err := nt.sendRecorded(ctx, cycle, ch, runArgs, *db)
			if err != nil {
				return err
			}
			note = nrep
			cut += cutMsgs
			cutSend = cutMsgs
			for _, msg := range lostMsgs {
				fmt.Fprintf(os.Stderr, "azhaq watch: %s\n", msg)
				lost = true
			}
			if *notifyCmd != "" {
				raw, _ := json.Marshal(ch)
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", *notifyCmd)
				cmd.Stdin = strings.NewReader(string(raw) + "\n")
				cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
				if err := cmd.Run(); err != nil {
					if ctx.Err() != nil {
						cut++ // the signal ended it: not a fault of the command
						fmt.Fprintln(os.Stderr, "azhaq watch: -notify-cmd was cut because the watch was interrupted")
					} else {
						fmt.Fprintf(os.Stderr, "azhaq watch: -notify-cmd: %v\n", err)
						lost, cmdFailed = true, true
					}
				}
			}
		}
		if note == nil && cmdFailed {
			note = newReport("notify")
			note.DB, note.what = *db, "notification requests"
		}
		if note != nil {
			if cmdFailed {
				note.Notes = append(note.Notes, "-notify-cmd failed (its error is above)")
			}
			if cut > 0 && note.Stopped == "" {
				note.Stopped = fmt.Sprintf("interrupted (Ctrl-C, kill) during cycle %d: its notification was cut", cycle)
			}
			note.carry(rep, lost, cut)
			note.emit(*jsonOut)
		}
		if cut > 0 {
			if cutSend > 0 {
				return exitErr{code: exitLimit} // the notification summary says the cut
			}
			return watchInterrupted(cycle, "its notification was cut", false, *jsonOut)
		}
		if *every <= 0 {
			// The run's exit code: 3 when something failed, 4 when a
			// limit stopped it, whatever changed. A notification that did
			// not arrive is a failure too: exit 3.
			if err := rep.err(); err != nil || !lost {
				return err
			}
			return exitErr{code: exitPartial}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
	}
}

// watchInterrupted ends a watch a signal cut during a cycle: stopped, exit
// 4, with the summary naming the cycle.
func watchInterrupted(cycle int, what string, notifying, asJSON bool) error {
	rep := newReport("watch")
	rep.Stopped = fmt.Sprintf("interrupted (Ctrl-C, kill) during cycle %d: %s", cycle, what)
	if notifying {
		rep.Notes = append(rep.Notes, "no notification of this cycle was sent because the watch was interrupted")
	}
	return rep.finish(asJSON, false)
}

// diffRuns compares the last two runs of a workspace.
func diffRuns(path string) (changes, error) {
	old, err := store.OpenExisting(path)
	if err != nil {
		return changes{}, err
	}
	defer old.Close()
	neu, err := store.OpenExisting(path)
	if err != nil {
		return changes{}, err
	}
	defer neu.Close()
	runs, err := old.Runs()
	if err != nil || len(runs) == 0 {
		return changes{}, err
	}
	last := runs[len(runs)-1]
	neu.UseRun(last.ID)
	ch := changes{DB: path, Run: last.Started}
	if len(runs) == 1 {
		ch.Baseline = true
		old.UseRun("\x00none") // a run that saw nothing: everything is added
	} else {
		prev := runs[len(runs)-2]
		ch.Previous = prev.Started
		old.UseRun(prev.ID)
	}
	d, err := store.Compare(old, neu)
	if err != nil {
		return ch, err
	}
	return changesBetween(old, neu, d, ch)
}

// changesBetween sorts what differs between two runs the way watch reports
// it; diff counts the same rows. ch holds the runs' dates and Baseline.
func changesBetween(old, neu *store.Store, d store.Diff, ch changes) (changes, error) {
	var err error
	if !ch.Baseline {
		if ch.Routes, err = diffRoutes(old, neu); err != nil {
			return ch, err
		}
	}
	newFacts := factsByEntity(neu)
	oldFacts := factsByEntity(old)
	newPorts, oldPorts := scansOf(neu), scansOf(old)
	// A URL is new when its identity (path with identifiers folded, query
	// names without values) was not in the previous run, one line each.
	oldIdent, newIdent := foldedURLs(old), foldedURLs(neu)
	seenNew, seenGone := map[string]bool{}, map[string]bool{}
	// The first URL of an identity, in order, stands for it: the same one every time.
	byKey := func(es []types.Entity) []types.Entity {
		es = slices.Clone(es)
		sort.SliceStable(es, func(i, j int) bool { return es[i].Key < es[j].Key })
		return es
	}
	d.Added, d.Removed = byKey(d.Added), byKey(d.Removed)
	for _, e := range d.Added {
		id := ""
		if e.Type == types.TypeURL {
			if id = foldURL(e.Key); oldIdent[id] || seenNew[id] {
				continue
			}
		}
		switch e.Type {
		case types.TypeHostname:
			if ips := newFacts[e.ID].ips; len(ips) > 0 {
				line := e.Key + " (" + strings.Join(ips, ", ") + ")"
				if svcs := svcsAt(newPorts, ips); len(svcs) > 0 {
					line += ": " + svcList(svcs)
				}
				ch.Hosts = append(ch.Hosts, line)
			}
		case types.TypeURL:
			f := newFacts[e.ID]
			switch {
			case f.catchAll:
			case f.status != 0 && isFront(e.Key):
				line := strings.TrimSpace(fmt.Sprintf("%s [%d] %s", e.Key, f.status, f.title))
				if len(f.tech) > 0 {
					line += " (" + techList(f.tech) + ")"
				}
				ch.Services = append(ch.Services, line)
				seenNew[id] = true
			case f.role != "script" && f.role != "asset" && f.role != "sourcemap" && !isStatic(e.Key):
				ch.URLs = append(ch.URLs, e.Key)
				seenNew[id] = true
			}
		}
	}
	for _, e := range d.Removed {
		id := ""
		if e.Type == types.TypeURL {
			if id = foldURL(e.Key); newIdent[id] || seenGone[id] {
				continue
			}
		}
		f := oldFacts[e.ID]
		switch {
		case e.Type == types.TypeHostname && len(f.ips) > 0:
			ch.GoneHosts = append(ch.GoneHosts, e.Key)
		case e.Type == types.TypeURL && f.status != 0 && isFront(e.Key):
			ch.GoneSvcs = append(ch.GoneSvcs, e.Key)
			seenGone[id] = true
		case e.Type == types.TypeURL && f.status != 0 && !f.catchAll && f.role != "script" && f.role != "asset" && f.role != "sourcemap" && !isStatic(e.Key):
			ch.GoneURLs = append(ch.GoneURLs, e.Key)
			seenGone[id] = true
		}
	}
	ch.Dangling = newDangling(old, neu)
	// What answered in both runs, differently: a page that now needs a
	// login, a service that changed its title or its product.
	for id, nf := range newFacts {
		of, ok := oldFacts[id]
		if !ok || nf.status == 0 || of.status == 0 || nf.catchAll || of.catchAll {
			continue
		}
		line := ""
		switch {
		case nf.status != of.status || nf.title != of.title:
			line = fmt.Sprintf("%s: [%d] %s → [%d] %s", nf.url, of.status, of.title, nf.status, nf.title)
		case nf.items > 0 && of.items > 0 && nf.items != of.items:
			// An API listing that grew or shrank: a user, a book, an order.
			line = fmt.Sprintf("%s: [%d] %d items → [%d] %d items", nf.url, of.status, of.items-1, nf.status, nf.items-1)
		}
		if pc := techChange(of.tech, nf.tech); pc != "" && isFront(nf.url) {
			if line == "" {
				line = strings.TrimSpace(fmt.Sprintf("%s: [%d] %s", nf.url, nf.status, nf.title))
			}
			line += " (" + pc + ")"
		}
		if line != "" {
			ch.Changed = append(ch.Changed, line)
		}
	}
	// Ports: per address, the open set where both runs scanned it, and the
	// product of a service that stayed open.
	names := namesByAddress(neu, newFacts)
	for ip, ns := range namesByAddress(old, oldFacts) {
		if _, ok := names[ip]; !ok {
			names[ip] = ns
		}
	}
	ports, changed := portsChanges(oldPorts, newPorts, names)
	ch.Ports = append(ch.Ports, ports...)
	ch.Changed = append(ch.Changed, changed...)
	ch.URLs = withoutRoutes(ch.URLs, ch.Routes, "new")
	ch.GoneURLs = withoutRoutes(ch.GoneURLs, ch.Routes, "gone")
	for _, xs := range [][]string{ch.Hosts, ch.Dangling, ch.Services, ch.URLs, ch.Ports, ch.Changed, ch.GoneHosts, ch.GoneSvcs, ch.GoneURLs} {
		sort.Strings(xs)
	}
	return ch, nil
}

type facts struct {
	ips         []string
	status      int
	url         string
	title, role string
	catchAll    bool
	portScanned bool     // a port scan asked it (its rows: scansOf)
	items       int      // items of a JSON listing, plus one; 0 when it is not one
	tech        []string // technologies the http answers showed, "Name" or "Name:version"
}

func factsByEntity(st *store.Store) map[string]facts {
	obs, _ := st.Observations()
	out := map[string]facts{}
	for _, o := range obs {
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		f := out[o.EntityID]
		switch o.Collector {
		case "azhaq-dns":
			if ips, ok := p["ips"].([]any); ok && p["wildcard"] == nil {
				for _, ip := range ips {
					f.ips = append(f.ips, fmt.Sprint(ip))
				}
			}
		case "azhaq-http":
			row, _ := httprow.ParseRow(o.Payload) // a field of another type is left out, as the key was
			if row.Status != 0 && f.status == 0 {
				f.status = row.Status
				f.url = row.URL
			}
			if row.Title != "" && f.title == "" {
				f.title = row.Title
			}
			if row.JSONItems != nil {
				f.items = *row.JSONItems + 1 // stored plus one: zero means not a listing
			}
			if row.Catchall {
				f.catchAll = true
			}
			for _, name := range row.Tech {
				if name != "" && !slices.Contains(f.tech, name) {
					f.tech = append(f.tech, name)
				}
			}
		case "azhaq-ports":
			if row, err := portscan.ParseRow(o.Payload); err == nil && row.Scanned > 0 {
				f.portScanned = true
			}
		}
		// What a detection template named: on the answer, or on the service
		// from a product check of the sweep. Said like a technology.
		if o.Collector == "azhaq-http" || o.Collector == "azhaq-paths" && o.Kind == "detected" {
			row, _ := httprow.ParseRow(o.Payload)
			for _, d := range row.Detected {
				name := d.Product
				if d.Version != "" {
					name += ":" + d.Version
				}
				if name != "" && !slices.Contains(f.tech, name) {
					f.tech = append(f.tech, name)
				}
			}
		}
		if r, ok := p["role"].(string); ok && f.role == "" {
			f.role = r
		}
		out[o.EntityID] = f
	}
	return out
}

// isStatic: a script, style sheet or image, which no one triages.
func isStatic(raw string) bool {
	c := webextract.ClassifyURL(raw)
	return c == "asset" || c == "script"
}

func isFront(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Path == "" || u.Path == "/")
}

// text is the change set as the terminal shows it: at most 20 lines per
// kind of change.
func (c changes) text() string { return c.notifyText(20) }

// notifyText is the same text with at most lines lines per kind of change
// (0: every one); what is left out is counted.
func (c changes) notifyText(lines int) string {
	var b strings.Builder
	when := c.Run.Local().Format("2006-01-02 15:04:05")
	if c.Baseline {
		fmt.Fprintf(&b, "azhaq watch %s: first run %s\n", c.DB, when)
	} else {
		fmt.Fprintf(&b, "azhaq watch %s: %s against %s\n", c.DB, when, c.Previous.Local().Format("2006-01-02 15:04:05"))
	}
	if !c.any() {
		b.WriteString("no change\n")
		return b.String()
	}
	section := func(sign, what string, xs []string) {
		if len(xs) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s %d %s\n", sign, len(xs), what)
		for i, x := range xs {
			if lines > 0 && i == lines {
				fmt.Fprintf(&b, "    … and %d more\n", len(xs)-lines)
				break
			}
			fmt.Fprintf(&b, "    %s\n", x)
		}
	}
	section("+", "hostnames that resolve", c.Hosts)
	section("!", "names that point nowhere", c.Dangling)
	section("+", "web services", c.Services)
	section("+", "URLs", c.URLs)
	section("~", "API routes", routeLines(c.Routes))
	section("~", "hosts whose open ports changed", c.Ports)
	section("~", "pages that answer differently", c.Changed)
	section("-", "hostnames gone", c.GoneHosts)
	section("-", "web services gone", c.GoneSvcs)
	section("-", "URLs gone", c.GoneURLs)
	return b.String()
}

// cmdNew lists what a workspace first saw within a window, for triage.
func cmdNew(args []string) error {
	fs := newFlags("new")
	db := fs.String("db", "", "workspace database (required)")
	since := fs.Duration("since", 7*24*time.Hour, "first seen within this long")
	jsonOut := fs.Bool("json", false, "JSONL")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *db == "" {
		return usagef("give -db WORKSPACE.db")
	}
	st, err := store.OpenExisting(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	// What the newest run still saw: a page removed since is not new.
	if runs, err := st.Runs(); err == nil && len(runs) > 0 {
		st.UseRun(runs[len(runs)-1].ID)
	}
	ents, err := st.Entities()
	if err != nil {
		return err
	}
	f := factsByEntity(st)
	cut := time.Now().Add(-*since)
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].Type != ents[j].Type {
			return ents[i].Type < ents[j].Type
		}
		return ents[i].FirstSeen.After(ents[j].FirstSeen)
	})
	enc := json.NewEncoder(os.Stdout)
	for _, e := range ents {
		if e.FirstSeen.Before(cut) || (e.Type != types.TypeHostname && e.Type != types.TypeURL && e.Type != types.TypeIPAddress) {
			continue
		}
		x := f[e.ID]
		if e.Type == types.TypeURL && (x.catchAll || x.role == "script" || x.role == "asset" || x.role == "sourcemap" || isStatic(e.Key)) {
			continue
		}
		if *jsonOut {
			row := map[string]any{"type": e.Type, "key": e.Key, "first_seen": e.FirstSeen, "last_seen": e.LastSeen}
			if len(x.ips) > 0 {
				row["ips"] = x.ips
			}
			if x.status != 0 {
				row["status"], row["title"] = x.status, x.title
			}
			if err := enc.Encode(row); err != nil {
				return err
			}
			continue
		}
		detail := ""
		switch {
		case len(x.ips) > 0:
			detail = strings.Join(x.ips, ", ")
		case x.status != 0:
			detail = strings.TrimSpace(fmt.Sprintf("[%d] %s", x.status, x.title))
		}
		fmt.Printf("%s  %-9s %s  %s\n", e.FirstSeen.Local().Format("2006-01-02 15:04:05"), e.Type, e.Key, detail)
	}
	return nil
}
