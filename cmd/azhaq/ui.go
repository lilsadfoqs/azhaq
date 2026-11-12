package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/collectors"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/runs"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

//go:embed uiweb
var uiWeb embed.FS

// uiCSP lets the page load only its own script and style and talk only
// to this server: the browser enforces it.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// cmdUI serves the kept runs to a browser on this machine. It reads the
// run home and the runs' workspaces and ledgers, and sends nothing to any target.
func cmdUI(args []string) error {
	fs := newFlags("ui")
	listen := fs.String("listen", "127.0.0.1:7190", "the loopback address to serve on (127.0.0.1:0 takes any free port); another address is refused")
	homeFlag := fs.String("home", "", "the run home to show (default $AZHAQ_HOME, else .azhaq in the current directory)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("ui takes flags only")
	}
	if !loopbackAddr(*listen) {
		return usagef("-listen %s: the page shows sessions and evidence, so it answers on a loopback address only (127.0.0.1, ::1, localhost)", *listen)
	}
	home, err := runHome(*homeFlag)
	if err != nil {
		return err
	}
	if _, err := os.Stat(runs.Dir(home)); os.IsNotExist(err) {
		return fmt.Errorf("%s (ui shows kept runs)", noRunsText(home))
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer l.Close()
	fmt.Fprintf(os.Stderr, "azhaq: ui: the runs of %s at http://%s/ (read-only; Ctrl-C stops)\n", runs.Dir(home), l.Addr())
	srv := &http.Server{Handler: uiHandler(home), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := stopContext()
	defer stop()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loopbackAddr(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return h == "localhost" || ip != nil && ip.IsLoopback()
}

// uiHandler is the page and its JSON API over the runs of home. It
// answers only requests that name a loopback host, so a page on another
// site cannot reach it through a name it controls.
func uiHandler(home string) http.Handler {
	mux := http.NewServeMux()
	web, _ := fs.Sub(uiWeb, "uiweb")
	static := http.FileServerFS(web)
	mux.Handle("GET /{$}", static)
	mux.Handle("GET /app.js", static)
	mux.Handle("GET /app.css", static)
	mux.Handle("GET /fonts/", static)
	mux.HandleFunc("GET /api/runs", func(w http.ResponseWriter, r *http.Request) { uiRuns(w, home) })
	mux.HandleFunc("GET /api/runs/{id}", func(w http.ResponseWriter, r *http.Request) { uiRun(w, home, r.PathValue("id")) })
	mux.HandleFunc("GET /api/runs/{id}/graph", func(w http.ResponseWriter, r *http.Request) { uiGraph(w, home, r.PathValue("id")) })
	mux.HandleFunc("GET /api/runs/{id}/node/{node}", func(w http.ResponseWriter, r *http.Request) {
		uiNode(w, home, r.PathValue("id"), r.PathValue("node"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHostHeader(r.Host) {
			http.Error(w, "this page answers on its loopback address only", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", uiCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		mux.ServeHTTP(w, r)
	})
}

func loopbackHostHeader(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = strings.Trim(host, "[]")
	}
	ip := net.ParseIP(h)
	return h == "localhost" || ip != nil && ip.IsLoopback()
}

func uiJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func uiError(w http.ResponseWriter, code int, err error) {
	uiJSON(w, code, map[string]string{"error": err.Error()})
}

// uiRunRow is a run in the list.
type uiRunRow struct {
	ID       string    `json:"id"`
	Command  string    `json:"command"`
	Target   string    `json:"target"`
	Started  time.Time `json:"started"`
	Status   string    `json:"status"`
	Exit     *int      `json:"exit,omitempty"`
	Time     string    `json:"time"`
	Requests string    `json:"requests"`
	Got      string    `json:"got"`
}

func uiRuns(w http.ResponseWriter, home string) {
	list, err := runs.List(home)
	if err != nil {
		uiError(w, http.StatusInternalServerError, err)
		return
	}
	rows := make([]uiRunRow, 0, len(list))
	for _, r := range list {
		s := runSummaryOf(r)
		rows = append(rows, uiRunRow{ID: r.ID, Command: r.Command, Target: r.Target, Started: r.Started,
			Status: runStatus(r), Exit: r.Exit, Time: runTime(r), Requests: s.requestsText(), Got: s.gotText()})
	}
	uiJSON(w, http.StatusOK, map[string]any{"home": runs.Dir(home), "runs": rows})
}

// uiLedger is what the run sent, counted from its ledger lines.
type uiLedger struct {
	Path        string         `json:"path"`
	Lines       int            `json:"lines"`
	ByClass     map[string]int `json:"by_class"`
	ByKind      map[string]int `json:"by_kind"`
	ByPurpose   map[string]int `json:"by_purpose"`
	ByCollector map[string]int `json:"by_collector"` // every line that names its collector, whatever its class
	Hosts       []uiCount      `json:"hosts"`        // targets, by host or address, the most asked first
	Sources     []uiCount      `json:"sources"`
}

type uiCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func uiRun(w http.ResponseWriter, home, id string) {
	rec, err := runs.Load(home, id)
	if err != nil {
		uiError(w, http.StatusNotFound, err)
		return
	}
	out := map[string]any{
		"record": rec, "status": runStatus(rec), "time": runTime(rec), "dir": runs.Dir(home) + string(os.PathSeparator) + rec.ID,
	}
	if rec.Exit != nil {
		for _, e := range exitCodes {
			if e.Code == *rec.Exit {
				out["exit_meaning"] = e.Meaning
			}
		}
	}
	if rec.Workspace != "" {
		if l, err := readRunLedger(rec); err == nil {
			out["ledger"] = l
		} else {
			out["ledger_error"] = err.Error()
		}
	}
	uiJSON(w, http.StatusOK, out)
}

// readRunLedger counts the ledger lines written while the run ran: a
// workspace named by -db may hold the lines of other runs.
func readRunLedger(rec runs.Record) (*uiLedger, error) {
	path := rec.Workspace + ".ledger.jsonl"
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no ledger beside the workspace (%s)", path)
	}
	end := time.Now()
	if rec.Ended != nil {
		end = *rec.Ended
	}
	l := &uiLedger{Path: path, ByClass: map[string]int{}, ByKind: map[string]int{}, ByPurpose: map[string]int{}, ByCollector: map[string]int{}}
	hosts, sources := map[string]int{}, map[string]int{}
	err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "seal" || e.NotSent || e.Time.Before(rec.Started) || e.Time.After(end) {
			return nil
		}
		class := e.Class
		if class == "" {
			class = ledger.ClassTarget
		}
		l.Lines++
		l.ByClass[class]++
		l.ByKind[e.Kind]++
		if e.Collector != "" {
			l.ByCollector[e.Collector]++
		}
		switch class {
		case ledger.ClassTarget:
			if e.Purpose != "" {
				l.ByPurpose[e.Purpose]++
			}
			hosts[ledgerHost(e)]++
		case ledger.ClassSource:
			sources[ledgerHost(e)]++
		}
		return nil
	})
	l.Hosts, l.Sources = topCounts(hosts), topCounts(sources)
	return l, err
}

func ledgerHost(e ledger.Entry) string {
	if u, err := url.Parse(e.Target); err == nil && u.Host != "" {
		return u.Host
	}
	if e.Target != "" {
		return e.Target
	}
	return e.Host
}

func topCounts(m map[string]int) []uiCount {
	out := make([]uiCount, 0, len(m))
	for k, v := range m {
		out = append(out, uiCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// uiGraphNode is an entity as the canvas draws it.
type uiGraphNode struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Key     string `json:"key"`
	New     bool   `json:"new"`     // first seen while this run ran
	Passive bool   `json:"passive"` // every observation came from a third-party source
	Status  int    `json:"status,omitempty"`
	Lead    string `json:"lead,omitempty"` // a finding's label (proved, version-only, conditional), or lead for a lead above info
	Hint    string `json:"hint,omitempty"` // a map hint on it (severity info): what to look at, not a finding
	Obs     int    `json:"obs"`
	// Capabilities are the capabilities of the collectors that observed
	// it, in run order: recorded on its observations, never from its type.
	Capabilities []string `json:"capabilities,omitempty"`
}

type uiGraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// openRunStore opens a run's workspace on its own run when the summary
// names it, else on the newest.
func openRunStore(rec runs.Record) (*store.Store, error) {
	if rec.Workspace == "" {
		return nil, fmt.Errorf("this run kept no workspace")
	}
	st, err := store.OpenExisting(rec.Workspace)
	if err != nil {
		return nil, err
	}
	var s struct {
		RunID string `json:"run_id"`
	}
	_ = json.Unmarshal(rec.Summary, &s)
	if s.RunID != "" {
		st.UseRun(s.RunID)
	} else if rs, err := st.Runs(); err == nil && len(rs) > 0 {
		st.UseRun(rs[len(rs)-1].ID)
	}
	return st, nil
}

func uiGraph(w http.ResponseWriter, home, id string) {
	rec, err := runs.Load(home, id)
	if err != nil {
		uiError(w, http.StatusNotFound, err)
		return
	}
	st, err := openRunStore(rec)
	if err != nil {
		uiJSON(w, http.StatusOK, map[string]any{"nodes": []any{}, "edges": []any{}, "note": err.Error()})
		return
	}
	ents, err := st.Entities()
	if err != nil {
		st.Close()
		uiError(w, http.StatusInternalServerError, err)
		return
	}
	obs, _ := st.Observations()
	edges, _ := st.Edges()
	st.Close()

	passive := passiveCollectors()
	nodes := make([]uiGraphNode, 0, len(ents))
	index := map[string]int{}
	byKey := map[string]int{}
	for _, e := range ents {
		index[e.ID] = len(nodes)
		byKey[string(e.Type)+"\x00"+e.Key] = len(nodes)
		nodes = append(nodes, uiGraphNode{ID: e.ID, Type: string(e.Type), Key: e.Key, New: !e.FirstSeen.Before(rec.Started), Passive: true})
	}
	active := map[string]bool{}
	byCollector := map[string]int{} // observations of this run's entities, by the collector that made them
	for _, o := range obs {
		i, ok := index[o.EntityID]
		if !ok {
			continue
		}
		n := &nodes[i]
		n.Obs++
		byCollector[o.Collector]++
		if c := capabilityOf(o.Collector); c != "" && !slices.Contains(n.Capabilities, c) {
			n.Capabilities = append(n.Capabilities, c)
		}
		if !passive[o.Collector] {
			active[n.ID] = true
		}
		if s := payloadStatus(o.Payload); s > 0 {
			n.Status = s
		}
	}
	for i := range nodes {
		slices.SortFunc(nodes[i].Capabilities, func(a, b string) int { return slices.Index(capabilityOrder, a) - slices.Index(capabilityOrder, b) })
		nodes[i].Passive = nodes[i].Obs > 0 && !active[nodes[i].ID]
	}
	if g, err := readGraph(rec.Workspace); err == nil {
		set := buildFindings(g)
		for _, r := range append(append(set.Findings, set.Identifications...), set.Leads...) {
			markFinding(nodes, byKey, r)
		}
	}
	outEdges := make([]uiGraphEdge, 0, len(edges))
	for _, e := range edges {
		if _, ok := index[e.From]; !ok {
			continue
		}
		if _, ok := index[e.To]; !ok {
			continue
		}
		outEdges = append(outEdges, uiGraphEdge{From: e.From, To: e.To, Type: e.Type})
	}
	uiJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": outEdges, "observations_by_collector": byCollector})
}

// payloadStatus is the HTTP status an observation records: its own, else
// its last hop's.
func payloadStatus(raw json.RawMessage) int {
	var p struct {
		Status int `json:"status"`
		Hops   []struct {
			Status int `json:"status"`
		} `json:"hops"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return 0
	}
	if p.Status > 0 {
		return p.Status
	}
	if n := len(p.Hops); n > 0 {
		return p.Hops[n-1].Status
	}
	return 0
}

func uiNode(w http.ResponseWriter, home, id, node string) {
	rec, err := runs.Load(home, id)
	if err != nil {
		uiError(w, http.StatusNotFound, err)
		return
	}
	st, err := openRunStore(rec)
	if err != nil {
		uiError(w, http.StatusNotFound, err)
		return
	}
	defer st.Close()
	ents, err := st.Entities()
	if err != nil {
		uiError(w, http.StatusInternalServerError, err)
		return
	}
	var ent *types.Entity
	for i := range ents {
		if ents[i].ID == node {
			ent = &ents[i]
			break
		}
	}
	if ent == nil {
		uiError(w, http.StatusNotFound, fmt.Errorf("no entity %q in this run", node))
		return
	}
	all, _ := st.Observations()
	passive := passiveCollectors()
	type obsOut struct {
		Collector  string          `json:"collector"`
		Source     string          `json:"source"`
		Kind       string          `json:"kind"`
		Passive    bool            `json:"passive"`
		Confidence float64         `json:"confidence"`
		ObservedAt time.Time       `json:"observed_at"`
		Payload    json.RawMessage `json:"payload"`
	}
	var out []obsOut
	for _, o := range all {
		if o.EntityID != node {
			continue
		}
		out = append(out, obsOut{Collector: o.Collector, Source: o.Source, Kind: o.Kind,
			Passive: passive[o.Collector], Confidence: o.Confidence,
			ObservedAt: o.ObservedAt, Payload: json.RawMessage(runs.MaskJSON(o.Payload))})
	}
	res := map[string]any{"entity": ent, "observations": out}
	if ent.Type == types.TypeURL {
		res["curl"] = "curl -i " + shellQuote(ent.Key)
	}
	uiJSON(w, http.StatusOK, res)
}

// passiveCollectors names the built-in collectors that ask third parties
// only; a collector the catalog does not know counts as one that sent.
// Built once: making the collectors sends nothing.
var passiveCollectors = sync.OnceValue(func() map[string]bool {
	cat := catalog.New()
	collectors.Register(cat, collectors.Options{})
	out := map[string]bool{}
	for _, n := range cat.Names() {
		if c, ok := cat.Get(n); ok && catalog.InfoOf(c).Kind == catalog.Passive {
			out[n] = true
		}
	}
	return out
})

// markFinding puts a finding or lead on its node: a finding's label
// (proved, version-only, conditional), lead for a lead above severity
// info, and a map hint's evidence for a lead of severity info, which is a
// place to look and not a finding.
func markFinding(nodes []uiGraphNode, byKey map[string]int, r findingRecord) {
	k := string(types.TypeURL) + "\x00" + r.URL
	if r.URL == "" {
		k = string(types.TypeHostname) + "\x00" + r.Host
		if _, ok := byKey[k]; !ok {
			k = string(types.TypeIPAddress) + "\x00" + r.Host
		}
	}
	i, ok := byKey[k]
	if !ok {
		return
	}
	n := &nodes[i]
	switch {
	case r.Label != "lead":
		n.Lead = r.Label
	case r.Severity != "" && r.Severity != "info":
		if n.Lead == "" {
			n.Lead = "lead"
		}
	case n.Hint == "":
		n.Hint = r.Evidence
	}
}

// capabilityOrder is azhaq's eight capabilities in the order a run goes
// through them.
var capabilityOrder = []string{"sources", "names", "web", "ports", "fuzz", "shots", "roles", "verify"}

// capabilityOf is the capability a collector belongs to, "" for one that
// belongs to none (a stage of a command, an unknown name).
func capabilityOf(collector string) string {
	switch strings.TrimPrefix(collector, "azhaq-") {
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
	}
	return ""
}
