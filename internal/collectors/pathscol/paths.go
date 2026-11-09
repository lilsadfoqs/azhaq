package pathscol

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/crawlscope"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

const Name = "azhaq-paths"

// SweepKind is the observation that says what became of the checks of an origin's sweep.
const SweepKind = "sweep"

const parallel = 6

// DefaultWordlist is a short recon list, not an exploit pack.
var DefaultWordlist = []string{
	"robots.txt",
	"sitemap.xml",
	"sitemap_index.xml",
	".well-known/security.txt",
	".well-known/openid-configuration",
	"login",
	"admin",
	"dashboard",
	"register",
	"signup",
	"api",
	"api/v1",
	"api/status",
	"rest",
	"graphql",
	"graphiql",
	"api/graphql",
	"v1/graphql",
	"gql",
	"playground",
	"swagger",
	"swagger.json",
	"swagger.yaml",
	"openapi.json",
	"openapi.yaml",
	"api-docs",
	"v2/api-docs",
	"v3/api-docs",
	"swagger/v1/swagger.json",
	"api/swagger.json",
	"api/openapi.json",
	"v3/api-docs.yaml",
	"swagger/v2/swagger.json",
	"swagger/doc.json",
	"api-json",
	"documentation/json",
	"api/schema",
	"apispec_1.json",
	"api-docs/v1/swagger.json",
	"docs/api-docs.json",
	"api/v1/openapi.json",
	"api/v1/swagger.json",
	"swagger-ui.html",
	"swagger-ui/index.html",
	"redoc",
	"docs",
	"health",
	"internal",
	"backup",
	".git/HEAD",
	"favicon.ico",
}

type Collector struct {
	Client   *http.Client
	Wordlist []string
	// Known, set by -known-files, makes the sweep ask only the files it
	// names (robots.txt, sitemaps), read every entry of them, and not sweep
	// under API bases.
	Known     bool
	probed    sync.Map // scheme://host (or scheme://host/api/v2/) → the URL whose task sweeps it; one sweep each
	planned   sync.Map // the same, claimed while no workspace is bound: a plan's, or a run's with none
	baseCount sync.Map // scheme://host → API bases swept
}

func New(client *http.Client) *Collector {
	return &Collector{Client: fetch.Client(client), Wordlist: DefaultWordlist}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func (c *Collector) Name() string { return Name }

// Info: this collector sends requests to the target.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http"}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

// Skip declines every URL on an origin but the one whose task sweeps it
// (the first one asked, in this process or before azhaq resume), and the
// first one under each API base it has not swept.
func (c *Collector) Skip(seed types.Seed) bool {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	if c.owner(origin, raw) == raw {
		return false
	}
	if c.Known {
		return true
	}
	b := apiBase(u.Path)
	// The root sweep asks /api/swagger.json and /api/openapi.json.
	return b == "" || b == "/api/" || c.owner(origin+b, raw) != raw
}

// specWords are where an API's description sits under its base
// (/identity/api/v2/openapi.json): servers that mount several APIs serve
// each one's there, not at the site's root.
var specWords = []string{"openapi.json", "openapi.yaml", "swagger.json", "swagger.yaml", "api-docs", "v3/api-docs",
	"v2/api-docs", "v3/api-docs/swagger-config", "swagger-resources", "swagger/v1/swagger.json"}

// maxBases bounds the API bases swept per origin.
const maxBases = 8

var versionSeg = lazyre.New(`^v\d+(\.\d+)?$`)

// apiBase is the base of the API a path is under (/api/, /api/v2/,
// /identity/api/v2/), or "" for a path under none, or under the root.
func apiBase(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	end := -1
	for i, seg := range segs[:min(len(segs), 5)] {
		low := strings.ToLower(seg)
		switch {
		case low == "api" || low == "rest" || low == "apis":
			end = i
		case versionSeg.MatchString(low) && (end == i-1 || i == 0):
			end = i
		}
	}
	if end < 0 {
		return ""
	}
	return "/" + strings.Join(segs[:end+1], "/") + "/"
}

// bases counts the API bases of origin swept so far, this one included.
func (c *Collector) bases(origin string) int {
	v, _ := c.baseCount.LoadOrStore(origin, new(atomic.Int32))
	return int(v.(*atomic.Int32).Add(1))
}

// owner is the URL whose task sweeps origin, claiming it for raw when
// nobody has.
//
// A claim made while none is bound (azhaq plan, or the estimate a run makes
// before it sends) is not the run's: it stays apart, so that the run's first
// claim lands in its workspace and a resume gives the sweep to the same task.
func (c *Collector) owner(origin, raw string) string {
	if catalog.Claim == nil {
		v, _ := c.planned.LoadOrStore(origin, raw)
		return v.(string)
	}
	if v, ok := c.probed.Load(origin); ok {
		return v.(string)
	}
	v, _ := c.probed.LoadOrStore(origin, catalog.Claim(Name+" "+origin, raw))
	return v.(string)
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	base, err := url.Parse(raw)
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	prefix := probePrefix(base.Path)
	origin := base.Scheme + "://" + base.Host
	var list []string
	root := false // the sweep of the origin's built-in checks, not of an API base
	switch b := apiBase(base.Path); {
	case c.owner(origin, raw) == raw:
		root = true
		list = c.Wordlist
		if len(list) == 0 {
			list = DefaultWordlist
		}
	case !c.Known && b != "" && b != "/api/" && c.owner(origin+b, raw) == raw && c.bases(origin) <= maxBases:
		// The root sweep asks /api/swagger.json and /api/openapi.json.
		prefix, list = b, specWords
	default:
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	meta := types.RunMeta{Status: types.StatusOK}
	var mu sync.Mutex
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var skipped atomic.Int32
	// What became of each check of the sweep: asked, answered by a request
	// sent before, or refused by the run's limits (and why).
	var sent, answered atomic.Int32
	refused := map[string]int{}
	tally := func(cached bool, err error) {
		switch {
		case err == nil || !stoppedBefore(err):
			if cached {
				answered.Add(1)
			} else {
				sent.Add(1)
			}
		case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		default:
			mu.Lock()
			refused[refusal(err)]++
			mu.Unlock()
		}
	}
	// probe asks one location and emits what it finds; it says whether the
	// answer was an API description.
	probe := func(target, path string) bool {
		purpose := ledger.PurposePathChecks
		if isDescLoc(path) || isGraphQLLoc(path) {
			purpose = ledger.PurposeDescriptions
		}
		res, cached, err := fetch.Do(ledger.WithPurpose(ctx, purpose), c.Client, target)
		tally(cached, err)
		if err != nil || !(interesting(res.Status) || isGraphQLLoc(path) && refusesGET(res.Status)) || fetch.CatchAll(ctx, c.Client, res) {
			return false
		}
		known := isDescLoc(path) && res.Status < 400 && describes(res.Body) || isGraphQLLoc(path)
		reqURL := target
		if n, err := normalize.URL(target); err == nil {
			reqURL = n
		}
		final := res.URL
		if n, err := normalize.URL(res.URL); err == nil {
			final = n
		}
		row := map[string]any{
			"url":       reqURL,
			"via":       "paths",
			"status":    res.Status,
			"path":      "/" + path,
			"final_url": final,
			"hops":      res.Hops,
		}
		if known {
			row[types.ExposedByKey] = raw
		}
		payload, _ := json.Marshal(row)
		mu.Lock()
		defer mu.Unlock()
		if err := emit(types.Observation{
			Collector:  Name,
			Source:     raw,
			Kind:       "url",
			Payload:    payload,
			Confidence: 0.75,
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			return false
		}
		meta.EmitCount++
		if res.Status == 200 && (strings.HasSuffix(path, "sitemap.xml") || path == "sitemap_index.xml") {
			for _, loc := range sitemapLocs(res.Body, c.Known) {
				c.hintURL(raw, loc, &meta, emit)
			}
		}
		if path == "robots.txt" && res.Status == 200 {
			refs, skipped := robotsRefs(res.Body, base, c.Known)
			for _, loc := range refs {
				c.hintURL(raw, loc, &meta, emit)
			}
			for _, x := range skipped {
				if emit(webextract.RejectedObs(Name, target, x, webextract.ReasonWildcard, "robots", "")) == nil {
					meta.EmitCount++
				}
			}
		}
		for _, u := range []string{reqURL, final} {
			if u == "" || !webextract.Hintable(u) {
				continue
			}
			low := strings.ToLower(u)
			if strings.HasSuffix(low, ".txt") || strings.HasSuffix(low, ".xml") || strings.HasSuffix(low, ".ico") {
				continue
			}
			keys := map[string]string{"url": u}
			if known {
				// A guess about the origin itself: read at any -depth.
				keys[types.KnownLocationKey], keys[types.ExposedByKey] = "1", raw
			}
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: keys})
		}
		return isDescLoc(path) && res.Status < 400 && describes(res.Body)
	}
	locs, descs := sweepWords(list)
	targetOf := func(path string) string {
		return locationOf(base, prefix, path)
	}
	planned := 0 // the checks of the sweep: its own URL is the page, not one of them
	for _, path := range append(slices.Clone(locs), descs...) {
		if targetOf(path) != raw {
			planned++
		}
	}
	if len(descs) > 0 {
		wg.Add(1)
		go func() {
			defer guard.Recover(ctx)
			defer wg.Done()
			for _, path := range descs {
				target := targetOf(path)
				if target == raw || ctx.Err() != nil {
					continue
				}
				if fetch.Described(origin) {
					skipped.Add(1)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
				}
				found := probe(target, path)
				<-sem
				if found {
					fetch.MarkDescribed(origin)
				}
			}
		}()
	}
	for _, path := range locs {
		if ctx.Err() != nil {
			break
		}
		target := targetOf(path)
		if target == raw {
			continue
		}
		wg.Add(1)
		go func(target, path string) {
			defer guard.Recover(ctx)
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			probe(target, path)
		}(target, path)
	}
	wg.Wait()
	if n := skipped.Load(); n > 0 {
		payload, _ := json.Marshal(map[string]any{"skipped_checks": n, "origin": origin})
		if err := emit(types.Observation{Collector: Name, Source: raw, Kind: "note", Payload: payload, Confidence: 1, ObservedAt: time.Now().UTC()}); err == nil {
			meta.EmitCount++
		}
	}
	if root {
		// What became of each check of the origin's sweep: the summary's path_checks.
		done := map[string]any{"origin": origin, "planned": planned, "sent": sent.Load(), "answered": answered.Load(), "described": skipped.Load()}
		if len(refused) > 0 {
			done["refused"] = refused
		}
		payload, _ := json.Marshal(done)
		if err := emit(types.Observation{Collector: Name, Source: raw, Kind: SweepKind, Payload: payload, Confidence: 1, ObservedAt: time.Now().UTC()}); err == nil {
			meta.EmitCount++
		}
	}
	return meta, ctx.Err()
}

// refusal is why a request was refused, without the URL the error wraps.
func refusal(err error) string {
	var d *neterr.Denied
	var k *neterr.Killed
	switch {
	case errors.As(err, &d):
		return strings.TrimPrefix(d.Error(), "not requested: ")
	case errors.As(err, &k):
		return "stopped: kill file " + k.Path + " exists"
	case errors.Is(err, neterr.ErrGuessCap):
		return "-host-guesses reached for this host"
	case errors.Is(err, neterr.ErrBudget):
		return "the request budget is spent"
	case errors.Is(err, neterr.ErrOutOfPort):
		return neterr.OutOfPortReason
	case errors.Is(err, neterr.ErrOutOfScope):
		return "outside the scope"
	case errors.Is(err, neterr.ErrNotRepeated):
		return "sent before the run was killed, and not sent again"
	case errors.Is(err, neterr.ErrOriginDown):
		return "the origin stopped answering"
	}
	return err.Error()
}

// stoppedBefore says a request was refused before it left: the scope, a
// -deny-path rule, the budget, the kill file or an origin that stopped
// answering, or the run was interrupted.
func stoppedBefore(err error) bool {
	return errors.Is(err, neterr.ErrDenied) || errors.Is(err, neterr.ErrOutOfScope) || errors.Is(err, neterr.ErrBudget) ||
		errors.Is(err, neterr.ErrNotRepeated) || errors.Is(err, neterr.ErrOriginDown) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// sweepWords splits a wordlist into the locations asked in any order and the
// guesses of an API description, which go one at a time, likeliest first.
func sweepWords(list []string) (locs, descs []string) {
	for _, path := range list {
		path = strings.TrimPrefix(path, "/")
		if path == "" {
			continue
		}
		if isDescLoc(path) {
			descs = append(descs, path)
		} else {
			locs = append(locs, path)
		}
	}
	slices.SortStableFunc(descs, func(a, b string) int { return descRank(a) - descRank(b) })
	return locs, descs
}

// HeldWords is how many words of list name a state change by their own path
// or query: the run holds those GETs back unless -send-state-changing is given.
func HeldWords(list []string) int {
	n := 0
	for _, w := range list {
		if w = strings.TrimPrefix(w, "/"); w == "" {
			continue
		}
		if word, _ := statechange.OfTarget("/" + w); word != "" {
			n++
		}
	}
	return n
}

// locationOf is the URL a word of the sweep asks, under prefix.
func locationOf(base *url.URL, prefix, path string) string {
	target := base.Scheme + "://" + base.Host + prefix + path
	if u, err := normalize.URL(target); err == nil {
		target = u
	}
	return target
}

// Sweep is what the sweep of the origin of raw asks of list, as URLs: the
// locations every sweep asks, and the guesses of an API description, which
// stop at the first that is one. The URL itself is not among them.
func Sweep(raw string, list []string) (locs, descs []string) {
	raw, err := normalize.URL(raw)
	if err != nil {
		return nil, nil
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, nil
	}
	words, guesses := sweepWords(list)
	prefix := probePrefix(base.Path)
	for _, w := range words {
		if t := locationOf(base, prefix, w); t != raw {
			locs = append(locs, t)
		}
	}
	for _, w := range guesses {
		if t := locationOf(base, prefix, w); t != raw {
			descs = append(descs, t)
		}
	}
	return locs, descs
}

var locRE = lazyre.New(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

func sitemapLocs(body []byte, all bool) []string {
	var out []string
	n := 64
	if all {
		n = -1
	}
	for _, m := range locRE.FindAllSubmatch(body, n) {
		if len(m) != 2 {
			continue
		}
		u, err := normalize.URL(string(m[1]))
		if err != nil {
			continue
		}
		out = append(out, u)
	}
	return out
}

func (c *Collector) hintURL(raw, loc string, meta *types.RunMeta, emit func(types.Observation) error) {
	if !crawlscope.Within(raw, loc) {
		if c.Known && crawlscope.Wide() {
			p, _ := json.Marshal(map[string]string{"url": loc, "via": "paths"})
			if emit(types.Observation{Collector: Name, Source: raw, Kind: "offsite", Payload: p, Confidence: 0.75, ObservedAt: time.Now().UTC()}) == nil {
				meta.EmitCount++
			}
		}
		return
	}
	if !webextract.Hintable(loc) {
		return
	}
	meta.NextHints = append(meta.NextHints, types.Seed{
		Type: types.TypeURL, Keys: map[string]string{"url": loc},
	})
}

// robotsRefs are the paths a robots.txt names, and the entries that are
// patterns, not paths. all lifts the 32 it stops at otherwise.
func robotsRefs(body []byte, base *url.URL, all bool) (out, patterns []string) {
	if base == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || ref == "/" {
			return
		}
		if strings.Contains(ref, "*") || strings.HasSuffix(ref, "$") {
			patterns = append(patterns, ref)
			return
		}
		u, err := base.Parse(ref)
		if err != nil {
			return
		}
		n, err := normalize.URL(u.String())
		if err != nil || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "sitemap":
			add(strings.TrimSpace(val))
		case "allow", "disallow":
			add(strings.TrimSpace(val))
		}
		if len(out) >= 32 && !all {
			break
		}
	}
	return out, patterns
}

// probePrefix is the directory under which the wordlist is joined.
// /app/sub → /app/sub/; /app/page.html → /app/; / → /.
func probePrefix(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.HasSuffix(p, "/") {
		return p
	}
	i := strings.LastIndex(p, "/")
	last := p[i+1:]
	if strings.Contains(last, ".") {
		if i <= 0 {
			return "/"
		}
		return p[:i+1]
	}
	return p + "/"
}

// refusesGET: a GraphQL endpoint's answer to a GET with no query, or to one
// it does not take.
func refusesGET(status int) bool {
	switch status {
	case 400, 405, 415, 422, 500:
		return true
	}
	return false
}

func interesting(status int) bool {
	switch status {
	case 200, 201, 204, 301, 302, 303, 307, 308, 401, 403:
		return true
	default:
		return false
	}
}

// KnownFiles is the sweep -known-files asks for: robots.txt, sitemaps, or both.
func KnownFiles(which string) []string {
	switch strings.ToLower(which) {
	case "robotstxt", "robots":
		return []string{"robots.txt"}
	case "sitemapxml", "sitemap":
		return []string{"sitemap.xml", "sitemap_index.xml"}
	}
	return []string{"robots.txt", "sitemap.xml", "sitemap_index.xml"}
}
