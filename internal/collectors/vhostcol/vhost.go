// Package vhostcol tries each name found, in scope, as a virtual host on the
// web services of the addresses in scope: one request for each (name,
// address, port), with the name as Host, compared with what the service
// answers a name that cannot exist, as ffuf -H "Host: FUZZ" does with its
// calibration. A name whose answer differs is a web service of its own: it
// goes on to the crawl by name.
package vhostcol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/pagesim"
	"github.com/lilsadfoqs/azhaq/types"
)

const (
	Name = "azhaq-vhost"
	// Kind is the observation of a name that a web service answers as a site
	// of its own.
	Kind = "vhost"
	// Calibrations is how many names that cannot exist are asked of a service
	// to learn its default answer.
	Calibrations = 2
	workers      = 8
)

// Collector joins two sets that grow while the run goes: the names found
// and the web services of the addresses in scope. Whichever arrives later
// makes the requests of the pairs it completes, so a pair is asked once.
type Collector struct {
	Client *http.Client
	// Ports are the web ports a name is asked on by azhaq-http (nil: 443 and
	// 80): a name that resolves to an address is requested there already.
	Ports []int
	// Scanned are the TCP ports the run scans: the names found are scanned
	// too, and a web port of a name goes on to be asked by name.
	Scanned []int

	mu       sync.Mutex
	names    map[string]bool
	services map[string]*service // ip:port
	byName   map[string]bool     // name:port: a service already asked by that name
	paired   map[string]bool
}

type service struct {
	scheme, ip, port string

	mu   sync.Mutex
	cals map[string]*calibration // by the zone the unknown names are made in
}

// calibration is what a service answers names that cannot exist.
type calibration struct {
	answers []answer
	shape   pagesim.Shape
	learned bool
	failed  bool
}

// answer is what a response is, apart from the Host that was sent.
type answer struct {
	status              int
	location            string
	length, words, line int
	page                pagesim.Page
	title               string
}

func New(client *http.Client) *Collector { return &Collector{Client: fetch.Client(client)} }

func (c *Collector) Name() string { return Name }

// Info: it sends requests to targets, after azhaq-http so a URL that did not
// answer is dropped. It holds what it has joined in this process, so workers
// never run it. The run skips it with -no-vhost and without a scope.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{After: "azhaq-http", Local: true}
}

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeHostname, types.TypeURL}
}

func (c *Collector) Outputs() []string { return []string{"application"} }

// Skip: a name that is no name, and a URL that is not the root of a web
// service, are not part of the join.
func (c *Collector) Skip(seed types.Seed) bool {
	switch seed.Type {
	case types.TypeHostname:
		h := normalize.Hostname(seed.Keys["fqdn"])
		return h == "" || net.ParseIP(h) != nil
	case types.TypeURL:
		_, _, _, ok := root(seed.Keys["url"])
		return !ok
	}
	return true
}

// root splits the URL of a web service's front page.
func root(raw string) (scheme, host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Hostname() == "" {
		return "", "", "", false
	}
	port = u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme, strings.ToLower(u.Hostname()), port, true
}

type pair struct {
	name string
	svc  *service
}

func (c *Collector) addName(name string) []pair {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.names == nil {
		c.names, c.services, c.byName, c.paired = map[string]bool{}, map[string]*service{}, map[string]bool{}, map[string]bool{}
	}
	if c.names[name] {
		return nil
	}
	c.names[name] = true
	var out []pair
	for _, s := range c.services {
		out = c.claim(out, name, s)
	}
	return out
}

func (c *Collector) addService(s *service, byName string) []pair {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.names == nil {
		c.names, c.services, c.byName, c.paired = map[string]bool{}, map[string]*service{}, map[string]bool{}, map[string]bool{}
	}
	if byName != "" {
		c.byName[byName+":"+s.port] = true
	}
	key := s.ip + ":" + s.port
	if c.services[key] != nil {
		return nil
	}
	c.services[key] = s
	var out []pair
	for n := range c.names {
		out = c.claim(out, n, s)
	}
	return out
}

// claim adds the pair to out unless it was asked or is asked by name already.
func (c *Collector) claim(out []pair, name string, s *service) []pair {
	k := name + "|" + s.ip + ":" + s.port
	if c.paired[k] {
		return out
	}
	c.paired[k] = true
	return append(out, pair{name, s})
}

// askedByName says the run asks a name that resolves to an address on the
// port: azhaq-http on its web ports, and the scan on the ports it scans.
func (c *Collector) askedByName(port string) bool {
	n, _ := strconv.Atoi(port)
	if slices.Contains(c.Scanned, n) {
		return true
	}
	if len(c.Ports) == 0 {
		return n == 443 || n == 80
	}
	return slices.Contains(c.Ports, n)
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	var todo []pair
	switch seed.Type {
	case types.TypeHostname:
		name := normalize.Hostname(seed.Keys["fqdn"])
		if name == "" || net.ParseIP(name) != nil || !egress.Allows(name) {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		todo = c.addName(name)
	case types.TypeURL:
		raw, err := normalize.URL(seed.Keys["url"])
		if err != nil {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		scheme, host, port, ok := root(raw)
		if !ok {
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		ips, byName := []string{host}, ""
		if net.ParseIP(host) == nil {
			ips, byName = egress.Resolve(ctx, host), host
		}
		for _, ip := range ips {
			if egress.AllowsAddr(ip, port) {
				todo = append(todo, c.addService(&service{scheme: scheme, ip: ip, port: port}, byName)...)
			} else if byName != "" {
				c.mu.Lock()
				c.byName[byName+":"+port] = true
				c.mu.Unlock()
			}
		}
	}
	return c.ask(ctx, todo, emit)
}

// finding is a name a service answers as a site of its own.
type finding struct {
	name string
	svc  *service
	ans  answer
	def  answer
}

func (c *Collector) ask(ctx context.Context, todo []pair, emit func(types.Observation) error) (types.RunMeta, error) {
	meta := types.RunMeta{Status: types.StatusOK}
	if len(todo) == 0 {
		return meta, nil
	}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		found []finding
		spent bool
		sem   = make(chan struct{}, workers)
	)
	for _, p := range todo {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p pair) {
			defer wg.Done()
			defer func() { <-sem }()
			f, err := c.try(ctx, p)
			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, neterr.ErrBudget) {
				spent = true
			}
			if f != nil {
				found = append(found, *f)
			}
		}(p)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}
	slices.SortFunc(found, func(a, b finding) int {
		return strings.Compare(a.name+"|"+a.svc.ip+":"+a.svc.port, b.name+"|"+b.svc.ip+":"+b.svc.port)
	})
	for _, f := range found {
		hint, obs := c.describe(ctx, f)
		if err := emit(obs); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if hint.Key() != "" {
			meta.NextHints = append(meta.NextHints, hint)
		}
	}
	if spent {
		meta.Status = types.StatusCapped
		return meta, neterr.ErrBudget
	}
	return meta, nil
}

// describe is the observation of a finding and the URL that goes on to be
// mapped by name: when the name resolves to the service's address, or to
// nothing (then it is pinned to the address). A name that resolves only
// elsewhere is not mapped here: the request by name would go there.
func (c *Collector) describe(ctx context.Context, f finding) (types.Seed, types.Observation) {
	host := hostHeader(f.name, f.svc)
	site := f.svc.scheme + "://" + host + "/"
	ips := egress.Resolve(ctx, f.name)
	here := slices.Contains(ips, f.svc.ip)
	var hint types.Seed
	mapped := ""
	switch {
	case here:
		mapped = "resolves"
	case len(ips) == 0:
		egress.Pin(f.name, f.svc.ip)
		mapped = "pinned"
	}
	if mapped != "" {
		if u, err := normalize.URL(site); err == nil {
			hint = types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u, types.SameTargetKey: "1"}}
		}
	}
	payload := map[string]any{
		"name": f.name, "address": f.svc.ip, "port": f.svc.port, "scheme": f.svc.scheme, "url": site,
		"status": f.ans.status, "length": f.ans.length, "title": f.ans.title,
		"default_status": f.def.status, "default_length": f.def.length, "default_title": f.def.title,
	}
	if mapped != "" {
		payload["mapped"] = mapped
	} else {
		payload["resolves_elsewhere"] = ips
	}
	raw, _ := json.Marshal(payload)
	return hint, types.Observation{Collector: Name, Source: site, Kind: Kind, Payload: raw, Confidence: 0.9, ObservedAt: time.Now().UTC()}
}

// hostHeader is the Host a browser sends for the name on the service's port.
func hostHeader(name string, s *service) string {
	if (s.scheme == "http" && s.port == "80") || (s.scheme == "https" && s.port == "443") {
		return name
	}
	return name + ":" + s.port
}

func (s *service) url() string {
	return s.scheme + "://" + net.JoinHostPort(s.ip, s.port) + "/"
}

// try asks one pair and says whether the answer differs from the default's.
func (c *Collector) try(ctx context.Context, p pair) (*finding, error) {
	n, s := p.name, p.svc
	c.mu.Lock()
	asked := c.byName[n+":"+s.port]
	c.mu.Unlock()
	if asked || (c.askedByName(s.port) && slices.Contains(egress.Resolve(ctx, n), s.ip)) {
		return nil, nil // azhaq-http requests the name itself there
	}
	host := hostHeader(n, s)
	if !egress.AllowsAddr(n, s.port) {
		return nil, nil // a Host header outside the scope is never sent
	}
	cal, err := c.calibrate(ctx, s, n)
	if err != nil || cal.failed {
		return nil, err
	}
	a, err := c.ask1(ctx, s, host)
	if err != nil {
		return nil, err
	}
	if cal.same(a) {
		return nil, nil
	}
	return &finding{name: n, svc: s, ans: a, def: cal.answers[0]}, nil
}

func (c *Collector) ask1(ctx context.Context, s *service, host string) (answer, error) {
	res, _, err := fetch.DoReq(ctx, c.Client, s.url(), &fetch.Req{Header: http.Header{"Host": {host}}})
	if err != nil {
		return answer{}, err
	}
	return read(res, host, s.ip), nil
}

// zoneOf is where the names that cannot exist are made for n: its registered
// domain, else the name's parent.
func zoneOf(n string) string {
	if z := normalize.RegistrableDomain(n); z != "" {
		return z
	}
	if _, rest, ok := strings.Cut(n, "."); ok {
		return rest
	}
	return n
}

// calibrate learns the answer of s to names that cannot exist, once for each
// zone: Calibrations random labels under it. When the scope does not allow
// such a name, the service's answer with no Host of the name's is the default.
func (c *Collector) calibrate(ctx context.Context, s *service, n string) (*calibration, error) {
	zone := zoneOf(n)
	s.mu.Lock()
	defer s.mu.Unlock()
	if cal := s.cals[zone]; cal != nil {
		return cal, nil
	}
	if s.cals == nil {
		s.cals = map[string]*calibration{}
	}
	cal := &calibration{}
	var pages []pagesim.Page
	hosts := make([]string, 0, Calibrations)
	for range Calibrations {
		var b [6]byte
		_, _ = rand.Read(b[:])
		h := hex.EncodeToString(b[:]) + "." + zone
		if !egress.AllowsAddr(h, s.port) {
			hosts = []string{""}
			break
		}
		hosts = append(hosts, hostHeader(h, s))
	}
	for _, h := range hosts {
		var rq *fetch.Req
		if h != "" {
			rq = &fetch.Req{Header: http.Header{"Host": {h}}}
		}
		res, _, err := fetch.DoReq(ctx, c.Client, s.url(), rq)
		if err != nil {
			if errors.Is(err, neterr.ErrBudget) || ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		a := read(res, h, s.ip)
		cal.answers = append(cal.answers, a)
		pages = append(pages, a.page)
	}
	if len(cal.answers) == 0 {
		cal.failed = true // nothing answers: the service is gone
	} else if shape, ok := pagesim.Learn(pages); ok {
		cal.shape, cal.learned = shape, true
	}
	s.cals[zone] = cal
	return cal, nil
}

// same says whether a is the default answer: one the calibration got, or a
// page of the shape the unknown names' pages share (a nonce, a counter).
func (cal *calibration) same(a answer) bool {
	for _, d := range cal.answers {
		if a.status == d.status && a.location == d.location && a.length == d.length && a.words == d.words && a.line == d.line {
			return true
		}
	}
	if !cal.learned {
		return false
	}
	for _, d := range cal.answers {
		if a.status != d.status || a.location != d.location {
			return false
		}
	}
	return cal.shape.Like(a.page)
}

// read takes what is the service's own in a response: the Host that was sent
// and the address are taken out of the body and the redirect, which a default
// page may repeat.
func read(res fetch.Result, host, ip string) answer {
	body := res.Body
	for _, h := range []string{host, ip} {
		if h != "" {
			body = bytes.ReplaceAll(body, []byte(h), []byte("{host}"))
		}
	}
	a := answer{status: res.Status, length: len(body), page: pagesim.Of(body)}
	a.title = a.page.Title
	a.words, a.line = fingerprint.Stats(body)
	if len(res.Hops) > 0 {
		a.location = res.Hops[0].Location
	}
	if u, err := url.Parse(a.location); err == nil && a.location != "" {
		a.location = u.RequestURI() // the same redirect under another host is the same answer
	}
	return a
}
