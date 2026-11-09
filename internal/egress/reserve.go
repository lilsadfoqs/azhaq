package egress

import (
	"slices"
	"strings"
	"sync"
)

// reserves is what each service a sweep found holds of the budget's reserve
// for web work: the keys that hold it with their share, and the origins
// (host:port) their mapping is done under.
type reserves struct {
	mu      sync.Mutex
	share   map[string]int64    // key -> what it set aside
	origins map[string][]string // key -> the origins its web work runs under
	keys    map[string][]string // origin -> the keys it is the mapping of
	fresh   []string            // keys set aside or given origins since TakeFresh
}

func (r *reserves) clear() {
	r.mu.Lock()
	r.share, r.origins, r.keys, r.fresh = nil, nil, nil, nil
	r.mu.Unlock()
}

// ReserveFor sets aside n requests for the web work of the service key (an
// address and port), as Reserve does, and remembers the share so that
// ReleaseFor can give back what is left of it. A key already held is not
// held twice.
func (p *Policy) ReserveFor(key string, n int64) {
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	if _, ok := p.resv.share[key]; ok || n <= 0 {
		return
	}
	if p.resv.share == nil {
		p.resv.share = map[string]int64{}
	}
	p.resv.share[key] = n
	p.reserve.Add(n)
}

// MapsUnder says the web work of the service key runs under origin (host:port,
// the host as a URL or a host seed names it, lower case), so that the work
// that ends on it ends the key's mapping.
func (p *Policy) MapsUnder(key string, origins ...string) {
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	if _, ok := p.resv.share[key]; !ok {
		return
	}
	if p.resv.origins == nil {
		p.resv.origins, p.resv.keys = map[string][]string{}, map[string][]string{}
	}
	for _, o := range origins {
		if !slices.Contains(p.resv.origins[key], o) {
			p.resv.origins[key] = append(p.resv.origins[key], o)
			p.resv.keys[o] = append(p.resv.keys[o], key)
		}
	}
	p.resv.fresh = append(p.resv.fresh, key)
}

// ReserveOrigins are the origins the web work of key runs under, nil when
// key holds nothing.
func (p *Policy) ReserveOrigins(key string) []string {
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	return slices.Clone(p.resv.origins[key])
}

// ReserveKeys are the held keys whose web work runs under origin.
func (p *Policy) ReserveKeys(origin string) []string {
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	var out []string
	for _, k := range p.resv.keys[strings.ToLower(origin)] {
		if _, ok := p.resv.share[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

// TakeFresh returns the keys that were given origins since it was last
// called, held ones only.
func (p *Policy) TakeFresh() []string {
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	var out []string
	for _, k := range p.resv.fresh {
		if _, ok := p.resv.share[k]; ok && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	p.resv.fresh = nil
	return out
}

// ReleaseFor ends the hold of the service key: what is left of the reserve
// above the shares of the services still holding is given back to the sweep.
// A key that holds nothing changes nothing.
func (p *Policy) ReleaseFor(key string) {
	p.resv.mu.Lock()
	defer p.resv.mu.Unlock()
	if _, ok := p.resv.share[key]; !ok {
		return
	}
	delete(p.resv.share, key)
	var rest int64
	for _, n := range p.resv.share {
		rest += n
	}
	for {
		r := p.reserve.Load()
		if r <= rest || p.reserve.CompareAndSwap(r, rest) {
			return
		}
	}
}

func ReserveFor(key string, n int64)          { Current().ReserveFor(key, n) }
func MapsUnder(key string, origins ...string) { Current().MapsUnder(key, origins...) }
func ReserveOrigins(key string) []string      { return Current().ReserveOrigins(key) }
func ReserveKeys(origin string) []string      { return Current().ReserveKeys(origin) }
func TakeFresh() []string                     { return Current().TakeFresh() }
func ReleaseFor(key string)                   { Current().ReleaseFor(key) }
