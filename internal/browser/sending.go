package browser

import (
	"context"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// hops is what one network ID has had: the requests of it listed in the ledger
// and the answers it got (a redirect answers a hop, a response the last one).
// A hop is answered when both exist for it, whichever came first.
type hops struct{ listed, answers int }

func (h *hops) settled() int { return min(h.listed, h.answers) }

// tally changes what id has had, and counts the hops that are answered now.
func (b *Browser) tally(id network.RequestID, listed, answers int) {
	if id == "" {
		return
	}
	if b.hops == nil {
		b.hops = map[network.RequestID]*hops{}
	}
	h := b.hops[id]
	if h == nil {
		h = &hops{}
		b.hops[id] = h
	}
	before := h.settled()
	h.listed += listed
	h.answers += answers
	if d := h.settled() - before; d > 0 {
		ledger.ChromeAnswered(d)
	}
	if h.listed > 0 && h.listed == h.answers {
		delete(b.hops, id) // all of it is settled
	}
}

// answered notes a response or a redirect for id.
func (b *Browser) answered(id network.RequestID) {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	b.tally(id, 0, 1)
}

// letGo is a request Chrome was let send, not yet seen leaving.
type letGo struct {
	ctx         context.Context
	method, url string
	at          time.Time
	t           *tab
	id          network.RequestID // its network ID, for a plain HTTP request the wire settles
}

// plain: a plain HTTP URL, whose requests the guard reads on the wire
// (wireSent); that, not Chrome's events, says when one left. Chrome's
// events cannot tell a retry that reached the server from one that did
// not, nor see a request no pause held.
func plain(raw string) bool { return strings.HasPrefix(raw, "http://") }

func wireKeyOf(method, raw string) string { return method + " " + raw }

// wireSent lists a plain HTTP request the guard saw leave: the oldest let
// go for that method and URL, or one Chrome took for a cache hit, or, when
// none waits for it (a retry whose count was given back, a request no
// pause held), one counted now. The ledger holds what reached the wire.
func (b *Browser) wireSent(method, raw string) {
	k := wireKeyOf(method, raw)
	b.sendMu.Lock()
	var g letGo
	var waited, cached bool
	if q := b.onWire[k]; len(q) > 0 {
		g, waited = q[0], true
		if b.onWire[k] = q[1:]; len(q) == 1 {
			delete(b.onWire, k)
		}
	} else if q := b.wireHit[k]; len(q) > 0 {
		g, cached = q[0], true
		if b.wireHit[k] = q[1:]; len(q) == 1 {
			delete(b.wireHit, k)
		}
	}
	b.sendMu.Unlock()
	switch {
	case waited:
		egress.Release(1)
	case cached:
		egress.Count(1) // taken for a cache hit, it left after all (a revalidation)
	default:
		egress.Count(1)
		g = letGo{ctx: b.root, method: method, url: raw}
		if g.ctx == nil {
			g.ctx = context.Background()
		}
	}
	ledger.Chrome(g.ctx, g.method, g.url)
	if g.id != "" {
		b.sendMu.Lock()
		b.tally(g.id, 1, 0)
		b.sendMu.Unlock()
	}
}

// sending notes a request just before it is continued. The ledger lists it
// once Chrome says it went out (sentOff); one Chrome drops after all (a
// retry on a dead connection) is neither listed nor counted. Without a
// network ID nothing would say so: it is listed now.
func (b *Browser) sending(id network.RequestID, g letGo) {
	if plain(g.url) && b.guard != nil {
		b.sendMu.Lock()
		defer b.sendMu.Unlock()
		if b.onWire == nil {
			b.onWire, b.wireKey = map[string][]letGo{}, map[network.RequestID]string{}
		}
		egress.Hold(1) // counted, not yet seen on the wire
		g.id = id
		k := wireKeyOf(g.method, g.url)
		b.onWire[k] = append(b.onWire[k], g)
		if id != "" {
			b.wireKey[id] = k
		}
		return
	}
	if id == "" {
		ledger.Chrome(g.ctx, g.method, g.url)
		return
	}
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	if b.out == nil {
		b.out = map[network.RequestID]letGo{}
	}
	if _, ok := b.out[id]; !ok {
		egress.Hold(1) // counted, not yet seen leaving
	}
	b.out[id] = g
}

// pausedAgain settles what was let go under id before Chrome paused it
// again: the same URL is a retry, so the first try never left (Chrome
// retries what got no answer) and its count is given back; another URL is
// a redirect's next hop, so the first one left.
func (b *Browser) pausedAgain(id network.RequestID, raw string) {
	if id == "" {
		return
	}
	b.sendMu.Lock()
	g, ok := b.out[id]
	delete(b.out, id)
	b.sendMu.Unlock()
	switch {
	case !ok:
	case g.url == raw:
		egress.Refund()
		egress.Release(1)
	default:
		egress.Release(1)
		ledger.ChromeAt(g.ctx, g.method, g.url, g.at)
		b.sendMu.Lock()
		b.tally(id, 1, 0)
		b.sendMu.Unlock()
	}
}

// sentOff lists the request Chrome sent under id (Network's
// requestWillBeSentExtraInfo: its headers went out). One already taken
// for a cache hit left after all (a revalidation): it is counted again.
func (b *Browser) sentOff(id network.RequestID) {
	b.sendMu.Lock()
	g, ok := b.out[id]
	delete(b.out, id)
	if ok {
		egress.Release(1)
	} else {
		if g, ok = b.cached[id]; ok {
			delete(b.cached, id)
			egress.Count(1)
		}
	}
	b.sendMu.Unlock()
	if ok {
		ledger.Chrome(g.ctx, g.method, g.url)
		b.sendMu.Lock()
		b.tally(id, 1, 0)
		b.sendMu.Unlock()
	}
}

// fromCache takes back a request Chrome answered from its cache (Network's
// requestServedFromCache): nothing left, so it is neither listed nor
// counted. It is kept aside in case its headers are heard of late.
func (b *Browser) fromCache(id network.RequestID) {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	if k, ok := b.wireKey[id]; ok {
		q := b.onWire[k]
		for i := len(q) - 1; i >= 0; i-- {
			if q[i].id == id {
				g := q[i]
				b.onWire[k] = append(q[:i:i], q[i+1:]...)
				if len(b.onWire[k]) == 0 {
					delete(b.onWire, k)
				}
				if b.wireHit == nil {
					b.wireHit = map[string][]letGo{}
				}
				b.wireHit[k] = append(b.wireHit[k], g)
				egress.Refund()
				egress.Release(1)
				return
			}
		}
		return
	}
	g, ok := b.out[id]
	if !ok {
		return
	}
	delete(b.out, id)
	if b.cached == nil {
		b.cached = map[network.RequestID]letGo{}
	}
	b.cached[id] = g
	egress.Refund()
	egress.Release(1)
}

// unheard lists what was let go for t (nil: for any page) and not heard
// of since: it may have left, and the ledger leaves nothing out.
func (b *Browser) unheard(t *tab) {
	b.sendMu.Lock()
	var left []letGo
	var ids []network.RequestID
	for id, g := range b.out {
		if t == nil || g.t == t {
			left = append(left, g)
			ids = append(ids, id)
			delete(b.out, id)
		}
	}
	for id, g := range b.cached {
		if t == nil || g.t == t {
			delete(b.cached, id)
		}
	}
	// A plain HTTP request the wire did not see did not leave: given back.
	notSent := 0
	for k, q := range b.onWire {
		var keep []letGo
		for _, g := range q {
			if t == nil || g.t == t {
				notSent++
			} else {
				keep = append(keep, g)
			}
		}
		if len(keep) == 0 {
			delete(b.onWire, k)
		} else {
			b.onWire[k] = keep
		}
	}
	for k, q := range b.wireHit {
		var keep []letGo
		for _, g := range q {
			if t != nil && g.t != t {
				keep = append(keep, g)
			}
		}
		if len(keep) == 0 {
			delete(b.wireHit, k)
		} else {
			b.wireHit[k] = keep
		}
	}
	b.sendMu.Unlock()
	for i := 0; i < notSent; i++ {
		egress.Refund()
	}
	egress.Release(notSent)
	egress.Release(len(left))
	for i, g := range left {
		ledger.ChromeAt(g.ctx, g.method, g.url, g.at)
		b.sendMu.Lock()
		b.tally(ids[i], 1, 0)
		b.sendMu.Unlock()
	}
}
