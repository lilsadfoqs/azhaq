package browser

import (
	"context"
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
}

// sending notes a request just before it is continued. The ledger lists it
// once Chrome says it went out (sentOff); one Chrome drops after all (a
// retry on a dead connection) is listed when its page ends (unheard): it
// may have left. Without a network ID nothing would say so: it is listed now.
func (b *Browser) sending(id network.RequestID, g letGo) {
	if id == "" {
		ledger.Chrome(g.ctx, g.method, g.url)
		return
	}
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	if b.out == nil {
		b.out = map[network.RequestID][]letGo{}
	}
	egress.Hold(1) // counted, not yet seen leaving
	b.out[id] = append(b.out[id], g)
}

// pausedAgain settles what was let go under id before Chrome paused it
// again. Another URL is a redirect's next hop: what went before left, and
// is listed. The same URL is a retry, and nothing says whether the try
// before it left (a dead keep-alive connection may have carried it to the
// server): it stays let go, listed when Chrome says it went out or when
// its page ends, never given back.
func (b *Browser) pausedAgain(id network.RequestID, raw string) {
	if id == "" {
		return
	}
	b.sendMu.Lock()
	q := b.out[id]
	if len(q) == 0 || q[len(q)-1].url == raw {
		b.sendMu.Unlock()
		return
	}
	delete(b.out, id)
	b.sendMu.Unlock()
	egress.Release(len(q))
	for _, g := range q {
		ledger.ChromeAt(g.ctx, g.method, g.url, g.at)
		b.sendMu.Lock()
		b.tally(id, 1, 0)
		b.sendMu.Unlock()
	}
}

// take removes and returns the oldest request let go under id.
func (b *Browser) take(id network.RequestID) (letGo, bool) {
	q := b.out[id]
	if len(q) == 0 {
		return letGo{}, false
	}
	if len(q) == 1 {
		delete(b.out, id)
	} else {
		b.out[id] = q[1:]
	}
	return q[0], true
}

// sentOff lists the request Chrome sent under id (Network's
// requestWillBeSentExtraInfo: its headers went out), the oldest let go.
// One already taken for a cache hit left after all (a revalidation): it is
// counted again.
func (b *Browser) sentOff(id network.RequestID) {
	b.sendMu.Lock()
	g, ok := b.take(id)
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
// requestServedFromCache): the latest let go under id did not leave, so it
// is neither listed nor counted. It is kept aside in case its headers are
// heard of late.
func (b *Browser) fromCache(id network.RequestID) {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	q := b.out[id]
	if len(q) == 0 {
		return
	}
	g := q[len(q)-1]
	if len(q) == 1 {
		delete(b.out, id)
	} else {
		b.out[id] = q[:len(q)-1]
	}
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
	for id, q := range b.out {
		var keep []letGo
		for _, g := range q {
			if t == nil || g.t == t {
				left = append(left, g)
				ids = append(ids, id)
			} else {
				keep = append(keep, g)
			}
		}
		if len(keep) == 0 {
			delete(b.out, id)
		} else {
			b.out[id] = keep
		}
	}
	for id, g := range b.cached {
		if t == nil || g.t == t {
			delete(b.cached, id)
		}
	}
	b.sendMu.Unlock()
	egress.Release(len(left))
	for i, g := range left {
		ledger.ChromeAt(g.ctx, g.method, g.url, g.at)
		b.sendMu.Lock()
		b.tally(ids[i], 1, 0)
		b.sendMu.Unlock()
	}
}
