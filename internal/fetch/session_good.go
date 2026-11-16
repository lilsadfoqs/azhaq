package fetch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// A run whose start page looks the same signed in and out has no check page.
// It keeps the pages that answered 200 with the session instead (goods), and
// when an answer looks like the end of the session (a 401, a 403, a redirect
// to another page) or a check is owed, asks some of them again. One that now
// turns the visitor away (401, 403, a redirect to a page whose form takes a
// password) was measured: the session ended, and that page is the check.
const (
	maxGoodSegs   = 64 // path segments that keep pages
	goodsPerSeg   = 2  // pages kept per segment, the newest
	maxGoodProbes = 3  // goods asked again for an answer that looked like the end
	maxDoubts     = 16 // checks that a 403 or a redirect to another page may cost
)

// good is a page that answered 200 with the session.
type good struct {
	url    string
	seg    string
	mark   int64 // GETs asked when it last answered
	probed int64 // order of the last time it was asked again; 0: never
}

// firstSeg is the host and first path segment of raw: pages under it tend to
// be protected alike.
func firstSeg(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	p, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	return u.Host + "/" + p
}

// keepGood notes that raw answered 200 with the session, when no check page
// is known. An answer that came after one that looked like the end is kept
// too: it may have been in flight before it, and a page that answers anyone
// never turns a visitor away, so it can only hold.
func (g *sessionGuard) keepGood(raw string, res Result) {
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	if g.remote || res.Status != http.StatusOK || !strings.Contains(ct, "html") && !strings.Contains(ct, "json") {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.s.Check != "" || g.lost != nil {
		return
	}
	seg := firstSeg(raw)
	n, segs := 0, map[string]bool{}
	for _, x := range g.goods {
		if x.url == raw {
			x.mark = g.total
			return
		}
		segs[x.seg] = true
		if x.seg == seg {
			n++
		}
	}
	switch {
	case n >= goodsPerSeg:
		// The newest pages of a segment stand for it: drop its oldest.
		i := slices.IndexFunc(g.goods, func(x *good) bool { return x.seg == seg })
		g.goods = slices.Delete(g.goods, i, i+1)
	case n == 0 && len(segs) >= maxGoodSegs:
		return
	}
	g.goods = append(g.goods, &good{url: raw, seg: seg, mark: g.total})
}

// doubt notes the answer to a GET that is not a 401 or a redirect to the
// sign-in page but may be the end of the session: a 403, or a redirect to
// another page. With no check page it asks for a check, which asks the goods
// again. The same answer (status and target) is worth a check the first 3
// times and then each time its count doubles, so a site that redirects its
// directories or forbids its folders is not asked about for each.
func (g *sessionGuard) doubt(raw string, status int, location string) {
	location = strings.TrimSpace(location)
	redirect := isRedirect(status) && location != ""
	if g.remote || status != http.StatusForbidden && !redirect || g.renewing.Load() {
		return
	}
	key := fmt.Sprint(status)
	if redirect {
		base, err := url.Parse(raw)
		if err != nil {
			return
		}
		to, err := base.Parse(location)
		if err != nil {
			return
		}
		if strings.TrimSuffix(to.Path, "/") == strings.TrimSuffix(base.Path, "/") {
			return // a trailing slash, a scheme: the page's own
		}
		key += " to " + to.Host + to.Path
	}
	g.mu.Lock()
	if g.s.Check != "" || len(g.goods) == 0 || g.lost != nil || g.doubts >= maxDoubts || !g.worth(key) {
		g.mu.Unlock()
		return
	}
	g.doubts++
	g.pass = true
	g.mu.Unlock()
	g.ends(raw, pathOf(raw)+" answered "+describe(Print{Status: status, Loc: locPath(raw, location)}), true)
}

// worth counts an answer's occurrences and says whether this one is worth a
// check: the 1st to 3rd, then each power of two (mu held).
func (g *sessionGuard) worth(key string) bool {
	if g.seen == nil {
		g.seen = map[string]int{}
	}
	g.seen[key]++
	n := g.seen[key]
	return n <= 3 || n&(n-1) == 0
}

// turnsAway says the answer of a page that answered 200 with the session
// sends the visitor to sign in: a 401, a 403, or a redirect (to loc) to a
// page whose form takes a password.
func turnsAway(ctx context.Context, p Print, loc string) bool {
	switch {
	case p.Status == http.StatusUnauthorized || p.Status == http.StatusForbidden:
		return true
	case isRedirect(p.Status) && loc != "":
		_, _, body, err := askRaw(ctx, loc, true, 256<<10)
		return err == nil && passwordInput.Match(body)
	}
	return false
}

// flipped asks kept pages again, with the session. One that now turns the
// visitor away, having answered 200 with the session, is the measured end of
// it: it becomes the check page, and the GETs asked before it last answered
// are dropped from the ones that may have been answered without the session
// (dropped says how many). When an answer asked for the check, up to
// maxGoodProbes pages are asked, the ones under the answer's segment first;
// otherwise a single page, the one asked again longest ago.
func (g *sessionGuard) flipped(ctx context.Context, signal string) (got Print, dropped int, ok bool) {
	g.mu.Lock()
	doubt := g.pass
	g.pass = false
	if !doubt && signal != "" {
		// A 401 or a redirect to the sign-in page: counted as a doubt is.
		key := signal
		if _, after, found := strings.Cut(signal, " answered "); found {
			key = after
		}
		doubt = g.worth(key)
	}
	cands := slices.Clone(g.goods)
	around := firstSeg(g.endAns)
	g.mu.Unlock()
	if len(cands) == 0 {
		return Print{}, 0, false
	}
	slices.SortStableFunc(cands, func(a, b *good) int {
		if doubt && (a.seg == around) != (b.seg == around) {
			if a.seg == around {
				return -1
			}
			return 1
		}
		if a.probed != b.probed {
			return int(a.probed - b.probed)
		}
		return int(b.mark - a.mark)
	})
	limit := 1
	if doubt {
		limit = maxGoodProbes
	}
	for _, c := range cands[:min(limit, len(cands))] {
		p, loc, _, err := askRaw(ctx, c.url, true, 0)
		if err != nil {
			return Print{}, 0, false
		}
		g.mu.Lock()
		g.probeSeq++
		c.probed = g.probeSeq
		g.mu.Unlock()
		if !turnsAway(ctx, p, loc) {
			continue
		}
		g.mu.Lock()
		g.s.Check, g.s.Want = c.url, Print{Status: http.StatusOK}
		if g.s.SignIn == "" {
			g.s.SignIn = p.Loc
		}
		// The GETs before its 200 were answered with the session.
		if i := min(max(int(c.mark-g.base), 0), len(g.asked)); i > 0 {
			g.asked = slices.Clone(g.asked[i:])
			g.base += int64(i)
			dropped = i
		}
		g.goods = nil
		g.mu.Unlock()
		return p, dropped, true
	}
	return Print{}, 0, false
}
