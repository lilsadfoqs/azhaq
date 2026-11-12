package hunt

import (
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/proof"
)

// One service reached by its address and by a name that resolves to it, and
// answering both the same, is one row: the routes of the two hosts have the
// same address, port, path and status, and the answers carry the same body
// hash. The row names the other URLs that answered the same. A route whose
// answer was not read on both hosts is not folded: nothing shows it equal.

// foldNames folds the URL routes that answered the same on every name of one
// address and port into the first of them (a route the target scope holds
// first, then by key).
func (h *hunter) foldNames() {
	if len(h.cands) < 2 {
		return
	}
	hashes := map[string]string{}
	for _, a := range proof.AnswersOf(h.in.Obs) {
		if a.Hash != "" {
			hashes[a.URL] = a.Hash
		}
	}
	groups := map[string][]*cand{}
	for _, c := range h.cands {
		if sig := h.answerSig(c, hashes); sig != "" {
			groups[sig] = append(groups[sig], c)
		}
	}
	for _, g := range groups {
		if len(g) < 2 {
			continue
		}
		sort.Slice(g, func(i, j int) bool {
			if (g[i].scope == "target") != (g[j].scope == "target") {
				return g[i].scope == "target"
			}
			return g[i].key < g[j].key
		})
		first := g[0]
		for _, c := range g[1:] {
			first.merge(c)
			delete(h.cands, c.typ+"\x00"+c.key)
		}
	}
}

// answerSig identifies what a URL route's answers are: the scheme, the
// address and port the host resolves to, the path and the status and body hash
// of every instance. "" when a host has no known address or an instance's
// answer was not read: such a route stands alone.
func (h *hunter) answerSig(c *cand, hashes map[string]string) string {
	if c.typ != "URL" || len(c.instances) == 0 {
		return ""
	}
	var parts []string
	head := ""
	for _, raw := range c.instances {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		hash, st := hashes[raw], h.status[raw]
		if hash == "" || st == 0 {
			return ""
		}
		addr := h.addrOf(u.Hostname())
		if addr == "" {
			return ""
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
		}
		if port == "" {
			return ""
		}
		at := u.Scheme + "://" + addr + ":" + port
		if head != "" && head != at {
			return ""
		}
		head = at
		parts = append(parts, strings.TrimPrefix(raw, u.Scheme+"://"+u.Host)+"="+strconv.Itoa(st)+"/"+hash)
	}
	sort.Strings(parts)
	return head + "\x00" + strings.Join(parts, "\x00")
}

// addrOf is the one address a host name resolved to: the host itself when it
// is an address.
func (h *hunter) addrOf(host string) string {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	if a, err := netip.ParseAddr(h.in.Addrs[host]); err == nil {
		return a.Unmap().String()
	}
	return ""
}

// merge folds o, a route of another name that answered the same, into c: what
// it shows that c does not, and where else the same answer came from.
func (c *cand) merge(o *cand) {
	for _, r := range o.reasons {
		if c.weights[r.Signal] == 0 || r.Signal == "cross-role" {
			if o.proved[r.Signal] {
				c.addProved(r.Signal, o.weights[r.Signal], r.Detail)
			} else {
				c.addW(r.Signal, o.weights[r.Signal], r.Detail)
			}
		}
	}
	c.fresh = c.fresh || o.fresh
	c.also = append(c.also, o.instances...)
	c.also = append(c.also, o.also...)
}
