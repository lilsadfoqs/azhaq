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
		at, part := instanceSig(raw, h.status[raw], hashes[raw], h.in.Addrs)
		if at == "" || (head != "" && head != at) {
			return ""
		}
		head = at
		parts = append(parts, part)
	}
	sort.Strings(parts)
	return head + "\x00" + strings.Join(parts, "\x00")
}

// AnswerSig is the signature of one URL's answer, by the rule the hunt rows
// fold by: the scheme, the address and port its host resolves to (addrs, by
// lower-case name), then the path, the status and the body hash. Two URLs with
// the same signature are one service answering the same under two names. ""
// when the host has no known address or the answer was not read (no status or
// no body hash): such a URL stands alone. Every command that lists one row for
// a service calls this, so they fold the same URLs.
func AnswerSig(raw string, status int, hash string, addrs map[string]string) string {
	at, part := instanceSig(raw, status, hash, addrs)
	if at == "" {
		return ""
	}
	return at + "\x00" + part
}

// instanceSig is the origin (scheme, address, port) and the answer (path,
// status, hash) of one URL, or "" for the origin when either is unknown.
func instanceSig(raw string, st int, hash string, addrs map[string]string) (at, part string) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || hash == "" || st == 0 {
		return "", ""
	}
	addr := addrOf(u.Hostname(), addrs)
	if addr == "" {
		return "", ""
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if port == "" {
		return "", ""
	}
	return u.Scheme + "://" + addr + ":" + port, strings.TrimPrefix(raw, u.Scheme+"://"+u.Host) + "=" + strconv.Itoa(st) + "/" + hash
}

// addrOf is the one address a host name resolved to: the host itself when it
// is an address.
func addrOf(host string, addrs map[string]string) string {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	if a, err := netip.ParseAddr(addrs[host]); err == nil {
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
