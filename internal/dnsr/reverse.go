package dnsr

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrHeld is the answer to a reverse lookup of a loopback, private or
// link-local address when the resolvers are the default public ones: the
// question is not sent.
var ErrHeld = errors.New("the reverse name of a loopback, private or link-local address is not sent to the default public resolvers (-resolvers names resolvers that are asked)")

// localNets are the ranges whose reverse names a public resolver is not
// asked: loopback, RFC 1918, RFC 6598 (carrier-grade NAT), link-local and
// IPv6 unique-local.
var localNets = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// LocalReverse says name is under in-addr.arpa or ip6.arpa and stands for
// addresses that are all loopback, private, shared (100.64.0.0/10) or
// link-local: a zone such as 10.in-addr.arpa counts, 172.in-addr.arpa does
// not (it holds public addresses too).
func LocalReverse(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	var pf netip.Prefix
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) > 4 {
			return false
		}
		var b [4]byte
		for i, l := range labels {
			var v int
			if _, err := fmt.Sscanf(l, "%d", &v); err != nil || v < 0 || v > 255 || fmt.Sprint(v) != l {
				return false
			}
			b[len(labels)-1-i] = byte(v)
		}
		pf = netip.PrefixFrom(netip.AddrFrom4(b), 8*len(labels))
	case strings.HasSuffix(name, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(labels) > 32 {
			return false
		}
		var b [16]byte
		for i, l := range labels {
			if len(l) != 1 || !strings.Contains("0123456789abcdef", l) {
				return false
			}
			v := byte(strings.Index("0123456789abcdef", l))
			n := len(labels) - 1 - i // the nibble's place, most significant first
			if n%2 == 0 {
				b[n/2] |= v << 4
			} else {
				b[n/2] |= v
			}
		}
		pf = netip.PrefixFrom(netip.AddrFrom16(b), 4*len(labels))
	default:
		return false
	}
	if pf.Bits() == 0 {
		return false
	}
	for _, n := range localNets {
		if n.Contains(pf.Addr()) && pf.Bits() >= n.Bits() {
			return true
		}
	}
	return false
}

// LocalAddr says a is loopback, private, shared (100.64.0.0/10), link-local or
// unique-local.
func LocalAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, n := range localNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// Named says the resolvers were given (-resolvers), not the public defaults.
func (p *Pool) Named() bool { return p.named }

// Hold says name is a reverse name that the pool does not send: it is under
// the local ranges (LocalReverse) and the resolvers are the default public
// ones, which the user did not name. A held name is counted for HeldNote.
func (p *Pool) Hold(name string) bool {
	if p.named || !LocalReverse(name) {
		return false
	}
	p.askMu.Lock()
	defer p.askMu.Unlock()
	p.held++
	if len(p.heldAt) < 3 {
		p.heldAt = append(p.heldAt, strings.TrimSuffix(strings.ToLower(name), "."))
	}
	return true
}

// HeldNote says how many reverse lookups were not sent and why, "" when none.
func (p *Pool) HeldNote() string {
	p.askMu.Lock()
	defer p.askMu.Unlock()
	if p.held == 0 {
		return ""
	}
	s := "s"
	if p.held == 1 {
		s = ""
	}
	return fmt.Sprintf("not asked: %d reverse lookup%s (%s) of loopback, private or link-local addresses: they would go to the default public resolvers, which are not given the addresses of a private network; name your own with -resolvers to ask them",
		p.held, s, strings.Join(p.heldAt, ", "))
}
