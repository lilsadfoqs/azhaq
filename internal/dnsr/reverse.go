package dnsr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// ErrHeld is the answer to a question the default public resolvers are not
// given and the system's resolver is not asked either (see Held): a record
// type the system's resolver cannot be asked for, or a zone of reverse names.
var ErrHeld = errors.New("the name is not sent to the default public resolvers: it is a reverse name of loopback, private or link-local addresses, or in a zone the root zone does not delegate (-resolvers names resolvers that are asked)")

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

// Held says name is one the pool does not send to its resolvers: a reverse
// name under the local ranges (LocalReverse) or a name in a zone no public
// resolver can answer (HeldZone), when the resolvers are the default public
// ones, which the user did not name. Query asks the system's resolver for a
// held reverse name and Resolve for a held name; nothing else is asked.
func (p *Pool) Held(name string) bool {
	return !p.named && (LocalReverse(name) || HeldZone(name))
}

// noteForward counts a name the system's resolver was asked in place of the
// default ones, and whether it answered. A name is counted once; past the
// cap the repeats are counted again, a few more names.
func (p *Pool) noteForward(name string, answered bool) {
	p.askMu.Lock()
	defer p.askMu.Unlock()
	if _, dup := p.zoneSeen[name]; dup {
		return
	}
	p.zoneHeld++
	if answered {
		p.zoneAnswered++
	}
	if len(p.zoneHeldAt) < 3 {
		p.zoneHeldAt = append(p.zoneHeldAt, name)
	}
	if len(p.zoneSeen) < zoneSeenCap {
		if p.zoneSeen == nil {
			p.zoneSeen = map[string]struct{}{}
		}
		p.zoneSeen[name] = struct{}{}
	}
}

// reverseAddr is the address a full reverse name stands for.
func reverseAddr(name string) (netip.Addr, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) != 4 {
			return netip.Addr{}, false
		}
		var b [4]byte
		for i, l := range labels {
			var v int
			if _, err := fmt.Sscanf(l, "%d", &v); err != nil || v < 0 || v > 255 || fmt.Sprint(v) != l {
				return netip.Addr{}, false
			}
			b[3-i] = byte(v)
		}
		return netip.AddrFrom4(b), true
	case strings.HasSuffix(name, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(labels) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for i, l := range labels {
			if len(l) != 1 || !strings.Contains("0123456789abcdef", l) {
				return netip.Addr{}, false
			}
			v := byte(strings.Index("0123456789abcdef", l))
			n := 31 - i
			if n%2 == 0 {
				b[n/2] |= v << 4
			} else {
				b[n/2] |= v
			}
		}
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

// systemPTR answers a PTR question about a local address from the system's
// resolver, as a response message, and counts it for HeldNote.
func (p *Pool) systemPTR(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	name := q.Question[0].Name
	ip, ok := reverseAddr(name)
	if !ok {
		return nil, ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	names, err := egress.SystemReverse(ctx, ip.String())
	m := new(dns.Msg)
	m.SetReply(q)
	var de *net.DNSError
	switch {
	case err == nil:
		for _, n := range names {
			m.Answer = append(m.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: dns.Fqdn(n)})
		}
	case errors.As(err, &de) && de.IsNotFound:
		m.Rcode = dns.RcodeNameError
	default:
		return nil, err
	}
	p.askMu.Lock()
	p.held++
	if len(m.Answer) > 0 {
		p.heldAnswered++
	}
	if len(p.heldAt) < 3 {
		p.heldAt = append(p.heldAt, strings.TrimSuffix(strings.ToLower(name), "."))
	}
	p.askMu.Unlock()
	return m, nil
}

// zoneSeenCap bounds the names kept to count each once.
const zoneSeenCap = 1 << 17

// HeldNote says how many reverse lookups were kept off the default
// resolvers and asked of the system's resolver instead, and how many it
// answered; "" when none.
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
	return fmt.Sprintf("%d reverse lookup%s (%s) of loopback, private or link-local addresses were kept off the default public resolvers, which are not given the addresses of a private network, and asked of the system's resolver instead: it answered %d; name your own resolvers with -resolvers to ask them instead",
		p.held, s, strings.Join(p.heldAt, ", "), p.heldAnswered)
}

// HeldZoneNote says how many names were kept off the default resolvers and
// asked of the system's resolver instead, and how many it answered; "" when
// none.
func (p *Pool) HeldZoneNote() string {
	p.askMu.Lock()
	defer p.askMu.Unlock()
	if p.zoneHeld == 0 {
		return ""
	}
	v := "are"
	if p.zoneHeld == 1 {
		v = "is"
	}
	return fmt.Sprintf("%d %s (%s) %s a single label or in a zone no public resolver can answer (a special-use name such as .test or .local, a top-level domain the root zone does not delegate such as .internal, .lan or .corp, or home.arpa): kept off the default public resolvers, which would only learn the names, and asked of the system's resolver instead: it answered %d; name your own resolvers with -resolvers to ask them instead",
		p.zoneHeld, map[bool]string{true: "name", false: "names"}[p.zoneHeld == 1], strings.Join(p.zoneHeldAt, ", "), v, p.zoneAnswered)
}
