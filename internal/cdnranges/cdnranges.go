package cdnranges

import (
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/gaissmai/bart"
	"golang.org/x/net/publicsuffix"
)

//go:embed sources_data.json
var sourcesData string

// tables are the ranges of one kind, a prefix table per provider, with
// the provider names in the order they are tried.
type tables struct {
	names []string
	by    map[string]*bart.Table[struct{}]
}

// document is the data's four members as raw JSON, found without reading
// what is in them: the 116,000 cloud ranges are only read by a caller that
// asks about a cloud, and the suffixes only by one that asks about a name.
var document = sync.OnceValue(func() map[string]string {
	m := map[string]string{}
	err := members(sourcesData, func(key, val string) { m[strings.ToLower(key)] = val })
	if err != nil {
		panic("cdnranges: sources_data.json: " + err.Error())
	}
	return m
})

// A kind is one member's ranges, read when first asked for.
type kind struct {
	key  string
	once sync.Once
	t    tables
}

var cdn, waf, cloud = &kind{key: "cdn"}, &kind{key: "waf"}, &kind{key: "cloud"}

func (k *kind) tables() tables {
	k.once.Do(func() { k.t = build(k.key) })
	return k.t
}

// suffixes maps a known suffix to its provider.
var suffixes = sync.OnceValue(func() map[string]string {
	var sources []string
	byName := map[string]string{}
	if err := members(document()["common"], func(source, list string) {
		sources = append(sources, source)
		byName[source] = list
	}); err != nil {
		panic("cdnranges: sources_data.json: " + err.Error())
	}
	sort.Strings(sources)
	out := map[string]string{}
	for _, s := range sources {
		err := strs(byName[s], func(suffix string) {
			if _, taken := out[suffix]; !taken {
				out[suffix] = s // upstream's last write wins, in map order
			}
		})
		if err != nil {
			panic("cdnranges: sources_data.json: " + err.Error())
		}
	}
	return out
})

func build(key string) tables {
	t := tables{by: map[string]*bart.Table[struct{}]{}}
	err := members(document()[key], func(provider, list string) {
		tab := new(bart.Table[struct{}])
		_ = strs(list, func(c string) {
			if p, err := netip.ParsePrefix(c); err == nil {
				tab.Insert(p, struct{}{})
			}
		})
		t.by[provider] = tab
		t.names = append(t.names, provider)
	})
	if err != nil {
		panic("cdnranges: sources_data.json: " + err.Error())
	}
	sort.Strings(t.names)
	return t
}

// match is the provider holding the most specific range around ip (the
// first by name among equals): upstream answers with whichever of them
// its map gives first.
func (t tables) match(ip netip.Addr) (bool, string) {
	best, bits := "", -1
	for _, name := range t.names {
		if p, _, ok := t.by[name].LookupPrefixLPM(netip.PrefixFrom(ip, ip.BitLen())); ok && p.Bits() > bits {
			best, bits = name, p.Bits()
		}
	}
	return bits >= 0, best
}

// Check says whether ip is in a CDN, WAF or cloud range, in that order:
// the provider and "cdn", "waf" or "cloud". A nil or malformed address is
// an error.
func Check(ip net.IP) (matched bool, provider, kind string, err error) {
	return check(ip, true)
}

// CheckEdge is Check without the cloud ranges, which are most of the data
// and hold no CDN or WAF: for a caller that does not report them.
func CheckEdge(ip net.IP) (matched bool, provider, kind string, err error) {
	return check(ip, false)
}

func check(ip net.IP, withCloud bool) (matched bool, provider, kind string, err error) {
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false, "", "", err
	}
	if ok, p := cdn.tables().match(addr); ok && p != "" {
		return true, p, "cdn", nil
	}
	if ok, p := waf.tables().match(addr); ok && p != "" {
		return true, p, "waf", nil
	}
	if withCloud {
		if ok, p := cloud.tables().match(addr); ok && p != "" {
			return true, p, "cloud", nil
		}
	}
	return false, "", "", nil
}

// CheckSuffix says whether one of fqdns ends in a known CDN or WAF suffix
// (its public suffix, or its registered domain).
func CheckSuffix(fqdns ...string) (matched bool, provider, kind string, err error) {
	suffix := suffixes()
	for _, fqdn := range fqdns {
		tld, sld, err := split(fqdn)
		if err != nil {
			return false, "", "", &parseError{err}
		}
		if p, ok := suffix[tld]; ok {
			return true, p, "waf", nil
		}
		if p, ok := suffix[sld+"."+tld]; ok {
			return true, p, "waf", nil
		}
	}
	return false, "", "", nil
}

type parseError struct{ err error }

func (e *parseError) Error() string { return "could not parse fqdn: " + e.err.Error() }
func (e *parseError) Unwrap() error { return e.err }

// split is a name's public suffix (private entries such as cloudfront.net
// included, as the list upstream reads) and the label before it.
func split(name string) (suffix, label string, err error) {
	n := strings.ToLower(name)
	switch {
	case n == "":
		return "", "", errors.New("name is blank")
	case n[0] == '.':
		return "", "", fmt.Errorf("name %s starts with a dot", n)
	}
	suffix, _ = publicsuffix.PublicSuffix(n)
	// A name with its root dot is refused, as upstream refuses it.
	if suffix == n || strings.HasSuffix(n, ".") {
		return "", "", fmt.Errorf("%s is a suffix", n)
	}
	left := strings.TrimSuffix(n, "."+suffix)
	if i := strings.LastIndexByte(left, '.'); i >= 0 {
		left = left[i+1:]
	}
	return suffix, left, nil
}

// EdgeOverlaps says whether a CDN or WAF range holds an address of pf, or
// pf holds one of theirs: whether any address of pf can be CheckEdge's.
func EdgeOverlaps(pf netip.Prefix) bool {
	for _, k := range []*kind{cdn, waf} {
		t := k.tables()
		for _, name := range t.names {
			if t.by[name].OverlapsPrefix(pf) {
				return true
			}
		}
	}
	return false
}
