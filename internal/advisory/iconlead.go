package advisory

import (
	"slices"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/types"
)

// An icon names a product by the hash of one image, which a template build
// or a framework's default icon shares with every site made from it. That is
// a lead to read, not an identification: no version, no advisory, until a
// read of the product itself (httpcol's confirmIcons) or another source
// names it too.

// iconProduct is a product an icon's hash matched, and what the run asked
// to settle it (empty when it asked nothing).
type iconProduct struct{ Product, Ask string }

// iconCand is the products one stored answer's icon named.
type iconCand struct {
	Host          string
	Port          int
	Origin, From  string
	Hash, IconURL string
	ObservedAt    time.Time
	Products      []iconProduct
}

// IconLead is what an icon's hash matched on one name and port, and nothing
// else named: "favicon matches X or Y".
type IconLead struct {
	Host, Origin, From string
	Port               int
	Hash, IconURL      string
	ObservedAt         time.Time
	Products           []string // every product the hash matches, none confirmed
	Asked              []string // what the run asked for each product, and what came back
}

// Says is the lead in words: "favicon matches X or Y".
func (l IconLead) Says() string {
	return "favicon matches " + strings.Join(l.Products, " or ")
}

// IconLeads are the products a hash of an icon named and no other evidence
// of the run did: not the listener's own banner, a header, a title, a
// technology, nor a template of the product matched on a read. The ones a read
// of the product itself settled are identifications and are not here.
func IconLeads(obs []types.StoredObservation) []IconLead {
	_, cands := pageAppsAndIcons(obs)
	if len(cands) == 0 {
		return nil
	}
	addrs := NameAddrs(obs)
	listenerOf := listenerFn(addrs)
	named := map[string]bool{} // listener + product the run's other rows name
	for _, s := range services(obs, false) {
		named[listenerOf(s)+"|"+identity(s.Product)] = true
	}
	var out []IconLead
	at := map[string]int{}
	for _, c := range cands {
		svc := Service{Host: c.Host, Port: c.Port, Proto: "tcp"}
		k := listenerOf(svc)
		for _, p := range c.Products {
			if named[k+"|"+identity(p.Product)] {
				continue
			}
			i, ok := at[k]
			if !ok {
				at[k] = len(out)
				i = len(out)
				out = append(out, IconLead{Host: c.Host, Port: c.Port, Origin: c.Origin, From: c.From, Hash: c.Hash, IconURL: c.IconURL, ObservedAt: c.ObservedAt})
			}
			l := &out[i]
			if slices.ContainsFunc(l.Products, func(x string) bool { return identity(x) == identity(p.Product) }) {
				continue
			}
			l.Products = append(l.Products, p.Product)
			ask := "not asked (stored by an azhaq that asked nothing)"
			if p.Ask != "" {
				ask = p.Ask
			}
			l.Asked = append(l.Asked, p.Product+": "+ask)
			if l.Hash == "" {
				l.Hash, l.IconURL = c.Hash, c.IconURL
			}
		}
	}
	return out
}
