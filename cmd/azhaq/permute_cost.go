package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/dnscol"
	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// permuteCost is the size of -permute's job in names and in time at the
// DNS rate: the names given to vary are known, the names found later add
// PerName each.
type permuteCost struct {
	Names      int     `json:"names"`      // names given that are varied
	Variations int     `json:"variations"` // distinct names asked for them
	PerName    int     `json:"per_name"`   // what one more name found adds, at most
	DNSRate    float64 `json:"dns_rate,omitempty"`
	Resolvers  int     `json:"resolvers,omitempty"`
	// UpperBound: the names were not resolved yet, and a name that does not
	// resolve is not varied.
	UpperBound bool     `json:"upper_bound,omitempty"`
	Seconds    *float64 `json:"seconds,omitempty"`          // Variations at the rate
	PerNameSec *float64 `json:"per_name_seconds,omitempty"` // PerName at the rate
}

// dnsServers is how many resolvers the pace holds: -dns-rate is the queries
// a second to each.
func dnsServers(named []string) int {
	if len(named) > 0 {
		return len(named)
	}
	return len(dnsr.DefaultResolvers)
}

// dnsSeconds is how long n queries take at rate a second to each of servers
// resolvers; nil when there is no pace to count from.
func dnsSeconds(n int, rate float64, servers int) *float64 {
	if rate <= 0 || servers <= 0 {
		return nil
	}
	s := math.Ceil(float64(n) / (rate * float64(servers)))
	return &s
}

func newPermuteCost(hosts []string, rate float64, resolvers []string) permuteCost {
	pc := permuteCost{Names: len(hosts), Variations: len(brutecol.PermuteNames(hosts)), PerName: brutecol.PermuteCount("name.example.com")}
	if rate > 0 {
		pc.DNSRate, pc.Resolvers = rate, dnsServers(resolvers)
	}
	pc.Seconds = dnsSeconds(pc.Variations, rate, pc.Resolvers)
	pc.PerNameSec = dnsSeconds(pc.PerName, rate, pc.Resolvers)
	return pc
}

// paceText says the time n names take at the rate, or "" with none.
func paceText(sec *float64, rate float64, resolvers int) string {
	if sec == nil {
		return ""
	}
	return fmt.Sprintf("about %s at -dns-rate %g on %s", aboutDuration(time.Duration(*sec*float64(time.Second))), rate, nOf(resolvers, "resolver", "resolvers"))
}

func (p permuteCost) text() string {
	var b strings.Builder
	if p.Names > 0 {
		up := ""
		if p.UpperBound {
			up = "up to "
		}
		fmt.Fprintf(&b, "%s%s of %s given", up, nOf(p.Variations, "variation name", "variation names"), nOf(p.Names, "name", "names"))
		if p.UpperBound {
			b.WriteString(" (an upper bound: a name that does not resolve is not varied)")
		}
		if t := paceText(p.Seconds, p.DNSRate, p.Resolvers); t != "" {
			b.WriteString(", " + t)
		}
		b.WriteString("; ")
	} else {
		b.WriteString("no name is given to vary; ")
	}
	fmt.Fprintf(&b, "each name found later adds up to %d", p.PerName)
	if t := paceText(p.PerNameSec, p.DNSRate, p.Resolvers); t != "" {
		fmt.Fprintf(&b, " (%s)", t)
	} else {
		b.WriteString(" (no -dns-rate: as fast as the resolvers answer)")
	}
	return b.String()
}

// permuteNotes say, once a run has varied names, how many variation names
// the job is and how long that takes at the DNS rate, and when the run was
// stopped, how many were left.
func permuteNotes(st *store.Store, rate float64, resolvers []string, stopped bool) []string {
	tasks, err := st.TasksOf(brutecol.PermuteName)
	if err != nil || len(tasks) == 0 {
		return nil
	}
	var all, open []types.Seed
	for _, t := range tasks {
		all = append(all, t.Seed)
		if !t.Done {
			open = append(open, t.Seed)
		}
	}
	hosts := brutecol.PermuteHosts(all)
	// A name DNS dropped (no address) never reaches Permute: it is not varied.
	hosts, dropped := varied(st, hosts, tasks)
	names := brutecol.PermuteNames(hosts)
	if len(names) == 0 && dropped == 0 {
		return nil
	}
	pc := newPermuteCost(hosts, rate, resolvers)
	if len(names) == 0 {
		return []string{"-permute: " + droppedText(dropped)}
	}
	note := fmt.Sprintf("-permute: %s varied, %s to ask (a name two of them make is asked once)", nOf(len(hosts), "name", "names"), nOf(len(names), "variation name", "variation names"))
	if t := paceText(pc.Seconds, pc.DNSRate, pc.Resolvers); t != "" {
		note += ", " + t
	}
	asked, _ := brutecol.PermuteProgress(brutecol.PermuteHosts(open))
	note += fmt.Sprintf("; %d asked", asked)
	if left := brutecol.PermuteLeft(brutecol.PermuteHosts(open)); stopped && left > 0 {
		note += fmt.Sprintf(", %d not asked when the run stopped (azhaq resume asks them)", left)
	}
	// The names the scope kept out make up the rest of the job's size.
	if out := brutecol.PermuteHeldOut(hosts); out > 0 {
		note += fmt.Sprintf(", %d held out by the scope (never asked: a resume does not ask them either)", out)
	}
	if dropped > 0 {
		note += "; " + droppedText(dropped)
	}
	return []string{note}
}

// droppedText says why names found were not varied.
func droppedText(n int) string {
	if n == 1 {
		return "1 name found did not resolve to an address of its own, so it was not varied"
	}
	return fmt.Sprintf("%d names found did not resolve to an address of their own, so they were not varied", n)
}

// varied is hosts without the ones of finished tasks Permute never ran on
// because DNS found no address for them, and how many those are. A name the
// run varied earlier, or whose answer is not in the store, stays.
func varied(st *store.Store, hosts []string, tasks []store.Task) ([]string, int) {
	pending := map[string]bool{} // finished and not varied in this process
	for _, t := range tasks {
		if h := normalize.Hostname(t.Seed.Keys["fqdn"]); t.Done && !brutecol.Varied(h) {
			pending[h] = true
		}
	}
	if len(pending) == 0 {
		return hosts, 0
	}
	obs, err := st.Observations()
	if err != nil {
		return hosts, 0
	}
	noAddr := map[string]bool{}
	for _, o := range obs {
		var p struct{ FQDN string }
		_ = json.Unmarshal(o.Payload, &p)
		h := normalize.Hostname(p.FQDN)
		switch {
		case o.Collector == brutecol.PermuteName:
			pending[h] = false // it was varied, in an earlier process
		case o.Collector == dnscol.Name && pending[h]:
			noAddr[h] = dnscol.NoAddress(o.Payload)
		}
	}
	var out []string
	dropped := 0
	for _, h := range hosts {
		if pending[h] && noAddr[h] {
			dropped++
			continue
		}
		out = append(out, h)
	}
	return out, dropped
}
