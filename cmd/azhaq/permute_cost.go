package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// permuteCost is the size of -permute's job in names and in time at the
// DNS rate: the names given to vary are known, the names found later add
// PerName each.
type permuteCost struct {
	Names      int      `json:"names"`      // names given that are varied
	Variations int      `json:"variations"` // distinct names asked for them
	PerName    int      `json:"per_name"`   // what one more name found adds, at most
	DNSRate    float64  `json:"dns_rate,omitempty"`
	Resolvers  int      `json:"resolvers,omitempty"`
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
		fmt.Fprintf(&b, "%s of %s given", nOf(p.Variations, "variation name", "variation names"), nOf(p.Names, "name", "names"))
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
	names := brutecol.PermuteNames(hosts)
	if len(names) == 0 {
		return nil
	}
	pc := newPermuteCost(hosts, rate, resolvers)
	note := fmt.Sprintf("-permute: %s varied, %s to ask (a name two of them make is asked once)", nOf(len(hosts), "name", "names"), nOf(len(names), "variation name", "variation names"))
	if t := paceText(pc.Seconds, pc.DNSRate, pc.Resolvers); t != "" {
		note += ", " + t
	}
	asked, _ := brutecol.PermuteProgress(brutecol.PermuteHosts(open))
	note += fmt.Sprintf("; %d asked", asked)
	if left := brutecol.PermuteLeft(brutecol.PermuteHosts(open)); stopped && left > 0 {
		note += fmt.Sprintf(", %d not asked when the run stopped (azhaq resume asks them)", left)
	}
	return []string{note}
}
