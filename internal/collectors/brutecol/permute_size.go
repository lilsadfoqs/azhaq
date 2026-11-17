package brutecol

import (
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/types"
)

// PermuteHosts are the names of seeds that Permute varies: not an apex, and
// not a name another variation found.
func PermuteHosts(seeds []types.Seed) []string {
	var out []string
	for _, s := range seeds {
		host := normalize.Hostname(s.Keys["fqdn"])
		if d := normalize.RegistrableDomain(host); d == "" || host == d || s.Keys[types.ViaKey] == types.ViaPermute {
			continue
		}
		out = append(out, host)
	}
	return out
}

// PermuteNames are the distinct names Permute asks for hosts: each name's
// variations, a name two of them make once. Scope and -max-names may hold
// some of them back.
func PermuteNames(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		h = normalize.Hostname(h)
		if d := normalize.RegistrableDomain(h); d == "" || h == d {
			continue
		}
		for _, n := range variants(h, PermuteWords) {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// progress is what Permute settled in this process: the names answered and
// the names scope held out, so a stopped run can say what is left.
var progress struct {
	mu          sync.Mutex
	asked, held map[string]bool
	ran         map[string]bool // the names Permute varied
}

// ResetPermuteProgress forgets what the last run settled.
func ResetPermuteProgress() {
	progress.mu.Lock()
	progress.asked, progress.held, progress.ran = map[string]bool{}, map[string]bool{}, map[string]bool{}
	progress.mu.Unlock()
}

// Varied says Permute varied host in this process: a name DNS dropped never
// reaches it.
func Varied(host string) bool {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	return progress.ran[normalize.Hostname(host)]
}

func markVaried(host string) {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if progress.ran == nil {
		progress.ran = map[string]bool{}
	}
	progress.ran[host] = true
}

func settle(name string, held bool) {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if progress.asked == nil {
		progress.asked, progress.held = map[string]bool{}, map[string]bool{}
	}
	if held {
		progress.held[name] = true
	} else {
		progress.asked[name] = true
	}
}

// PermuteProgress is how many permutation names were asked, and how many
// there are in all: those asked and the ones the names in open still make.
func PermuteProgress(open []string) (asked, total int) {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	left := 0
	for _, n := range PermuteNames(open) {
		if !progress.asked[n] && !progress.held[n] {
			left++
		}
	}
	return len(progress.asked), len(progress.asked) + left
}

// PermuteLeft is how many of the names open makes were not asked or held out.
func PermuteLeft(open []string) int {
	asked, total := PermuteProgress(open)
	return total - asked
}

// PermuteHeldOut is how many of the names hosts make the scope held out: they
// were never asked and a resume does not ask them either.
func PermuteHeldOut(hosts []string) int {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	n := 0
	for _, name := range PermuteNames(hosts) {
		if progress.held[name] && !progress.asked[name] {
			n++
		}
	}
	return n
}
