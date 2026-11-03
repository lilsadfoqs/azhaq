package egress

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A guess is a request for a name nobody told the run: a path of the built-in
// sweep or of a wordlist, a parameter name, a field name a GraphQL server's
// errors are asked for. The collectors that send them are named here; a host
// may be sent only so many (-host-guesses), and the rest are refused, as a
// spent budget refuses them, and listed.
var guessers = map[string]bool{
	"azhaq-paths": true, "azhaq-dirs": true, "azhaq-params": true, "azhaq-graphql-schema": true,
}

var (
	guessMu   sync.Mutex
	guessCap  int64
	guessSent = map[string]int64{}
	guessLeft = map[string]map[string]int64{} // host → collector → requests refused
)

// SetHostGuesses is the most guesses one host is sent; 0 sets none.
func SetHostGuesses(n int64) {
	guessMu.Lock()
	defer guessMu.Unlock()
	guessCap = max(n, 0)
	guessSent = map[string]int64{}
	guessLeft = map[string]map[string]int64{}
}

// HostGuesses is the cap SetHostGuesses set.
func HostGuesses() int64 {
	guessMu.Lock()
	defer guessMu.Unlock()
	return guessCap
}

// admitGuess counts a guess against its host, or refuses it with
// neterr.ErrBudget once the host has had its share.
func admitGuess(req *http.Request) error {
	if req.URL == nil || req.Response != nil {
		return nil
	}
	col := ledger.CollectorOf(req.Context())
	if !guessers[col] {
		return nil
	}
	guessMu.Lock()
	defer guessMu.Unlock()
	if guessCap <= 0 {
		return nil
	}
	h := req.URL.Host
	if guessSent[h] >= guessCap {
		if guessLeft[h] == nil {
			guessLeft[h] = map[string]int64{}
		}
		guessLeft[h][col]++
		MarkRefused(req.Context())
		return neterr.ErrBudget
	}
	guessSent[h]++
	return nil
}

// GuessNotes say, for each host that reached its share, what was not asked.
func GuessNotes() []string {
	guessMu.Lock()
	defer guessMu.Unlock()
	var out []string
	for _, h := range slices.Sorted(maps.Keys(guessLeft)) {
		var by []string
		var total int64
		for _, c := range slices.Sorted(maps.Keys(guessLeft[h])) {
			by = append(by, fmt.Sprintf("%s %d", c, guessLeft[h][c]))
			total += guessLeft[h][c]
		}
		out = append(out, fmt.Sprintf("%s reached -host-guesses %d: %d guesses were not sent (%s): the rest of those lists is not asked, and azhaq resume asks it with a larger -host-guesses", h, guessCap, total, joinComma(by)))
	}
	return out
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
