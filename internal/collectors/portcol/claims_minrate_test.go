package portcol

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// -min-rate N sets the pace to N when no rate is given or the rate is
// lower; a higher rate stays. The scanner paces the loopback once it has a
// rate, so -min-rate paces it too.
func TestMinRateSetsThePaceWhenNoRateIsGivenOrItIsLower(t *testing.T) {
	for _, c := range []struct{ have, min, want float64 }{
		{0, 500, 500},
		{100, 500, 500},
		{1000, 500, 1000},
		{0, 0, 0},
	} {
		s := &portscan.Scanner{Rate: c.have}
		(&Collector{Scanner: s}).Apply(Config{MinRate: c.min})
		if s.Rate != c.want {
			t.Errorf("rate %v with -min-rate %v: %v, want %v", c.have, c.min, s.Rate, c.want)
		}
	}
}
