package portcol

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// -min-rate only raises the pace: under the default pace (-rate 0 is 1500, and
// loopback unpaced) or under -rate it leaves the pace alone; above either it is
// the pace.
func TestMinRateOnlyRaisesThePace(t *testing.T) {
	for _, tt := range []struct {
		rate, min, want float64
	}{
		{0, 0, 0},
		{200, 0, 200},
		{0, 500, 0}, // under the default 1500: the default pace stays
		{0, portscan.DefaultRate, 0},
		{0, 5000, 5000},
		{200, 500, 500},
		{2000, 500, 2000},
		{2000, 3000, 3000},
	} {
		c := &Collector{Scanner: &portscan.Scanner{Rate: tt.rate}}
		c.Apply(Config{MinRate: tt.min})
		if c.Scanner.Rate != tt.want {
			t.Errorf("-rate %v -min-rate %v: pace %v, want %v", tt.rate, tt.min, c.Scanner.Rate, tt.want)
		}
	}
}
