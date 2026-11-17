package portcol

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
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

// Under the default's start, -min-rate is the least its adaptive pace backs off
// to, and a -host-rate given is the most it rises to; a given -rate takes
// neither (#451).
func TestMinRateAndHostRateShapeTheAdaptivePace(t *testing.T) {
	c := &Collector{Scanner: &portscan.Scanner{}}
	c.Apply(Config{MinRate: 600})
	if c.Scanner.Rate != 0 || c.Scanner.MinRate != 600 {
		t.Errorf("pace %v, floor %v, want the default pace with a floor of 600", c.Scanner.Rate, c.Scanner.MinRate)
	}
	c = &Collector{Scanner: &portscan.Scanner{Rate: 200}}
	c.Apply(Config{MinRate: 100})
	if c.Scanner.MinRate != 0 || c.Scanner.Rate != 200 {
		t.Errorf("a given rate got floor %v and pace %v", c.Scanner.MinRate, c.Scanner.Rate)
	}
	fetch.SetHostRate(4000)
	defer fetch.SetHostRate(0)
	if got := New(nil, nil, 0).Scanner.Ceiling; got != 4000 {
		t.Errorf("ceiling %v with -host-rate 4000", got)
	}
}
