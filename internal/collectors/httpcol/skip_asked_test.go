package httpcol

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// A run that asks its targets as given leaves out the name met in a URL: it
// is not asked on 443 and 80. A name given bare, an address and a URL stay.
func TestSkipAskedOnlyLeavesTheNameOfAURL(t *testing.T) {
	fromURL := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "app.test", types.FromURLKey: "http://app.test:3001/"}}
	bare := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "app.test", types.BareKey: "1"}}
	page := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://app.test:3001/"}}
	for _, tc := range []struct {
		name string
		seed types.Seed
		only bool
		skip bool
	}{
		{"name of a URL, asked as given", fromURL, true, true},
		{"name of a URL, as run does", fromURL, false, false},
		{"bare name", bare, true, false},
		{"the URL itself", page, true, false},
	} {
		c := &Collector{AskedOnly: tc.only}
		if got := c.Skip(tc.seed); got != tc.skip {
			t.Errorf("%s: Skip = %v, want %v", tc.name, got, tc.skip)
		}
	}
}
