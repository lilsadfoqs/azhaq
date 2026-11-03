package engine

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// The name derived from a URL the user named, or from a redirect's
// destination, says so: a collector that guesses a name's schemes leaves it
// out, so the URL stays one target.
func TestDerivedHostnameOfANamedURLSaysSo(t *testing.T) {
	host := func(s types.Seed) types.Seed {
		for _, d := range derivedSeeds(s) {
			if d.Type == types.TypeHostname {
				return d
			}
		}
		t.Fatalf("no hostname derived from %v", s.Keys)
		return types.Seed{}
	}
	for name, keys := range map[string]map[string]string{
		"given":    {"url": "http://h.test/a", types.GivenKey: "1"},
		"redirect": {"url": "https://h.test/en/", types.RedirectKey: "1"},
	} {
		if host(types.Seed{Type: types.TypeURL, Keys: keys}).Keys[types.NamedURLKey] == "" {
			t.Errorf("%s: the derived name does not say its URL was named", name)
		}
	}
	if host(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://h.test/a"}}).Keys[types.NamedURLKey] != "" {
		t.Error("a URL a run found marks its name as named")
	}
}
