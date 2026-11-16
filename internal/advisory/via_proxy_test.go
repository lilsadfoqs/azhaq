package advisory

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// A version only a header gave, through a -proxy that could not be asked for
// its own answer, is matched to no advisory; the name stays, and the
// verification (which reads the version itself) still sees the service.
func TestAHeaderVersionThroughAnUnaskedProxyIsMatchedToNothing(t *testing.T) {
	read := obsOf("azhaq-http", "http", map[string]any{"url": "http://a.test/", "server": "nginx/1.18.0"})
	marked := obsOf("azhaq-http", "http", map[string]any{"url": "http://b.test/", "server": "nginx/1.18.0", "via_proxy": []string{"Server"}})
	if got := Services([]types.StoredObservation{read, marked}); len(got) != 1 || got[0].Host != "a.test" {
		t.Errorf("services %+v, want only the answer no proxy may have touched", got)
	}
	if got := ServicesAnyVersion([]types.StoredObservation{marked}); len(got) != 1 || got[0].Product != "nginx" {
		t.Errorf("any-version services %+v, want the marked one kept for verification", got)
	}
	tech := obsOf("azhaq-http", "http", map[string]any{"url": "http://c.test/", "tech": []string{"PHP:8.1.2"}, "via_proxy": []string{"tech:PHP:8.1.2"}})
	for _, a := range pageApps([]types.StoredObservation{tech}) {
		if a.Version != "" {
			t.Errorf("page app %+v keeps a version a header gave through an unasked proxy", a)
		}
	}
}
