package ledger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A line names what its request was for: the mark a collector put on the
// context, else what the URL names for a collector that reads pages; the
// account counts the same, and a ledger with the purposes in it verifies.
func TestLinesNameWhatTheirRequestsWereFor(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	then := Account()
	c := &http.Client{Transport: Wrap(http.DefaultTransport)}
	crawler := WithCollector(context.Background(), "azhaq-http")
	for _, r := range []struct {
		ctx  context.Context
		path string
	}{
		{crawler, "/about"},
		{crawler, "/main.js"},
		{crawler, "/styles.css"},
		{crawler, "/main.js.map"},
		{crawler, "/logo.png"},
		{WithPurpose(crawler, PurposeControls), "/rest/x8f3k"},
		{WithPurpose(WithCollector(context.Background(), "azhaq-paths"), PurposeDescriptions), "/openapi.json"},
		{WithPurpose(WithCollector(context.Background(), "azhaq-paths"), PurposePathChecks), "/robots.txt"},
		{WithCollector(context.Background(), "azhaq-dirs"), "/admin"},
		{WithCollector(context.Background(), "azhaq-advisories"), "/version"},
	} {
		req, _ := http.NewRequestWithContext(r.ctx, http.MethodGet, srv.URL+r.path, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	TCP(WithCollector(context.Background(), "azhaq-ports"), "", "192.0.2.1:80")
	UDP(WithCollector(context.Background(), "azhaq-ports"), "", "192.0.2.1:53")
	want := []string{PurposePages, PurposeScripts, PurposeScripts, PurposeScripts, PurposeAssets, PurposeControls,
		PurposeDescriptions, PurposePathChecks, PurposeSweep, PurposeOther, PurposeConnections, PurposeDatagrams}
	var got []Entry
	for _, e := range linesOf(t, l, path) {
		if e.Kind != KindSeal {
			got = append(got, e)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%d lines, want %d: %+v", len(got), len(want), got)
	}
	by := map[string]int64{}
	for i, e := range got {
		if e.Purpose != want[i] {
			t.Errorf("line %d (%s %s): purpose %q, want %q", i+1, e.Collector, e.Target, e.Purpose, want[i])
		}
		by[e.Purpose]++
	}
	acc := map[string]int64{}
	for k, n := range Account() {
		if d := n - then[k]; d > 0 && k.Class == ClassTarget {
			acc[k.Purpose] += d
		}
	}
	for p, n := range by {
		if acc[p] != n {
			t.Errorf("%s: the ledger has %d lines, the account %d", p, n, acc[p])
		}
	}
	if c, err := Verify(path); err != nil || c.Entries != len(got) {
		t.Errorf("a ledger with purposes does not verify: %+v %v", c, err)
	}
}
