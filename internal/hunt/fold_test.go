package hunt

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/types"
)

func hashObs(url, hash string) types.StoredObservation {
	raw, _ := json.Marshal(map[string]any{"url": url, "status": 200, "body_hash": hash})
	return types.StoredObservation{EntityID: url, Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: raw, ObservedAt: now}}
}

func foldInput(hashes map[string]string, addrs map[string]string, urls ...string) Input {
	in := Input{DB: "w.db", Now: now, Since: 7 * 24 * time.Hour, Addrs: addrs}
	for _, u := range urls {
		in.Rows = append(in.Rows, urlRow(u, "api", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"id"} }))
		if h, ok := hashes[u]; ok {
			in.Obs = append(in.Obs, hashObs(u, h))
		}
	}
	return in
}

// A route at an address and at a name that resolves to it, answering the same
// body, is one row that names the other URL; a different body, an answer that
// was not read, or a name of another address leaves one row each.
func TestARouteAnsweredTheSameAtAnAddressAndItsNameIsOneRow(t *testing.T) {
	const a, n = "http://127.0.0.1:8080/api/v1/users", "http://localhost:8080/api/v1/users"
	addrs := map[string]string{"localhost": "127.0.0.1"}
	rows := Build(foldInput(map[string]string{a: "aa", n: "aa"}, addrs, a, n))
	if len(rows) != 1 {
		t.Fatalf("same body: %d rows %+v, want 1", len(rows), rows)
	}
	if rows[0].Key != a || len(rows[0].AlsoAt) != 1 || rows[0].AlsoAt[0] != n || !has(&rows[0], "same-answer") {
		t.Errorf("the row %+v must name %s as answering the same", rows[0], n)
	}
	for name, in := range map[string]Input{
		"another body":       foldInput(map[string]string{a: "aa", n: "bb"}, addrs, a, n),
		"unread answer":      foldInput(map[string]string{a: "aa"}, addrs, a, n),
		"another address":    foldInput(map[string]string{a: "aa", n: "aa"}, map[string]string{"localhost": "127.0.0.2"}, a, n),
		"an unresolved name": foldInput(map[string]string{a: "aa", n: "aa"}, nil, a, n),
		"another port":       foldInput(map[string]string{a: "aa", "http://localhost:8081/api/v1/users": "aa"}, addrs, a, "http://localhost:8081/api/v1/users"),
	} {
		if got := Build(in); len(got) != 2 {
			t.Errorf("%s: %d rows, want 2: %+v", name, len(got), got)
		}
	}
}

// Three names of one address that answer the same are one row listing the
// other two, in the order of their URLs.
func TestThreeNamesAnsweringTheSameAreOneRow(t *testing.T) {
	hashes := map[string]string{}
	var urls []string
	addrs := map[string]string{}
	for _, h := range []string{"a.test", "b.test", "c.test"} {
		u := fmt.Sprintf("http://%s/api/orders", h)
		urls = append(urls, u)
		hashes[u], addrs[h] = "ff", "10.0.0.5"
	}
	rows := Build(foldInput(hashes, addrs, urls...))
	if len(rows) != 1 || len(rows[0].AlsoAt) != 2 {
		t.Fatalf("%d rows %+v, want 1 with 2 others", len(rows), rows)
	}
}
