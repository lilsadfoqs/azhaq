package store

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// run is a run of a target: entities with the rows they were given.
type run map[string][][3]string // key -> collector, kind, payload

func compareRuns(t *testing.T, oldRun, newRun run) Diff {
	t.Helper()
	open := func(name string, r run) *Store {
		st, err := Open(filepath.Join(t.TempDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		now := time.Now().UTC()
		for key, rows := range r {
			typ := types.TypeHostname
			if strings.Contains(key, "://") {
				typ = types.TypeURL
			}
			e, err := st.UpsertEntity(typ, key, now)
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range rows {
				if _, err := st.AddObservation(e.ID, types.Observation{Collector: o[0], Kind: o[1], Payload: json.RawMessage(o[2]), ObservedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
		}
		return st
	}
	d, err := Compare(open("a.db", oldRun), open("b.db", newRun))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func keys(es []types.Entity) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Key)
	}
	return out
}

// The same page with its query names in another order is one URL, and one
// URL stands for it when a run holds both spellings.
func TestCompareQueryOrderIsOneURL(t *testing.T) {
	d := compareRuns(t,
		run{"http://h/latest.php?sort=name&sortorder=ASC&filter_rst=1": nil, "http://h/other": nil},
		run{"http://h/latest.php?filter_rst=1&sort=name&sortorder=ASC": nil, "http://h/latest.php?sort=name&sortorder=ASC&filter_rst=1": nil, "http://h/other": nil})
	if len(d.Added)+len(d.Removed) != 0 {
		t.Errorf("a reordered query is a new and a gone URL: +%v -%v", keys(d.Added), keys(d.Removed))
	}
	d = compareRuns(t, run{"http://h/a.php?x=1&y=2": nil}, run{"http://h/a.php?y=2&x=1&z=3": nil, "http://h/a.php?y=2&x=1": nil})
	if !reflect.DeepEqual(keys(d.Added), []string{"http://h/a.php?y=2&x=1&z=3"}) || len(d.Removed) != 0 {
		t.Errorf("+%v -%v, want only the URL with a new name", keys(d.Added), keys(d.Removed))
	}
}

// A token in the query (a per-visit key) is no new URL, a new query name is.
func TestCompareTokenValuesAreOneURL(t *testing.T) {
	d := compareRuns(t,
		run{"http://h/index.php?reconnect=1&sid=f34f757d65d157eb": nil},
		run{"http://h/index.php?reconnect=1&sid=d243c53758192467": nil, "http://h/index.php?reconnect=1&sid=d243c53758192467&x=1": nil})
	if !reflect.DeepEqual(keys(d.Added), []string{"http://h/index.php?reconnect=1&sid=d243c53758192467&x=1"}) || len(d.Removed) != 0 {
		t.Errorf("+%v -%v, want only the URL with a new name", keys(d.Added), keys(d.Removed))
	}
}

// A conversation id is a number that changes between two visits of one page:
// the URLs are paired, and the rows that name them (a redirect's location, a
// link) are compared with its value left out. A value that is not a number,
// and a number with no partner, are changes.
func TestCompareANumberThatChangesIsOnePage(t *testing.T) {
	page := func(id, cid string) [][3]string {
		return [][3]string{{"azhaq-http", "application", `{"status":302,"location":"http://h/login.seam;jsessionid=AB12?conversationId=` + cid + `","final_url":"http://h/login.seam?conversationId=` + cid + `"}`}}
	}
	d := compareRuns(t,
		run{"http://h/login.seam?conversationId=2": nil, "http://h/summary.seam": page("s", "2")},
		run{"http://h/login.seam?conversationId=7": nil, "http://h/summary.seam": page("s", "7")})
	if len(d.Added)+len(d.Removed)+len(d.NewObs) != 0 || d.Paired != 1 {
		t.Errorf("+%v -%v obs %d paired %d, want one pair and nothing else", keys(d.Added), keys(d.Removed), len(d.NewObs), d.Paired)
	}
	d = compareRuns(t, run{"http://h/list?sortorder=ASC": nil}, run{"http://h/list?sortorder=DESC": nil})
	if len(d.Added) != 1 || len(d.Removed) != 1 || d.Paired != 0 {
		t.Errorf("a value that is not a number was paired: +%v -%v", keys(d.Added), keys(d.Removed))
	}
	d = compareRuns(t, run{"http://h/login.seam?conversationId=2": nil}, run{"http://h/login.seam?conversationId=7": nil, "http://h/login.seam?conversationId=9": nil})
	if len(d.Added) != 1 || len(d.Removed) != 0 || d.Paired != 1 {
		t.Errorf("one number paired of two: +%v -%v paired %d", keys(d.Added), keys(d.Removed), d.Paired)
	}
}

func form(fields string) run {
	return run{"http://h/": {{"azhaq-crawl", "form", `{"method":"POST","action":"http://h/","fields":` + fields + `,"via":"html"}`}}}
}

// A form whose field name is the page's anti-forgery token is the same form
// when only that name changed; another field is a change.
func TestCompareAFormTokenNameIsNoChange(t *testing.T) {
	d := compareRuns(t,
		form(`["username","password","1d932908ff67e1635ed75e5c860c165a"]`),
		form(`["username","password","496d3a105298e68e55a710c831fbd30d"]`))
	if len(d.NewObs) != 0 {
		t.Errorf("a token field name is a change: %+v", d.NewObs)
	}
	d = compareRuns(t,
		form(`["username","password","1d932908ff67e1635ed75e5c860c165a"]`),
		form(`["username","password","remember","496d3a105298e68e55a710c831fbd30d"]`))
	if len(d.NewObs) != 1 {
		t.Errorf("a new field is no change: %d rows", len(d.NewObs))
	}
}

// A secret whose value is the name of a form's field on the run's pages is that form's
// token. One that no form names is a key, and its change is one.
func TestCompareASecretThatIsAFormTokenIsNoChange(t *testing.T) {
	row := func(token string, withForm bool) run {
		r := run{"http://h/": {{"azhaq-js", "secrets", `{"secrets":[{"name":"csrf.token","kind":"generic-secret","value":"` + token + `","context":"x ` + token[:6] + `","entropy":3.7}]}`}}}
		if withForm {
			r["http://h/login"] = [][3]string{{"azhaq-crawl", "form", `{"fields":["username","` + token + `"]}`}}
		}
		return r
	}
	if d := compareRuns(t, row("3d567aa69a92b5bb879821706feb67fc", true), row("14572cb093a45490a6a9f2a910c4cb63", true)); len(d.NewObs) != 0 {
		t.Errorf("a form's token was reported as a changed secret: %d rows", len(d.NewObs))
	}
	if d := compareRuns(t, row("3d567aa69a92b5bb879821706feb67fc", false), row("14572cb093a45490a6a9f2a910c4cb63", false)); len(d.NewObs) != 1 {
		t.Errorf("a secret no form names changed and was not reported: %d rows", len(d.NewObs))
	}
}

// What records when or how a row was asked is not compared; what the target
// answered is.
func TestCompareLeavesOutWhenAndHowAskedButNotWhatAnswered(t *testing.T) {
	same := []struct{ name, collector, kind, a, b string }{
		{"asked_at, ms and cookies of an answer", "azhaq-http", "application",
			`{"status":200,"title":"x","asked_at":"2026-11-16T06:41:19Z","ms":226,"cookies":[{"name":"JSESSIONID"}]}`,
			`{"status":200,"title":"x","asked_at":"2026-11-16T06:42:47Z","ms":7}`},
		{"a timeout where the headers or the body were read", "azhaq-http", "error",
			`{"error":"context deadline exceeded"}`,
			`{"error":"context deadline exceeded (Client.Timeout or context cancellation while reading body)"}`},
		{"observed_at of a proof", "azhaq-verify", "verify",
			`{"service":"jdwp","label":"proved","proof":{"observed_at":"2026-11-16T06:42:02Z","method":"JDWP-Handshake","excerpt":"JDWP-Handshake"}}`,
			`{"service":"jdwp","label":"proved","proof":{"observed_at":"2026-11-16T06:43:21Z","method":"JDWP-Handshake","excerpt":"JDWP-Handshake"}}`},
		{"the DNS message id of a read", "azhaq-verify", "verify",
			`{"service":"dns","product":"ISC BIND","version":"9.10","evidence":"\\x00I\\xf6\\xec\\x85\\x00","proof":{"observed_at":"a","request_bytes":"\\x00\\x1e\\xf6\\xec\\x01","excerpt":"\\x00I\\xf6\\xec\\x85","reproduce":"printf '%b' '\\x00\\x1e\\xf6\\xec\\x01' | nc h 53"}}`,
			`{"service":"dns","product":"ISC BIND","version":"9.10","evidence":"\\x00I-\\xa3\\x85\\x00\\x00","proof":{"observed_at":"b","request_bytes":"\\x00\\x1e-\\xa3\\x01","excerpt":"\\x00I-\\xa3\\x85","reproduce":"printf '%b' '\\x00\\x1e-\\xa3\\x01' | nc h 53"}}`},
		{"the progress of a port scan", "azhaq-ports", "ports",
			`{"host":"h","ip":"10.0.0.1","open":[80],"scanned":65535}`,
			`{"host":"h","ip":"10.0.0.1","open":[],"scanned":15,"asked_ports":"26,37","checkpoint":true,"partial":true,"pass":1,"ports_left":1025}`},
		{"how many checks of a sweep were sent", "azhaq-paths", "sweep",
			`{"origin":"http://h","planned":40,"sent":38,"answered":1,"described":1,"product_checks":{"listed":1134,"sent":1130}}`,
			`{"origin":"http://h","planned":40,"sent":37,"answered":2,"described":1,"product_checks":{"listed":1134,"sent":1131}}`},
		{"the name an advisory's read was sent to", "azhaq-advisories", "advisory",
			`{"advisory_id":"CVE-1","host":"catalog.h","names":["a","b"],"origin":"http://mall.h"}`,
			`{"advisory_id":"CVE-1","host":"catalog.h","names":["a","b"],"origin":"http://www.h"}`},
	}
	for _, c := range same {
		d := compareRuns(t, run{"h": {{c.collector, c.kind, c.a}}}, run{"h": {{c.collector, c.kind, c.b}}})
		if len(d.NewObs) != 0 {
			t.Errorf("%s is compared: %+v", c.name, d.NewObs)
		}
	}
	differ := []struct{ name, collector, kind, a, b string }{
		{"a status", "azhaq-http", "application", `{"status":200,"asked_at":"a"}`, `{"status":403,"asked_at":"b"}`},
		{"an open port", "azhaq-ports", "ports", `{"host":"h","open":[80],"scanned":1000}`, `{"host":"h","open":[80,8080],"scanned":1000}`},
		{"the listed product checks", "azhaq-paths", "sweep", `{"planned":40,"product_checks":{"listed":1134,"sent":1130}}`, `{"planned":40,"product_checks":{"listed":1200,"sent":1130}}`},
		{"a DNS version", "azhaq-verify", "verify", `{"service":"dns","version":"9.10","evidence":"\\x00I\\xf6\\xec"}`, `{"service":"dns","version":"9.18","evidence":"\\x00I\\xf6\\xec"}`},
		{"a DNS refusal", "azhaq-verify", "verify-declined", `{"service":"dns","evidence":"rcode REFUSED"}`, `{"service":"dns","evidence":"rcode NOERROR"}`},
		{"a JDWP answer", "azhaq-verify", "verify", `{"service":"jdwp","proof":{"excerpt":"JDWP-Handshake"}}`, `{"service":"jdwp","proof":{"excerpt":"other"}}`},
		{"an error of another kind", "azhaq-http", "error", `{"error":"context deadline exceeded"}`, `{"error":"connection refused"}`},
	}
	for _, c := range differ {
		d := compareRuns(t, run{"h": {{c.collector, c.kind, c.a}}}, run{"h": {{c.collector, c.kind, c.b}}})
		if len(d.NewObs) != 1 {
			t.Errorf("%s is not compared: %d rows", c.name, len(d.NewObs))
		}
	}
}

// Every field diff leaves out by row type is a field of that row's type, so
// a renamed field breaks here and not silently in the comparison.
func TestVolatileFieldsAreRowFields(t *testing.T) {
	tags := func(v any) map[string]bool {
		out := map[string]bool{}
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			if n, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ","); n != "" {
				out[n] = true
			}
		}
		return out
	}
	http, ports := tags(httprow.Row{}), tags(portscan.Row{})
	for _, k := range volatileAnswer {
		if !http[k] && k != "answer_hash" {
			t.Errorf("%q is no field of httprow.Row", k)
		}
	}
	for _, k := range volatileByRow["azhaq-http application"] {
		if !http[k] {
			t.Errorf("%q is no field of httprow.Row", k)
		}
	}
	if !ports["checkpoint"] {
		t.Error("checkpoint is no field of portscan.Row")
	}
}
