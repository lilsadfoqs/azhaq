package main

import (
	"strings"
	"testing"
)

const goneTarget = "azq-lab-gone-7c1e.us-east-1.elasticbeanstalk.com"

// allRowsArgs is a run over a zone with two dangling CNAMEs among the
// guessed and permuted names.
func allRowsArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	resolvers := serveZone(t, fakeZone{
		a: map[string]string{
			"azqlab.lan": "192.0.2.1", "www.azqlab.lan": "192.0.2.1", "api.azqlab.lan": "192.0.2.2",
			"mail.azqlab.lan": "192.0.2.3", "www-dev.azqlab.lan": "192.0.2.4",
		},
		cname:  map[string]string{"docs.azqlab.lan": goneTarget, "assets.azqlab.lan": goneTarget},
		nxGone: true,
	})
	words := writeList(t, "www", "api", "mail", "docs", "assets")
	return append([]string{"run", "-domain", "azqlab.lan", "-passive", "-sources", "none", "-no-history", "-dns-brute", words,
		"-permute", "-resolvers", resolvers, "-dns-rate", "0", "-max-time", "30s", "-allow", "azqlab.lan", "-allow", "192.0.2.0/24",
		"-web-ports", "65534", "-no-paths", "-no-favicon", "-no-tech", "-no-follow", "-ledger", "off"}, extra...)
}

func storedNames(t *testing.T, db string) map[string]bool {
	t.Helper()
	out, _, err := captureBoth(t, func() error {
		return run([]string{"query", "-db", db, "-type", "Hostname", "-fields", "key", "-json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range jsonRows(t, out) {
		got[r["key"].(string)] = true
	}
	return got
}

// -all-rows prints every stored row, and a takeover candidate is a row
// in the default view too: the map never folds one into a summary row.
func TestRunAllRowsPrintsEveryStoredNameAndTakeoverCandidates(t *testing.T) {
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, allRowsArgs(t, "-all-rows", "-db", "a.db")...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: notes %q", code, rep.Notes)
	}
	printed := map[string]bool{}
	for _, r := range jsonRows(t, out) {
		if k, _ := r["key"].(string); k != "" {
			printed[k] = true
		}
	}
	stored := storedNames(t, "a.db")
	for _, d := range []string{"docs.azqlab.lan", "assets.azqlab.lan"} {
		if !stored[d] {
			t.Fatalf("%s is not stored: %v", d, stored)
		}
	}
	for n := range stored {
		if !printed[n] {
			t.Errorf("stored name %s is not a printed row:\n%s", n, out)
		}
	}
	if len(rep.Takeover) != 2 {
		t.Fatalf("takeover candidates %+v, want docs and assets", rep.Takeover)
	}
	for _, c := range rep.Takeover {
		if !printed[c.Host] {
			t.Errorf("takeover candidate %s is not a printed row", c.Host)
		}
	}
}

func TestRunTextViewNeverFoldsATakeoverCandidate(t *testing.T) {
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, allRowsArgs(t, "-db", "d.db")...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, h := range []string{"docs.azqlab.lan", "assets.azqlab.lan"} {
		if !strings.Contains(out, h) {
			t.Errorf("takeover candidate %s is no line of the map:\n%s", h, out)
		}
	}
}

// -stream prints one found line for each row the map prints.
func TestRunStreamLinesAreTheMapsRowsWithDeadNames(t *testing.T) {
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, allRowsArgs(t, "-stream", "-all-rows", "-db", "s.db")...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: notes %q", code, rep.Notes)
	}
	streamed, mapped := map[string]bool{}, map[string]bool{}
	for _, r := range jsonRows(t, out) {
		key, _ := r["key"].(string)
		if r["type"] == "found" {
			streamed[key] = true
		} else if key != "" {
			mapped[key] = true
		}
	}
	for _, d := range []string{"docs.azqlab.lan", "assets.azqlab.lan", "azqlab.lan"} {
		if !mapped[d] {
			t.Errorf("%s is no map row: %v", d, keysOf(mapped))
		}
	}
	if !equalSets(streamed, mapped) {
		t.Errorf("the stream keys %v are not the map keys %v", keysOf(streamed), keysOf(mapped))
	}
}
