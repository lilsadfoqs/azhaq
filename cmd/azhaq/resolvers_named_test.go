package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// dnsLines is how many dns lines of the ledger at path name the
// system's resolver, and how many name the resolver at lab.
func dnsLines(t *testing.T, path, lab string) (system, toLab int) {
	t.Helper()
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "dns" {
			switch e.Target {
			case "system":
				system++
			case lab:
				toLab++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return system, toLab
}

// With -resolvers named, a run asks them for every name it uses: the seed's
// own, a .test name, the DNS brute force. Nothing goes to the system's resolver.
func TestRunWithNamedResolversNeverAsksTheSystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>home</title></html>`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	var asked atomic.Int64
	lab := serveCountingZone(t, &asked, map[string]string{"app.lab.test": "127.0.0.1", "www.lab.test": "127.0.0.1"})
	dir := t.TempDir()
	led := filepath.Join(dir, "run.ledger.jsonl")
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("www\nghost\nnothere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := cli(t, "run", "-url", "http://app.lab.test:"+u.Port()+"/", "-domain", "lab.test", "-allow", "lab.test", "-dns-brute", words,
		"-resolvers", lab, "-sources", "none", "-ledger", led, "-db", filepath.Join(dir, "run.db"), "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	system, toLab := dnsLines(t, led, lab)
	if system != 0 {
		t.Errorf("%d dns lines went to the system's resolver, want none", system)
	}
	if toLab == 0 || int64(toLab) != asked.Load() {
		t.Errorf("the ledger lists %d queries to the resolver, it was asked %d times", toLab, asked.Load())
	}
	if rep.Requests == 0 {
		t.Errorf("the page behind the resolver's answer was never requested: %+v", rep)
	}
}
