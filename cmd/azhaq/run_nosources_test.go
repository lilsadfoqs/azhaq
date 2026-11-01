package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// thirdPartyCatcher stands in for every third party a run could ask: it is
// the run's proxy for them, and counts what reaches it.
func thirdPartyCatcher(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Error(w, "caught", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		t.Setenv(k, srv.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	return &n
}

// -sources none means no third party is asked: not a subdomain source, an
// archive, RDAP, a search engine or RIPEstat. A run with it sends to the
// resolvers and the targets, and its ledger holds no source line.
func TestRunSourcesNoneAsksNoThirdParty(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AZHAQ_DATA_DIR", dir)
	caught := thirdPartyCatcher(t)
	resolvers := serveZone(t, fakeZone{a: map[string]string{"app.example.com": "192.0.2.1"}})
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("app\nnope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := cli(t, "run", "-domain", "example.com", "-sources", "none", "-dns-brute", words, "-permute",
		"-resolvers", resolvers, "-depth", "0", "-passive", "-db", "r.db", "-ledger", "r.ledger", "-quiet")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	var dns, source int
	if err := ledger.Read("r.ledger", func(e ledger.Entry) error {
		switch e.Class {
		case ledger.ClassDNS:
			dns++
		case ledger.ClassSource:
			source++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if source != 0 || caught.Load() != 0 {
		t.Errorf("-sources none sent %d requests to third parties (the ledger lists %d)", caught.Load(), source)
	}
	if dns == 0 {
		t.Error("the run asked no resolver: the test checks nothing")
	}
}

// The plan says what the run will do: no collector that asks a third party,
// no source query, and why.
func TestPlanSourcesNoneListsNoThirdParty(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := cli(t, "plan", "-domain", "example.com", "-sources", "none", "-dns-brute", words)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, name := range []string{"azhaq-rdap", "azhaq-search", "azhaq-subdomains", "azhaq-urls", "azhaq-asn"} {
		if strings.Contains(out, name) {
			t.Errorf("the plan lists %s:\n%s", name, out)
		}
	}
	for _, want := range []string{"source queries: none", "-sources none: no third party is asked"} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan lacks %q:\n%s", want, out)
		}
	}
	// Without it the same run asks the archives and RDAP.
	out, _, _ = cli(t, "plan", "-domain", "example.com", "-dns-brute", words)
	if !strings.Contains(out, "azhaq-rdap") || strings.Contains(out, "-sources none") {
		t.Errorf("the plan without -sources none:\n%s", out)
	}
}

// A flag that picks a third party to ask cannot go with a run that asks none:
// it is a usage error naming both, not an ignored flag.
func TestRunSourcesNoneRefusesFlagsThatAskAnArchive(t *testing.T) {
	t.Chdir(t.TempDir())
	thirdPartyCatcher(t) // a run that is not refused must not reach a public host
	for _, extra := range [][]string{{"-urls-sources", "wayback"}, {"-urls-archive", "wayback=http://127.0.0.1:1/"}, {"-asn", "AS13335"}} {
		_, errOut, code := cli(t, append([]string{"run", "-domain", "example.com", "-sources", "none", "-passive", "-db", "r.db", "-ledger", "off"}, extra...)...)
		if code != exitUsage || !strings.Contains(errOut, "-sources none") || !strings.Contains(errOut, extra[0]) {
			t.Errorf("%v: exit %d\n%s", extra, code, errOut)
		}
	}
}
