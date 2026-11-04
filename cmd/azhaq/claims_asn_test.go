package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// ripeStandIn answers for stat.ripe.net: AS64500 announces three prefixes
// (one twice), AS64501 is a server error.
func ripeStandIn(t *testing.T) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch as := r.URL.Query().Get("resource"); {
		case as == "AS64500" && r.URL.Path == "/data/announced-prefixes/data.json":
			fmt.Fprint(w, `{"data":{"prefixes":[{"prefix":"192.0.2.0/24"},{"prefix":"198.51.100.0/25"},{"prefix":"192.0.2.0/24"}]}}`)
		case as == "AS64500" && r.URL.Path == "/data/as-overview/data.json":
			fmt.Fprint(w, `{"data":{"holder":"EXAMPLE-AS"}}`)
		default:
			http.Error(w, "no", http.StatusInternalServerError)
		}
	}))
	old := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	t.Cleanup(func() { http.DefaultTransport = old; srv.Close() })
}

// asn asks RIPEstat and nothing else: each prefix once, nothing sent to an
// address of the AS, -silent prints the prefixes alone, and any failure is
// exit 3 (a prefix or an address has no answer to tell from a failure).
func TestASNAsksRIPEstatOnlyListsEachPrefixOnceAndAnyFailureIsExit3(t *testing.T) {
	ripeStandIn(t)
	db := filepath.Join(t.TempDir(), "asn.db")
	out, errOut, code := cli(t, "asn", "-a", "AS64500", "-db", db)
	if code != exitOK || out != "192.0.2.0/24\n198.51.100.0/25\n" {
		t.Fatalf("exit %d, %q\n%s", code, out, errOut)
	}
	var source, target int
	if err := ledger.Read(db+".ledger.jsonl", func(e ledger.Entry) error {
		switch {
		case e.Kind == ledger.KindSeal:
		case e.Class == ledger.ClassSource:
			source++
		case e.IsTarget():
			target++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if source != 2 || target != 0 {
		t.Errorf("the ledger lists %d requests to RIPEstat and %d to targets: the addresses of the AS are not asked", source, target)
	}
	// -silent: the prefixes, no progress, no summary of a run that went well.
	out, errOut, code = cli(t, "asn", "-a", "AS64500", "-silent")
	if code != exitOK || out != "192.0.2.0/24\n198.51.100.0/25\n" || strings.TrimSpace(errOut) != "" {
		t.Errorf("-silent: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// An AS RIPEstat does not answer for is a failure, whatever else answered.
	for _, args := range [][]string{{"-a", "AS64501"}, {"-a", "AS64500", "-a", "AS64501"}} {
		if _, errOut, code := cli(t, append([]string{"asn"}, args...)...); code != exitPartial {
			t.Errorf("%v: exit %d, want 3\n%s", args, code, errOut)
		}
	}
}
