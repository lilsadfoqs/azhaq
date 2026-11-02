package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/tlstest"
)

// An HTTPS server that curl -k completes (RSA key exchange or DHE only, which
// crypto/tls does not offer) is probed, crawled, mapped by run and named by
// ports, with its TLS version and suite in the rows and nothing failed; the
// invariants run() holds every command to (the summary's requests are the
// ledger's lines) cover the fallback's connections.
func TestCommandsReachAServerThatNeedsTheFallbackTLSClient(t *testing.T) {
	for name, suite := range map[string]uint16{"rsa": tlstest.RSAGCM, "dhe": tlstest.DHEGCM} {
		t.Run(name, func(t *testing.T) {
			srv := tlstest.Serve(t, 0, 0, suite)
			_, port, _ := net.SplitHostPort(srv.Addr)
			url := "https://" + srv.Addr + "/"
			t.Chdir(t.TempDir())
			for _, args := range [][]string{
				{"probe", "-u", url, "-allow", "127.0.0.1"},
				{"crawl", "-u", url, "-allow", "127.0.0.1", "-db", "c.db"},
				{"run", "-url", url, "-allow", "127.0.0.1", "-sources", "none", "-db", "r.db"},
			} {
				out, rep, code := runContract(t, args...)
				if code != exitOK || len(rep.Failed) != 0 || len(rep.Unreachable) != 0 {
					t.Errorf("%s: exit %d failed %+v unreachable %v\n%s", args[0], code, rep.Failed, rep.Unreachable, out)
				}
				if !strings.Contains(out, "200") {
					t.Errorf("%s: no 200 in the rows:\n%s", args[0], out)
				}
			}
			out, rep, code := runContract(t, "ports", "-host", "127.0.0.1", "-p", port, "-allow", "127.0.0.1")
			if code != exitOK || len(rep.Failed) != 0 {
				t.Fatalf("ports: exit %d %+v", code, rep.Failed)
			}
			for _, want := range []string{`"service":"https"`, `"tls":true`, `"tls_version":"tls12"`, fmt.Sprintf(`"cipher":"TLS_%s`, map[string]string{"rsa": "RSA_WITH_AES_128_GCM_SHA256", "dhe": "DHE_RSA_WITH_AES_256_GCM_SHA384"}[name])} {
				if !strings.Contains(out, want) {
					t.Errorf("ports rows lack %s:\n%s", want, out)
				}
			}
		})
	}
}
