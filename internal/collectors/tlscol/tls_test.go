package tlscol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/tlstest"
	"github.com/lilsadfoqs/azhaq/types"
)

func TestSANHintsStayOnSite(t *testing.T) {
	col := &Collector{}
	cert := &x509.Certificate{
		DNSNames: []string{
			"api.example.test",
			"www.example.test",
			"dead.traefik.default",
			"cdn.other.test",
		},
		NotAfter: time.Now().Add(time.Hour),
	}
	meta, err := col.emitState("www.example.test", tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.NextHints) != 1 || meta.NextHints[0].Key() != "api.example.test" {
		t.Fatalf("hints %+v", meta.NextHints)
	}
}

// A name whose port 443 refuses the connection has no TLS service there: it
// is not a failed target, as an address of a network that serves none is not.
func TestRefusedTLSPortIsNotAFailure(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	col := &Collector{Port: port, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	var got int
	meta, err := col.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "localhost"}},
		func(types.Observation) error { got++; return nil })
	if err != nil || meta.Status != types.StatusOK || got != 0 {
		t.Errorf("status %q error %v observations %d", meta.Status, err, got)
	}
}

// A server whose suites crypto/tls does not offer still gives its
// certificate: the handshake runs again with the fallback client, counted
// like the first.
func TestCertificateOfAServerWithLegacySuites(t *testing.T) {
	srv := tlstest.Serve(t, 0, 0, tlstest.RSAGCM)
	_, port, _ := net.SplitHostPort(srv.Addr)
	col := &Collector{Port: port}
	var rows []types.Observation
	before := egress.Sent()
	meta, err := col.Run(context.Background(), types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}},
		func(o types.Observation) error { rows = append(rows, o); return nil })
	if err != nil || meta.Status != types.StatusOK || len(rows) != 1 {
		t.Fatalf("status %q error %v rows %d", meta.Status, err, len(rows))
	}
	if !strings.Contains(string(rows[0].Payload), "legacy.test") {
		t.Errorf("row %s", rows[0].Payload)
	}
	if n := egress.Sent() - before; n != 2 {
		t.Errorf("%d connections counted, want the failed handshake and the fallback's", n)
	}
}
