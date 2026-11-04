package portcol

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// A CDN or WAF address is not asked UDP ports, though its TCP ports are
// asked: the datagram never reaches it.
func TestACDNAddressIsNotAskedUDPPorts(t *testing.T) {
	var datagrams atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			datagrams.Add(1)
		}
	}()
	udpPort := pc.LocalAddr().(*net.UDPAddr).Port
	tcpPort := serve(t, "127.0.0.1:0")
	pool := dnsr.New(dnsr.Options{Resolvers: []string{"192.0.2.1"}, PerSecond: -1})
	pool.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			if strings.HasPrefix(q.Question[0].Name, "shop.") {
				c, _ := dns.NewRR(q.Question[0].Name + " 60 IN CNAME x.cloudfront.net.")
				a, _ := dns.NewRR("x.cloudfront.net. 60 IN A 127.0.0.1")
				m.Answer = append(m.Answer, c, a)
			} else {
				a, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 127.0.0.1")
				m.Answer = append(m.Answer, a)
			}
		}
		return m, nil
	}
	for _, edge := range []bool{true, false} {
		datagrams.Store(0)
		var tcp atomic.Int32
		c := New(pool, []int{tcpPort}, 0)
		c.Scanner.Take = func() error { tcp.Add(1); return nil }
		c.Scanner.Detect = portscan.DetectNone
		c.Scanner.Timeout = 150e6
		c.UDPPorts = []int{udpPort}
		c.IPv6 = func() bool { return false }
		name := map[bool]string{true: "shop.example.org", false: "plain.example.org"}[edge]
		seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": name}}
		if _, err := c.Run(context.Background(), seed, func(types.Observation) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if edge && (datagrams.Load() != 0 || tcp.Load() == 0) {
			t.Errorf("a CDN address: %d datagrams, %d TCP connects, want no datagram and its TCP ports asked", datagrams.Load(), tcp.Load())
		}
		if !edge && datagrams.Load() == 0 {
			t.Error("an address that is no CDN's was asked no datagram")
		}
	}
}
