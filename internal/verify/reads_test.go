package verify

import (
	"slices"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

func redisSvc(host, version string, tls bool) advisory.Service {
	return advisory.Service{Host: host, IP: "10.0.0.9", Port: 6379, Proto: "tcp", Service: "redis", Product: "Redis", Version: version, TLS: tls}
}

// One listener reached by its address and by two names is one read, sent to the
// first name, which lists the others; a name that read another version, a read
// that depends on the name (TLS: its SNI) and another port are reads of their own.
func TestReadsAreOneForAListenerWhateverNamesReachedIt(t *testing.T) {
	addrs := map[string]string{"redis.example.com": "10.0.0.9", "www.example.com": "10.0.0.9"}
	got := Reads([]advisory.Service{
		redisSvc("10.0.0.9", "5.0.7", false),
		redisSvc("www.example.com", "5.0.7", false),
		redisSvc("redis.example.com", "", false),
	}, addrs)
	if len(got) != 1 {
		t.Fatalf("%d reads, want 1: %+v", len(got), got)
	}
	if want := []string{"10.0.0.9", "redis.example.com", "www.example.com"}; !slices.Equal(got[0].Names, want) {
		t.Errorf("names %v, want %v", got[0].Names, want)
	}
	if h := got[0].Svc.Host; h != "redis.example.com" || got[0].Svc.Version != "5.0.7" {
		t.Errorf("read of %s %q, want the first name with the version a name stated", h, got[0].Svc.Version)
	}

	other := redisSvc("shop.example.com", "6.2.1", false)
	if n := len(Reads([]advisory.Service{redisSvc("10.0.0.9", "5.0.7", false), other}, addrs)); n != 2 {
		t.Errorf("a name that read another version: %d reads, want 2", n)
	}
	if n := len(Reads([]advisory.Service{redisSvc("10.0.0.9", "5.0.7", true), redisSvc("www.example.com", "5.0.7", true)}, addrs)); n != 2 {
		t.Errorf("reads inside TLS name the host in the handshake: %d reads, want 2", n)
	}
	moved := redisSvc("www.example.com", "5.0.7", false)
	moved.Port = 6380
	if n := len(Reads([]advisory.Service{redisSvc("10.0.0.9", "5.0.7", false), moved}, addrs)); n != 2 {
		t.Errorf("another port: %d reads, want 2", n)
	}
}
