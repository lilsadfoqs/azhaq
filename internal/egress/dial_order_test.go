package egress

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"
)

// A name with only IPv6 addresses is dialed at them even with no route for
// IPv6 (loopback ::1 needs none); it was given nothing to dial, and the dial
// returned no connection and no error.
func TestDialOrderKeepsAnIPv6OnlyName(t *testing.T) {
	v4, v6 := []string{"192.0.2.1"}, []string{"::1"}
	for _, c := range []struct {
		name              string
		v4, v6            []string
		routable          bool
		primary, fallback []string
	}{
		{"both, routable", v4, v6, true, v6, v4},
		{"both, not routable", v4, v6, false, v4, nil},
		{"IPv6 only, not routable", nil, v6, false, v6, nil},
		{"IPv6 only, routable", nil, v6, true, v6, nil},
		{"IPv4 only", v4, nil, true, v4, nil},
	} {
		p, f := dialOrder(c.v4, c.v6, c.routable)
		if !slices.Equal(p, c.primary) || !slices.Equal(f, c.fallback) {
			t.Errorf("%s: primary %v fallback %v, want %v %v", c.name, p, f, c.primary, c.fallback)
		}
	}
}

// With no address at all the dial fails: never a nil connection and no error.
func TestDialEitherWithNoAddressIsAnError(t *testing.T) {
	c, err := dialEither(context.Background(), &net.Dialer{Timeout: time.Second}, "tcp", "80", nil, nil)
	if c != nil || err == nil {
		t.Fatalf("conn %v, err %v: want no connection and an error", c, err)
	}
}
