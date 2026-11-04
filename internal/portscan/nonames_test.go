package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

// silentListener accepts and says nothing until the test ends.
func silentListener(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	t.Cleanup(func() {
		l.Close()
		close(done)
		for _, c := range held {
			c.Close()
		}
	})
	return l.Addr().(*net.TCPAddr).Port
}

// -detect none connects and closes: no row names a service, not even the
// registered name of the port; the other modes still mark that name with "?".
func TestDetectNoneNamesNoService(t *testing.T) {
	port := silentListener(t)
	wellKnown[port] = "ssh"
	t.Cleanup(func() { delete(wellKnown, port) })
	for _, c := range []struct {
		detect  Detect
		service string
	}{{DetectNone, ""}, {DetectBanner, "ssh?"}} {
		s := &Scanner{Detect: c.detect, Banner: 100 * time.Millisecond, Timeout: time.Second}
		r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
		if err != nil || len(r.Open) != 1 {
			t.Fatalf("detect %v: %d open, %v", c.detect, len(r.Open), err)
		}
		if got := r.Open[0].Service; got != c.service {
			t.Errorf("detect %v: service %q, want %q", c.detect, got, c.service)
		}
	}
}

// The registered name of a port still tells a web port from another under
// -detect none, so run's web mapping does not ask an ssh port for a page.
func TestDetectNoneKeepsWebFromOtherPorts(t *testing.T) {
	for name, web := range map[string]bool{"http": true, "ssh": false} {
		port := silentListener(t)
		wellKnown[port] = name
		t.Cleanup(func() { delete(wellKnown, port) })
		s := &Scanner{Detect: DetectNone}
		r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
		if err != nil || len(r.Open) != 1 {
			t.Fatalf("%s: %d open, %v", name, len(r.Open), err)
		}
		if r.Open[0].Service != "" || r.Open[0].Web() != web {
			t.Errorf("%s: service %q, Web() %v, want \"\" and %v", name, r.Open[0].Service, r.Open[0].Web(), web)
		}
	}
}

// A silent UDP port is named from its number in the other modes, and not
// under -detect none.
func TestDetectNoneNamesNoUDPService(t *testing.T) {
	port, _ := udpListener(t, nil)
	udpNames[port] = "ntp"
	t.Cleanup(func() { delete(udpNames, port) })
	for _, c := range []struct {
		detect  Detect
		service string
	}{{DetectNone, ""}, {DetectBanner, "ntp?"}} {
		s := &Scanner{Detect: c.detect, Timeout: 150 * time.Millisecond}
		r, err := s.ScanUDP(context.Background(), "", "127.0.0.1", []int{port})
		if err != nil || len(r.OpenFiltered) != 1 {
			t.Fatalf("detect %v: %+v, %v", c.detect, r, err)
		}
		if got := r.OpenFiltered[0].Service; got != c.service {
			t.Errorf("detect %v: service %q, want %q", c.detect, got, c.service)
		}
	}
}
