package main

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
)

// holdingListener accepts and says nothing until the test ends.
func holdingListener(t *testing.T, addr string) (net.Listener, error) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	return l, nil
}

// A usual port of a service no probe asked about is not named under
// -detect none (naabu prints host:port); the other modes still mark the
// registered name with a "?".
func TestPortsDetectNoneRowsNameNoService(t *testing.T) {
	var port string
	for _, p := range []string{"9092", "5000", "3000", "8888", "9000", "8000"} {
		if _, err := holdingListener(t, "127.0.0.1:"+p); err == nil {
			port = p
			break
		}
	}
	if port == "" {
		t.Skip("no usual port free on 127.0.0.1")
	}
	for detect, wantService := range map[string]bool{"none": false, "banner": true} {
		out, _, code := cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-detect", detect, "-connect-timeout", "400", "-allow", "127.0.0.1", "-json")
		if code != exitOK {
			t.Fatalf("-detect %s: exit %d", detect, code)
		}
		var row map[string]any
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "{") && strings.Contains(l, `"port":`+port) {
				if err := json.Unmarshal([]byte(l), &row); err != nil {
					t.Fatal(err)
				}
			}
		}
		if row == nil {
			t.Fatalf("-detect %s: no row for port %s:\n%s", detect, port, out)
		}
		svc, has := row["service"].(string)
		if has != wantService || (has && !strings.HasSuffix(svc, "?")) {
			t.Errorf("-detect %s: service %q (present %v), want present %v and marked with ?", detect, svc, has, wantService)
		}
	}
}
