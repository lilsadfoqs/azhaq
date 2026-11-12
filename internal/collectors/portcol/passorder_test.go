package portcol

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/types"
)

// A block of sixteen loopback listeners under a cap below pass 1 plus pass 2:
// every address is asked its pass-1 ports before any port of pass 2, and pass 2
// spends what is left.
func TestBlockAsksPassOneOnEveryAddressBeforePassTwo(t *testing.T) {
	var port int
	var ips []string
	for i := 0; i < 16; i++ {
		ip := fmt.Sprintf("127.0.9.%d", i)
		l, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		port = l.Addr().(*net.TCPAddr).Port
		ips = append(ips, ip)
	}
	first := []int{port - 1, port, port + 1}
	cap := int32(len(ips)*len(first) + 6)
	var takes atomic.Int32
	var mu sync.Mutex
	opened := map[string]bool{}
	c := New(nil, first, 0)
	c.Apply(Config{Escalate: true})
	c.Scanner.Banner = 20 * time.Millisecond
	c.Scanner.Take = func() error {
		if takes.Add(1) > cap {
			return neterr.ErrBudget
		}
		return nil
	}
	c.Scanner.Opened = func(ip string, p int) {
		if p == port {
			mu.Lock()
			opened[ip] = true
			mu.Unlock()
		}
	}
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.9.0/28"}}, func(types.Observation) error { return nil })
	if !stopped(err) {
		t.Fatalf("the cap did not stop the scan: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(opened) != len(ips) {
		t.Errorf("%d of %d addresses were asked their pass-1 ports before the cap was spent", len(opened), len(ips))
	}
	if got := min(takes.Load(), cap); got != cap {
		t.Errorf("%d connects, want the cap of %d spent by pass 2", got, cap)
	}
}
