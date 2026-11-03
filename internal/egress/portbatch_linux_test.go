//go:build linux

package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// batchResult is how one port of a TCPBatch ended.
type batchResult struct {
	conn net.Conn
	rtt  time.Duration
	err  error
}

func runBatch(t *testing.T, d *PortDialer, ctx context.Context, ip string, ports []int) []batchResult {
	t.Helper()
	got := make([]batchResult, len(ports))
	seen := make([]int, len(ports))
	d.TCPBatch(ctx, "", ip, ports, func(i int, c net.Conn, rtt time.Duration, err error) {
		got[i] = batchResult{c, rtt, err}
		seen[i]++
	})
	for i, n := range seen {
		if n != 1 {
			t.Errorf("port %d of the batch was reported %d times, want once", i, n)
		}
	}
	return got
}

// A batch ends each port as a connect of its own does: an open one with a
// connection that works, a refused one with ECONNREFUSED, one that never
// answers with a timeout, and every connect is recorded once.
func TestTCPBatchEndsEachPortLikeTCP(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	addr, accepted := listener(t)
	_, p, _ := net.SplitHostPort(addr)
	open := atoiPort(t, p)
	gone, _ := net.Listen("tcp", "127.0.0.1:0")
	_, gp, _ := net.SplitHostPort(gone.Addr().String())
	closed := atoiPort(t, gp)
	gone.Close()
	// A listener that never accepts, with its queue full, leaves a connect unanswered.
	stuck, stuckPort := fullQueue(t)
	defer stuck()

	d := NewPortDialer(300*time.Millisecond, nil, "", "")
	ports := []int{open, closed, stuckPort}
	d.Reserve(context.Background(), "", []string{addr, net.JoinHostPort("127.0.0.1", gp), net.JoinHostPort("127.0.0.1", itoa(stuckPort))})
	t0 := time.Now()
	got := runBatch(t, d, context.Background(), "127.0.0.1", ports)
	if got[0].err != nil || got[0].conn == nil || got[0].rtt <= 0 {
		t.Fatalf("the open port: %+v", got[0])
	}
	got[0].conn.Close()
	if !errors.Is(got[1].err, syscall.ECONNREFUSED) || got[1].conn != nil {
		t.Errorf("the closed port: %+v", got[1])
	}
	var ne net.Error
	if got[2].conn != nil || !errors.As(got[2].err, &ne) || !ne.Timeout() {
		t.Errorf("the port that never answers: %+v", got[2])
	}
	if d := time.Since(t0); d < 250*time.Millisecond || d > 2*time.Second {
		t.Errorf("the batch took %v for a 300 ms timeout", d)
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != 1 {
		t.Errorf("%d connections accepted, want 1", accepted.Load())
	}
	if e := entries(); len(e) != 3 {
		t.Errorf("ledger %v: each connect is recorded once, by Reserve", e)
	}
}

// The kill file and the scope hold each connect of a batch, and nothing is
// connected after the file exists.
func TestTCPBatchHoldsTheKillFileAndTheScope(t *testing.T) {
	Reset()
	defer Reset()
	addr, accepted := listener(t)
	_, p, _ := net.SplitHostPort(addr)
	port := atoiPort(t, p)
	d := NewPortDialer(time.Second, nil, "", "")

	SetScope(func(h string) bool { return false })
	got := runBatch(t, d, context.Background(), "127.0.0.1", []int{port})
	if !errors.Is(got[0].err, neterr.ErrOutOfScope) {
		t.Errorf("a port outside the scope: %+v", got[0])
	}
	Reset()

	path := filepath.Join(t.TempDir(), "run.stop")
	stop := SetKill(path)
	defer stop()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got = runBatch(t, d, context.Background(), "127.0.0.1", []int{port, port})
	for i, r := range got {
		if !errors.Is(r.err, neterr.ErrKilled) || r.conn != nil {
			t.Errorf("port %d after the kill file: %+v", i, r)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Errorf("%d connections after the kill file", accepted.Load())
	}
}

// A batch waiting on a port that does not answer ends when ctx does.
func TestTCPBatchEndsWithItsContext(t *testing.T) {
	Reset()
	defer Reset()
	stuck, stuckPort := fullQueue(t)
	defer stuck()
	d := NewPortDialer(10*time.Second, nil, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	t0 := time.Now()
	got := runBatch(t, d, ctx, "127.0.0.1", []int{stuckPort})
	if !errors.Is(got[0].err, context.Canceled) || time.Since(t0) > 2*time.Second {
		t.Errorf("%+v after %v", got[0], time.Since(t0))
	}
}

// Many batches at once see each port once, and a connection that was made is
// usable.
func TestTCPBatchesRunAtOnce(t *testing.T) {
	Reset()
	defer Reset()
	addr, _ := listener(t)
	_, p, _ := net.SplitHostPort(addr)
	port := atoiPort(t, p)
	d := NewPortDialer(time.Second, nil, "", "")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := runBatch(t, d, context.Background(), "127.0.0.1", []int{port, port, port, port})
			for _, r := range got {
				if r.err != nil {
					t.Error(r.err)
					continue
				}
				r.conn.Close()
			}
		}()
	}
	wg.Wait()
}

// fullQueue listens with a queue of one that nothing drains, and fills it, so
// the next connect gets no answer.
func fullQueue(t *testing.T) (stop func(), port int) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skip(err)
	}
	sa := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(fd, sa); err != nil {
		t.Skip(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Skip(err)
	}
	bound, _ := syscall.Getsockname(fd)
	port = bound.(*syscall.SockaddrInet4).Port
	var held []net.Conn
	for i := 0; i < 4; i++ {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 100*time.Millisecond)
		if err == nil {
			held = append(held, c)
		}
	}
	return func() {
		for _, c := range held {
			c.Close()
		}
		syscall.Close(fd)
	}, port
}

func atoiPort(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// The ledger's rule for a batch: the lines Reserve wrote are the connects'
// and a stop that came after them does not take them back (each connect
// begins, and no other line is made); a connect made after the stop has no
// line and is given back to the budget the caller counted.
func TestTCPBatchHasOneLedgerLinePerConnectThatBegan(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	addr, _ := listener(t)
	_, p, _ := net.SplitHostPort(addr)
	port := atoiPort(t, p)
	d := NewPortDialer(time.Second, nil, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	addrs := []string{addr, addr, addr}
	d.Reserve(ctx, "", addrs)
	cancel() // the stop comes after the lines
	for range addrs {
		if err := Take(); err != nil {
			t.Fatal(err)
		}
	}
	got := runBatch(t, d, ctx, "127.0.0.1", []int{port, port, port})
	for _, r := range got {
		if r.conn != nil {
			r.conn.Close()
		}
	}
	if e := entries(); len(e) != 3 {
		t.Errorf("ledger %v: want the 3 lines Reserve wrote, and no more", e)
	}
	if Sent() != 3 {
		t.Errorf("%d counted, want 3: each connect began", Sent())
	}

	// After the stop: nothing is reserved, nothing is written, all are given back.
	before := len(entries())
	d.Reserve(ctx, "", addrs)
	for range addrs {
		if err := Take(); err != nil {
			t.Fatal(err)
		}
	}
	got = runBatch(t, d, ctx, "127.0.0.1", []int{port, port, port})
	for i, r := range got {
		if !errors.Is(r.err, context.Canceled) || r.conn != nil {
			t.Errorf("port %d after the stop: %+v", i, r)
		}
	}
	if n := len(entries()) - before; n != 0 {
		t.Errorf("%d lines for connects that never began", n)
	}
	if Sent() != 3 {
		t.Errorf("%d counted, want 3: the three after the stop are given back", Sent())
	}
}
