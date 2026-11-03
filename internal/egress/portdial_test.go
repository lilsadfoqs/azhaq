package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/scope"
)

func listener(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), n
}

func TestPortDialerRecordsAndHoldsTheScope(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	addr, _ := listener(t)
	d := NewPortDialer(time.Second, nil, "", "")
	c, err := d.TCP(context.Background(), "app.test", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// A name in scope reaches an address the rules do not name; a name and an
	// address outside both do not.
	SetScope(func(h string) bool { return h == "app.test" })
	if c, err := d.TCP(context.Background(), "app.test", addr); err != nil {
		t.Fatalf("a name in scope: %v", err)
	} else {
		c.Close()
	}
	if _, err := d.TCP(context.Background(), "other.test", addr); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("a name outside the scope: %v", err)
	}
	SetScope(func(h string) bool { return h == "127.0.0.1" })
	if c, err := d.TCPDirect(context.Background(), "", addr); err != nil {
		t.Fatalf("an address in scope: %v", err)
	} else {
		c.Close()
	}
	got := entries()
	if len(got) != 3 || got[0] != "tcp/target" {
		t.Fatalf("ledger %v: the refused connect is not recorded, the others are", got)
	}
}

func TestPortDialerStopsAtTheKillFile(t *testing.T) {
	Reset()
	defer Reset()
	addr, accepted := listener(t)
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)()
	d := NewPortDialer(time.Second, nil, "", "")
	if _, err := d.TCP(context.Background(), "", addr); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("%v", err)
	}
	ua, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	if _, err := d.UDP(context.Background(), "", ua); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("udp: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatalf("%d connections reached the listener", accepted.Load())
	}
}

func TestPortDialerUDPIsRecorded(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	d := NewPortDialer(time.Second, nil, "", "")
	ua, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	c, err := d.UDP(context.Background(), "", ua)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c, err = d.UDPAnySource(context.Background(), "", ua)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := entries(); len(got) != 2 || got[0] != "udp/target" {
		t.Fatalf("ledger %v", got)
	}
}

// Connects reserved in a batch are held to the same controls as any other:
// an address outside the scope is not recorded and not connected to; once the
// kill file exists nothing more is reserved, and what was reserved before it
// goes out, as its line says.
func TestReservedConnectsKeepTheirControls(t *testing.T) {
	Reset()
	defer Reset()
	path := filepath.Join(t.TempDir(), "r.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer func() { ledger.Use(nil); l.Close() }()
	ok, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ok.Close()
	rules := scope.Rules{Allow: []string{ok.Addr().String()}}.Compile()
	SetScope(rules.Allows)
	SetScopeAddr(rules.AllowsAddr)
	d := NewPortDialer(time.Second, nil, "", "")
	other := "127.0.0.1:1"
	d.Reserve(context.Background(), "", []string{ok.Addr().String(), other})
	if n := l.Count(); n != 1 {
		t.Errorf("%d lines for a batch of one allowed address and one outside the scope", n)
	}
	if _, err := d.TCP(context.Background(), "", other); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Errorf("an address outside the scope: %v", err)
	}
	kill := filepath.Join(t.TempDir(), "stop")
	defer SetKill(kill)()
	if err := os.WriteFile(kill, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Reserved before the kill file: its line is made, so the connect is.
	c, err := d.TCP(context.Background(), "", ok.Addr().String())
	if err != nil {
		t.Fatalf("a connect reserved before the kill file: %v", err)
	}
	c.Close()
	// Reserved after it: no line, and its connect is refused.
	d.Reserve(context.Background(), "", []string{ok.Addr().String()})
	if n := l.Count(); n != 1 {
		t.Errorf("%d lines after a reserve with the kill file in place, want the 1 from before", n)
	}
	if _, err := d.TCP(context.Background(), "", ok.Addr().String()); !errors.Is(err, neterr.ErrKilled) {
		t.Errorf("a connect after the kill file: %v", err)
	}
}

// Two scans of one address reserve its connects twice and make them twice:
// each connect is a line once, as the connects counted are.
func TestReservedConnectsOfTwoScansAreRecordedOnce(t *testing.T) {
	Reset()
	defer Reset()
	l, err := ledger.Open(filepath.Join(t.TempDir(), "d.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer func() { ledger.Use(nil); l.Close() }()
	ok, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ok.Close()
	d := NewPortDialer(time.Second, nil, "", "")
	addr := ok.Addr().String()
	d.Reserve(context.Background(), "", []string{addr})
	d.Reserve(context.Background(), "", []string{addr})
	for i := 0; i < 2; i++ {
		c, err := d.TCP(context.Background(), "", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if n := l.Count(); n != 2 {
		t.Errorf("%d lines for 2 reserved connects", n)
	}
}

// A connect is a line when it begins; one that never began has none and is
// given back to the budget its caller counted it in.
func TestAConnectThatNeverBeganHasNoLineAndIsGivenBack(t *testing.T) {
	Reset()
	defer Reset()
	l, err := ledger.Open(filepath.Join(t.TempDir(), "n.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer func() { ledger.Use(nil); l.Close() }()
	var accepted atomic.Int64
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	d := NewPortDialer(time.Second, nil, "", "")
	addr := ln.Addr().String()
	count := func() {
		if err := Take(); err != nil {
			t.Fatal(err)
		}
	}
	// Stopped by the end of its context after it was counted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	count()
	if _, err := d.TCP(ctx, "", addr); err == nil {
		t.Fatal("a connect with a finished context was made")
	}
	// Stopped by the kill file.
	kill := filepath.Join(t.TempDir(), "stop")
	stop := SetKill(kill)
	defer stop()
	count() // counted before the file appeared
	_ = os.WriteFile(kill, nil, 0o600)
	if _, err := d.TCP(context.Background(), "", addr); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("a connect after the kill file: %v", err)
	}
	stop()
	if n, c := l.Count(), Sent(); n != 0 || c != 0 || accepted.Load() != 0 {
		t.Fatalf("lines %d, counted %d, accepted %d: want 0 each", n, c, accepted.Load())
	}
	// One that is made is all three.
	count()
	c, err := d.TCP(context.Background(), "", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	time.Sleep(50 * time.Millisecond)
	if n, c := l.Count(), Sent(); n != 1 || c != 1 || accepted.Load() != 1 {
		t.Fatalf("lines %d, counted %d, accepted %d: want 1 each", n, c, accepted.Load())
	}
}

// A reserved connect whose context ends before it begins still goes out: its
// line says it did.
func TestAReservedConnectOutlivesAStopThatCameBeforeIt(t *testing.T) {
	Reset()
	defer Reset()
	l, err := ledger.Open(filepath.Join(t.TempDir(), "h.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer func() { ledger.Use(nil); l.Close() }()
	var accepted atomic.Int64
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	d := NewPortDialer(time.Second, nil, "", "")
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	d.Reserve(ctx, "", []string{addr, addr, addr})
	cancel() // the stop lands between the lines and the connects
	for i := 0; i < 3; i++ {
		c, err := d.TCP(ctx, "", addr)
		if err == nil {
			c.Close()
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := l.Count(); n != 3 || accepted.Load() != 3 {
		t.Fatalf("lines %d, accepted %d: a line says a connect went out", n, accepted.Load())
	}
}
