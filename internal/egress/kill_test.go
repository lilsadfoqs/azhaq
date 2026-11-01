package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/miekg/dns"
)

func TestKillFileStopsSpendAndTake(t *testing.T) {
	Reset()
	defer Reset()
	path := filepath.Join(t.TempDir(), "run.stop")
	stop := SetKill(path)
	defer stop()
	if err := Spend(context.Background()); err != nil || Take() != nil || Spent() {
		t.Fatal("refused before the file exists")
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * KillCheck)
	for Killed() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	for _, err := range []error{Spend(context.Background()), Take()} {
		if !errors.Is(err, neterr.ErrKilled) || !errors.Is(err, neterr.ErrBudget) || err.Error() != "stopped: kill file "+path+" exists" {
			t.Fatalf("after the file exists: %v", err)
		}
	}
	if !Spent() {
		t.Error("Spent is false with the kill file there")
	}
	stop()
	if Killed() != nil {
		t.Error("still killed after the watch ended")
	}
	// A file there at the start refuses at once.
	defer SetKill("")
	SetKill(path)
	if Take() == nil {
		t.Error("a kill file that was there at the start did not refuse")
	}
}

// The file is never waited for: the first send after it exists is refused,
// whatever the poll has seen, by every way out.
func TestEverySendLooksForTheKillFileItself(t *testing.T) {
	Reset()
	defer Reset()
	path := filepath.Join(t.TempDir(), "run.stop")
	defer SetKill(path)()
	srv, hits := counting(t)
	addr, accepted := listener(t)
	dnsAddr, queries := fakeDNS(t)
	client := TargetClient(TargetOptions{})
	d := NewPortDialer(time.Second, nil, "", "")
	if err := get(client, srv.URL+"/a"); err != nil {
		t.Fatalf("before the file: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ua, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	q := new(dns.Msg)
	q.SetQuestion("a.test.", dns.TypeA)
	_, tcpErr := d.TCP(context.Background(), "", addr)
	_, udpErr := d.UDP(context.Background(), "", ua)
	_, dnsErr := NewDNSExchanger(time.Second, "").ExchangeAt(context.Background(), q, dnsAddr)
	_, srcErr := DialSource(context.Background(), "tcp", addr)
	for name, err := range map[string]error{
		"spend":       Spend(context.Background()),
		"spendnopace": SpendUnpaced(context.Background()),
		"take":        Take(),
		"pace":        Pace(context.Background()),
		"http":        get(client, srv.URL+"/b"),
		"tcp":         tcpErr,
		"udp":         udpErr,
		"dns":         dnsErr,
		"source":      srcErr,
	} {
		if !errors.Is(err, neterr.ErrKilled) {
			t.Errorf("%s after the file exists: %v", name, err)
		}
	}
	if hits.Load() != 1 || accepted.Load() != 0 || queries.Load() != 0 {
		t.Errorf("sent after the file: %d requests (1 before it), %d connections, %d queries", hits.Load(), accepted.Load(), queries.Load())
	}
}
