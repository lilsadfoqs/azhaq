package main

import (
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/types"
)

// show opens the label hunt prints for a listener: host:port, the host an
// address or a name that points to it, with or without the protocol (#591).
func TestShowAcceptsTheListenerLabelHuntPrints(t *testing.T) {
	if addrs, err := net.LookupHost("localhost"); err != nil || !slices.Contains(addrs, "127.0.0.1") {
		t.Skipf("localhost does not resolve to 127.0.0.1: %v %v", addrs, err)
	}
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newRedisFixture(t, redisInfoResp())
	port := strconv.Itoa(fx.port)
	db := filepath.Join(t.TempDir(), "w.db")
	if _, errOut, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "localhost", "-p", port, "-db", db, "-json"})
	}); err != nil {
		t.Fatalf("ports: %v\n%s", err, errOut)
	}
	for _, label := range []string{"127.0.0.1:" + port, "127.0.0.1:" + port + "/tcp", "localhost:" + port, "LOCALHOST:" + port + "/tcp"} {
		out, _, err := captureBoth(t, func() error { return cmdShow([]string{"-db", db, label}) })
		if err != nil || !strings.HasPrefix(out, "Port 127.0.0.1:"+port+"/tcp") {
			t.Errorf("show %s: err %v, out %.80q", label, err, out)
		}
	}
	for _, label := range []string{"localhost:" + port + "/udp", "localhost:1", "nowhere.test:" + port} {
		if _, _, err := captureBoth(t, func() error { return cmdShow([]string{"-db", db, label}) }); err == nil {
			t.Errorf("show %s found a row", label)
		}
	}
}

// A name found through the run's own name → address rows opens the port row of
// that address, though the row lists no name.
func TestPortLabelRowMapsANameByItsAddress(t *testing.T) {
	row := func(key string, names ...string) engine.MapEntry {
		return engine.MapEntry{Entity: types.Entity{Type: types.TypePort, Key: key}, Names: names}
	}
	rows := []engine.MapEntry{row("10.0.0.9:6379/udp"), row("10.0.0.9:6379/tcp"), row("10.0.0.9:80/tcp", "app.test")}
	addrs := map[string]string{"redis.test": "10.0.0.9", "app.test": "10.0.0.9"}
	for label, want := range map[string]string{
		"redis.test:6379": "10.0.0.9:6379/tcp", "redis.test:6379/udp": "10.0.0.9:6379/udp", "app.test:80": "10.0.0.9:80/tcp", "10.0.0.9:6379": "10.0.0.9:6379/tcp",
	} {
		if got := portLabelRow(rows, addrs, label); got == nil || got.Entity.Key != want {
			t.Errorf("%s: %v, want %s", label, got, want)
		}
	}
	// Its address has port 80 open, so the name's does: that is what a name that points there is.
	if got := portLabelRow(rows, addrs, "redis.test:80"); got == nil || got.Entity.Key != "10.0.0.9:80/tcp" {
		t.Errorf("redis.test:80 found %v", got)
	}
	if got := portLabelRow(rows, addrs, "redis.test:81"); got != nil {
		t.Errorf("redis.test:81 found %v", got.Entity.Key)
	}
}
