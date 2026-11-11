package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// nextOf are the next lines of a JSON summary.
func nextOf(sum map[string]any) []string {
	var out []string
	list, _ := sum["next"].([]any)
	for _, n := range list {
		out = append(out, n.(string))
	}
	return out
}

// listenOnCatalogPort serves on a catalogued port the top 1000 leaves out, the
// first of them that is free here.
func listenOnCatalogPort(t *testing.T, answer string) int {
	t.Helper()
	top, _ := portscan.Ports("top-1000")
	for _, p := range portscan.CatalogPorts() {
		if slices.Contains(top, p) {
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					buf := make([]byte, 512)
					_, _ = c.Read(buf)
					_, _ = c.Write([]byte(answer))
				}()
			}
		}()
		return p
	}
	t.Skip("every catalogued port outside the top 1000 is taken here")
	return 0
}

// A scan of the top 1000 leaves out the ports azhaq names and checks: the
// next passes name them, with the count and the connects, before the pass of
// the whole range.
func TestTopListScanNamesTheCatalogPortsItLeftOut(t *testing.T) {
	port := listenOnCatalogPort(t, "VERSION 1.6.21\r\n")
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", "top-1000", "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-ledger", "off")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	top, _ := portscan.Ports("top-1000")
	left := 0
	for _, p := range portscan.UsualPorts() {
		if !slices.Contains(top, p) {
			left++
		}
	}
	if left == 0 {
		t.Fatal("the usual set holds nothing the top 1000 lacks")
	}
	next := nextOf(sumMap(t, errOut))
	var cat, full = -1, -1
	for i, n := range next {
		switch {
		case strings.Contains(n, "-p top-1000,"+portscan.Compact(catalogLeft(top, ""))):
			cat = i
			want := strconv.Itoa(left) + " ports of the usual set"
			if !strings.Contains(n, want) || !strings.Contains(n, "were not asked on 1 address: "+strconv.Itoa(left)+" connects") {
				t.Errorf("the line is %q, want %q and %d connects on 1 address", n, want, left)
			}
		case strings.Contains(n, "-p full"):
			full = i
		}
	}
	if cat < 0 || full < 0 || cat > full {
		t.Fatalf("want the usual-set pass before the full-range one (at %d and %d) in %q (port %d)", cat, full, next, port)
	}
}

// A scan that asked the usual set, or every port, leaves none out.
func TestNoCatalogPassWhenNothingIsLeftOut(t *testing.T) {
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", portscan.Compact(portscan.UsualPorts()), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-ledger", "off")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, n := range nextOf(sumMap(t, errOut)) {
		if strings.Contains(n, "of the usual set") {
			t.Errorf("a scan of the usual set names the usual set: %q", n)
		}
	}
	if got := catalogLeft(portscan.UsualPorts(), ""); len(got) != 0 {
		t.Errorf("left out of the usual set: %v", got)
	}
	if got := catalogLeft(nil, ""); got != nil {
		t.Errorf("a scan of no TCP port left out %v", got)
	}
	// -ep keeps a port out: it is the user's, not left out.
	all := catalogLeft([]int{80}, "")
	less := catalogLeft([]int{80}, "6379,27017")
	if len(all)-len(less) != 2 {
		t.Errorf("-ep 6379,27017 took %d of %d out, want 2", len(all)-len(less), len(all))
	}
}

// run says it too, with the list it was given and the run's own connects.
func TestRunNamesTheCatalogPortsItsListLeftOut(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	port := portOfURL(srv.URL)
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", "off", "-db", "n.db", "-ports", "top-100,"+port, "-quiet", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	asked, _ := portscan.Ports("top-100," + port)
	want := 0
	for _, p := range portscan.UsualPorts() {
		if !slices.Contains(asked, p) {
			want++
		}
	}
	found := false
	for _, n := range nextOf(sumMap(t, errOut)) {
		if strings.Contains(n, "of the usual set") {
			found = true
			if !strings.Contains(n, "top-100,"+port+","+portscan.Compact(catalogLeft(asked, ""))) || !strings.Contains(n, strconv.Itoa(want)+" ports of the usual set") || !strings.Contains(n, ": "+strconv.Itoa(want)+" connects)") {
				t.Errorf("%q, want the list with the %d ports added, %d connects", n, want, want)
			}
		}
	}
	if !found {
		t.Errorf("no usual-set pass in %q", errOut)
	}
}

func servicesObs(services ...map[string]any) []types.StoredObservation {
	raw, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "ip": "127.0.0.1", "services": services})
	return []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw}}}
}

// Each service a check reads is named by the -verify pass with what its check
// sends; a service with no check is not, and a run that found none says
// nothing.
func TestVerifyPassNamesEachCheckedKind(t *testing.T) {
	for _, c := range verify.Checks() {
		why, cost := verifyPass(servicesObs(map[string]any{"port": 1000, "service": c.Service}))
		if !strings.Contains(why, c.Request+" to "+c.Service) || !strings.Contains(why, "no credential") || cost.Connects != 1 {
			t.Errorf("%s: %q, %v", c.ID, why, cost)
		}
	}
	for name := range verify.NoCheck {
		if why, _ := verifyPass(servicesObs(map[string]any{"port": 1000, "service": name})); why != "" {
			t.Errorf("%s has no check and the pass says %q", name, why)
		}
	}
	two, cost := verifyPass(servicesObs(
		map[string]any{"port": 1, "service": "redis"}, map[string]any{"port": 2, "service": "redis"}, map[string]any{"port": 3, "service": "memcached"}, map[string]any{"port": 4, "service": "ssh"}))
	if cost.Connects != 3 || !strings.Contains(two, "3 services found") || strings.Count(two, "INFO server") != 1 {
		t.Errorf("%q %v: want 3 services, each check named once", two, cost)
	}
	if why, _ := verifyPass(nil); why != "" {
		t.Errorf("no service: %q", why)
	}
}

// ports names -verify when it found a service with a check and was not given
// it, with the connects it adds: the reads are what the run sent more with
// -verify, one connect for each service.
func TestPortsNamesVerifyAndItsCostIsMeasured(t *testing.T) {
	fx := newRedisFixture(t, redisInfoResp())
	scan := func(extra ...string) map[string]any {
		t.Chdir(t.TempDir())
		args := append([]string{"ports", "-host", "127.0.0.1", "-p", strconv.Itoa(fx.port), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-ledger", "off"}, extra...)
		_, errOut, code := cli(t, args...)
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, errOut)
		}
		return sumMap(t, errOut)
	}
	plain := scan()
	var line string
	for _, n := range nextOf(plain) {
		if strings.Contains(n, "read-only check") {
			line = n
		}
	}
	if line == "" || !strings.Contains(line, " -verify") || !strings.Contains(line, "INFO server to redis") || !strings.Contains(line, "no credential") || !strings.Contains(line, "1 connect more") {
		t.Fatalf("no -verify pass in %q", nextOf(plain))
	}
	with := scan("-verify")
	for _, n := range nextOf(with) {
		if strings.Contains(n, "read-only check") {
			t.Errorf("-verify was given and the run names it: %q", n)
		}
	}
	if more := with["requests"].(float64) - plain["requests"].(float64); more != 1 {
		t.Errorf("-verify sent %v requests more for one service, the pass says 1 connect", more)
	}
	// Nothing found: nothing said.
	dead, _ := strconv.Atoi(deadPort(t))
	t.Chdir(t.TempDir())
	_, errOut, _ := cli(t, "ports", "-host", "127.0.0.1", "-p", strconv.Itoa(dead), "-json", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "d.db"))
	for _, n := range nextOf(sumMap(t, errOut)) {
		if strings.Contains(n, "read-only check") {
			t.Errorf("no service was found and the run names -verify: %q", n)
		}
	}
}

// run names it too, with its own command line.
func TestRunNamesVerifyWhenAServiceWithACheckWasFound(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	fx := newRedisFixture(t, redisInfoResp())
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", "off", "-db", "n.db", "-ports", "top-100,"+strconv.Itoa(fx.port), "-quiet", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	found := false
	for _, n := range nextOf(sumMap(t, errOut)) {
		if strings.Contains(n, "read-only check") {
			found = true
			if !strings.Contains(n, "INFO server to redis") || !strings.Contains(n, "-verify") || !strings.Contains(n, "1 connect more") {
				t.Errorf("%q", n)
			}
		}
	}
	if !found {
		t.Errorf("no -verify pass in %q", errOut)
	}
}
