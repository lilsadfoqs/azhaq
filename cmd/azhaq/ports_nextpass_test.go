package main

import (
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
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
	for _, p := range portscan.DefaultPorts() {
		if !slices.Contains(top, p) {
			left++
		}
	}
	if left == 0 {
		t.Fatal("the default set holds nothing the top 1000 lacks")
	}
	next := nextOf(sumMap(t, errOut))
	var cat, full = -1, -1
	for i, n := range next {
		switch {
		case strings.Contains(n, "-p top-1000,default"):
			cat = i
			want := strconv.Itoa(left) + " ports of the default set"
			if !strings.Contains(n, want) || !strings.Contains(n, "were not asked on 1 address: "+strconv.Itoa(left)+" connects") {
				t.Errorf("the line is %q, want %q and %d connects on 1 address", n, want, left)
			}
		case strings.Contains(n, "-p full"):
			full = i
		}
	}
	if cat < 0 || full < 0 || cat > full {
		t.Fatalf("want the default-set pass before the full-range one (at %d and %d) in %q (port %d)", cat, full, next, port)
	}
}

// A scan that asked the default set, or every port, leaves none out.
func TestNoCatalogPassWhenNothingIsLeftOut(t *testing.T) {
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", "default", "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-ledger", "off")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, n := range nextOf(sumMap(t, errOut)) {
		if strings.Contains(n, "of the default set") {
			t.Errorf("a scan of the default set names the default set: %q", n)
		}
	}
	if got := catalogLeft(portscan.DefaultPorts(), ""); len(got) != 0 {
		t.Errorf("left out of the default set: %v", got)
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
	for _, p := range portscan.DefaultPorts() {
		if !slices.Contains(asked, p) {
			want++
		}
	}
	found := false
	for _, n := range nextOf(sumMap(t, errOut)) {
		if strings.Contains(n, "of the default set") {
			found = true
			if !strings.Contains(n, "top-100,"+port+",default") || !strings.Contains(n, strconv.Itoa(want)+" ports of the default set") || !strings.Contains(n, ": "+strconv.Itoa(want)+" connects)") {
				t.Errorf("%q, want the list with ,default and %d ports, %d connects", n, want, want)
			}
		}
	}
	if !found {
		t.Errorf("no default-set pass in %q", errOut)
	}
}
