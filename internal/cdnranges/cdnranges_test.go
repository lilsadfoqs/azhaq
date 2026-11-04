package cdnranges

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"testing"
)

func TestScanReadsJSON(t *testing.T) {
	doc := ` { "a" : { "x":["1.0.0.0/8", "2.0.0.0/8"] , "y" : [ ] },
	  "bA":["q\"r","s"], "n": 12, "z":{"k":[]} } `
	got := map[string]string{}
	var order []string
	if err := members(doc, func(k, v string) { got[k] = v; order = append(order, k) }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"a", "bA", "n", "z"}) {
		t.Errorf("keys %q", order)
	}
	if got["n"] != "12" || got["z"] != `{"k":[]}` {
		t.Errorf("values %q", got)
	}
	var strsGot []string
	if err := strs(got["bA"], func(s string) { strsGot = append(strsGot, s) }); err != nil || !reflect.DeepEqual(strsGot, []string{`q"r`, "s"}) {
		t.Errorf("strings %q %v", strsGot, err)
	}
	var inner []string
	_ = members(got["a"], func(k, v string) {
		_ = strs(v, func(s string) { inner = append(inner, k+"="+s) })
	})
	if !reflect.DeepEqual(inner, []string{"x=1.0.0.0/8", "x=2.0.0.0/8"}) {
		t.Errorf("nested %q", inner)
	}
	for _, bad := range []string{``, `[1]`, `{"a" 1}`, `{"a":`, `{"a":["b"`} {
		if members(bad, func(k, v string) { _ = strs(v, func(string) {}) }) == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// The scanner finds the same members the data holds.
func TestDocumentHasTheFourMembers(t *testing.T) {
	d := document()
	for _, k := range []string{"cdn", "waf", "cloud", "common"} {
		if len(d[k]) < 10 {
			t.Errorf("member %s: %.20q", k, d[k])
		}
	}
	if len(suffixes()) < 50 {
		t.Errorf("%d suffixes", len(suffixes()))
	}
}

// CheckEdge answers for CDNs and WAFs as Check does, and knows no cloud:
// the 116,000 ranges of the clouds are not read for it.
func TestCheckEdgeLeavesTheCloudOut(t *testing.T) {
	for _, ip := range []string{"104.16.0.1", "2606:4700::1", "151.101.1.1"} {
		wm, wp, wk, _ := Check(net.ParseIP(ip))
		gm, gp, gk, err := CheckEdge(net.ParseIP(ip))
		if err != nil || wm != gm || wp != gp || wk != gk {
			t.Errorf("%s: Check %v %q %q, CheckEdge %v %q %q %v", ip, wm, wp, wk, gm, gp, gk, err)
		}
	}
	// An address only a cloud holds.
	var cloudIP net.IP
	for _, ip := range []string{"3.5.140.2", "52.95.0.1", "34.64.0.1", "20.33.0.1", "13.107.6.152"} {
		if m, _, k, _ := Check(net.ParseIP(ip)); m && k == "cloud" {
			cloudIP = net.ParseIP(ip)
			break
		}
	}
	if cloudIP == nil {
		t.Fatal("no cloud address among the samples")
	}
	if m, p, k, _ := CheckEdge(cloudIP); m {
		t.Errorf("%s: CheckEdge says %q %q", cloudIP, p, k)
	}
	if _, _, _, err := CheckEdge(nil); err == nil {
		t.Error("nil address: no error")
	}
}

// What a port scan pays for its CDN check: asked in a process of its own,
// CheckEdge allocates a few hundred kilobytes, where reading the whole
// data into the heap took 17 MB.
func TestCheckEdgeAllocatesLittle(t *testing.T) {
	if os.Getenv("AZHAQ_EDGE_HELPER") != "" {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		CheckEdge(net.ParseIP("104.16.0.1"))
		CheckEdge(net.ParseIP("8.8.8.8"))
		runtime.ReadMemStats(&after)
		fmt.Printf("alloc=%d\n", after.TotalAlloc-before.TotalAlloc)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCheckEdgeAllocatesLittle$")
	cmd.Env = append(os.Environ(), "AZHAQ_EDGE_HELPER=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if _, err := fmt.Sscanf(string(out[bytes.Index(out, []byte("alloc=")):]), "alloc=%d", &n); err != nil {
		t.Fatalf("no count in %q", out)
	}
	if n > 2<<20 {
		t.Errorf("CheckEdge allocated %d bytes", n)
	}
	t.Logf("CheckEdge allocated %d bytes", n)
}

// EdgeOverlaps agrees with asking CheckEdge of each address of a range.
func TestEdgeOverlapsAgreesWithCheckEdge(t *testing.T) {
	for _, c := range []struct {
		pf   string
		want bool
	}{
		{"104.16.0.0/24", true},   // Cloudflare
		{"104.0.0.0/8", true},     // holds Cloudflare's
		{"127.0.0.0/8", false},    // loopback
		{"10.0.0.0/24", false},    // private
		{"2606:4700::/120", true}, // Cloudflare's IPv6
	} {
		pf := netip.MustParsePrefix(c.pf)
		if got := EdgeOverlaps(pf); got != c.want {
			t.Errorf("EdgeOverlaps(%s) = %v, want %v", c.pf, got, c.want)
		}
		if pf.Bits() >= 24 && pf.Addr().Is4() || pf.Bits() >= 120 {
			any := false
			for a := pf.Addr(); pf.Contains(a); a = a.Next() {
				if m, _, _, _ := CheckEdge(net.IP(a.AsSlice())); m {
					any = true
				}
			}
			if any != c.want {
				t.Errorf("%s: CheckEdge finds an edge address: %v, want %v", c.pf, any, c.want)
			}
		}
	}
}
