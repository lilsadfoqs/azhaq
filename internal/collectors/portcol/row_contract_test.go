package portcol

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// contractRun runs c on seed and returns the payload of every row it emitted,
// whatever the run returned (a stopped run is an error).
func contractRun(t *testing.T, c *Collector, seed types.Seed) []string {
	t.Helper()
	var raws []string
	_, _ = c.Run(context.Background(), seed, func(o types.Observation) error {
		if o.Collector != Name {
			t.Errorf("collector %q", o.Collector)
		}
		raws = append(raws, string(o.Payload))
		return nil
	})
	return raws
}

// fitRow fails the test for a payload that portscan.Row does not hold whole: a key
// the writer emits and the type lacks.
func fitRow(t *testing.T, scenario string, raws []string) []portscan.Row {
	t.Helper()
	if len(raws) == 0 {
		t.Errorf("%s: no row", scenario)
	}
	var rows []portscan.Row
	for _, raw := range raws {
		r, err := portscan.ParseRowStrict([]byte(raw))
		if err != nil {
			t.Errorf("%s: %v in %s", scenario, err, raw)
		}
		rows = append(rows, r)
	}
	return rows
}

func udpListeners(t *testing.T) (answer, quiet, gone int) {
	t.Helper()
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { a.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := a.ReadFrom(buf)
			if err != nil {
				return
			}
			a.WriteTo([]byte("hi"), from)
		}
	}()
	quiet = silentUDP(t, "127.0.0.1:0")
	g, _ := net.ListenPacket("udp", "127.0.0.1:0")
	gone = g.LocalAddr().(*net.UDPAddr).Port
	g.Close()
	return a.LocalAddr().(*net.UDPAddr).Port, quiet, gone
}

// nameFor answers from zones: a name's records, as full resource records.
func nameFor(t *testing.T, zones map[string][]string) *dnsr.Pool {
	pool := dnsr.New(dnsr.Options{Resolvers: []string{"192.0.2.1"}, PerSecond: -1})
	pool.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		name := strings.TrimSuffix(q.Question[0].Name, ".")
		if zones[name] == nil {
			m.Rcode = dns.RcodeNameError
		}
		for _, text := range zones[name] {
			rr, err := dns.NewRR(text)
			if err != nil {
				t.Fatal(err)
			}
			if rr.Header().Rrtype == q.Question[0].Qtype || rr.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, rr)
			}
		}
		return m, nil
	}
	return pool
}

// Every row the collector writes fits portscan.Row, key for key: one address,
// a name, a name that does not resolve or has no route, a range and the rows a
// limit leaves, with TCP, UDP and both passes of the default scan.
func TestEveryRowTheCollectorWritesFitsRow(t *testing.T) {
	tcp := listener(t)
	answer, quiet, gone := udpListeners(t)
	ip := types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}

	t.Run("address", func(t *testing.T) {
		c := New(nil, []int{tcp, tcp + 1}, 0)
		c.UDPPorts = []int{answer, quiet, gone}
		c.Scanner.Timeout = 300 * time.Millisecond
		rows := fitRow(t, "address", contractRun(t, c, ip))
		if r := rows[0]; r.Host != "127.0.0.1" || r.IP != "127.0.0.1" || r.Scanned != 2 || len(r.Services) != 1 || len(r.UDPServices) != 2 || r.UDPClosed != 1 {
			t.Errorf("row %+v", r)
		}
	})
	t.Run("discovery", func(t *testing.T) {
		c := New(nil, []int{tcp}, 0)
		c.Discover = DiscoverFirst
		rows := fitRow(t, "discovery", contractRun(t, c, ip))
		if rows[0].Up == nil {
			t.Error("a scan with discovery has no up")
		}
	})
	t.Run("name", func(t *testing.T) {
		pool := nameFor(t, map[string][]string{
			"web.example.org":  {"web.example.org. 60 IN A 127.0.0.1", "web.example.org. 60 IN AAAA 2001:db8::1"},
			"shop.example.org": {"shop.example.org. 60 IN CNAME x.cloudfront.net.", "x.cloudfront.net. 60 IN A 127.0.0.1"},
			"six.example.org":  {"six.example.org. 60 IN AAAA 2001:db8::1"},
		})
		for _, exclude := range []bool{false, true} {
			c := New(pool, []int{tcp}, 0)
			c.IPv6 = func() bool { return false }
			c.ExcludeCDN = exclude
			rows := fitRow(t, "name", contractRun(t, c, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "shop.example.org"}}))
			if rows[0].Host != "shop.example.org" || rows[0].IP != "127.0.0.1" || rows[0].CDN == "" || rows[0].Note == "" {
				t.Errorf("exclude=%v: row %+v", exclude, rows[0])
			}
		}
		c := New(pool, []int{tcp}, 0)
		c.IPv6 = func() bool { return false }
		if r := fitRow(t, "dual", contractRun(t, c, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "web.example.org"}}))[0]; len(r.Unrouted) != 1 || r.IP != "127.0.0.1" {
			t.Errorf("dual row %+v", r)
		}
		if r := fitRow(t, "six", contractRun(t, c, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "six.example.org"}}))[0]; len(r.Unrouted) != 1 || r.IP != "" || r.Host != "six.example.org" {
			t.Errorf("IPv6-only row %+v", r)
		}
		if r := fitRow(t, "unresolved", contractRun(t, c, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "none.example.org"}}))[0]; r.Unresolved == "" || r.IP != "" || r.Host != "none.example.org" {
			t.Errorf("unresolved row %+v", r)
		}
	})
	t.Run("range", func(t *testing.T) {
		silent2 := silentUDP(t, "127.0.0.2:0") // answers nothing: its address has a silent-only row
		c := New(nil, []int{tcp}, 0)
		c.UDPPorts = []int{silent2}
		c.Scanner.Timeout = 150 * time.Millisecond
		var rng, silent, addr int
		for _, r := range fitRow(t, "range", contractRun(t, c, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.0/30"}})) {
			switch {
			case r.Range:
				rng++
				if r.Prefix != "127.0.0.0/30" || r.Addresses != 4 || r.Host != "" || r.IP != "" {
					t.Errorf("range row %+v", r)
				}
			case r.UDPSilentOnly:
				silent++
			default:
				addr++
				if r.Prefix != "127.0.0.0/30" || r.Host != r.IP || r.IP == "" {
					t.Errorf("address row of a range %+v", r)
				}
			}
		}
		if rng != 1 || addr == 0 || silent != 1 {
			t.Errorf("%d range rows, %d address rows, %d silent-only rows", rng, addr, silent)
		}
	})
	t.Run("one address as a range", func(t *testing.T) {
		c := New(nil, []int{tcp}, 0)
		c.UDPPorts = []int{answer, quiet, gone}
		c.Scanner.Timeout = 150 * time.Millisecond
		fitRow(t, "slash 32", contractRun(t, c, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.1/32"}}))
	})
}

// The rows of scans a limit stopped, and the checkpoints kept as they go.
func TestEveryStoppedRowFitsRow(t *testing.T) {
	tcp := listener(t)
	answer, quiet, gone := udpListeners(t)
	budget := func(c *Collector, n int32) {
		var takes atomic.Int32
		c.Scanner.Take = func() error {
			if takes.Add(1) > n {
				return neterr.ErrBudget
			}
			return nil
		}
	}
	t.Run("address", func(t *testing.T) {
		ports := []int{tcp, tcp + 1, tcp + 2, tcp + 3, tcp + 4, tcp + 5}
		c := New(nil, ports, 0)
		budget(c, 3)
		rows := fitRow(t, "stopped address", contractRun(t, c, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}))
		if last := rows[len(rows)-1]; !last.Partial || last.Asked == "" {
			t.Errorf("last row %+v", last)
		}
	})
	t.Run("udp", func(t *testing.T) {
		c := New(nil, []int{tcp}, 0)
		c.UDPPorts = []int{answer, quiet, gone}
		c.Scanner.Timeout = 150 * time.Millisecond
		budget(c, 5)
		rows := fitRow(t, "stopped udp", contractRun(t, c, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}))
		if last := rows[len(rows)-1]; !last.Partial || last.UDPScanned == 0 {
			t.Errorf("last row %+v", last)
		}
	})
	t.Run("second pass", func(t *testing.T) {
		c := New(nil, []int{tcp}, 0)
		c.Escalate = true
		c.Scanner.Detect = portscan.DetectNone
		budget(c, 40)
		var pass2 bool
		for _, r := range fitRow(t, "stopped second pass", contractRun(t, c, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}})) {
			pass2 = pass2 || r.Partial && r.Pass == 2 && r.PortsLeft > 0
		}
		if !pass2 {
			t.Error("no partial row names the second pass")
		}
	})
	t.Run("range", func(t *testing.T) {
		c := New(nil, []int{tcp, tcp + 1}, 0)
		c.Workers = 1
		c.Escalate = true
		c.Scanner.Detect = portscan.DetectNone
		budget(c, 5)
		var stopped, checkpoint bool
		for _, r := range fitRow(t, "stopped range", contractRun(t, c, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.0/29"}})) {
			if r.Range && r.Stopped {
				stopped = stopped || r.Swept != "" && r.AddressesOf == 8
			}
			checkpoint = checkpoint || r.Checkpoint
		}
		if !stopped || !checkpoint {
			t.Errorf("stopped row %v, checkpoint %v", stopped, checkpoint)
		}
	})
}

// The helpers that write the keys a run seldom reaches: a threshold, silent TCP
// ports, a row past the UDP list, a CDN edge, a stopped UDP scan.
func TestRowHelpersWriteOnlyKnownKeys(t *testing.T) {
	c := New(nil, nil, 0)
	row := c.row("h.example", "10.0.0.1", []int{1, 2, 3}, &scan{open: []portscan.Open{{Port: 1}}, silent: []int{2}, unprobed: 1, capped: true, up: true}, "Fastly", true)
	var rep portscan.UDPReport
	for p := 1; p <= maxListed+1; p++ {
		rep.OpenFiltered = append(rep.OpenFiltered, portscan.UDPPort{Port: p, State: portscan.UDPOpenFiltered})
	}
	rep.Closed, rep.ClosedPorts, rep.Limited = 40, []int{7, 8}, 3
	rep.Stopped = []portscan.UDPStop{{Port: 9, Asked: 1}, {Port: 10}}
	c.Scanner.Detect = portscan.DetectNone
	c.udpRow(row, rep, 20)
	row[outScopeKey] = 2
	row[unroutedKey] = []string{"2001:db8::1"}
	c.markPartial(row, []int{1, 2, 3})
	c.markPass(row, 2, 5)
	row[CheckpointKey] = true
	row["prefix"] = "10.0.0.0/24"
	got := fitRow(t, "helpers", []string{mustJSON(t, row)})[0]
	if !got.Threshold || got.UDPUnlisted != maxListed+1 || !got.UDPOneRequest || got.UDPAsked["1"] != "9" || got.UDPUnasked != 1 || got.PortsOutsideScope != 2 {
		t.Errorf("row %+v", got)
	}
	fitRow(t, "silent only", []string{mustJSON(t, silentRow("10.0.0.2", "10.0.0.0/24", rep, 20))})
}

// The keys named in the writer's source are all fields of Row: a key added
// to a row without its field fails here even if no scenario above reaches it.
func TestWriterKeysAreRowFields(t *testing.T) {
	tags := map[string]bool{}
	rt := reflect.TypeOf(portscan.Row{})
	for i := 0; i < rt.NumField(); i++ {
		tags[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	files, _ := os.ReadDir(".")
	index := regexp.MustCompile(`\b(?:row|rng|payload)\["([a-z_0-9]+)"\]`)
	konst := regexp.MustCompile(`\b\w*Key\s*=\s*"([a-z_0-9]+)"`)
	literal := regexp.MustCompile(`map\[string\]any\{[^}]*\}`)
	quoted := regexp.MustCompile(`"([a-z_0-9]+)":`)
	var keys []string
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range []*regexp.Regexp{index, konst} {
			for _, m := range re.FindAllSubmatch(src, -1) {
				keys = append(keys, string(m[1]))
			}
		}
		for _, lit := range literal.FindAll(src, -1) {
			for _, m := range quoted.FindAllSubmatch(lit, -1) {
				if !strings.HasPrefix(string(m[1]), "_") { // outScopeKey + "_addresses", added below
					keys = append(keys, string(m[1]))
				}
			}
		}
	}
	keys = append(keys, outScopeKey+"_addresses")
	if len(keys) < 40 {
		t.Fatalf("found %d keys in the source: the patterns no longer match it", len(keys))
	}
	slices.Sort(keys)
	for _, k := range slices.Compact(keys) {
		if !tags[k] {
			t.Errorf("the writer emits %q, which portscan.Row has no field for", k)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
