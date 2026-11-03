package main

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/store"
)

// udpSilentAt binds a silent UDP port at addr (host:port) and reads what it
// is sent.
func udpSilentAt(t *testing.T, addr string) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// A range with silent hosts: 127.0.0.2 answers nothing on its three ports and
// 127.0.0.3 is silent on one and refuses two. By default the output has one row
// for the address that showed life (its silent ports as a count, a list, how
// many were asked and how many it refused), the summary counts the address
// that answered nothing, and no silent port is lost: the workspace holds all
// four in the rows' udp_open_filtered, and -udp-rows prints each of them.
func TestPortsUDPRangeOfSilentHostsIsAggregated(t *testing.T) {
	t.Chdir(t.TempDir())
	first := udpSilentAt(t, "127.0.0.2:0")
	ports := []int{first}
	for i := 1; i < 3; i++ {
		ports = append(ports, udpSilentAt(t, fmt.Sprintf("127.0.0.2:%d", first+i)))
	}
	if net.ParseIP("127.0.0.3") == nil {
		t.Skip("no 127.0.0.3")
	}
	udpSilentAt(t, fmt.Sprintf("127.0.0.3:%d", first)) // the other two ports of 127.0.0.3 are closed
	pu := fmt.Sprintf("%d-%d", first, first+2)

	out, rep, code := runContract(t, "ports", "127.0.0.0/29", "-p", "none", "-pu", pu, "-connect-timeout", "200ms", "-db", "r.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%+v", code, rep)
	}
	var rows []map[string]any
	for _, l := range lines(out) {
		var r map[string]any
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("not a row: %q", l)
		}
		rows = append(rows, r)
	}
	if len(rows) != 1 || rows[0]["ip"] != "127.0.0.3" || rows[0]["ports"] != fmt.Sprint(first) || rows[0]["silent"] != float64(1) ||
		rows[0]["asked"] != float64(3) || rows[0]["refused"] != float64(2) || rows[0]["port"] != nil {
		t.Fatalf("the default output is not one aggregate row of the address that answered something: %v", rows)
	}
	notes := strings.Join(rep.Notes, "\n")
	if rep.Counts["open|filtered"] != 1 || !strings.Contains(notes, "1 addresses of the ranges answered no UDP port (no reply, no ICMP port unreachable; 3 ports asked of each, 3 ports open|filtered in all)") {
		t.Errorf("the summary does not aggregate the silent address: counts %v\n%s", rep.Counts, notes)
	}

	st, err := store.OpenExisting("r.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kept := map[string][]int{}
	for _, p := range payloads(st, "azhaq-ports") {
		ip, _ := p["ip"].(string)
		if p["range"] == true || ip == "" {
			continue
		}
		for _, x := range p["udp_open_filtered"].([]any) {
			kept[ip] = append(kept[ip], int(x.(float64)))
		}
	}
	slices.Sort(kept["127.0.0.2"])
	if !slices.Equal(kept["127.0.0.2"], ports) || !slices.Equal(kept["127.0.0.3"], []int{first}) {
		t.Errorf("the stored rows hold %v, want every silent port of both addresses", kept)
	}

	out, rep, code = runContract(t, "ports", "127.0.0.0/29", "-p", "none", "-pu", pu, "-connect-timeout", "200ms", "-udp-rows")
	if code != exitOK || len(lines(out)) != 4 || rep.Results != 4 {
		t.Errorf("-udp-rows: exit %d, %d rows, want the 4 silent ports\n%s", code, len(lines(out)), out)
	}
}
