package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/store"
)

// leftOutField reads the summary's ports_left_out: its count and the ports it names.
func leftOutField(t *testing.T, sum map[string]any) (count int, ports []int, ok bool) {
	t.Helper()
	m, ok := sum["ports_left_out"].(map[string]any)
	if !ok {
		return 0, nil, false
	}
	count = int(m["count"].(float64))
	for _, p := range m["ports"].([]any) {
		ports = append(ports, int(p.(map[string]any)["port"].(float64)))
	}
	return count, ports, true
}

// A named set narrower than default says which service ports default asks that
// it does not: the count and the first few, in the summary's notes and in
// ports_left_out. An explicit list, or a set that reaches default, says none.
func TestNarrowPortSetNamesTheServicePortsLeftOut(t *testing.T) {
	t.Chdir(t.TempDir())
	port := listenOnCatalogPort(t, "VERSION 1.6.21\r\n")
	top, _ := portscan.Ports("top-1000")
	gap := portscan.ServiceGap(top, nil)
	if !slices.Contains(gap, port) {
		t.Fatalf("port %d is not in the gap", port)
	}
	db := func() string { return filepath.Join(t.TempDir(), "w.db") }

	_, errOut, _ := cli(t, "ports", "-host", "127.0.0.1", "-p", "top-1000", "-db", db(), "-json", "-ledger", "off")
	sum := sumMap(t, errOut)
	n, shown, ok := leftOutField(t, sum)
	if !ok || n != len(gap) || len(shown) == 0 || shown[0] != gap[0] {
		t.Fatalf("ports_left_out is %v, want count %d from port %d", sum["ports_left_out"], len(gap), gap[0])
	}
	if !strings.Contains(notesOf(sum), "-p top-1000 leaves out "+strconv.Itoa(len(gap))+" service ports that -p default asks ("+strconv.Itoa(gap[0])) {
		t.Errorf("no note names the ports left out: %s", notesOf(sum))
	}

	// The set plus one of the ports leaves that one out of the gap; the lot leaves none.
	_, errOut, _ = cli(t, "ports", "-host", "127.0.0.1", "-p", "top-1000,"+strconv.Itoa(port), "-db", db(), "-json", "-ledger", "off")
	if n, _, _ := leftOutField(t, sumMap(t, errOut)); n != len(gap)-1 {
		t.Errorf("with port %d asked the count is %d, want %d", port, n, len(gap)-1)
	}
	_, errOut, _ = cli(t, "ports", "-host", "127.0.0.1", "-p", "top-1000,"+portscan.Compact(gap), "-db", db(), "-json", "-ledger", "off")
	if _, _, ok := leftOutField(t, sumMap(t, errOut)); ok {
		t.Errorf("a set with every service port reports a gap: %v", sumMap(t, errOut)["ports_left_out"])
	}
	// What -ep keeps out is not left out by the set: the user asked it.
	_, errOut, _ = cli(t, "ports", "-host", "127.0.0.1", "-p", "top-1000", "-ep", strconv.Itoa(port), "-db", db(), "-json", "-ledger", "off")
	if n, _, _ := leftOutField(t, sumMap(t, errOut)); n != len(gap)-1 {
		t.Errorf("with -ep %d the count is %d, want %d", port, n, len(gap)-1)
	}
	// An explicit list is no named set: the gap is not listed for it.
	_, errOut, _ = cli(t, "ports", "-host", "127.0.0.1", "-p", "22,80", "-db", db(), "-json", "-ledger", "off")
	if _, _, ok := leftOutField(t, sumMap(t, errOut)); ok || strings.Contains(notesOf(sumMap(t, errOut)), "leaves out") {
		t.Errorf("an explicit list names a gap: %v", sumMap(t, errOut))
	}
	// run takes -ports, and says it with that flag.
	sum = runJSON(t, "run", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-ports", "top-1000", "-sources", "none", "-passive", "-depth", "0", "-port-detect", "none", "-db", db())
	if n, _, ok := leftOutField(t, sum); !ok || n != len(gap) || !strings.Contains(notesOf(sum), "-ports top-1000 leaves out ") {
		t.Errorf("run -ports top-1000: ports_left_out %v, notes %s", sum["ports_left_out"], notesOf(sum))
	}
}

// plan states the gap too, in its JSON and its text, and sends nothing.
func TestPlanNamesTheServicePortsANarrowSetLeavesOut(t *testing.T) {
	t.Chdir(t.TempDir())
	top, _ := portscan.Ports("top-1000")
	gap := portscan.ServiceGap(top, nil)
	args := []string{"plan", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-ports", "top-1000"}
	out, _, _ := cli(t, append(args, "-json")...)
	var p struct {
		Left struct {
			Count int `json:"count"`
			Ports []struct {
				Port    int    `json:"port"`
				Service string `json:"service"`
			} `json:"ports"`
		} `json:"ports_left_out"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &p); err != nil {
		t.Fatal(err)
	}
	if p.Left.Count != len(gap) || len(p.Left.Ports) == 0 || p.Left.Ports[0].Port != gap[0] || p.Left.Ports[0].Service == "" {
		t.Errorf("plan's ports_left_out is %+v, want count %d from port %d", p.Left, len(gap), gap[0])
	}
	out, _, _ = cli(t, args...)
	if !strings.Contains(out, "ports left out: -ports top-1000 leaves out "+strconv.Itoa(len(gap))+" service ports") {
		t.Errorf("plan's text has no ports left out line:\n%s", out)
	}
	out, _, _ = cli(t, "plan", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-ports", "default")
	if strings.Contains(out, "ports left out") {
		t.Errorf("-ports default leaves nothing out:\n%s", out)
	}
}

// A host with no open port among the ports asked says how many were asked
// and what default adds, whether the list is named or explicit: a range counts
// its quiet addresses. A host that answered gets no note.
func TestQuietHostNamesWhatDefaultWouldAdd(t *testing.T) {
	t.Chdir(t.TempDir())
	_, dead, _ := net.SplitHostPort(deadPort(t))
	live := listenOnCatalogPort(t, "VERSION 1.6.21\r\n")
	gap := portscan.ServiceGap([]int{atoi(dead)}, nil)
	want := "no port answered among the 1 asked; -p default adds " + strconv.Itoa(len(gap)) + " service ports (" + portscan.GapList(gap) + ")"

	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, _ := cli(t, "ports", "-host", "127.0.0.1", "-p", dead, "-db", db, "-json", "-ledger", "off")
	if n := notesOf(sumMap(t, errOut)); !strings.Contains(n, want) {
		t.Errorf("the quiet host has no note %q: %s", want, n)
	}
	// The host's stored row carries it: an address given alone (a block of one) and a name.
	if got := rowNotes(t, db); len(got) != 1 || !strings.Contains(got[0], "no port answered among the 1 asked; -p default adds ") {
		t.Errorf("the address's row has notes %q", got)
	}
	db = filepath.Join(t.TempDir(), "w.db")
	cli(t, "ports", "-host", "localhost", "-p", dead, "-db", db, "-json", "-ledger", "off")
	if got := rowNotes(t, db); len(got) != 1 || !strings.Contains(got[0], "no port answered among the 1 asked; -p default adds ") {
		t.Errorf("the name's row has notes %q", got)
	}
	// An answer on a port asked: no note, and a port nobody listens on among others does not make one.
	_, errOut, _ = cli(t, "ports", "-host", "127.0.0.1", "-p", dead+","+strconv.Itoa(live), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-ledger", "off")
	if n := notesOf(sumMap(t, errOut)); strings.Contains(n, "no port answered") {
		t.Errorf("a host that answered has the quiet note: %s", n)
	}
	// A range: the note counts its quiet addresses.
	_, errOut, _ = cli(t, "ports", "-host", "127.7.7.0/30", "-allow", "127.7.7.0/30", "-p", dead, "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-ledger", "off")
	if n := notesOf(sumMap(t, errOut)); !strings.Contains(n, "no port answered among the 1 asked on 4 of the 4 addresses; -p default adds ") {
		t.Errorf("the range's note does not count its quiet addresses: %s", n)
	}
}

// rowNotes are the notes of the port rows a database holds.
func rowNotes(t *testing.T, db string) []string {
	t.Helper()
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, _ := st.Observations()
	var notes []string
	for _, o := range obs {
		if row, err := portscan.ParseRow(o.Payload); o.Collector == "azhaq-ports" && err == nil && row.Note != "" {
			notes = append(notes, row.Note)
		}
	}
	return notes
}
