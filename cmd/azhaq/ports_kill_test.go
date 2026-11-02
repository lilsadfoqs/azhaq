package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A port scan killed with SIGKILL keeps the ports it had finished, once a
// second: the resume asks the ports after them, finds what the rest holds,
// and says how many connects of the killed run it made again.
func TestPortsResumeAfterSIGKILLAsksOnlyThePortsAfterTheCheckpoint(t *testing.T) {
	early, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer early.Close()
	lo := early.Addr().(*net.TCPAddr).Port
	late, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lo+4000))
	if err != nil {
		t.Skipf("no port %d to listen on: %v", lo+4000, err)
	}
	defer late.Close()
	for _, l := range []net.Listener{early, late} {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "k.db")
	spec := fmt.Sprintf("%d-%d", lo, lo+4000)
	cmd := exec.Command(os.Args[0], "ports", "-host", "127.0.0.1", "-p", spec, "-order", "asc", "-rate", "1500", "-detect", "none", "-allow", "127.0.0.1", "-db", db, "-json")
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2200 * time.Millisecond)
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	if raw, _ := os.ReadFile(db + ".ledger.jsonl"); strings.Contains(string(raw), `"kind":"seal"`) || !strings.Contains(string(raw), `"kind":"tcp"`) {
		t.Fatalf("the killed run's ledger is sealed or has no connect:\n%.300s", raw)
	}

	dataDirs.Store(t.Name(), dir)
	ledgerHoldsAKilledRun(t)
	out, rep, code := runContract(t, "resume", "-db", db)
	if code != exitOK {
		t.Fatalf("resume: exit %d\n%+v", code, rep)
	}
	if !strings.Contains(out, fmt.Sprintf(`"port":%d`, lo+4000)) {
		t.Errorf("the open port the kill left unasked is not in the resume's rows:\n%s", out)
	}
	if rep.Requests > 3000 {
		t.Errorf("the resume made %d connects of the 4001 ports: it asked them all again", rep.Requests)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !regexp.MustCompile(`\d+ connects? made before the run was killed had no stored answer`).MatchString(notes) {
		t.Errorf("the notes do not say how many connects were asked again:\n%s", notes)
	}
}
