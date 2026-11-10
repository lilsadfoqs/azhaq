package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A ports run started with a list of resolvers and stopped by -max-requests is
// resumed with those resolvers and no flag given again: the list is kept in
// the stored run, not as a temporary file that is gone by then, and every name
// the resume looks up goes to them.
func TestPortsResumeKeepsTheResolversItWasStartedWith(t *testing.T) {
	t.Chdir(t.TempDir())
	ports := listenOpen(t, 6)
	spec := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
	a := zoneOf(t, "scan.example", []string{"127.0.0.1"}, nil)
	b := zoneOf(t, "scan.example", []string{"127.0.0.1"}, nil)
	list := a + "," + b
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "azhaq-list-*"))
	if _, rep, code := runContract(t, "ports", "-host", "scan.example", "-p", spec, "-order", "asc", "-detect", "none", "-resolvers", list, "-ledger", "l.jsonl", "-max-requests", "2", "-db", "w.db"); code != exitLimit {
		t.Fatalf("first run: exit %d\n%+v", code, rep)
	}
	// The temporary lists the run made are gone, as a run that ended long ago left them.
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "azhaq-list-*"))
	for _, f := range after {
		if !slices.Contains(before, f) {
			t.Errorf("the run left %s behind", f)
		}
	}
	_, rep, code := runContract(t, "resume", "-db", "w.db", "-max-requests", "0")
	if code != exitOK {
		t.Fatalf("resume: exit %d, want 0\n%+v", code, rep)
	}
	var dnsTargets []string
	if err := ledger.Read("l.jsonl", func(e ledger.Entry) error {
		if e.Kind == "dns" {
			dnsTargets = append(dnsTargets, e.Target)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(dnsTargets) == 0 {
		t.Fatal("no DNS query in the ledger")
	}
	for _, tg := range dnsTargets {
		if !strings.Contains(tg, a) && !strings.Contains(tg, b) {
			t.Errorf("a DNS query went to %s, not to the resolvers %s of the run", tg, list)
		}
	}
}

// A resolvers file is stored as the resolvers it holds: gone or rewritten
// before the resume, the run still asks the ones it started with.
func TestKeptArgsStoreAResolversFileAsItsList(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(f, []byte("# mine\n1.1.1.1\n\ntcp:9.9.9.9:53\n1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-resolvers", f}, {"-resolvers=" + f}} {
		got := keptArgs(args)
		if want := []string{"-resolvers=1.1.1.1:53,tcp:9.9.9.9:53"}; !slices.Equal(got, want) {
			t.Errorf("keptArgs(%v) = %v, want %v", args, got, want)
		}
	}
	// A list stays as given.
	if got := keptArgs([]string{"-resolvers", "8.8.8.8"}); !slices.Equal(got, []string{"-resolvers=8.8.8.8"}) {
		t.Errorf("a list: %v", got)
	}
}

// The file is deleted after the run stops: the resume asks the file's
// resolvers all the same.
func TestResumeKeepsTheResolversOfAFileThatIsGone(t *testing.T) {
	t.Chdir(t.TempDir())
	ports := listenOpen(t, 6)
	spec := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
	a := zoneOf(t, "scan.example", []string{"127.0.0.1"}, nil)
	file := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(file, []byte(a+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, rep, code := runContract(t, "ports", "-host", "scan.example", "-p", spec, "-order", "asc", "-detect", "none", "-resolvers", file, "-ledger", "l.jsonl", "-max-requests", "2", "-db", "w.db"); code != exitLimit {
		t.Fatalf("first run: exit %d\n%+v", code, rep)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, rep, code := runContract(t, "resume", "-db", "w.db", "-max-requests", "0"); code != exitOK {
		t.Fatalf("resume: exit %d, want 0\n%+v", code, rep)
	}
	n := 0
	if err := ledger.Read("l.jsonl", func(e ledger.Entry) error {
		if e.Kind == "dns" {
			n++
			if !strings.Contains(e.Target, a) {
				t.Errorf("a DNS query went to %s, not to the resolver %s of the file", e.Target, a)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no DNS query in the ledger")
	}
}
