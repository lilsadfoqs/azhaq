package main

import (
	"net"
	"os"
	"strings"
	"testing"
)

// The name of a URL given with its own port is asked on 443 and 80 as a
// guess: nothing listening there is a note, not a failed target, and the
// service the URL names is mapped and swept as asked.
func TestRefusedGuessOfADerivedNameIsNotAFailure(t *testing.T) {
	port := portsServer(t)
	zone := serveZone(t, fakeZone{a: map[string]string{"hub.example.test": "127.0.0.1"}})
	t.Chdir(t.TempDir())
	if err := os.WriteFile("words.txt", []byte("admin\nlogin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, rep, code := runContract(t, "run", "-url", "http://hub.example.test:"+port+"/", "-probe", "-dirs", "words.txt",
		"-resolvers", zone, "-allow", "example.test", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-db", "d.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	if !strings.Contains(out, `"key":"http://hub.example.test:`+port+`/"`) || !strings.Contains(out, `"coverage":"visited"`) {
		t.Errorf("the URL given was not mapped:\n%s", out)
	}
	if n := strings.Join(rep.Notes, "\n"); !strings.Contains(n, "no web service on 443 or 80") || !strings.Contains(n, "hub.example.test") {
		t.Errorf("notes %q do not say the guess found no web service", rep.Notes)
	}
}

// One URL of a list that refuses the connection is one failed target: the
// URLs before and after it are mapped all the same, and the exit code is 3.
func TestOneRefusedTargetDoesNotStopTheOthers(t *testing.T) {
	a, b := portsServer(t), portsServer(t)
	shut, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	_, shutPort, _ := net.SplitHostPort(shut.Addr().String())
	shut.Close()
	t.Chdir(t.TempDir())
	list := hostsFile(t, "http://127.0.0.1:"+a+"/", "http://127.0.0.1:"+shutPort+"/", "http://127.0.0.1:"+b+"/")
	out, rep, code := runContract(t, "run", "-list", list, "-sources", "none", "-parallel", "1", "-db", "m.db")
	if code != exitPartial {
		t.Fatalf("exit %d: failed %+v unreachable %v", code, rep.Failed, rep.Unreachable)
	}
	for _, p := range []string{a, b} {
		if !strings.Contains(out, `"key":"http://127.0.0.1:`+p+`/"`) {
			t.Errorf("the service on %s was not mapped:\n%s", p, out)
		}
	}
	if len(rep.Failed) != 1 || rep.Failed[0].Count != 1 || rep.Failed[0].Targets[0] != "http://127.0.0.1:"+shutPort+"/" {
		t.Errorf("the refused target is not one failure: %+v", rep.Failed)
	}
}
