package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The server's resolvers, sources, skipped collectors and takeover check are
// fixed at start and reach every command that takes them, whatever a call
// says; the commands that do not take an option are not given it.
func TestMCPHeldRunOptionsReachTheCommands(t *testing.T) {
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1", "-allow", "lab.test"}, locked: true, budget: 100,
		held: heldRun{Resolvers: "127.0.0.1:5399", Sources: "crtsh", Skip: "rdap", NoTakeover: true}}
	t.Setenv("FAKE_SUMMARY", `{"type":"summary","command":"run","exit":0,"requests":1}`)
	calls := map[string]map[string]any{
		"azhaq_plan":       {"domain": "lab.test"},
		"azhaq_map":        {"domain": "lab.test", "workspace": "w"},
		"azhaq_subdomains": {"domain": "lab.test"},
		"azhaq_probe":      {"targets": []any{"http://127.0.0.1/"}},
		"azhaq_ports":      {"hosts": []any{"127.0.0.1"}},
	}
	for tool, args := range calls {
		_ = os.Remove(filepath.Join(dir, "args"))
		callText(t, s, tool, args)
		raw, _ := os.ReadFile(filepath.Join(dir, "args"))
		line := strings.SplitN(string(raw), "\n", 2)[0]
		has := func(opt string) bool { return strings.Contains(line+" ", " "+opt+" ") }
		cmd := strings.Fields(line)[0]
		mapping := cmd == "run" || cmd == "plan"
		switch {
		case !has("-resolvers 127.0.0.1:5399"):
			t.Errorf("%s: %s lacks the held resolvers: %s", tool, cmd, line)
		case mapping && (!has("-sources crtsh") || !has("-skip rdap") || !has("-no-takeover")):
			t.Errorf("%s: %s lacks a held option: %s", tool, cmd, line)
		case cmd == "subs" && (!has("-sources crtsh") || has("-no-takeover") || has("-skip rdap")):
			t.Errorf("%s: subs takes the sources, not the options of a map: %s", tool, line)
		case (cmd == "probe" || cmd == "ports") && strings.Contains(line, "-sources"):
			t.Errorf("%s: %s takes no -sources: %s", tool, cmd, line)
		}
	}
	// A resumed run and roles' runs get them too.
	for _, cmd := range []string{"resume", "roles"} {
		if got := strings.Join(s.held.options(cmd), " "); got != "-sources crtsh -no-history -skip rdap -no-takeover -resolvers 127.0.0.1:5399" {
			t.Errorf("%s gets %q", cmd, got)
		}
	}
	// No call can set them: the schemas have no such argument.
	if err := checkArgs("azhaq_plan", map[string]any{"domain": "lab.test", "resolvers": []any{"8.8.8.8"}, "sources": "none"}); err == nil {
		t.Error("a call sets resolvers and sources: they must be the server's alone")
	}

	text, _ := callText(t, s, "azhaq_scope", nil)
	var got struct {
		Options map[string]any `json:"run_options"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil || got.Options["resolvers"] != "127.0.0.1:5399" || got.Options["sources"] != "crtsh" || got.Options["no_takeover"] != true {
		t.Errorf("azhaq_scope does not show the held options: %v %s", err, text)
	}
	text, _ = callText(t, s, "azhaq_status", nil)
	if !strings.Contains(text, `"run_options"`) {
		t.Errorf("azhaq_status does not show the held options: %s", text)
	}

	// No sources named at start: no third party, so the subdomain tool,
	// which is one, is refused. That is the default, not only -sources none.
	for _, held := range []heldRun{{Sources: "none"}, {}} {
		s.held = held
		if text, isErr := callText(t, s, "azhaq_subdomains", map[string]any{"domain": "lab.test"}); !isErr || !strings.Contains(text, "asks no third party") {
			t.Errorf("azhaq_subdomains with sources %q: %v %s", held.Sources, isErr, text)
		}
	}
	s.held = heldRun{Resolvers: "127.0.0.1:5399", Sources: "crtsh", Skip: "rdap", NoTakeover: true}
}

// A run this server started comes back through azhaq_resume with the options
// it was held to.
func TestMCPResumeKeepsTheHeldOptions(t *testing.T) {
	for _, k := range []string{"resolvers", "sources", "no-takeover"} {
		if !mcpRunFlags[k] {
			t.Errorf("-%s is not a run option a resume may bring back", k)
		}
	}
}

// An option no run takes is refused when the server starts.
func TestMCPRefusesBadHeldOptions(t *testing.T) {
	for _, c := range []struct{ resolvers, sources, skip, want string }{
		{"not a resolver!", "", "", "-resolvers"},
		{"", "nosuchsource", "", "-sources"},
		{"", "", "nosuchcollector", "-skip"},
	} {
		if _, err := checkHeld(c.resolvers, c.sources, c.skip, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if _, err := checkHeld("127.0.0.1:5399", "none", "rdap", true); err != nil {
		t.Errorf("good options refused: %v", err)
	}
}

// With -resolvers set and -sources none a domain map asks no third party and
// every name goes to the given resolver: the plan lists no collector that asks
// one, and the resolver is the one that is asked.
func TestMCPMapHeldToResolversAndNoSources(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>home</title></html>`)
	}))
	defer site.Close()
	var asked atomic.Int64
	lab := serveCountingZone(t, &asked, map[string]string{"app.lab.test": "127.0.0.1"})
	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nAZHAQ_TEST_AS_MAIN=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &mcpServer{exe: exe, dir: filepath.Join(dir, "ws"), lock: []string{"-allow", "lab.test"}, locked: true,
		held: heldRun{Resolvers: lab, Sources: "none"}}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	text, isErr := callText(t, s, "azhaq_plan", map[string]any{"domain": "lab.test"})
	if isErr {
		t.Fatalf("plan: %s", text)
	}
	for _, third := range []string{"azhaq-rdap", "azhaq-search", "azhaq-subdomains", "azhaq-urls"} {
		if strings.Contains(text, third) {
			t.Errorf("the plan lists %s, which asks a third party: %s", third, text)
		}
	}
	text, isErr = callText(t, s, "azhaq_map", map[string]any{"url": "http://app.lab.test:" + srvPort(t, site) + "/", "workspace": "w"})
	if isErr {
		t.Fatalf("map: %s", text)
	}
	if asked.Load() == 0 {
		t.Errorf("the lab resolver was never asked: %s", text)
	}
}

// A server started with -send-state-changing gives it to azhaq_roles as to
// the other tools, and without it roles holds the GETs back.
func TestMCPRolesGetsSendStateChangingLikeTheOtherTools(t *testing.T) {
	roles := []any{map[string]any{"name": "anon"}, map[string]any{"name": "user", "header": []any{"Authorization: Bearer x"}}}
	for _, on := range []bool{true, false} {
		dir := t.TempDir()
		s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 100,
			held: heldRun{SendStateChanging: on}}
		t.Setenv("FAKE_SUMMARY", `{"type":"summary","command":"roles","exit":0,"requests":1}`)
		callText(t, s, "azhaq_roles", map[string]any{"url": "http://127.0.0.1/", "roles": roles})
		raw, _ := os.ReadFile(filepath.Join(dir, "args"))
		line := strings.SplitN(string(raw), "\n", 2)[0]
		if !strings.HasPrefix(line, "roles ") {
			t.Fatalf("not a roles call: %s", line)
		}
		if got := strings.Contains(line+" ", " -send-state-changing "); got != on {
			t.Errorf("send-state-changing at start %v: roles got it %v: %s", on, got, line)
		}
		if on && strings.Index(line, " -- ") > strings.Index(line, "-send-state-changing") {
			t.Errorf("the flag is a run option and goes after --: %s", line)
		}
	}
}

// A -resolvers file is held as the resolvers it holds, as resume keeps it: a
// file removed after the start changes nothing a held run asks.
func TestMCPHeldKeepsTheResolversOfAFileThatIsGone(t *testing.T) {
	file := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(file, []byte("# mine\n127.0.0.1:5399\n\ntcp:127.0.0.2:5399\n127.0.0.1:5399\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := checkHeld(file, "none", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	const want = "127.0.0.1:5399,tcp:127.0.0.2:5399"
	if h.Resolvers != want {
		t.Fatalf("held resolvers %q, want %q", h.Resolvers, want)
	}
	for _, cmd := range []string{"run", "resume", "dns", "subs"} {
		if got := strings.Join(h.options(cmd), " "); !strings.Contains(got, "-resolvers "+want) {
			t.Errorf("%s gets %q", cmd, got)
		}
	}
	if v := h.view()["resolvers"]; v != want {
		t.Errorf("azhaq_scope shows %v", v)
	}
	// A list stays as given.
	if h, err = checkHeld("8.8.8.8", "none", "", false); err != nil || h.Resolvers != "8.8.8.8" {
		t.Errorf("a list: %q %v", h.Resolvers, err)
	}
}
