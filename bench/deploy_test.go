package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// What watch -json says after the deploy of bench/truth/deploy/expected.md.
const deployAnswer = `{"db":"w.db","run":"2026-11-01T23:30:09+07:00","previous":"2026-11-01T23:30:08+07:00","routes":[` +
	`{"kind":"new","host":"h","route":"/api/v2/export","methods_added":["POST"],"fields_added":["userId","format"],"script":"http://h/main.js"},` +
	`{"kind":"methods","host":"h","route":"/api/orders/{id}","methods_added":["DELETE"],"script":"http://h/main.js"},` +
	`{"kind":"fields","host":"h","route":"/api/profile","method":"PUT","fields_added":["role"],"script":"http://h/main.js"},` +
	`{"kind":"gone","host":"h","route":"/api/legacy/report","methods_removed":["GET"],"script":"http://h/main.js"}]}`

func TestExpectedMdIsReadAsFourChanges(t *testing.T) {
	raw, err := deployFS.ReadFile("truth/deploy/expected.md")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"fields PUT /api/profile +role", "gone /api/legacy/report", "methods /api/orders/{id} +DELETE", "new POST /api/v2/export fields format,userId"}
	if got := expectedChanges(string(raw)); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("expected.md read as %v, want %v", got, want)
	}
	got, other, err := routeChanges([]byte(deployAnswer), "http://h/main.js")
	if err != nil || len(other) != 0 || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("answer read as %v, other %v, err %v", got, other, err)
	}
	// A route tied to another script, or anything else reported, is not "exactly the expected".
	_, other, _ = routeChanges([]byte(strings.Replace(deployAnswer, `"routes":[`, `"urls":["u"],"routes":[`, 1)), "http://h/other.js")
	if len(other) != 5 {
		t.Errorf("other %v: four routes with the wrong script and one extra key", other)
	}
}

func skipWithoutPython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
}

// The check runs watch against the real fixture app: it passes, and it puts v1 back.
func TestDeployCheckPassesOnTheFixture(t *testing.T) {
	skipWithoutPython(t)
	old := azhaq
	azhaq = smokeBin
	t.Cleanup(func() { azhaq = old })
	dir := t.TempDir()
	lab, err := startDeployLab(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lab.stop()
	raw, _ := deployFS.ReadFile("truth/deploy/expected.md")
	probs, detail := deployProblems(dir, lab, expectedChanges(string(raw)))
	if len(probs) > 0 {
		t.Fatalf("%v (%s)", probs, detail)
	}
	if v, _ := os.ReadFile(dir + "/deploy.state"); strings.TrimSpace(string(v)) != "v1" {
		t.Errorf("the lab was left on %q", v)
	}
}

// A deploy that changes nothing, or a watch that stays quiet about one, fails it.
func TestDeployCheckFailsWhenTheDeployIsNotSeen(t *testing.T) {
	skipWithoutPython(t)
	old := azhaq
	azhaq = smokeBin
	t.Cleanup(func() { azhaq = old })
	dir := t.TempDir()
	lab, err := startDeployLab(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lab.stop()
	lab.deploy = func(v string) error { return nil } // v2 never reaches the app
	raw, _ := deployFS.ReadFile("truth/deploy/expected.md")
	probs, _ := deployProblems(dir, lab, expectedChanges(string(raw)))
	if len(probs) != 1 || !strings.Contains(probs[0], "differs from expected.md: missing") {
		t.Fatalf("problems %v", probs)
	}
}
