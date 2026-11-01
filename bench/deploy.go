package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// The deploy lab (bench/truth/deploy) is an app whose API routes change
// when it is deployed. labs.sh serves it on 127.0.0.1:5040 with a
// $HOME/lab/deploy command; without that lab the bench starts its own copy.
// expected.md is the change set a v1 to v2 deploy must make `watch` report.

//go:embed truth/deploy
var deployFS embed.FS

const deployLabURL = "http://127.0.0.1:5040"

// deployLab is a deploy lab and the way to deploy a version in it.
type deployLab struct {
	base   string // http://127.0.0.1:PORT, no slash
	deploy func(version string) error
	stop   func()
}

// startDeployLab uses the lab of labs.sh when it answers and has its
// command, else serves a copy of the fixture from dir on a free port.
func startDeployLab(dir string) (*deployLab, error) {
	if cmd := filepath.Join(os.Getenv("HOME"), "lab", "deploy"); fileExists(cmd) {
		if resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(deployLabURL + "/"); err == nil {
			resp.Body.Close()
			return &deployLab{base: deployLabURL, stop: func() {},
				deploy: func(v string) error { return exec.Command(cmd, v).Run() }}, nil
		}
	}
	app := filepath.Join(dir, "deploy-app")
	if err := copyFS(deployFS, "truth/deploy", app); err != nil {
		return nil, err
	}
	state := filepath.Join(dir, "deploy.state")
	deploy := func(v string) error { return os.WriteFile(state, []byte(v+"\n"), 0o644) }
	if err := deploy("v1"); err != nil {
		return nil, err
	}
	port := freePorts(1)[0]
	p := exec.Command("python3", "-I", filepath.Join(app, "app.py"), fmt.Sprint(port), state)
	if err := p.Start(); err != nil {
		return nil, fmt.Errorf("python3 -I app.py: %v", err)
	}
	l := &deployLab{base: fmt.Sprintf("http://127.0.0.1:%d", port), deploy: deploy,
		stop: func() { _ = p.Process.Kill(); _, _ = p.Process.Wait() }}
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			return l, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.stop()
	return nil, fmt.Errorf("the deploy app did not start on port %d", port)
}

// copyFS writes the tree of fsys under root into dst.
func copyFS(fsys fs.FS, root, dst string) error {
	return fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out := filepath.Join(dst, strings.TrimPrefix(p, root))
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, raw, 0o755)
	})
}

var (
	reNewRoute = regexp.MustCompile("^- \\*\\*New route:\\*\\* `([A-Z]+) (\\S+)`, body fields (.+?)\\.?$")
	reNewVerb  = regexp.MustCompile("^- \\*\\*New method on a known route:\\*\\* `(\\S+)` gains `([A-Z]+)`")
	reNewField = regexp.MustCompile("^- \\*\\*New body field on a known route:\\*\\* `([A-Z]+) (\\S+)` gains `(\\w+)`")
	reGone     = regexp.MustCompile("^- \\*\\*Route gone from the bundle:\\*\\* `(\\S+)`")
	reTicked   = regexp.MustCompile("`(\\w+)`")
)

// expectedChanges reads expected.md into one line per change, in the form
// routeChanges gives a `watch -json` answer.
func expectedChanges(md string) []string {
	var out []string
	for _, l := range strings.Split(md, "\n") {
		l = strings.TrimSpace(l)
		if m := reNewRoute.FindStringSubmatch(l); m != nil {
			var f []string
			for _, t := range reTicked.FindAllStringSubmatch(m[3], -1) {
				f = append(f, t[1])
			}
			sort.Strings(f)
			out = append(out, fmt.Sprintf("new %s %s fields %s", m[1], m[2], strings.Join(f, ",")))
		} else if m := reNewVerb.FindStringSubmatch(l); m != nil {
			out = append(out, fmt.Sprintf("methods %s +%s", m[1], m[2]))
		} else if m := reNewField.FindStringSubmatch(l); m != nil {
			out = append(out, fmt.Sprintf("fields %s %s +%s", m[1], m[2], m[3]))
		} else if m := reGone.FindStringSubmatch(l); m != nil {
			out = append(out, "gone "+m[1])
		}
	}
	sort.Strings(out)
	return out
}

// routeChanges reads the routes of a `watch -json` answer into the lines
// expectedChanges writes; other holds what else the answer reports.
func routeChanges(raw []byte, script string) (changes, other []string, err error) {
	var o map[string]json.RawMessage
	if err = json.Unmarshal(raw, &o); err != nil {
		return nil, nil, err
	}
	var routes []struct {
		Kind    string   `json:"kind"`
		Route   string   `json:"route"`
		Method  string   `json:"method"`
		Added   []string `json:"methods_added"`
		Fields  []string `json:"fields_added"`
		Removed []string `json:"methods_removed"`
		Script  string   `json:"script"`
	}
	if r, ok := o["routes"]; ok {
		if err = json.Unmarshal(r, &routes); err != nil {
			return nil, nil, err
		}
	}
	for _, r := range routes {
		sort.Strings(r.Fields)
		switch r.Kind {
		case "new":
			changes = append(changes, fmt.Sprintf("new %s %s fields %s", strings.Join(r.Added, ","), r.Route, strings.Join(r.Fields, ",")))
		case "methods":
			changes = append(changes, fmt.Sprintf("methods %s +%s", r.Route, strings.Join(r.Added, ",")))
		case "fields":
			changes = append(changes, fmt.Sprintf("fields %s %s +%s", r.Method, r.Route, strings.Join(r.Fields, ",")))
		case "gone":
			changes = append(changes, "gone "+r.Route)
		default:
			other = append(other, "route kind "+r.Kind)
		}
		if r.Script != script {
			other = append(other, fmt.Sprintf("%s is tied to %q, not %q", r.Route, r.Script, script))
		}
	}
	sort.Strings(changes)
	for k := range o {
		if !slices.Contains([]string{"db", "run", "previous", "routes"}, k) {
			other = append(other, "reported "+k)
		}
	}
	sort.Strings(other)
	return changes, other, nil
}

// deployProblems runs watch against the lab on v1, again with no deploy,
// deploys v2 and runs it once more, and lists what is not as expected.md
// says: the unchanged run must say "no change", the deployed one report
// exactly the expected routes, each tied to the bundle that calls it. The
// lab is put back on v1.
func deployProblems(dir string, lab *deployLab, expected []string) (problems []string, detail string) {
	defer func() { _ = lab.deploy("v1") }()
	hostPort := strings.TrimPrefix(lab.base, "http://")
	db := filepath.Join(dir, "deploy-"+time.Now().Format("150405.000")+".db")
	watch := func(json bool) azResult {
		args := []string{"watch", "-db", db}
		if json {
			args = append(args, "-json")
		}
		return azExec(dir, 5*time.Minute, append(args, "--", "-url", lab.base+"/", "-allow", hostPort)...)
	}
	if err := lab.deploy("v1"); err != nil {
		return []string{"could not deploy v1: " + err.Error()}, ""
	}
	if r := watch(false); r.exit != 0 || !strings.Contains(r.stdout, "first run") {
		problems = append(problems, fmt.Sprintf("the first run exit %d, says %q", r.exit, clip(r.stdout, 80)))
	}
	if r := watch(false); r.exit != 0 || !strings.Contains(r.stdout, "no change") {
		problems = append(problems, fmt.Sprintf("with no deploy: exit %d, says %q, not \"no change\"", r.exit, clip(r.stdout, 120)))
	}
	if err := lab.deploy("v2"); err != nil {
		return append(problems, "could not deploy v2: "+err.Error()), ""
	}
	r := watch(true)
	got, other, err := routeChanges([]byte(strings.TrimSpace(r.stdout)), lab.base+"/main.js")
	if err != nil {
		return append(problems, fmt.Sprintf("after the deploy: exit %d, not JSON: %v", r.exit, err)), ""
	}
	if r.exit != 0 {
		problems = append(problems, fmt.Sprintf("after the deploy: exit %d", r.exit))
	}
	if missing, extra := diffMultiset(expected, got); len(missing)+len(extra) > 0 {
		problems = append(problems, fmt.Sprintf("the change set differs from expected.md: missing %v, extra %v", missing, extra))
	}
	if len(other) > 0 {
		problems = append(problems, fmt.Sprintf("the answer also reports: %v", other))
	}
	return problems, fmt.Sprintf("%d changes after the deploy: %s", len(got), strings.Join(got, "; "))
}

// benchDeploy is the monitoring check of the labs: watch notices a deploy.
func benchDeploy() {
	dir, _ := filepath.Abs(filepath.Join(work, "deploy"))
	must(os.MkdirAll(dir, 0o755))
	const name = "watch: a deploy that changes routes is reported as expected.md says, and no deploy is \"no change\""
	lab, err := startDeployLab(dir)
	if err != nil {
		addCheck(name, false, "no deploy lab: %v", err)
		return
	}
	defer lab.stop()
	raw, _ := deployFS.ReadFile("truth/deploy/expected.md")
	expected := expectedChanges(string(raw))
	if len(expected) != 4 {
		addCheck(name, false, "bench/truth/deploy/expected.md has %d changes the check can read, want 4", len(expected))
		return
	}
	probs, detail := deployProblems(dir, lab, expected)
	addCheck(name, len(probs) == 0, "azhaq watch -db DB -- -url %s/ -allow HOST: v1, v1 again, then v2; %s%s", lab.base, detail, listProblems(probs))
}

func listProblems(p []string) string {
	if len(p) == 0 {
		return ""
	}
	return " | " + strings.Join(p, " | ")
}
