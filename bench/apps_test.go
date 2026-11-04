package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDocker replaces the docker CLI: calls are recorded, and reply says
// what each returns. It restores the real one when the test ends.
func fakeDocker(t *testing.T, reply func(args []string) (string, error)) *[][]string {
	t.Helper()
	var calls [][]string
	old, oldWait := docker, waitEvery
	docker = func(args ...string) (string, error) {
		calls = append(calls, args)
		return reply(args)
	}
	waitEvery = 10 * time.Millisecond
	t.Cleanup(func() { docker, waitEvery = old, oldWait })
	return &calls
}

// switchApp answers 200 once on() is called and 503 before.
func switchApp(t *testing.T) (app labApp, on func()) {
	t.Helper()
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "starting", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(srv.Close)
	return labApp{name: "azq-test", url: srv.URL, flags: []string{"-p", "127.0.0.1:1:1"}, image: "img:1"}, func() { up.Store(true) }
}

func TestEnsureLabApp(t *testing.T) {
	t.Run("an app that answers is left alone", func(t *testing.T) {
		app, on := switchApp(t)
		on()
		calls := fakeDocker(t, func([]string) (string, error) { return "", errors.New("docker must not be called") })
		if err := ensureLabApp(app, time.Second); err != nil || len(*calls) != 0 {
			t.Fatalf("err %v, docker calls %v", err, *calls)
		}
	})
	t.Run("no container: it is created as labs.sh does", func(t *testing.T) {
		app, on := switchApp(t)
		calls := fakeDocker(t, func(a []string) (string, error) {
			switch a[0] {
			case "inspect":
				return "Error: No such object", errors.New("exit status 1")
			case "run":
				on()
			}
			return "", nil
		})
		if err := ensureLabApp(app, time.Second); err != nil {
			t.Fatal(err)
		}
		want := "run -d --name azq-test -p 127.0.0.1:1:1 img:1"
		if got := strings.Join((*calls)[len(*calls)-1], " "); got != want {
			t.Fatalf("docker %q, want %q", got, want)
		}
	})
	t.Run("a stopped container is started", func(t *testing.T) {
		app, on := switchApp(t)
		calls := fakeDocker(t, func(a []string) (string, error) {
			switch a[0] {
			case "inspect":
				return "false", nil
			case "start":
				on()
			}
			return "", nil
		})
		if err := ensureLabApp(app, time.Second); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join((*calls)[len(*calls)-1], " "); got != "start azq-test" {
			t.Fatalf("docker %q", got)
		}
	})
	t.Run("a running container that stays silent is restarted once", func(t *testing.T) {
		app, on := switchApp(t)
		calls := fakeDocker(t, func(a []string) (string, error) {
			switch a[0] {
			case "inspect":
				return "true", nil
			case "restart":
				on()
			}
			return "", nil
		})
		if err := ensureLabApp(app, 100*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		var verbs []string
		for _, c := range *calls {
			verbs = append(verbs, c[0])
		}
		if strings.Join(verbs, " ") != "inspect restart" {
			t.Fatalf("docker verbs %v", verbs)
		}
	})
	t.Run("a container that cannot be created is an error that says why", func(t *testing.T) {
		app, _ := switchApp(t)
		fakeDocker(t, func(a []string) (string, error) {
			if a[0] == "run" {
				return "pull access denied", errors.New("exit status 125")
			}
			return "", errors.New("exit status 1")
		})
		err := ensureLabApp(app, 50*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "pull access denied") || !strings.Contains(err.Error(), app.url) {
			t.Fatalf("err %v", err)
		}
	})
}

// A claims run with every app down records one failed check for each case
// that needs one, named as the case would name it, and does not stop.
func TestClaimsCasesSkippedWhenTheirAppIsDown(t *testing.T) {
	old := rec
	rec = record{}
	t.Cleanup(func() { rec = old })
	labs := &labSet{dead: map[string]error{}}
	for _, u := range []string{claimJuice, claimVampi, claimDVWA} {
		labs.dead[u] = errors.New(u + " not up after 3m0s")
	}
	c := &claims{row: &claimsRow{}, only: map[string]bool{}, labs: labs, dir: t.TempDir(), chrome: true}
	c.caseRun()
	c.caseBrowser()
	c.caseShots()
	c.caseDVWA()
	c.caseRoles()
	c.caseSweeps()
	c.caseMCP()
	c.caseBudget()
	c.caseKill()
	c.caseKillShots()
	c.selfCheck()
	got := map[string]string{}
	for _, ck := range rec.Checks {
		if ck.Pass {
			t.Errorf("%s passed with its app down", ck.Name)
		}
		got[ck.Name] = ck.Detail
	}
	var want []string
	for _, n := range []string{"run", "run -browser", "run -login", "run -login -browser", "roles", "roles -replay-writes put", "dirs", "fuzz", "params"} {
		for _, p := range []string{"unpaced", "rate 10", "rate 2"} {
			want = append(want, checkName(n, p))
		}
	}
	want = append(want, checkName("shots", "unpaced"), checkName("shots", "rate 2"),
		checkName("mcp budget 60", "unpaced"), checkName("mcp budget 2", "unpaced"), checkName("budget -max-requests 40", "unpaced"),
		checkName("kill switch run", "rate 10"), checkName("kill switch run", "rate 2"), checkName("kill switch shots", "rate 5"),
		"claims: the counter forwards and logs a WebSocket upgrade (Juice Shop socket.io)")
	for _, n := range want {
		d, ok := got[n]
		if !ok {
			t.Errorf("no failed check %q", n)
		} else if !strings.Contains(d, "not up after 3m0s") {
			t.Errorf("%q: detail %q does not say why", n, d)
		}
		delete(got, n)
	}
	for n := range got {
		t.Errorf("unexpected check %q", n)
	}
}

// With one app down the cases that use the others still run: a dead Juice
// Shop fails its own checks and nothing else.
func TestClaimsSkipsOnlyTheDeadApp(t *testing.T) {
	old := rec
	rec = record{}
	t.Cleanup(func() { rec = old })
	app, on := switchApp(t)
	on()
	labs := &labSet{apps: []labApp{{name: "x", url: app.url}}, wait: time.Second, dead: map[string]error{claimJuice: errors.New("down")}}
	c := &claims{row: &claimsRow{}, only: map[string]bool{}, labs: labs}
	if c.needs(claimJuice, "run", "unpaced") {
		t.Fatal("a dead app was reported up")
	}
	if !c.needs(app.url, "roles", "unpaced") {
		t.Fatal("an app that answers was reported down")
	}
	if len(rec.Checks) != 1 || rec.Checks[0].Pass || rec.Checks[0].Name != checkName("run", "unpaced") {
		t.Fatalf("checks %+v", rec.Checks)
	}
}

// bench's table of lab apps is what .github/ci/labs.sh starts, with the
// image of bench/images.env, the one list of pinned images.
func TestLabAppsMatchLabsScript(t *testing.T) {
	raw, err := os.ReadFile("../.github/ci/labs.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, a := range labApps {
		var line string
		for _, l := range strings.Split(script, "\n") {
			if strings.Contains(l, "--name "+a.name+" ") {
				line = l
			}
		}
		if line == "" {
			t.Errorf("labs.sh does not start %s", a.name)
			continue
		}
		for _, w := range append(append([]string(nil), a.flags...), a.image) {
			if !strings.Contains(line, w) {
				t.Errorf("%s: labs.sh does not have %q: %s", a.name, w, line)
			}
		}
		if port := a.url[strings.LastIndex(a.url, ":")+1:]; !strings.Contains(line, "127.0.0.1:"+port+":") {
			t.Errorf("%s: labs.sh does not publish port %s", a.name, port)
		}
	}
}

// Every image of the labs and of the bench's compose file is pinned by tag
// and digest, and is the one bench/images.env lists: three places name each
// image (labs.sh, compose.yaml and the list), and none may differ.
func TestLabImagesPinnedFromOneList(t *testing.T) {
	pin := regexp.MustCompile(`^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	images := labImages()
	if len(images) < 5 {
		t.Fatalf("images.env holds %d images: %v", len(images), images)
	}
	listed := map[string]bool{}
	for k, v := range images {
		listed[v] = true
		if !pin.MatchString(v) {
			t.Errorf("%s=%s is not pinned by tag and digest", k, v)
		}
	}
	used := map[string]bool{}
	files := map[string]string{"compose.yaml": "image: ", "../.github/ci/labs.sh": "docker run -d"}
	for file, marker := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if !strings.Contains(l, marker) || strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			f := strings.Fields(l)
			img := f[len(f)-1]
			if !listed[img] {
				t.Errorf("%s names %s, which images.env does not list: %s", file, img, l)
			}
			used[img] = true
		}
	}
	for k, v := range images {
		if !used[v] {
			t.Errorf("%s=%s is in no compose.yaml or labs.sh", k, v)
		}
	}
}

// Requests per route are compared cross-multiplied, so that no division
// rounds: azhaq is held to katana's ratio, and a tool that found nothing has
// none.
func TestPerRouteAtMost(t *testing.T) {
	for _, c := range []struct {
		az, azr, ref, refr int
		want               bool
	}{
		{29, 29, 29, 29, true},  // the same ratio
		{94, 80, 29, 25, false}, // 1.175 against 1.16
		{93, 80, 29, 25, false}, // 1.1625 against 1.16: 93*25 = 2325 > 29*80 = 2320
		{92, 80, 29, 25, true},  // 1.15 against 1.16
		{16, 12, 19, 13, true},  // 1.33 against 1.46
		{10, 0, 29, 25, false},  // azhaq found no route
		{10, 5, 0, 0, false},    // the reference found none
	} {
		if got := perRouteAtMost(c.az, c.azr, c.ref, c.refr); got != c.want {
			t.Errorf("%d requests for %d routes against %d for %d: %v, want %v", c.az, c.azr, c.ref, c.refr, got, c.want)
		}
	}
	if perRoute(0, 0) != "no route" || perRoute(29, 25) != "1.16" {
		t.Errorf("perRoute: %q, %q", perRoute(0, 0), perRoute(29, 25))
	}
}
