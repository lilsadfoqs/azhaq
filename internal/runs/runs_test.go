package runs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMaskHidesSecrets(t *testing.T) {
	in := []string{"-url", "https://me:hunter2@app.test/", "-login-pass", "hunter2", "-H", "Authorization: Bearer abc",
		"-header=Cookie: s=1", "-role", "user=Authorization: Bearer xyz", "-token=t0k", "-H", "Accept: x", "-no-cookies", "-rate", "5"}
	out := strings.Join(Mask(in), " ")
	for _, secret := range []string{"hunter2", "Bearer abc", "s=1", "xyz", "t0k"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q still shows %q", out, secret)
		}
	}
	for _, kept := range []string{"Accept: x", "-no-cookies", "-rate 5", "app.test", "Authorization:"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q lost %q", out, kept)
		}
	}
}

func TestMaskJSON(t *testing.T) {
	out := string(MaskJSON([]byte(`{"headers":{"set-cookie":"sid=1","server":"nginx"},"auth":true,"lines":["Authorization: Bearer q"]}`)))
	if strings.Contains(out, "sid=1") || strings.Contains(out, "Bearer q") || !strings.Contains(out, "nginx") || !strings.Contains(out, `"auth":true`) {
		t.Fatal(out)
	}
}

func TestTargetAndSlug(t *testing.T) {
	cases := map[string][]string{
		"https://App.Example.com/x": {"-rate", "5", "-url", "https://App.Example.com/x"},
		"example.com":               {"example.com", "-passive"},
		"10.0.0.0/24":               {"-cidr=10.0.0.0/24"},
	}
	for want, args := range cases {
		if got := TargetOf(args); got != want {
			t.Errorf("TargetOf(%v) = %q", args, got)
		}
	}
	if s := Slug("https://App.Example.com:8443/x?y"); s != "app.example.com" {
		t.Errorf("slug %q", s)
	}
	if s := Slug("../../etc/passwd"); strings.Contains(s, "/") || strings.Contains(s, "..") {
		t.Errorf("slug %q", s)
	}
}

func TestStartFinishListRemove(t *testing.T) {
	home := t.TempDir()
	a, err := Start(home, "run", []string{"-url", "https://a.test/"}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Start(home, "run", []string{"-url", "https://a.test/"}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Dir == b.Dir {
		t.Fatal("two runs in one folder")
	}
	a.SetSummary([]byte(`{"requests":3}`), "", []string{"out.txt"})
	if err := a.Finish(0, ""); err != nil {
		t.Fatal(err)
	}
	list, err := List(home)
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %v", list, err)
	}
	got, _ := Load(home, filepath.Base(a.Dir))
	if got.Status != StatusDone || got.Exit == nil || !strings.Contains(string(got.Summary), `"requests": 3`) || !filepath.IsAbs(got.Wrote[0]) {
		t.Fatalf("%+v", got)
	}
	if fi, _ := os.Stat(filepath.Join(a.Dir, recordFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("run.json mode %v", fi.Mode())
	}
	if !Alive(Record{Pid: os.Getpid()}) {
		t.Fatal("this process is not alive")
	}
	if err := Remove(home, "../"+filepath.Base(home)); err == nil {
		t.Fatal("removed outside the home")
	}
	if err := os.Mkdir(filepath.Join(Dir(home), "notarun"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Remove(home, "notarun"); err == nil {
		t.Fatal("removed a folder with no run.json")
	}
	old, _ := Older(home, time.Now().Add(time.Hour))
	if len(old) != 2 {
		t.Fatalf("older %v", old)
	}
}

func TestHomeOff(t *testing.T) {
	t.Setenv("AZHAQ_HOME", "none")
	if _, ok := Home(); ok {
		t.Fatal("AZHAQ_HOME=none still keeps runs")
	}
	t.Setenv("AZHAQ_HOME", "rel/home")
	if h, ok := Home(); !ok || !filepath.IsAbs(h) {
		t.Fatalf("%q %v", h, ok)
	}
}

func TestHomeDefaultsToTheWorkingDirectory(t *testing.T) {
	t.Setenv("AZHAQ_HOME", "")
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	t.Chdir(dir)
	h, ok := Home()
	if !ok || h != filepath.Join(dir, ".azhaq") {
		t.Fatalf("%q %v, want %s", h, ok, filepath.Join(dir, ".azhaq"))
	}
}

// A run discarded leaves no folder that Start made for it, and keeps a home
// that was there before.
func TestDiscardRemovesTheFoldersItMade(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, ".azhaq")
	r, err := Start(home, "run", []string{"-url", "http://a.test/"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("the home Start made is left: %v", err)
	}
	if err := os.MkdirAll(Dir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	r, err = Start(home, "run", nil, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(Dir(home)); err != nil {
		t.Fatalf("a home that was there before went: %v", err)
	}
}
