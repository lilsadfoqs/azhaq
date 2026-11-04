package main

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// shotsRow compares screenshots with gowitness on the same targets and
// the same Chrome: the five local apps and three pages the bench serves
// (a login page, a default web server page, an admin page).
type shotsRow struct {
	Profile       string  `json:"profile,omitempty"`
	Targets       int     `json:"targets"`
	Azhaq         int     `json:"azhaq"`
	Gowitness     int     `json:"gowitness"`
	AzhaqOK       int     `json:"azhaq_confirmed"` // files that decode and are not one colour
	GowitnessOK   int     `json:"gowitness_confirmed"`
	AzhaqSeconds  float64 `json:"azhaq_seconds"`
	GowitnessSecs float64 `json:"gowitness_seconds"`
	memPair
	Unpaced bool `json:"gowitness_unpaced,omitempty"` // polite: gowitness has no rate option, so the times are not compared
	// Requests the targets received from each tool, the median of its runs.
	AzhaqRequests     int `json:"azhaq_requests,omitempty"`
	GowitnessRequests int `json:"gowitness_requests,omitempty"`
}

// shotFronts puts a counting reverse proxy in front of each page: both tools
// are given the proxy's address, so what it receives is every request the
// page's server would have got from the tool, Chrome's own included. A forward
// proxy given to Chrome would not do: Chrome sends loopback pages around it.
type shotFronts struct {
	total atomic.Int64
	marks map[string][]int64 // tool → the total when each of its runs began, and when the last ended
	stops []func()
}

// front is the address of a counting proxy for target, which keeps its path.
func (f *shotFronts) front(target string) string {
	u, err := url.Parse(target)
	must(err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	up := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: u.Scheme, Host: u.Host})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.total.Add(1)
		up.ServeHTTP(w, r)
	})}
	go srv.Serve(ln)
	f.stops = append(f.stops, func() { _ = srv.Close() })
	u.Host = ln.Addr().String()
	return u.String()
}

// begin notes that a run of tool starts; end that its last run is over.
func (f *shotFronts) begin(tool string) {
	if f.marks == nil {
		f.marks = map[string][]int64{}
	}
	f.marks[tool] = append(f.marks[tool], f.total.Load())
}

func (f *shotFronts) end(tool string) { f.begin(tool) }

// median is the requests of a run of tool, the middle of its runs.
func (f *shotFronts) median(tool string) int {
	var per []float64
	m := f.marks[tool]
	for i := 1; i < len(m); i++ {
		per = append(per, float64(m[i]-m[i-1]))
	}
	return int(median(per))
}

func (f *shotFronts) close() {
	for _, stop := range f.stops {
		stop()
	}
}

// shotPages serves three pages with content a blank screenshot would lack.
func shotPages() (base string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	page := func(title, body string) string {
		return `<html><head><title>` + title + `</title><style>body{font-family:sans-serif;margin:40px}.box{background:#246;color:#fff;padding:20px;width:300px}</style></head><body>` + body + `</body></html>`
	}
	pages := map[string]string{
		"/login": page("Sign in", `<div class="box"><h1>Sign in</h1><form><input name=user><input type=password name=pw><button>Log in</button></form></div>`),
		"/nginx": page("Welcome to nginx!", `<h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p>`),
		"/admin": page("Admin", `<div class="box"><h1>Admin</h1></div><table border=1><tr><td>users</td><td>12</td></tr><tr><td>orders</td><td>345</td></tr></table>`),
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := pages[r.URL.Path]; ok {
			fmt.Fprint(w, p)
			return
		}
		http.NotFound(w, r)
	})}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String(), func() { _ = srv.Close() }
}

func benchShots() *shotsRow {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		if chrome, err = exec.LookPath("chromium"); err != nil {
			logf("screenshots: no Chrome, skipped")
			addCheck("screenshots: Chrome is installed", false, "neither google-chrome nor chromium is in PATH")
			return nil
		}
	}
	// The lab apps it pictures are brought up first, as claims does.
	newLabSet().start("http://127.0.0.1:3001", "http://127.0.0.1:5002", "http://127.0.0.1:5013", "http://127.0.0.1:5020", "http://127.0.0.1:5030")
	base, stop := shotPages()
	defer stop()
	targets := []string{juiceURL, vampiURL, "http://127.0.0.1:5013/", "http://127.0.0.1:5020/", "http://127.0.0.1:5030/", base + "/login", base + "/nginx", base + "/admin"}
	if polite() {
		// At 5 requests per second the eight pages took over seven minutes a tool.
		targets = []string{juiceURL, base + "/login", base + "/nginx", base + "/admin"}
	}
	// The pages are asked through counting proxies, the same for both tools.
	fronts := &shotFronts{}
	defer fronts.close()
	for i, t := range targets {
		targets[i] = fronts.front(t)
	}
	dir, _ := filepath.Abs(filepath.Join(work, "shots-"+time.Now().Format("150405")+"-"+prof))
	must(os.MkdirAll(dir, 0o755))
	list := filepath.Join(dir, "targets.txt")
	must(os.WriteFile(list, []byte(strings.Join(targets, "\n")+"\n"), 0o644))
	row := &shotsRow{Profile: prof, Targets: len(targets)}

	azArgs := func(i int) []string {
		fronts.begin("azhaq")
		a := []string{"shots", "-l", list, "-dir", filepath.Join(dir, fmt.Sprintf("azhaq%d", i)), "-silent", "-chrome-no-sandbox"}
		return append(a, pick([]string(nil), []string{"-rate", politeHTTP})...)
	}
	// gowitness has no rate option, so it runs with its defaults in both
	// profiles (with -t 1 it shoots the first page and times out on the rest).
	gwArgs := func(i int) []string {
		fronts.begin("gowitness")
		return []string{"scan", "file", "-f", list, "--chrome-path", chrome, "-s", filepath.Join(dir, fmt.Sprintf("gowitness%d", i)), "-q"}
	}
	out, m := timedArgs("shots", 20*time.Minute, dir, azhaq, azArgs)
	fronts.end("azhaq")
	row.Azhaq, row.AzhaqSeconds = len(lines(out)), m.Seconds
	row.AzhaqOK = countShots(filepath.Join(dir, "azhaq0"))
	_, gm := timedArgs("shots", 20*time.Minute, dir, ref("gowitness"), gwArgs)
	fronts.end("gowitness")
	row.GowitnessSecs = gm.Seconds
	row.AzhaqRequests, row.GowitnessRequests = fronts.median("azhaq"), fronts.median("gowitness")
	row.set(m, gm)
	row.GowitnessOK = countShots(filepath.Join(dir, "gowitness0"))
	row.Gowitness = row.GowitnessOK
	if files, _ := os.ReadDir(filepath.Join(dir, "gowitness0")); len(files) > 0 {
		row.Gowitness = len(files)
	}
	cmds := cmdLine(azhaq, azArgs(0)...) + " vs " + cmdLine("gowitness", gwArgs(0)...)
	note := fmt.Sprintf("%s; %d targets; azhaq listed %d, gowitness wrote %d files; %s%s", share(row.AzhaqOK, row.GowitnessOK), row.Targets, row.Azhaq, row.Gowitness, ratios(row.AzhaqSeconds, row.GowitnessSecs, row.memPair), azErr(m))
	cost := shotCost(row, cmds)
	if polite() {
		// gowitness cannot be paced: its time at full speed is no polite reference.
		cost()
		addCheck("screenshots: results ≥ the reference's, confirmed by the image files: each decodes and is not one colour", row.AzhaqOK >= row.GowitnessOK,
			"azhaq %d, reference %d; %s | %s", row.AzhaqOK, row.GowitnessOK, note, cmds)
		row.Unpaced = true
		return row
	}
	cost()
	barOne("screenshots", row.AzhaqOK, row.GowitnessOK, row.AzhaqSeconds, row.GowitnessSecs, "the image files: each decodes and is not one colour", cmds, note)
	return row
}

// shotCostBar is how many times the reference's requests azhaq may send for
// the same pictures. The time bar of barOne is tighter.
const shotCostBar = 1.25

// shotCost is the check that azhaq asks the pages for at most shotCostBar
// times what gowitness does. It is run once the row is filled.
func shotCost(row *shotsRow, cmds string) func() {
	return func() {
		name := fmt.Sprintf("screenshots: requests to the targets ≤ %.2f× the reference's", shotCostBar)
		if why, gone := refGone[vsTool(cmds)]; gone {
			addCheck(name, false, "the reference did not run: %s | %s", why, cmds)
			return
		}
		ok := row.GowitnessRequests > 0 && float64(row.AzhaqRequests) <= shotCostBar*float64(row.GowitnessRequests)
		addCheck(name, ok, "azhaq %d, reference %d (what the targets received, the median of the runs; each page asked through a counting proxy) | %s",
			row.AzhaqRequests, row.GowitnessRequests, cmds)
	}
}

// countShots counts the image files in dir that decode and hold more than
// one colour: a screenshot of a blank page is not a result.
func countShots(dir string) int {
	n := 0
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		fh, err := os.Open(filepath.Join(dir, f.Name()))
		if err != nil {
			continue
		}
		img, _, err := image.Decode(fh)
		fh.Close()
		if err != nil {
			continue
		}
		b := img.Bounds()
		seen := map[uint32]bool{}
		for y := b.Min.Y; y < b.Max.Y && len(seen) < 2; y += max(1, b.Dy()/40) {
			for x := b.Min.X; x < b.Max.X && len(seen) < 2; x += max(1, b.Dx()/40) {
				r, g, bl, _ := img.At(x, y).RGBA()
				seen[(r>>11)<<10|(g>>11)<<5|bl>>11] = true
			}
		}
		if len(seen) > 1 {
			n++
		}
	}
	return n
}
