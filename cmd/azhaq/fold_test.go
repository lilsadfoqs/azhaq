package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A single-page app as Juice Shop serves it: every path outside /rest/ and
// /api/ answers the one shell, those directories answer an unknown path with
// a 404, a script names the routes, and the page loads product images.
//
// confirmed answers for itself; shell is the routes the app has disabled or
// draws in the browser (the shell answers them); gone answers 404.
type juiceTruth struct {
	confirmed, shell, gone []string
	images                 []string
}

func juiceShop(t *testing.T) (*httptest.Server, juiceTruth) {
	t.Helper()
	truth := juiceTruth{
		confirmed: []string{"/rest/products/search", "/api/Challenges", "/rest/languages", "/rest/admin/application-version", "/ftp"},
		shell:     []string{"/about", "/contact", "/basket", "/profile", "/search", "/score-board", "/privacy-security/privacy-policy", "/deluxe-membership"},
	}
	for i := 1; i <= 12; i++ {
		truth.gone = append(truth.gone, fmt.Sprintf("/api/Feedbacks/%d", i))
	}
	truth.gone = append(truth.gone, "/rest/memories", "/rest/deluxe-membership", "/rest/chatbot/status")
	for i := 1; i <= 9; i++ {
		truth.images = append(truth.images, fmt.Sprintf("/assets/public/images/products/item%d.jpg", i))
	}
	var named []string
	for _, p := range slices.Concat(truth.confirmed, truth.shell, truth.gone) {
		named = append(named, fmt.Sprintf("'%s'", p))
	}
	js := "var routes=[" + strings.Join(named, ",") + "];\n"
	shell := `<html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root><script src="/main.js"></script>`
	for _, im := range truth.images {
		shell += `<img src="` + im + `">`
	}
	for _, g := range truth.gone {
		shell += `<a href="` + g + `">x</a>`
	}
	shell += `</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, js)
		case slices.Contains(truth.images, p):
			w.Header().Set("Content-Type", "image/jpeg")
			io.WriteString(w, "jpg")
		case p == "/rest/products/search" || p == "/rest/languages" || p == "/rest/admin/application-version" || p == "/api/Challenges":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"status":"success","data":%q}`, p)
		case p == "/ftp":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><head><title>listing: /ftp</title></head><body><ul><li>legal.md</li></ul></body></html>`)
		case strings.HasPrefix(p, "/rest/") || strings.HasPrefix(p, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"not found"}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, shell)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, truth
}

// controlComparison is the comparison made by hand: each URL asked as a user
// would, its answer set beside the answer to a path that cannot exist in
// its directory. It is the oracle the folded counts are held to.
func controlComparison(t *testing.T, srv *httptest.Server, paths []string) (same, notFound, own int) {
	t.Helper()
	get := func(p string) (int, string) {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, p := range paths {
		dir := p[:strings.LastIndex(strings.TrimSuffix(p, "/"), "/")+1]
		cs, cb := get(dir + "zq9xk3v7wq")
		st, body := get(p)
		switch {
		case st == http.StatusNotFound:
			notFound++
		case st == cs && body == cb:
			same++
		default:
			own++
		}
	}
	return same, notFound, own
}

func foldedBy(sum map[string]any) map[string]int {
	out := map[string]int{}
	raw, _ := json.Marshal(sum["folds"])
	var gs []struct {
		Class string `json:"class"`
		Count int    `json:"count"`
	}
	_ = json.Unmarshal(raw, &gs)
	for _, g := range gs {
		out[g.Class] += g.Count
	}
	return out
}

// The default crawl list holds the routes that answer for themselves, and
// the summary counts, in a line each, the answers a path that cannot exist
// gets too: the shell, the 404s. The counts are what a hand-made comparison
// with the control finds, and no confirmed route is among them.
func TestCrawlFoldsWhatTheControlProves(t *testing.T) {
	srv, truth := juiceShop(t)
	same, notFound, own := controlComparison(t, srv, slices.Concat(truth.confirmed, truth.shell, truth.gone))
	if same != len(truth.shell) || notFound != len(truth.gone) || own != len(truth.confirmed) {
		t.Fatalf("the oracle: %d same as the control, %d 404, %d own; truth says %d, %d, %d", same, notFound, own, len(truth.shell), len(truth.gone), len(truth.confirmed))
	}

	out, errOut := crawlOut(t, srv, "-silent")
	listed := map[string]bool{}
	for _, l := range lines(out) {
		listed[strings.TrimPrefix(l, srv.URL)] = true
	}
	for _, p := range truth.confirmed {
		if !listed[p] {
			t.Errorf("the default list lacks the confirmed route %s:\n%s", p, out)
		}
	}
	for _, p := range slices.Concat(truth.shell, truth.gone) {
		if listed[p] {
			t.Errorf("the default list holds %s, which the control shows is not a route", p)
		}
	}

	_, errJSON := crawlOut(t, srv, "-json")
	sum := sumMap(t, errJSON)
	counts, _ := sum["counts"].(map[string]any)
	for k := range counts {
		if strings.HasPrefix(k, "folded ") { // -json lists every row: nothing is left out of it
			t.Errorf("-json counts a fold as left out: %v", counts)
		}
	}
	folds := foldedBy(sum)
	if folds["catchall"] != same || folds["not-found"] != notFound {
		t.Errorf("-json folds %v, the control comparison finds %d same, %d 404", folds, same, notFound)
	}

	// -silent: the notes say how many rows each class holds, and the control.
	for _, want := range []string{
		fmt.Sprintf("folded catchall: %d URLs of %s answer as the control does", same, srv.URL),
		"GET /",
		"→ 200 text/html",
		`"OWASP Juice Shop"`,
		fmt.Sprintf("folded not-found: %d URLs answered 404 or 410", notFound),
		"/api/Feedbacks/{n} ×12",
		"-all-rows lists them",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the notes lack %q:\n%s", want, errOut)
		}
	}

	// -all-rows is the flat list of before: every row, the folded ones too.
	flat, _ := crawlOut(t, srv, "-silent", "-all-rows")
	got := map[string]bool{}
	for _, l := range lines(flat) {
		got[strings.TrimPrefix(l, srv.URL)] = true
	}
	for _, p := range slices.Concat(truth.confirmed, truth.shell, truth.gone) {
		if !got[p] {
			t.Errorf("-all-rows lacks %s:\n%s", p, flat)
		}
	}
	if len(got) <= len(listed)+same+notFound-1 {
		t.Errorf("-all-rows lists %d URLs, the default %d", len(got), len(listed))
	}
}

// -json lists every row, each folded one with its class, and the summary
// says how many rows each class holds. A row's class is the class of what
// the server answered: none of the confirmed routes has one.
func TestCrawlJSONMarksTheFoldOfEachRow(t *testing.T) {
	srv, truth := juiceShop(t)
	out, errOut := crawlOut(t, srv, "-json")
	fold := map[string]string{}
	for _, l := range lines(out) {
		var row struct{ URL, Fold string }
		if json.Unmarshal([]byte(l), &row) == nil && row.URL != "" {
			fold[strings.TrimPrefix(row.URL, srv.URL)] = row.Fold
		}
	}
	for _, p := range truth.confirmed {
		if f, ok := fold[p]; !ok || f != "" {
			t.Errorf("%s is a confirmed route: fold %q (listed %v)", p, f, ok)
		}
	}
	for _, p := range truth.shell {
		if fold[p] != "catchall" {
			t.Errorf("%s answers as the control does: fold %q", p, fold[p])
		}
	}
	for _, p := range truth.gone {
		if fold[p] != "not-found" {
			t.Errorf("%s answers 404: fold %q", p, fold[p])
		}
	}
	sum := sumMap(t, errOut)
	if sum["results"] != float64(len(fold)) {
		t.Errorf("results %v, rows printed %d", sum["results"], len(fold))
	}
	raw, _ := json.Marshal(sum["folds"])
	var gs []struct {
		Class    string
		Origin   string
		Count    int
		Controls []struct {
			URL    string
			Status int
			Type   string
			Title  string
		}
	}
	_ = json.Unmarshal(raw, &gs)
	var shell bool
	for _, g := range gs {
		if g.Class == "catchall" {
			shell = true
			if g.Origin != srv.URL || len(g.Controls) == 0 || g.Controls[0].Status != 200 || g.Controls[0].Title != "OWASP Juice Shop" || !strings.HasPrefix(g.Controls[0].URL, srv.URL+"/") {
				t.Errorf("the catch-all group does not say which control it matched: %s", raw)
			}
		}
	}
	if !shell {
		t.Errorf("the summary has no catch-all fold: %s", raw)
	}
}

// run's text view counts the folded rows in a line of their class each, as
// many results as lines printed; -all-rows prints one line a row, as before.
func TestRunFoldsInTheDefaultView(t *testing.T) {
	srv, truth := juiceShop(t)
	same, notFound, _ := controlComparison(t, srv, slices.Concat(truth.confirmed, truth.shell, truth.gone))
	run := func(extra ...string) (string, report) {
		t.Helper()
		args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-catchall-after", "0", "-json", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
		out, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return out, lastReport(t, errOut)
	}
	text := func(extra ...string) (string, report) {
		t.Helper()
		args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-catchall-after", "0", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
		out, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return out, report{Notes: []string{errOut}}
	}
	_, flat := run()
	out, _ := text()
	for _, p := range truth.confirmed {
		if !strings.Contains(out, srv.URL+p) {
			t.Errorf("the default view lacks the confirmed route %s:\n%s", p, out)
		}
	}
	for _, p := range slices.Concat(truth.shell, truth.gone) {
		if strings.Contains(out, "URL "+srv.URL+p+" ") {
			t.Errorf("the default view lists %s, which the control shows is not a route:\n%s", p, out)
		}
	}
	for _, want := range []string{
		fmt.Sprintf("folded catchall: %d URLs of %s answer as the control does", same, srv.URL),
		"→ 200 text/html",
		fmt.Sprintf("folded not-found: %d URLs answered 404 or 410", notFound),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the default view lacks %q:\n%s", want, out)
		}
	}
	if n := len(lines(out)); n >= flat.Results {
		t.Errorf("the default view prints %d lines, the flat list has %d rows", n, flat.Results)
	}
	all, _ := text("-all-rows")
	if strings.Contains(all, "folded catchall") {
		t.Errorf("-all-rows folds:\n%s", all)
	}
	for _, p := range slices.Concat(truth.shell, truth.gone) {
		if strings.Contains(p, "/api/Feedbacks/") {
			p = "/api/Feedbacks/{n}" // the twelve ids are one templated row, as before
		}
		if !strings.Contains(all, "URL "+srv.URL+p+" ") {
			t.Errorf("-all-rows lacks %s:\n%s", p, all)
		}
	}
}

// What the summary counts adds up in the folded view: results + folded =
// stored, with the groups' lines among the results; -json lists every row,
// and its results are the rows.
func TestRunFoldedViewAddsUp(t *testing.T) {
	srv, _ := juiceShop(t)
	args := []string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
		"-catchall-after", "0", "-quiet", "-db", filepath.Join(t.TempDir(), "w.db")}
	_, errOut, err := captureBoth(t, func() error { return cmdRun(append(args, "-json")) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	flat := lastReport(t, errOut)
	if flat.Stored == 0 || len(flat.Folds) < 2 || flat.Results+*flat.Folded != flat.Stored {
		t.Fatalf("-json: stored %d, results %d, folds %v", flat.Stored, flat.Results, flat.Folds)
	}
	_, errOut, err = captureBoth(t, func() error { return cmdRun(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	m := regexp.MustCompile(`(\d+) map rows \((\d+) stored: .*; (\d+) folded into`).FindStringSubmatch(errOut)
	if m == nil {
		t.Fatalf("no counts in the summary:\n%s", errOut)
	}
	results, stored, folded := atoi(m[1]), atoi(m[2]), atoi(m[3])
	if stored != flat.Stored || results+folded != stored || results >= flat.Results {
		t.Errorf("the folded view: %d results + %d folded, %d stored; -json: %d results of %d", results, folded, stored, flat.Results, flat.Stored)
	}
	if !strings.Contains(errOut, "folded by what the run's requests measured") {
		t.Errorf("no note says what was folded:\n%s", errOut)
	}
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// A server-rendered app as DVNA serves it: no shell, an unknown path is a 404
// page, and the sign-in gate redirects. Nothing a user can open is folded;
// the 404s are, counted as the control comparison counts them.
func TestCrawlFoldsNothingConfirmedOnDVNA(t *testing.T) {
	real := []string{"/login", "/register", "/forgotpw", "/learn", "/app/usersearch", "/app/ping", "/app/calc", "/app/products"}
	missing := []string{"/app/admin/users", "/app/bulkproducts", "/app/modifyproduct", "/app/legacy", "/old/login", "/old/register"}
	home := `<html><head><title>Damn Vulnerable NodeJS Application</title></head><body>`
	for _, p := range append(slices.Clone(real), missing...) {
		home += `<a href="` + p + `">` + p + `</a>`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch {
		case r.URL.Path == "/":
			io.WriteString(w, home+`</body></html>`)
		case slices.Contains(real, r.URL.Path):
			fmt.Fprintf(w, `<html><head><title>DVNA %s</title></head><body>%s</body></html>`, r.URL.Path, r.URL.Path)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Error</title></head><body><pre>Cannot GET %s</pre></body></html>`, r.URL.Path)
		}
	}))
	defer srv.Close()
	same, notFound, own := controlComparison(t, srv, append(slices.Clone(real), missing...))
	if same != 0 || notFound != len(missing) || own != len(real) {
		t.Fatalf("the oracle: %d, %d, %d", same, notFound, own)
	}
	out, errOut := crawlOut(t, srv, "-silent")
	listed := map[string]bool{}
	for _, l := range lines(out) {
		listed[strings.TrimPrefix(l, srv.URL)] = true
	}
	for _, p := range real {
		if !listed[p] {
			t.Errorf("the default list lacks %s:\n%s", p, out)
		}
	}
	for _, p := range missing {
		if listed[p] {
			t.Errorf("the default list holds %s, which answers 404", p)
		}
	}
	if !strings.Contains(errOut, fmt.Sprintf("folded not-found: %d URLs answered 404 or 410", len(missing))) || strings.Contains(errOut, "folded catchall") {
		t.Errorf("the notes: %s", errOut)
	}
	_, errJSON := crawlOut(t, srv, "-json")
	folds := foldedBy(sumMap(t, errJSON))
	if len(folds) != 1 || folds["not-found"] != notFound {
		t.Errorf("folds %v, the control comparison finds %d 404", folds, notFound)
	}
}

// A family of real pages that a control of the same shape matches by title,
// size and lines (an item page that prints its own path and a number that
// follows from it) is not the control's page: it is listed, not folded, and
// its rows are not counted as catch-all folds.
func TestCrawlListsATemplatedRouteThatOnlyHasTheControlsShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch p := r.URL.Path; {
		case p == "/":
			io.WriteString(w, `<html><title>home</title><a href="/catalog">catalog</a></html>`)
		case p == "/catalog":
			io.WriteString(w, `<html><title>catalog</title><body>`)
			for i := 1; i <= 12; i++ {
				fmt.Fprintf(w, `<a href="/item/%d">item</a> `, i)
			}
			io.WriteString(w, `</body></html>`)
		case strings.HasPrefix(p, "/item/"):
			fmt.Fprintf(w, "<html><title>%s</title><body><h1>Item %s</h1><p>stock: %d</p></body></html>", p, p, len(p)*7)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	out, errOut := crawlOut(t, srv, "-silent")
	for i := 1; i <= 12; i++ {
		if !strings.Contains(out, fmt.Sprintf("%s/item/%d\n", srv.URL, i)) {
			t.Errorf("the default list lacks /item/%d:\n%s", i, out)
		}
	}
	if strings.Contains(errOut, "folded catchall") {
		t.Errorf("pages of their own were folded as the control: %s", errOut)
	}
}

// A fold view is a view of the same rows: the audit that compares the summary
// with the rows it printed agrees with every one of them, for run and crawl, in
// text, -json and -all-rows, with and without -no-catchall: exit 0, complete,
// no internal error.
func TestFoldViewsPassTheSummaryAudit(t *testing.T) {
	srv, _ := juiceShop(t)
	runArgs := func(extra ...string) []string {
		return append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-catchall-after", "0", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
	}
	crawlArgs := func(extra ...string) []string {
		return append([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
	}
	for name, c := range map[string]struct {
		cmd  func([]string) error
		args []string
	}{
		"run text":                 {cmdRun, runArgs()},
		"run -all-rows":            {cmdRun, runArgs("-all-rows")},
		"run -json":                {cmdRun, runArgs("-json")},
		"run -json -all-rows":      {cmdRun, runArgs("-json", "-all-rows")},
		"run -no-catchall":         {cmdRun, runArgs("-no-catchall")},
		"run -no-catchall -json":   {cmdRun, runArgs("-no-catchall", "-json")},
		"crawl":                    {cmdCrawl, crawlArgs()},
		"crawl -all-rows":          {cmdCrawl, crawlArgs("-all-rows")},
		"crawl -json":              {cmdCrawl, crawlArgs("-json")},
		"crawl -silent":            {cmdCrawl, crawlArgs("-silent")},
		"crawl -json -all-rows":    {cmdCrawl, crawlArgs("-json", "-all-rows")},
		"crawl -no-catchall":       {cmdCrawl, crawlArgs("-no-catchall")},
		"crawl -assets -hints":     {cmdCrawl, crawlArgs("-assets", "-hints")},
		"crawl -json -no-catchall": {cmdCrawl, crawlArgs("-json", "-no-catchall")},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{}, c.args...)
			if !slices.Contains(args, "-json") {
				// the text summary says the same; ask for the JSON one beside it
				_, errOut, err := captureBoth(t, func() error { return c.cmd(args) })
				if err != nil || strings.Contains(errOut, "internal error") {
					t.Fatalf("text: %v\n%s", err, errOut)
				}
				args = append(args, "-json")
			}
			// Text view with a JSON summary is not a mode: the text rows are checked above.
			_, errOut, err := captureBoth(t, func() error { return c.cmd(args) })
			if err != nil {
				t.Fatalf("%v\n%s", err, errOut)
			}
			sum := sumMap(t, errOut)
			if sum["exit"] != float64(0) || sum["complete"] != true || sum["error"] != nil {
				t.Errorf("the summary: exit %v, complete %v, error %v", sum["exit"], sum["complete"], sum["error"])
			}
		})
	}
}
