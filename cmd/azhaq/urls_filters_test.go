package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// vulnwebArchives serves OTX's answer for vulnweb.com as it was recorded
// (testdata/urls/otx-vulnweb.json: 67 URLs, 33 of them with a status) and a
// Wayback CDX answer in its shape: the filtered one when the query carries a
// filter, as the archive applies it itself.
func vulnwebArchives(t *testing.T) (flags []string, asked func() []string) {
	t.Helper()
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(testdataDir, "urls", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.URL.RequestURI())
		mu.Unlock()
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/wayback" && q.Get("page") == "0" && len(q["filter"]) > 0:
			fmt.Fprint(w, read("wayback-vulnweb-cdx-filtered.json"))
		case r.URL.Path == "/wayback" && q.Get("page") == "0":
			fmt.Fprint(w, read("wayback-vulnweb-cdx.json"))
		case r.URL.Path == "/wayback":
			w.WriteHeader(http.StatusBadRequest)
		case strings.HasPrefix(r.URL.Path, "/otx/"):
			fmt.Fprint(w, read("otx-vulnweb.json"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	for name, path := range map[string]string{"wayback": "/wayback", "otx": "/otx"} {
		flags = append(flags, "-archive", name+"="+srv.URL+path)
	}
	return flags, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(reqs) }
}

// The four commands of issue 370, against the recorded OTX answer. gau
// prints the 67 URLs of OTX with and without --mc and --ft, as OTX takes no
// filter. azhaq lists 59 (it drops junk and joins a URL written with and
// without a slash), and with -mc it judges the rows that have a status: 22
// carry one that is not 200 or 301, and the 33 with none stay. The summary
// counts both.
func TestURLsFiltersJudgeOnlyTheRowsThatHaveTheField(t *testing.T) {
	flags, _ := vulnwebArchives(t)
	base := append([]string{"-d", "vulnweb.com", "-providers", "otx", "-subs", "-urls-threads", "1", "-urls-timeout", "20s", "-urls-pause", "0", "-sort"}, flags...)
	list := func(extra ...string) ([]string, map[string]any) {
		t.Helper()
		out, _, err := urlsRun(t, append(append([]string{}, base...), append(extra, "-silent")...)...)
		if err != nil {
			t.Fatal(err)
		}
		_, errOut, err := urlsRun(t, append(append([]string{}, base...), append(extra, "-json")...)...)
		if err != nil {
			t.Fatal(err)
		}
		return out, sumMap(t, errOut)
	}
	notes := func(sum map[string]any) string { return fmt.Sprint(sum["notes"]) }

	// Command 2: no filter, nothing counted as filtered.
	plain, sum := list()
	if len(plain) != 59 {
		t.Errorf("no filters: %d URLs, want 59", len(plain))
	}
	counts, _ := sum["counts"].(map[string]any)
	for k := range counts {
		if strings.HasPrefix(k, "left out by") {
			t.Errorf("no filter, yet the summary counts %s", k)
		}
	}
	// The files gau keeps are left out as scanner probes, and counted.
	junk, _ := sum["junk"].(map[string]any)
	if junk["scanner probe"] != float64(3) || !strings.Contains(notes(sum), "3 scanner probe") {
		t.Errorf("the .exe and .xsl probes are not counted: junk %v\n%s", junk, notes(sum))
	}
	for _, u := range []string{"http://testphp.vulnweb.com/7zSo1DIz.exe", "http://testphp.vulnweb.com/NhYzAp8A.exe", "http://testphp.vulnweb.com/acunetix_xsl_inclusion_test.xsl"} {
		if slices.Contains(plain, u) {
			t.Errorf("%s is listed", u)
		}
	}

	// Command 4: the filters of the issue.
	got, sum := list("-mc", "200,301", "-ft", "text/html", "-blacklist", "png,jpg,svg")
	if len(got) != 42 {
		t.Errorf("filters: %d URLs, want 42 (59, less the blacklist and the 404 and 403 rows)", len(got))
	}
	counts, _ = sum["counts"].(map[string]any)
	if counts["left out by -mc"] != float64(22) {
		t.Errorf("counts: %v", counts)
	}
	row := sum["sources"].(map[string]any)
	if _, ok := row["urls"].(map[string]any)["otx"]; !ok {
		t.Errorf("sources: %v", row)
	}
	for _, want := range []string{
		"otx: -mc left out 22 URLs",
		"otx: 33 URLs have no recorded status, which -mc needs: they are kept, not judged",
		"otx has no type of its captures: its ",
		"not filtered by -ft",
	} {
		if !strings.Contains(notes(sum), want) {
			t.Errorf("no note %q in\n%s", want, notes(sum))
		}
	}
	// -fc names the 404s: 21 rows go, 15 of the 59 listed URLs were among them.
	got, sum = list("-fc", "404")
	if len(got) != 44 || sum["counts"].(map[string]any)["left out by -fc"] != float64(21) {
		t.Errorf("-fc 404: %d URLs, counts %v", len(got), sum["counts"])
	}
}

// Wayback applies the filters in its own query, so what it gives passed
// them and the summary says it could not count what they left out.
func TestURLsFiltersSentToWaybackAreSaidNotCounted(t *testing.T) {
	flags, asked := vulnwebArchives(t)
	args := append([]string{"-d", "testphp.vulnweb.com", "-providers", "wayback,otx", "-urls-pause", "0", "-sort", "-mc", "200,301", "-ft", "text/html", "-json"}, flags...)
	_, errOut, err := urlsRun(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	sum := sumMap(t, errOut)
	var sent bool
	for _, r := range asked() {
		if strings.HasPrefix(r, "/wayback") && strings.Contains(r, "statuscode%3A200%7C301") && strings.Contains(r, "%21mimetype%3Atext%2Fhtml") {
			sent = true
		}
	}
	if !sent {
		t.Errorf("the filters were not sent to wayback: %v", asked())
	}
	if n := sum["sources"].(map[string]any)["urls"].(map[string]any)["wayback"]; n != float64(3) {
		t.Errorf("wayback gave %v, want the 3 of its filtered answer", n)
	}
	if !strings.Contains(fmt.Sprint(sum["notes"]), "applied in the archive's own query, so the URLs they left out are not counted: wayback -mc, -ft") {
		t.Errorf("notes: %v", sum["notes"])
	}
}
