package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Nothing is sent before the plan is printed: the server holds its first
// answer until the plan's estimate has been read on stderr.
func TestQuickstartSendsNothingBeforeThePlanIsPrinted(t *testing.T) {
	planSeen := make(chan struct{})
	var once sync.Once
	var firstBeforePlan atomic.Bool
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			select {
			case <-planSeen:
			case <-time.After(10 * time.Second):
				firstBeforePlan.Store(true) // the plan was not printed in 10 s of a request waiting for it
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>t</title><body>hi</body></html>`)
	}))
	defer srv.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	was := os.Stderr
	os.Stderr = pw
	done := make(chan string)
	go func() {
		var all strings.Builder
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			all.WriteString(sc.Text() + "\n")
			if strings.Contains(sc.Text(), "estimate:") {
				once.Do(func() { close(planSeen) })
			}
		}
		done <- all.String()
	}()
	_, _, code := func() (string, string, int) {
		out, errOut, err := captureStdoutOnly(t, func() error {
			e := run([]string{"quickstart", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-depth", "0", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "q.db")})
			return e
		})
		return out, errOut, exitCode(err)
	}()
	pw.Close()
	os.Stderr = was
	errOut := <-done
	if code != exitOK || firstBeforePlan.Load() || requests.Load() == 0 || !strings.Contains(errOut, "estimate:") {
		t.Errorf("exit %d, a request waited for the plan: %v, %d requests:\n%s", code, firstBeforePlan.Load(), requests.Load(), errOut)
	}
}

func captureStdoutOnly(t *testing.T, f func() error) (string, string, error) {
	t.Helper()
	out, err := captureStdout(t, f)
	return out, "", err
}

// The summary's next ends with the commands that go on in the workspace and
// the wider passes it did not make, and nothing is run for them: the run sends
// what the explicit run sends. With -quiet or -json the plan is not printed.
func TestQuickstartNextCommandsAreNotRunAndQuietOrJSONPrintNoPlan(t *testing.T) {
	var hitsQ, hitsR atomic.Int64
	qs, rs := juiceShaped(&hitsQ), juiceShaped(&hitsR)
	defer qs.Close()
	defer rs.Close()
	dir := t.TempDir()
	common := []string{"-allow", "127.0.0.1", "-sources", "none", "-json"}
	_, errOut, code := cli(t, append([]string{"quickstart", qs.URL + "/"}, append(common, "-db", filepath.Join(dir, "q.db"))...)...)
	qsum := sumMap(t, errOut)
	_, errOut2, code2 := cli(t, append([]string{"run", "-url", rs.URL + "/"}, append(common, "-db", filepath.Join(dir, "r.db"))...)...)
	rsum := sumMap(t, errOut2)
	if code != exitOK || code2 != exitOK || qsum["requests"] != rsum["requests"] || hitsQ.Load() != hitsR.Load() {
		t.Errorf("quickstart sent %v requests (%d at the server), run %v (%d): the passes it names are not to be run", qsum["requests"], hitsQ.Load(), rsum["requests"], hitsR.Load())
	}
	var next []string
	for _, n := range qsum["next"].([]any) {
		next = append(next, n.(string))
	}
	all := strings.Join(next, "\n")
	for _, want := range []string{"azhaq hunt -db ", "azhaq query -db ", "azhaq show -db ", "-ports top-1000", "-dirs @common"} {
		if !strings.Contains(all, want) {
			t.Errorf("next lacks %q:\n%s", want, all)
		}
	}
	for _, flag := range []string{"-json", "-quiet"} {
		_, errOut, code := cli(t, "quickstart", qs.URL+"/", "-allow", "127.0.0.1", "-sources", "none", flag, "-db", filepath.Join(dir, "p"+flag+".db"))
		if code != exitOK || strings.Contains(errOut, "estimate:") || strings.Contains(errOut, "plan") {
			t.Errorf("%s: exit %d, stderr has the plan:\n%s", flag, code, errOut)
		}
	}
}
