package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// probe counts a row for each input and path it printed: two ports and two
// paths, one path a 404, are four rows, all four answered, so `answered`
// and `without an answer` add up to the summary's `results`.
func TestProbeCountsEveryRowOfAPortAndPathMatrix(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone.php" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("<title>ok</title>"))
	})
	a, b := httptest.NewServer(h), httptest.NewServer(h)
	defer a.Close()
	defer b.Close()
	port := func(s *httptest.Server) string {
		_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
		return p
	}
	out, errOut, code := cli(t, "probe", "-u", "127.0.0.1", "-p", port(a)+","+port(b), "-path", "/,/gone.php", "-sc", "-json", "-ledger", "off")
	rep := sumMap(t, errOut)
	rows := strings.Count(strings.TrimSpace(out), "\n") + 1
	counts, _ := rep["counts"].(map[string]any)
	answered, _ := counts["answered"].(float64)
	none, _ := counts["without an answer"].(float64)
	if rows != 4 || rep["results"] != float64(4) || int(answered)+int(none) != 4 || answered != 4 {
		t.Errorf("exit %d: %d rows, results %v, counts %v; stdout:\n%s", code, rows, rep["results"], counts, out)
	}
	if strings.Count(out, `"status_code":404`) != 2 || strings.Count(out, `"status_code":200`) != 2 {
		t.Errorf("rows %s", out)
	}
}
