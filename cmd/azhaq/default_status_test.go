package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A moved route answered 308 is matched by default, as 301 and 307 are, by
// every command that sweeps with the default matcher; 304 and the others
// ffuf leaves out stay out.
func TestDefaultMatchCodesIncludeTheRedirects(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/moved": 308, "/old": 301, "/temp": 307, "/same": 304})
	words := wlist(t, "moved", "old", "temp", "same", "nothing")
	for _, c := range []struct {
		name string
		run  func() (string, error)
	}{
		{"dirs", func() (string, error) {
			out, _, err := captureBoth(t, func() error {
				return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-silent", "-ledger", "off"})
			})
			return out, err
		}},
		{"run -dirs", func() (string, error) {
			out, _, err := captureBoth(t, func() error {
				return run([]string{"run", "-url", srv.URL + "/", "-dirs", words, "-sources", "none", "-no-paths", "-db", filepath.Join(t.TempDir(), "r.db"), "-json", "-ledger", "off"})
			})
			return out, err
		}},
		{"fuzz", func() (string, error) {
			rows, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", words, "-ledger", "off")
			return strings.Join(rows, "\n"), err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := c.run()
			if err != nil {
				t.Logf("%v", err)
			}
			for _, p := range []string{"/moved", "/old", "/temp"} {
				if !strings.Contains(out, p) {
					t.Errorf("%s is not listed:\n%s", p, out)
				}
			}
			if strings.Contains(out, "/same") || strings.Contains(out, "/nothing") {
				t.Errorf("a 304 or a 404 is listed:\n%s", out)
			}
		})
	}
}
