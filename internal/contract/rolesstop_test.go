package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The kill file of azhaq roles, roles.stop in its -dir, stops the runs of the
// roles and the history reads and replay after them: one created while the
// history is read ends it, and roles exits 4.
func TestRolesKillFileStopsTheReplayToo(t *testing.T) {
	l := newLabs(t)
	var entries [][2]string
	for i := 1; i <= 10; i++ {
		entries = append(entries, [2]string{"GET", fmt.Sprintf("/api/v1/h%d", i)})
	}
	h := l.File("alice.har", har(l.Site, entries...))
	kill := filepath.Join(l.Dir, "rd", "roles.stop")
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() { // the first history read is the signal
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			for k := range l.Site.Wire.HTTP() {
				if strings.Contains(k, "/api/v1/h") {
					_ = os.MkdirAll(filepath.Dir(kill), 0o755)
					_ = os.WriteFile(kill, nil, 0o644)
					return
				}
			}
		}
	}()
	r := RunRaw(t, l.Dir, nil, "roles", "-role", "anon", "-har", "alice="+h, "-replay", "-rate", "5", "-dir", "rd", "-json", "--", "-url", l.Site.URL, "-allow", l.Allow(), "-depth", "0", "-no-paths")
	if r.Code != 4 || !strings.Contains(r.Summary.Stopped, "the kill switch") {
		t.Errorf("exit %d, stopped %q: want 4 and the kill switch\n%s", r.Code, r.Summary.Stopped, r.Stderr)
	}
	reads := 0
	for k := range l.Site.Wire.HTTP() {
		if strings.Contains(k, "/api/v1/h") {
			reads++
		}
	}
	if reads == 0 || reads >= 10 {
		t.Errorf("the history was read %d times of 10: the kill file made while it was read did not stop it", reads)
	}
}
