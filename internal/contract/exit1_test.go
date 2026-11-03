package contract

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Exit 1 is a command that could not do its job, not a finding and not a
// usage error: a database it cannot open, or Chrome missing for -browser.
func TestExitOneIsACommandThatCouldNotDoItsJob(t *testing.T) {
	l := newLabs(t)
	r := RunRaw(t, l.Dir, nil, "query", "-db", filepath.Join(l.Dir, "no", "such", "dir", "w.db"), "-json")
	if r.Code != 1 {
		t.Errorf("a database that cannot be opened: exit %d, want 1\n%s", r.Code, r.Stderr)
	}
	r = RunRaw(t, l.Dir, Env{"AZHAQ_CHROME=" + filepath.Join(l.Dir, "no-chrome"), "AZHAQ_CHROME_NO_SANDBOX="}, "crawl", "-u", l.Site.URL, "-browser", "-json")
	if r.Code != 1 {
		t.Errorf("Chrome missing for -browser: exit %d, want 1\n%s", r.Code, r.Stderr)
	}
	if n := l.Site.Wire.Total(); n != 0 {
		t.Errorf("%d requests were sent before Chrome was found missing", n)
	}
}

// A server ends with a signal and exits 0: watch -every waits for its next
// run, and Ctrl-C ends it with the summary of the run before.
func TestWatchEveryEndsOnASignalWithExit0(t *testing.T) {
	l := newLabs(t)
	cmd := exec.Command(binPath, "watch", "-db", "w.db", "-every", "1h", "-json", "--", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none")
	cmd.Dir = l.Dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + l.Dir, "AZHAQ_DATA_DIR=" + filepath.Join(l.Dir, "data")}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(t, cmd.Start())
	for i := 0; l.Site.Wire.Total() == 0; i++ {
		if i > 400 {
			_ = cmd.Process.Kill()
			t.Fatalf("watch sent nothing:\n%s", stderr.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond) // the first run ends and watch waits for the next
	must(t, cmd.Process.Signal(syscall.SIGINT))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("watch did not end on SIGINT:\n%s", stderr.String())
	}
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		t.Errorf("exit %d, want 0\n%s", code, stderr.String())
	}
}
