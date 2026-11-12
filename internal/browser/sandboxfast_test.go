package browser

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// fakeRefusingChrome prints Chrome's sandbox error as the first start; the
// second one (with --no-sandbox) touches a marker file and exits. linger
// leaves a child holding Chrome's output open for 60 s, as Chrome's helper
// processes do.
func fakeRefusingChrome(t *testing.T, linger bool) (path, marker string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the stand-in is a shell script")
	}
	dir := t.TempDir()
	path, marker = filepath.Join(dir, "chrome"), filepath.Join(dir, "second")
	hold := ""
	if linger {
		hold = "sleep 60 &"
	}
	body := `#!/bin/sh
for a in "$@"; do
  if [ "$a" = "--no-sandbox" ]; then : > ` + marker + `; exit 1; fi
done
echo "[1:1:0101/000000.000000:FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox! Update your kernel" >&2
` + hold + `
exit 1
`
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, marker
}

// A sandbox refusal is read from the first Chrome's exit and its line, and
// the start without the sandbox follows within a second, not after the
// launch timeout.
func TestSandboxFallbackStartsAtOnce(t *testing.T) {
	for _, linger := range []bool{false, true} {
		t.Setenv("AZHAQ_CHROME_NO_SANDBOX", "")
		path, marker := fakeRefusingChrome(t, linger)
		b := &Browser{ChromePath: path, AllowNoSandbox: true, Timeout: 20 * time.Second}
		t.Cleanup(fetch.Reset)
		begin := time.Now()
		_ = b.Start() // the stand-in is no Chrome: the second start fails too
		fi, err := os.Stat(marker)
		if err != nil {
			t.Fatalf("linger=%v: the start without the sandbox never happened: %v", linger, err)
		}
		if d := fi.ModTime().Sub(begin); d > time.Second {
			t.Errorf("linger=%v: the fallback started after %v, want under 1 s", linger, d)
		}
		if r := b.Unsandboxed(); !strings.Contains(r, "No usable sandbox") || !strings.Contains(r, "refused start with the sandbox cost") {
			t.Errorf("linger=%v: reason %q does not give Chrome's line and what the fallback cost", linger, r)
		}
		b.Close()
	}
}

// Without the flag that allows it, a sandbox refusal ends the start at once
// too: the error is ErrNoSandbox, not a wait for the launch timeout.
func TestSandboxRefusalEndsTheStartAtOnce(t *testing.T) {
	t.Setenv("AZHAQ_CHROME_NO_SANDBOX", "")
	path, _ := fakeRefusingChrome(t, true)
	b := &Browser{ChromePath: path, Timeout: 20 * time.Second}
	t.Cleanup(fetch.Reset)
	begin := time.Now()
	err := b.Start()
	if !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("got %v, want ErrNoSandbox", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("the refusal took %v to be read", d)
	}
}
