package browser

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// noSandboxChrome is a Chrome that exits the way one does where the system
// gives it no sandbox, unless it is started with --no-sandbox.
func noSandboxChrome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the stand-in is a shell script")
	}
	real, err := Find()
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "chrome")
	body := fmt.Sprintf(`#!/bin/sh
for a in "$@"; do
  if [ "$a" = "--no-sandbox" ]; then exec %q "$@"; fi
done
echo "[1:1:0101/000000.000000:FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox! Update your kernel or see https://chromium.googlesource.com/chromium/src/+/main/docs/linux/suid_sandbox_development.md" >&2
exit 1
`, real)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

// Where Chrome has no sandbox, it is started once more without it, and the
// browser says why.
func TestChromeWithoutSandboxRetries(t *testing.T) {
	t.Setenv("AZHAQ_CHROME_NO_SANDBOX", "")
	b := &Browser{ChromePath: noSandboxChrome(t)}
	t.Cleanup(fetch.Reset)
	if err := b.Start(); err != nil {
		t.Fatalf("Chrome did not start without its sandbox: %v", err)
	}
	defer b.Close()
	if r := b.Unsandboxed(); !strings.Contains(r, "No usable sandbox") {
		t.Errorf("reason %q, want Chrome's own line", r)
	}
}

// With the sandbox required, there is no retry: Chrome does not start.
func TestChromeRequireSandbox(t *testing.T) {
	t.Setenv("AZHAQ_CHROME_NO_SANDBOX", "")
	b := &Browser{ChromePath: noSandboxChrome(t), RequireSandbox: true}
	t.Cleanup(fetch.Reset)
	err := b.Start()
	if !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("got %v, want ErrNoSandbox", err)
	}
	if b.Unsandboxed() != "" {
		t.Errorf("Chrome was started without its sandbox: %q", b.Unsandboxed())
	}
}

// A Chrome that has its sandbox is not told to drop it.
func TestChromeWithSandboxKeepsIt(t *testing.T) {
	t.Setenv("AZHAQ_CHROME_NO_SANDBOX", "")
	b := startChrome(t)
	if r := b.Unsandboxed(); r != "" {
		t.Skipf("this system gives Chrome no sandbox: %s", r)
	}
}
