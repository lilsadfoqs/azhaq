package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var binPath string

// TestMain builds the binary once; AZHAQ_BIN names one to use instead.
func TestMain(m *testing.M) {
	code := func() int {
		if binPath = os.Getenv("AZHAQ_BIN"); binPath != "" {
			return m.Run()
		}
		dir, err := os.MkdirTemp("", "azhaq-contract-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		binPath = filepath.Join(dir, "azhaq")
		build := exec.Command("go", "build", "-o", binPath, "./cmd/azhaq")
		build.Dir = moduleRoot()
		if out, err := build.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "building azhaq: %v\n%s", err, out)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

// moduleRoot is the directory of go.mod above the tests.
func moduleRoot() string {
	dir, _ := os.Getwd()
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if d == filepath.Dir(d) {
			return dir
		}
	}
}

// Summary is the JSON summary a command prints on stderr under -json: the
// fields the invariants read.
type Summary struct {
	Command     string         `json:"command"`
	Complete    bool           `json:"complete"`
	Exit        int            `json:"exit"`
	Results     int            `json:"results"`
	LeftOut     int            `json:"left_out"`
	Stored      int            `json:"stored"`
	Folded      *int           `json:"folded"` // run: stored rows a printed row holds; nil when the summary has no such field
	Counts      map[string]int `json:"counts"`
	Requests    int64          `json:"requests"`
	DNSQueries  int64          `json:"dns_queries"`
	Unreachable []string       `json:"unreachable"`
	Failed      []struct {
		Collector string `json:"collector"`
		Source    string `json:"source"`
		Error     string `json:"error"`
		Partial   bool   `json:"partial"`
		Fanout    bool   `json:"fanout"`
	} `json:"failed"`
	Skipped []struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	} `json:"skipped"`
	Degraded bool     `json:"degraded"`
	Stopped  string   `json:"stopped"`
	Resume   string   `json:"resume"`
	Notes    []string `json:"notes"`
}

// Result is one finished run of the binary.
type Result struct {
	Args    []string
	Stdout  string
	Stderr  string
	Code    int
	Summary Summary
	Has     bool // the stderr had a summary
	Dir     string
}

// Rows are the JSON objects of stdout, one per line.
func (r Result) Rows(t testing.TB) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(r.Stdout, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%s: stdout line is not JSON: %q", strings.Join(r.Args, " "), l)
		}
		out = append(out, m)
	}
	return out
}

// Env are the extra variables of a run.
type Env []string

// Run runs the binary with args in dir (a new one when empty), with its own
// data directory, and fails the test when the run printed no summary.
func Run(t testing.TB, dir string, args ...string) Result {
	t.Helper()
	r := RunRaw(t, dir, nil, args...)
	if !r.Has {
		t.Fatalf("%s: no summary on stderr (exit %d)\n%s", strings.Join(args, " "), r.Code, r.Stderr)
	}
	return r
}

// RunRaw is Run without the summary check, and with extra environment.
func RunRaw(t testing.TB, dir string, env Env, args ...string) Result {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = dir
	// No proxy, config or history of the machine leaks in.
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"AZHAQ_DATA_DIR=" + filepath.Join(dir, "data"),
		"AZHAQ_NO_HINTS=1",
	}, env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("running azhaq %s: %v", strings.Join(args, " "), err)
		}
		code = ee.ExitCode()
	}
	res := Result{Args: args, Stdout: so.String(), Stderr: se.String(), Code: code, Dir: dir}
	res.Summary, res.Has = lastSummary(res.Stderr)
	return res
}

func lastSummary(stderr string) (s Summary, ok bool) {
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "{") || !strings.Contains(l, `"type":"summary"`) {
			continue
		}
		var x Summary
		if json.Unmarshal([]byte(l), &x) == nil {
			s, ok = x, true
		}
	}
	return s, ok
}
