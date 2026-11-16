package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// `hunt -db` and `query -db`, run as commands from a second shell, read the
// rows a run has committed while it still holds a batch open, and the writer
// is not held up.
func TestHuntAndQueryCommandsReadAWorkspaceARunIsStillWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BeginRun("r1", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRunArgs([]string{"-host", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	ent, err := st.UpsertEntity(types.TypeHostname, "127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	add := func(port int) {
		raw, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "ip": "127.0.0.1",
			"services": []map[string]any{{"port": port, "service": "redis", "product": "Redis", "version": "7.2.0"}}})
		if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw, ObservedAt: time.Now()}); err != nil {
			t.Error(err)
		}
	}
	add(20001) // committed: the run is still going and has more to write
	var hunted, queried, after string
	var wrote time.Duration
	st.Batch(func() {
		t0 := time.Now()
		add(20002)
		wrote = time.Since(t0)
		hunted, _, _ = cli(t, "hunt", "-db", path, "-json")
		queried, _, _ = cli(t, "query", "-db", path, "-json")
	})
	after, _, _ = cli(t, "hunt", "-db", path, "-json")
	if !strings.Contains(hunted, "127.0.0.1:20001") {
		t.Errorf("hunt did not list the committed listener while the run held a batch open:\n%s", hunted)
	}
	if !strings.Contains(queried, "127.0.0.1") {
		t.Errorf("query did not list the workspace a run is still writing:\n%s", queried)
	}
	if wrote > 5*time.Second {
		t.Errorf("the run's write took %s: a reader held it up", wrote)
	}
	if !strings.Contains(after, "127.0.0.1:20002") {
		t.Errorf("the row the run committed after is not listed:\n%s", after)
	}
}

// Where a user looks first says how to read a run that is still going.
func TestHelpAndPagesSayHowToReadARunThatIsStillGoing(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		want []string
	}{
		{"help hunt", []string{"help", "hunt"}, []string{"reads a workspace a run is still writing"}},
		{"run -h", []string{"run", "-h"}, []string{"-stream prints a found line as each listener is named", "azhaq hunt -db FILE from a second shell lists the rows stored so far"}},
	} {
		out, errOut, _ := cli(t, c.args...)
		for _, w := range c.want {
			if !strings.Contains(out+errOut, w) {
				t.Errorf("%s lacks %q", c.name, w)
			}
		}
	}
	for page, want := range map[string]string{
		"../../docs/START.md":         "azhaq hunt -db app.db",
		"../../docs/commands/run.md":  "azhaq hunt -db WORKSPACE",
		"../../docs/commands/hunt.md": "reads a workspace a `run` is still writing",
	} {
		raw, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s does not say %q", page, want)
		}
	}
}
