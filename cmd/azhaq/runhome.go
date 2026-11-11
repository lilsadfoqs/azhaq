package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/runs"
)

// recordedCommands are the commands that send to targets or make a
// workspace: each run of one gets its folder under the run home. The
// others only read (query, show, report, export, diff, ledger, plan,
// hunt, gallery, ui, runs, help, docs) or serve (mcp, worker), and leave
// nothing to keep.
var recordedCommands = map[string]bool{
	"quickstart": true, "run": true, "roles": true, "resume": true, "watch": true, "ingest": true,
	"subs": true, "dns": true, "probe": true, "crawl": true, "urls": true, "ports": true,
	"dirs": true, "fuzz": true, "params": true, "asn": true, "shots": true,
}

// currentRun is the folder of the command running now, nil when it is
// not recorded or $AZHAQ_HOME is none.
var currentRun *runs.Run

// startRun makes the folder of a recorded command. When the run home
// cannot be made the run fails, before it sends
// anything, unless the person named where the workspace goes (-db, -dir
// or $AZHAQ_DB): then the run goes on, not kept in the home. It never
// falls back to another folder on its own.
func startRun(name string, args []string) error {
	currentRun = nil
	if !recordedCommands[name] || asksHelp(args) {
		return nil
	}
	home, ok := runs.Home()
	if !ok {
		return nil
	}
	r, err := runs.Start(home, name, args, version)
	if err != nil {
		if namesWorkspace(args) {
			fmt.Fprintf(os.Stderr, "azhaq: the run is not kept in %s: %v (AZHAQ_HOME=none turns keeping off)\n", runs.Dir(home), err)
			return nil
		}
		return fmt.Errorf("cannot keep the run in %s: %v; nothing was sent. Give -db DIR/x.db to keep the workspace in a folder you can write, "+
			"or set AZHAQ_HOME=DIR to keep runs there (AZHAQ_HOME=none keeps none)", runs.Dir(home), err)
	}
	currentRun = r
	return nil
}

// namesWorkspace says the arguments, or $AZHAQ_DB, say where the workspace goes.
func namesWorkspace(args []string) bool {
	if os.Getenv("AZHAQ_DB") != "" {
		return true
	}
	for _, a := range args {
		if a == "--" {
			break
		}
		a = strings.TrimLeft(a, "-")
		if a == "db" || a == "dir" || strings.HasPrefix(a, "db=") || strings.HasPrefix(a, "dir=") {
			return true
		}
	}
	return false
}

// noLastText is why a command without -db found no workspace to read.
func noLastText() string {
	if h, ok := runs.Home(); ok {
		return fmt.Sprintf("no run was kept in this folder (%s); run one here first, or set AZHAQ_HOME to the run home that holds it", runs.Dir(h))
	}
	return fmt.Sprintf("no %s in this folder (AZHAQ_HOME=none keeps no run home)", lastDBFile)
}

// endRun records how the command ended. A command refused for its usage
// sent nothing and made nothing: its folder goes.
func endRun(args []string, err error) {
	r := currentRun
	currentRun = nil
	if r == nil {
		return
	}
	code := exitCode(err)
	if code == exitUsage && !hasWorkspace(r) {
		_ = r.Discard()
		return
	}
	text := ""
	if err != nil {
		text = err.Error()
	}
	_ = r.Finish(code, text)
	if stderrIsTerminal() && !wantsJSON(args) && !slices.Contains(args, "-quiet") && !slices.Contains(args, "-silent") {
		fmt.Fprintf(os.Stderr, "azhaq: kept in %s (azhaq ui shows it)\n", r.Dir)
	}
}

func hasWorkspace(r *runs.Run) bool {
	if r.Record().Workspace != "" {
		return true
	}
	_, err := os.Stat(filepath.Join(r.Dir, runs.WorkspaceFile))
	return err == nil
}

// recordSummary hands a command's summary to its run folder.
func recordSummary(rep *report) {
	if currentRun == nil {
		return
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		return
	}
	currentRun.SetSummary(raw, rep.DB, rep.Wrote)
}

// runFolderDB is the workspace a recorded command keeps when the person
// names none, "" when the command is not recorded.
func runFolderDB() string {
	if currentRun == nil {
		return ""
	}
	return filepath.Join(currentRun.Dir, runs.WorkspaceFile)
}

// runFolderPath is name inside the run folder, "" when not recorded.
func runFolderPath(name string) string {
	if currentRun == nil {
		return ""
	}
	return filepath.Join(currentRun.Dir, name)
}

func asksHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		switch a {
		case "-h", "-help", "--help":
			return true
		}
	}
	return false
}

// lastDBPath is where the last run's workspace is recorded: in the run
// home when runs are kept, else .azhaq-last in the current directory.
func lastDBPath() string {
	if h, ok := runs.Home(); ok {
		return filepath.Join(h, "last")
	}
	return lastDBFile
}

// runIndexPath is the index of workspaces by input, for the diff with the
// previous run of the same input: in the run home when runs are kept.
func runIndexPath() string {
	if h, ok := runs.Home(); ok {
		return filepath.Join(h, "index.json")
	}
	return runIndexFile
}

// writeHomeFile writes a file of the run home (mode 0600, the home 0700)
// or of the current directory.
func writeHomeFile(path string, raw []byte) error {
	mode := os.FileMode(0o644)
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		mode = 0o600
	}
	return os.WriteFile(path, raw, mode)
}
