package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/store"
)

func ingestFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Without -db ingest makes a new file in the current directory (or uses
// $AZHAQ_DB), and it prints no rows, only its summary.
func TestIngestWithoutDBMakesANewFileAndPrintsNoRows(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AZHAQ_DB", "")
	in := ingestFile(t, "urls.txt", "https://a.example.test/\nhttps://b.example.test/x\nc.example.test\n")
	out, errOut, err := captureBoth(t, func() error { return cmdIngest([]string{in}) })
	if err != nil || out != "" {
		t.Fatalf("exit %d, stdout %q (want no rows), stderr %q", exitCode(err), out, errOut)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "azhaq-*.db"))
	if len(files) != 1 || !strings.Contains(errOut, "ingest: 3 facts") || !strings.Contains(errOut, filepath.Base(files[0])) {
		t.Errorf("files %v, summary %q: want one new azhaq-TIME-PID.db named in the summary", files, errOut)
	}
	st, err := store.OpenExisting(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if ents, _ := st.Entities(); len(ents) < 3 {
		t.Errorf("the new file holds %d entities", len(ents))
	}
	// A file named by $AZHAQ_DB is the one used, not a new one.
	named := filepath.Join(dir, "named.db")
	t.Setenv("AZHAQ_DB", named)
	if _, _, err := captureBoth(t, func() error { return cmdIngest([]string{in}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(named); err != nil {
		t.Errorf("$AZHAQ_DB was not used: %v", err)
	}
	if more, _ := filepath.Glob(filepath.Join(dir, "azhaq-*.db")); len(more) != 1 {
		t.Errorf("a second azhaq-*.db was made: %v", more)
	}
}

// The lines naabu repeats fold into one row; naabu says nothing of the
// service, so the row has none.
func TestIngestNaabuLinesFoldIntoOnePortRowWithNoService(t *testing.T) {
	db := filepath.Join(t.TempDir(), "n.db")
	in := ingestFile(t, "naabu.json", strings.Repeat(`{"ip":"192.0.2.7","port":8080,"protocol":"tcp"}`+"\n", 3)+
		`{"host":"a.example.test","ip":"192.0.2.7","port":8080,"protocol":"tcp"}`+"\n"+
		`{"ip":"192.0.2.7","port":22,"protocol":"tcp"}`+"\n")
	if _, errOut, err := captureBoth(t, func() error { return cmdIngest([]string{in, "-db", db}) }); err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	out, _, code := runContract(t, "query", "-db", db, "-type", "Port")
	if code != exitOK {
		t.Fatalf("query exit %d", code)
	}
	rows := jsonRows(t, out)
	if len(rows) != 2 {
		t.Fatalf("port rows %v, want one for 8080 (its 4 lines folded) and one for 22", rows)
	}
	for _, r := range rows {
		for _, k := range []string{"service", "product", "version"} {
			if r[k] != nil && r[k] != "" {
				t.Errorf("row %v names a %s: naabu says nothing of the service", r["key"], k)
			}
		}
	}
}

// A line that cannot be read is skipped and named in a note, never a failure:
// the exit code stays 0.
func TestIngestUnreadableLineIsSkippedAndNotedNeverAFailure(t *testing.T) {
	in := ingestFile(t, "mixed.jsonl", `{"host":"a.example.test","ip":"192.0.2.1"}`+"\n"+`{"this is not":`+"\n"+`https://b.example.test/`+"\n")
	_, errOut, code := cli(t, "ingest", in, "-db", filepath.Join(t.TempDir(), "m.db"), "-json")
	rep := sumMap(t, errOut)
	notes, _ := rep["notes"].([]any)
	if code != exitOK || rep["exit"] != 0.0 || len(notes) != 1 || !strings.Contains(notes[0].(string), "not read and skipped") || rep["failures"] != 0.0 {
		t.Errorf("exit %d, summary %v", code, rep)
	}
}
