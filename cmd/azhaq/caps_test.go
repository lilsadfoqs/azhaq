package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

var capFlags = []string{"-no-paths", "-no-favicon", "-no-tech", "-sources", "none"}

// A run has no default cap on its tasks: a site with hundreds of templated
// URLs is mapped whole in one run, not stopped at a number the user never gave.
func TestRunStartsNoCapOnTasksByDefault(t *testing.T) {
	t.Chdir(t.TempDir())
	defer fetch.SetProbeToken(fetch.ProbeToken())
	fetch.SetProbeToken("p3n0thodzmue")
	srv := pageSite(t, 3, 700)
	_, rep, code := runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "w.db", "-depth", "3"}, capFlags...)...)
	if code != exitOK {
		t.Fatalf("exit %d, stopped %q, failed %+v", code, rep.Stopped, rep.Failed)
	}
	if rep.Requests < 700 {
		t.Errorf("%d requests were sent, want the 700 items and the pages", rep.Requests)
	}
}

// -max-items names itself when it stops a run, a resume given the same cap
// goes on from where the run was, and the rows end as an uncapped run's.
func TestMaxItemsStopsNamedAndResumeAtTheSameCapFinishes(t *testing.T) {
	t.Chdir(t.TempDir())
	defer fetch.SetProbeToken(fetch.ProbeToken())
	fetch.SetProbeToken("p3n0thodzmue")
	srv := pageSite(t, 6, 0)
	full, _, code := runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "full.db", "-depth", "8"}, capFlags...)...)
	if code != exitOK {
		t.Fatalf("uncapped run: exit %d", code)
	}
	_, rep, code := runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "cap.db", "-depth", "8", "-max-items", "6"}, capFlags...)...)
	if code != exitLimit || !strings.Contains(rep.Stopped, "-max-items 6 reached") {
		t.Fatalf("exit %d, stopped %q", code, rep.Stopped)
	}
	var last string
	for i := 0; code != exitOK; i++ {
		if i == 20 {
			t.Fatalf("still stopped after %d resumes: %+v", i, rep)
		}
		last, rep, code = runContract(t, "resume", "-db", "cap.db", "-max-items", "6")
		if code != exitOK && code != exitLimit {
			t.Fatalf("resume: exit %d: %+v", code, rep)
		}
	}
	if got, want := rowKeys(t, last), rowKeys(t, full); !reflect.DeepEqual(got, want) {
		t.Errorf("rows after the resumes\n%v\nrows of an uncapped run\n%v", got, want)
	}
}

// What -depth leaves unasked is named with its flag and its count, and a
// resume with a larger -depth asks it: the rows end as a deep run's.
func TestDepthCapIsNamedAndResumeWithALargerDepthAsksIt(t *testing.T) {
	t.Chdir(t.TempDir())
	defer fetch.SetProbeToken(fetch.ProbeToken())
	fetch.SetProbeToken("p3n0thodzmue")
	srv := pageSite(t, 6, 0)
	deep, _, code := runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "deep.db", "-depth", "9"}, capFlags...)...)
	if code != exitOK {
		t.Fatalf("deep run: exit %d", code)
	}
	_, rep, code := runContract(t, append([]string{"run", "-url", srv.URL + "/", "-db", "shallow.db", "-depth", "2"}, capFlags...)...)
	if code != exitOK {
		t.Fatalf("shallow run: exit %d, failed %+v", code, rep.Failed)
	}
	if n := strings.Join(rep.Notes, "\n"); !strings.Contains(n, "-depth 2: ") || !strings.Contains(n, "found past it were not asked") {
		t.Errorf("notes %q do not name -depth", rep.Notes)
	}
	out, rep, code := runContract(t, "resume", "-db", "shallow.db", "-depth", "9")
	if code != exitOK {
		t.Fatalf("resume -depth 9: exit %d: %+v", code, rep)
	}
	if got, want := rowKeys(t, out), rowKeys(t, deep); !reflect.DeepEqual(got, want) {
		t.Errorf("rows after the resume\n%v\nrows of the deep run\n%v", got, want)
	}
}
