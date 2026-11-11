package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// cutWayback serves a Wayback Machine that gives its first page and then
// fails (how: "504" or "cut", a connection closed mid-answer), beside an OTX
// that answers. With bad set, Wayback fails at once instead.
func cutWayback(t *testing.T, how string, bad bool) []string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wayback" && !bad && r.URL.Query().Get("page") == "0":
			fmt.Fprint(w, `[["original"],["http://example.org/w1"],["http://example.org/w2"]]`)
		case r.URL.Path == "/wayback" && how == "cut":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
		case r.URL.Path == "/wayback":
			http.Error(w, "Gateway Time-out", http.StatusGatewayTimeout)
		case strings.HasPrefix(r.URL.Path, "/otx/"):
			fmt.Fprint(w, `{"url_list":[{"url":"http://example.org/o1","httpcode":200}],"has_next":false}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return []string{"-archive", "wayback=" + srv.URL + "/wayback", "-archive", "otx=" + srv.URL + "/otx"}
}

func runCutWayback(t *testing.T, how string, bad bool, extra ...string) (int, report, string) {
	t.Helper()
	t.Chdir(t.TempDir())
	args := append([]string{"urls", "-d", "example.org", "-providers", "wayback,otx", "-urls-pause", "0", "-retries", "0", "-json"}, cutWayback(t, how, bad)...)
	out, errOut, err := captureBoth(t, func() error { return run(append(args, extra...)) })
	return exitCode(err), lastReport(t, errOut), out
}

// An archive that fails after giving URLs did not answer in full: the set is
// short, so complete is false, though the exit stays 0 while another archive
// answered in full (3 with -strict-exit).
func TestURLsArchiveCutAfterURLsMakesCompleteFalse(t *testing.T) {
	for _, how := range []string{"504", "cut"} {
		t.Run(how, func(t *testing.T) {
			code, rep, out := runCutWayback(t, how, false)
			if code != exitOK || rep.Complete || rep.Failures != 1 || rep.Exit != exitOK {
				t.Errorf("exit %d, complete %v, failures %d, want exit 0, complete false, 1 failure", code, rep.Complete, rep.Failures)
			}
			if rep.Sources == nil || !slices.Equal(rep.Sources.PartialSources, []string{"wayback"}) || rep.Sources.Answered != 1 {
				t.Errorf("sources %+v", rep.Sources)
			}
			if !strings.Contains(out, "http://example.org/w1") || !strings.Contains(out, "http://example.org/o1") {
				t.Errorf("what the archives gave is not listed: %s", out)
			}
			if code, rep, _ := runCutWayback(t, how, false, "-strict-exit"); code != exitPartial || rep.Complete {
				t.Errorf("-strict-exit: exit %d, complete %v, want 3 and false", code, rep.Complete)
			}
		})
	}
}

// An archive that fails at once, giving nothing, beside one that answers
// leaves complete true and exit 0.
func TestURLsArchiveFailedAtOnceKeepsCompleteTrue(t *testing.T) {
	code, rep, _ := runCutWayback(t, "504", true)
	if code != exitOK || !rep.Complete || rep.Failures != 1 || rep.Sources == nil || len(rep.Sources.PartialSources) != 0 {
		t.Errorf("exit %d, complete %v, failures %d, sources %+v: want exit 0, complete true", code, rep.Complete, rep.Failures, rep.Sources)
	}
}

// Every archive answering leaves complete true and exit 0.
func TestURLsEveryArchiveAnsweredIsComplete(t *testing.T) {
	t.Chdir(t.TempDir())
	flags := recordedArchives(t, "")
	_, errOut, err := captureBoth(t, func() error {
		return run(append([]string{"urls", "-d", "example.org", "-json", "-urls-pause", "0"}, flags...))
	})
	if rep := lastReport(t, errOut); exitCode(err) != exitOK || !rep.Complete || rep.Failures != 0 {
		t.Errorf("exit %d, complete %v, failures %d", exitCode(err), rep.Complete, rep.Failures)
	}
}
