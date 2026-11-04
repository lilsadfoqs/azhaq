package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// An archive that failed after giving URLs did not answer in full: with no
// other archive answering, the run is a partial set (exit 3, complete false).
func TestURLsNoArchiveAnsweredInFullIsPartial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wayback" && r.URL.Query().Get("page") == "0":
			fmt.Fprint(w, `[["original"],["http://example.org/a"],["http://example.org/b"]]`)
		case r.URL.Path == "/wayback":
			http.Error(w, "down", http.StatusGatewayTimeout)
		default:
			http.Error(w, "down", http.StatusGatewayTimeout)
		}
	}))
	defer srv.Close()
	args := []string{"urls", "-d", "example.org", "-providers", "wayback,commoncrawl", "-urls-pause", "0", "-json",
		"-archive", "wayback=" + srv.URL + "/wayback", "-archive", "commoncrawl=" + srv.URL + "/cc"}
	out, errOut, err := captureBoth(t, func() error { return run(slices.Clone(args)) })
	rep := lastReport(t, errOut)
	if exitCode(err) != exitPartial || rep.Complete || rep.Sources == nil || rep.Sources.Answered != 0 || !strings.Contains(out, "http://example.org/a") {
		t.Errorf("no archive answered in full: exit %d, complete %v, sources %+v", exitCode(err), rep.Complete, rep.Sources)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "the set is partial: no archive answered in full") {
		t.Errorf("notes %q", rep.Notes)
	}
}
