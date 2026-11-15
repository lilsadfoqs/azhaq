package pathscol

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/detect"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
)

// DetectedKind is the observation that names the products a path's answer
// matched in the detection templates (internal/detect).
const DetectedKind = "detected"

var (
	detectOnce  sync.Once
	detectWords []string
)

// ProductWords are the paths the detection templates ask, as the sweep
// words them (no leading slash), less the built-in checks: the product
// checks a root sweep asks besides its path checks. Left out: a path whose
// name or query declares a state change (install, start, logout), which a
// run never sends unasked, and the root with a query, which is the page.
func ProductWords() []string {
	detectOnce.Do(func() {
		for _, p := range detect.Paths() {
			w := strings.TrimPrefix(p, "/")
			if w == "" || slices.Contains(DefaultWordlist, w) {
				continue
			}
			if path, _, _ := strings.Cut(w, "?"); path == "" || strings.HasPrefix(strings.ToLower(path), "%3f") {
				continue
			}
			if word, _ := statechange.OfTarget("/" + w); word != "" {
				continue
			}
			detectWords = append(detectWords, w)
		}
	})
	return detectWords
}

// answer is what a template sees of a fetch: the last hop's status and headers, and the body.
func answer(path string, res fetch.Result) detect.Response {
	status, header := res.Status, res.Header
	if n := len(res.Hops); n > 1 {
		status = res.Hops[n-1].Status
	}
	if res.FinalHeader != nil {
		header = res.FinalHeader
	}
	if header == nil {
		header = http.Header{}
	}
	return detect.Response{Path: path, Status: status, Header: header, Body: res.Body}
}
