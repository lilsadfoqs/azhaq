package paramcol

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lilsadfoqs/azhaq/types"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// lengthControls counts the requests that carry one name, made of "~" and
// letters as long as limit (5 characters): the names no page reads that a
// change in size alone is checked against.
func lengthControls(raws []string) int {
	n := 0
	for _, raw := range raws {
		if strings.Contains(raw, "&") || !strings.HasPrefix(raw, "~") {
			continue
		}
		if name, _, _ := strings.Cut(raw, "="); len(name) == len("limit") {
			n++
		}
	}
	return n
}

// A name whose only evidence is a change in size is checked once more before
// it is kept: four names no page reads, as long as it, are asked. A name
// whose evidence is its status is not asked that way.
func TestAChangeInSizeAloneIsCheckedAgainstFourNamesAsLongAsIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reacts func(w http.ResponseWriter)
		why    string
		want   int
	}{
		{"size", func(w http.ResponseWriter) { fmt.Fprint(w, strings.Repeat(" <li>row</li>", 40)) }, "size", 4},
		{"status", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, "status", 0},
	} {
		fetch.Reset()
		var mu sync.Mutex
		var raws []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			raws = append(raws, r.URL.RawQuery)
			mu.Unlock()
			if r.URL.Query().Get("limit") != "" {
				tc.reacts(w)
			}
			fmt.Fprint(w, "<html><body>profile</body></html>")
		}))
		words := []string{"limit"}
		for i := 0; i < 40; i++ {
			words = append(words, fmt.Sprintf("field%d", i))
		}
		c := New(srv.Client(), Options{Words: words, Chunk: 10, Rate: 10000, Threads: 1})
		got := runOn(t, c, srv.URL+"/profile")
		srv.Close()
		why, _ := got["why"].(map[string]any)
		if len(why) != 1 || why["limit"] != tc.why {
			t.Errorf("%s: found %v", tc.name, got)
		}
		mu.Lock()
		if n := lengthControls(raws); n != tc.want {
			t.Errorf("%s: %d requests with one name no page reads as long as limit, want %d (queries %q)", tc.name, n, tc.want, raws)
		}
		mu.Unlock()
	}
}

// requiredAs answers a request that lacks a required field with status, and
// names the first one missing, as a validator does.
func requiredAs(t *testing.T, status int, required ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, f := range required {
			if !r.URL.Query().Has(f) {
				w.WriteHeader(status)
				fmt.Fprintf(w, `{"status":"fail","message":"'%s' is a required property"}`, f)
				return
			}
		}
		fmt.Fprint(w, `{"status":"success"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A page that refuses a request without its input with a 400 or a 422 is
// asked again with the names found given, while a pass finds more, at most 3
// passes: five required fields, one found at first, three more by the passes,
// and the fifth is left.
func TestRequiredFieldsAreAskedForAtMostThreePassesAfterA400Or422(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnprocessableEntity} {
		fetch.Reset()
		srv := requiredAs(t, status, "f1", "f2", "f3", "f4", "f5")
		words := []string{"f1", "f2", "f3", "f4", "f5", "email", "debug"}
		for i := 0; i < 30; i++ {
			words = append(words, fmt.Sprintf("noise%d", i))
		}
		got := runOn(t, New(srv.Client(), Options{Words: words, Rate: 10000}), srv.URL+"/login")
		if fmt.Sprint(got["params"]) != "[f1 f2 f3 f4]" {
			t.Errorf("%d: found %v, want the first field and three passes' worth, and not the fifth", status, got["params"])
		}
		why, _ := got["why"].(map[string]any)
		if strings.Contains(fmt.Sprint(why["f1"]), "once") || !strings.Contains(fmt.Sprint(why["f4"]), "once") {
			t.Errorf("%d: why %v", status, why)
		}
	}
}

// A page that answers a request without its input (200) is not asked again
// with the names found: no request after the first pass carries the name found
// together with the rest of the list.
func TestAPageThatAnswersWithoutInputIsNotAskedAgain(t *testing.T) {
	carrying := func(status int) int {
		fetch.Reset()
		var mu sync.Mutex
		with := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Has("q") {
				mu.Lock()
				if len(q) > 5 {
					with++ // q together with a group of names
				}
				mu.Unlock()
				fmt.Fprint(w, strings.Repeat("<li>row</li>", 40))
				return
			}
			w.WriteHeader(status)
			fmt.Fprint(w, "needs q")
		}))
		defer srv.Close()
		words := []string{"q"}
		for i := 0; i < 200; i++ {
			words = append(words, fmt.Sprintf("noise%d", i))
		}
		got := runOn(t, New(srv.Client(), Options{Words: words, Chunk: 20, Rate: 10000, Threads: 1}), srv.URL+"/s")
		if fmt.Sprint(got["params"]) != "[q]" {
			t.Fatalf("status %d: found %v", status, got["params"])
		}
		mu.Lock()
		defer mu.Unlock()
		return with
	}
	if ok, bad := carrying(http.StatusOK), carrying(http.StatusBadRequest); ok > 2 || bad < 8 {
		t.Errorf("requests with q and a group: %d when the page answers 200, %d when it answers 400: want a few and one for each group of the list", ok, bad)
	}
}

// A page that answers 429, 418 or 503 to the requests fails the search: the
// error says the status and the row says it was not fully searched.
func TestAPageThatAnswers429418Or503FailsTheSearch(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusTeapot, http.StatusServiceUnavailable} {
		fetch.Reset()
		var mu sync.Mutex
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n++
			over := n > 2
			mu.Unlock()
			if over {
				http.Error(w, "slow down", status)
				return
			}
			fmt.Fprint(w, "ok page")
		}))
		var words []string
		for i := 0; i < 600; i++ {
			words = append(words, fmt.Sprintf("name%d", i))
		}
		c := New(srv.Client(), Options{Words: words, Rate: 10000, Backoff: []time.Duration{time.Millisecond, time.Millisecond}})
		var got map[string]any
		meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
			return json.Unmarshal(o.Payload, &got)
		})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) || meta.Status != types.StatusError {
			t.Errorf("%d: the page did not fail the search: %v %v", status, meta, err)
		}
		if note, _ := got["note"].(string); !strings.Contains(note, "not fully searched") {
			t.Errorf("%d: note %v", status, got)
		}
	}
}
