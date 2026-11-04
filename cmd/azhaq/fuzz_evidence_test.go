package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// matcherServer is the stand-in the matcher tests were measured on, with
// ffuf v2.1.0 and with azhaq: four 302 answers, one of which has a Location
// header that names index.php, and answers whose bodies hold a word.
func matcherServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			w.Header().Set("Location", "index.php")
			w.WriteHeader(http.StatusFound)
		case "/b", "/c", "/d":
			w.Header().Set("Location", "/other")
			w.WriteHeader(http.StatusFound)
		case "/ok":
			fmt.Fprint(w, "hello needle")
		case "/plain":
			fmt.Fprint(w, "hello")
		default:
			http.Error(w, "nope", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fuzzWords runs fuzz -json and gives the words that matched, sorted, and
// the JSON rows by word.
func fuzzWords(t *testing.T, args ...string) ([]string, map[string]map[string]any) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error { return cmdFuzz(append(args, "-json")) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	var words []string
	rows := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			t.Fatalf("not JSON: %q", line)
		}
		u, _ := m["url"].(string)
		w := u[strings.LastIndex(u, "/")+1:]
		words = append(words, w)
		rows[w] = m
	}
	sort.Strings(words)
	return words, rows
}

// -mc and -mr join with ffuf's -mmode (or, by default), -mr reads the headers
// as well as the body, and -fmode does the same for the filters. Each case is
// what ffuf v2.1.0 printed for the same flags against this stand-in.
func TestFuzzMatcherModesFollowFfuf(t *testing.T) {
	srv := matcherServer(t)
	words := wlist(t, "a", "b", "c", "d", "ok", "plain", "zzz")
	for _, c := range []struct {
		name  string
		flags []string
		want  string
	}{
		{"-mc with -mr, or (the default)", []string{"-mc", "302", "-mr", "Location: index.php"}, "a b c d"},
		{"-mc with -mr, and", []string{"-mc", "302", "-mr", "Location: index.php", "-mmode", "and"}, "a"},
		{"-mr alone reads a header", []string{"-mr", "Location: index.php"}, "a"},
		{"-mr alone reads the body", []string{"-mr", "needle"}, "ok"},
		{"-mc with a body -mr, or", []string{"-mc", "302", "-mr", "needle"}, "a b c d ok"},
		{"-mc with a body -mr, and", []string{"-mc", "302", "-mr", "needle", "-mmode", "and"}, ""},
		{"-fr on a header", []string{"-mc", "all", "-fr", "Location: /other"}, "a ok plain zzz"},
		{"-fmode and", []string{"-mc", "302", "-fr", "index.php", "-fmode", "and"}, "b c d"},
		{"-mmode and, -mc and -ms", []string{"-mc", "302", "-ms", "0", "-mmode", "and"}, "a b c d"},
	} {
		got, _ := fuzzWords(t, append([]string{"-u", srv.URL + "/FUZZ", "-w", words}, c.flags...)...)
		if g := strings.Join(got, " "); g != c.want {
			t.Errorf("%s: %v matched %q, ffuf matched %q", c.name, c.flags, g, c.want)
		}
	}
}

// A match says which matcher held and what it held on, so -mc 302 -mr
// 'Location: index.php' tells the answer that had the header from the three
// that only had the status.
func TestFuzzMatchRowSaysWhatMatched(t *testing.T) {
	srv := matcherServer(t)
	words := wlist(t, "a", "b", "ok")
	got, rows := fuzzWords(t, "-u", srv.URL+"/FUZZ", "-w", words, "-mc", "302,200", "-mr", "Location: index.php|needle", "-ms", "12")
	if strings.Join(got, " ") != "a b ok" {
		t.Fatalf("matched %v", got)
	}
	matchers := func(word string) map[string]map[string]any {
		out := map[string]map[string]any{}
		list, _ := rows[word]["matched"].([]any)
		for _, x := range list {
			m := x.(map[string]any)
			out[m["matcher"].(string)] = m
		}
		return out
	}
	a, b, ok := matchers("a"), matchers("b"), matchers("ok")
	if len(a) != 2 || a["-mc"]["got"] != "302" || a["-mc"]["value"] != "302,200" {
		t.Errorf("a: %v", a)
	}
	re := a["-mr"]
	if re == nil || re["in"] != "headers" || re["text"] != "Location: index.php" || !strings.Contains(re["context"].(string), "\r\nLocation: index.php\r\n") {
		t.Errorf("a's -mr: %v", re)
	}
	if len(b) != 1 || b["-mr"] != nil || b["-mc"]["got"] != "302" {
		t.Errorf("b only has its status to match on: %v", b)
	}
	if re := ok["-mr"]; len(ok) != 3 || re == nil || re["in"] != "body" || re["text"] != "needle" || !strings.HasSuffix(re["context"].(string), "hello needle") || ok["-ms"]["got"] != "12" {
		t.Errorf("ok: %v", ok)
	}
	if rows["a"]["control"] != nil {
		t.Errorf("no -ac, so no control: %v", rows["a"]["control"])
	}

	// The text line says the same, in the line.
	out, errOut, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, "a", "b"), "-mc", "302", "-mr", "Location: index.php"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		switch {
		case strings.HasPrefix(line, "a "):
			if !strings.Contains(line, `Matched: -mc 302; -mr Location: index.php found in the headers: "`) || !strings.Contains(line, `Location: index.php\r\n`) {
				t.Errorf("line of a: %s", line)
			}
		case strings.HasPrefix(line, "b "):
			if !strings.HasSuffix(line, "Matched: -mc 302]") {
				t.Errorf("line of b: %s", line)
			}
		default:
			t.Errorf("unexpected line %q", line)
		}
	}
	// And the multi-line form (-v) has its own lines.
	out, _, err = captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", wlist(t, "a"), "-mr", "Location: index.php", "-v"})
	})
	if err != nil || !strings.Contains(out, "| MATCHED | -mr Location: index.php found in the headers:") {
		t.Errorf("-v: %v\n%s", err, out)
	}
}

// With -ac the run has controls: the answers to names that cannot exist. A
// match that is the same answer as one (here let through by -fmode and: its
// size is filtered, its status is not) says so, with the control's URL; one
// that is not does not.
func TestFuzzMatchRowSaysItIsTheControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			fmt.Fprint(w, "a real page of its own")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "no such item: %s", strings.TrimPrefix(r.URL.Path, "/"))
	}))
	t.Cleanup(srv.Close)
	words := wlist(t, "real", "foo", "bar")
	args := []string{"-u", srv.URL + "/FUZZ", "-w", words, "-mc", "all", "-ac", "-fmode", "and", "-fc", "500", "-fs", "0", "-mr", "item"}
	got, rows := fuzzWords(t, args...)
	if strings.Join(got, " ") != "bar foo real" {
		t.Fatalf("matched %v", got)
	}
	for _, w := range []string{"foo", "bar"} {
		c, _ := rows[w]["control"].(map[string]any)
		if c == nil || c["status"] != 400.0 || !strings.HasPrefix(c["url"].(string), srv.URL+"/") || strings.HasSuffix(c["url"].(string), "/"+w) {
			t.Errorf("%s answers as the control does: %v", w, rows[w])
		}
	}
	if rows["real"]["control"] != nil {
		t.Errorf("a real page is no control's answer: %v", rows["real"])
	}
	out, _, err := captureBoth(t, func() error { return cmdFuzz(args) })
	if err != nil || !strings.Contains(out, "Control: the same answer as the -ac control "+srv.URL+"/") {
		t.Errorf("the text line: %v\n%s", err, out)
	}
}
