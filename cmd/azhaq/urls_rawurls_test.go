package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The archive has a URL with its default port and without. By default that
// is one line, normalised; -raw-urls prints each string as the archive gave
// it, as gau does, in text, -json, -o and with -sort; the workspace keeps
// the normalised URL and the archive's string beside it.
func TestURLsRawURLsPrintsEachStringTheArchiveGave(t *testing.T) {
	flags := archivesOf(t, map[string][]string{"wayback": {"http://example.org:80/x", "http://example.org/x", "http://example.org:80/x", "http://example.org/y?a=1"}})
	base := append([]string{"-d", "example.org", "-providers", "wayback", "-urls-pause", "0", "-silent"}, flags...)
	sorted := func(l []string) []string { l = slices.Clone(l); slices.Sort(l); return l }

	got, _, err := urlsRun(t, base...)
	if err != nil || !slices.Equal(sorted(got), []string{"http://example.org/x", "http://example.org/y?a=1"}) {
		t.Errorf("default printed %v (%v)", got, err)
	}
	want := []string{"http://example.org/x", "http://example.org/y?a=1", "http://example.org:80/x"}
	got, _, err = urlsRun(t, append(base, "-raw-urls")...)
	if err != nil || !slices.Equal(sorted(got), sorted(want)) {
		t.Errorf("-raw-urls printed %v (%v), want %v", got, err, want)
	}
	got, _, err = urlsRun(t, append(base, "-raw-urls", "-sort")...)
	if err != nil || !slices.Equal(got, sorted(want)) {
		t.Errorf("-raw-urls -sort printed %v (%v), want %v", got, err, sorted(want))
	}

	out, _, err := captureBoth(t, func() error { return run(append([]string{"urls", "-raw-urls", "-json"}, base...)) })
	if err != nil {
		t.Fatal(err)
	}
	norm := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var o struct{ URL, Normalized string }
		if json.Unmarshal([]byte(l), &o) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		norm[o.URL] = o.Normalized
	}
	if norm["http://example.org:80/x"] != "http://example.org/x" || norm["http://example.org/x"] != "http://example.org/x" || len(norm) != 3 {
		t.Errorf("-raw-urls -json: url and normalized %v", norm)
	}

	file := filepath.Join(t.TempDir(), "out.txt")
	if _, _, err := urlsRun(t, append(base, "-raw-urls", "-o", file)...); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if got := strings.Fields(string(b)); !slices.Equal(sorted(got), sorted(want)) {
		t.Errorf("-o holds %v, want %v", got, want)
	}

	dir := t.TempDir()
	t.Chdir(dir)
	db := filepath.Join(dir, "u.db")
	if _, _, err := urlsRun(t, append(base, "-raw-urls", "-db", db)...); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(db + ".urls.jsonl")
	var urls, raws []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var o map[string]string
		if json.Unmarshal([]byte(l), &o) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		urls = append(urls, o["url"])
		raws = append(raws, o["raw"])
	}
	if slices.Contains(urls, "http://example.org:80/x") || !slices.Contains(raws, "http://example.org:80/x") || len(urls) != 3 {
		t.Errorf("the workspace list holds urls %v raw %v", urls, raws)
	}
}

// -raw already prints the archive's strings: -raw-urls beside it changes nothing.
func TestURLsRawURLsWithRawIsRaw(t *testing.T) {
	flags := archivesOf(t, map[string][]string{"wayback": {"http://example.org:80/x", "http://example.org:80/x"}})
	base := append([]string{"-d", "example.org", "-providers", "wayback", "-urls-pause", "0", "-silent", "-raw"}, flags...)
	want := []string{"http://example.org:80/x", "http://example.org:80/x"}
	for _, extra := range [][]string{nil, {"-raw-urls"}} {
		if got, _, err := urlsRun(t, append(base, extra...)...); err != nil || !slices.Equal(got, want) {
			t.Errorf("-raw %v printed %v (%v)", extra, got, err)
		}
	}
}
