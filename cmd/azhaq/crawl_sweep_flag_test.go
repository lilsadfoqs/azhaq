package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// -sweep means one thing on every command: cover the whole scope. crawl asks
// the built-in paths with -builtin-paths.
func TestCrawlSweepIsTheScopesSweepAndBuiltinPathsAsksThePaths(t *testing.T) {
	fs, rf := flagsOf("crawl"), flagsOf("run")
	if fs.Lookup("builtin-paths") == nil {
		t.Fatal("crawl has no -builtin-paths")
	}
	got, want := fs.Lookup("sweep"), rf.Lookup("sweep")
	if got == nil || got.Usage != want.Usage {
		t.Errorf("crawl -sweep is not run's -sweep: %+v", got)
	}
	if strings.Contains(fs.Lookup("builtin-paths").Usage, "whole scope") {
		t.Error("-builtin-paths describes the scope")
	}
}

// -sweep alone names no built-in path: the paths of a plain crawl stay unasked,
// and a note says where they went.
func TestCrawlSweepDoesNotAskTheBuiltinPaths(t *testing.T) {
	srv := newAskedSite(t, map[string]string{
		"/":           `<html><body><a href="/about">about</a></body></html>`,
		"/about":      "about",
		"/robots.txt": "User-agent: *\nDisallow: /hidden\n",
		"/.git/HEAD":  "ref: refs/heads/main",
	}, nil)
	_, errOut := crawlOut(t, srv.Server, "-sweep")
	got := srv.asked()
	if got["/robots.txt"] || got["/.git/HEAD"] {
		t.Errorf("-sweep asked the built-in paths: %v", got)
	}
	if !strings.Contains(errOut, "the built-in paths are -builtin-paths") {
		t.Errorf("no note names -builtin-paths:\n%s", errOut)
	}
	srv.reset()
	_, errOut = crawlOut(t, srv.Server, "-sweep", "-builtin-paths")
	if !srv.asked()["/robots.txt"] || strings.Contains(errOut, "the built-in paths are -builtin-paths") {
		t.Errorf("-sweep -builtin-paths: asked %v\n%s", srv.asked(), errOut)
	}
}

// Without a range in -allow or -scope, -sweep has nothing to cover: a usage
// error before anything is sent, as on run.
func TestCrawlSweepWithoutARangeIsAUsageError(t *testing.T) {
	_, _, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", "http://127.0.0.1:1/", "-sweep", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "-builtin-paths") {
		t.Errorf("exit %d, %v", exitCode(err), err)
	}
}

// -sweep alone is a target: the scope's ranges. No URL is asked for.
func TestCrawlSweepAloneStartsFromTheScope(t *testing.T) {
	_, _, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-allow", "127.7.7.0/30", "-sweep", "-silent", "-max-requests", "30", "-timeout", "20s", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if exitCode(err) == exitUsage {
		t.Errorf("a usage error: %v", err)
	}
}
