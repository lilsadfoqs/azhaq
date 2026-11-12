package statechange

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// camel is a word in camelCase after "do": start_over is doStartOver.
func camel(w string) string {
	var b strings.Builder
	b.WriteString("do")
	for _, part := range strings.Split(w, "_") {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// Every word of the list names a GET by itself as a path segment, run into a
// longer name in snake_case, kebab-case and camelCase, in a query value that
// names an action, and in a query value that is itself a path.
func TestEveryWordHoldsAGet(t *testing.T) {
	for _, w := range Verbs {
		snake := strings.ReplaceAll(w, "_", "-") // a path segment that is the word
		for _, c := range []struct{ name, raw string }{
			{"segment", "http://h/" + snake},
			{"last segment", "http://h/api/ScriptCron/" + snake},
			{"upper case", "http://h/" + strings.ToUpper(snake)},
			{"with an extension", "http://h/" + snake + ".php"},
			{"snake_case", "http://h/do_" + w},
			{"camelCase", "http://h/api/" + camel(w)},
			{"kebab-case", "http://h/x-" + snake + "-y"},
			{"action value", "http://h/p?action=" + w},
			{"cmd value", "http://h/p?x=1&cmd=" + w},
			{"path in a query value", "http://h/server/index.php?s=/user/" + snake},
			{"escaped path in a query value", "http://h/p?r=%2Fapi%2Fx%2F" + snake},
		} {
			if got := OfURL(c.raw); got != w {
				t.Errorf("%s: OfURL(%q) = %q, want %q", c.name, c.raw, got, w)
			}
		}
	}
}

// The words added to the old list match as written: a longer word that holds
// one is not it. start and run are whole words, never substrings.
func TestAddedWordsMatchAsWritten(t *testing.T) {
	for _, w := range Exact {
		if strings.Contains(w, "_") {
			continue
		}
		for _, form := range []string{w + "s", w + "ed", w + "ing", w + "er", w + "ers", w + "able", "pre" + w + "fix", "x" + w, w + "time"} {
			if got := OfURL("http://h/" + form); got != "" {
				t.Errorf("OfURL(/%s) = %q: it names %s, and is not it", form, got, w)
			}
			if oldActionVerbs[w] {
				continue // an action value has read their forms since before they were path words
			}
			if got := OfURL("http://h/p?action=" + form); got != "" {
				t.Errorf("OfURL(?action=%s) = %q", form, got)
			}
		}
	}
}

// Read-only paths that hold a word of the list as a part of a longer one, or
// near it, are sent.
func TestCommonReadOnlyPathsAreNotHeld(t *testing.T) {
	for _, p := range []string{
		"/startup-guide", "/startups", "/running-jobs", "/runtime", "/runner", "/runners", "/rerun", "/runs", "/running",
		"/starter-kit", "/started", "/getting-started", "/starting-lineup",
		"/uploads", "/uploads/2020/05/", "/wp-content/uploads/", "/uploaded", "/uploader",
		"/installed-plugins", "/installation", "/installer", "/installs", "/reinstall",
		"/imports", "/imported", "/importer", "/export", "/exports",
		"/synchronize", "/syncing", "/synced", "/triggers", "/triggered",
		"/stopwatch", "/bus/stops", "/stopped", "/stopping",
		"/executive", "/execution", "/executions", "/executor", "/executed",
		"/initial", "/initials", "/initialization", "/initiative", "/initialized",
		"/restoration", "/restaurants", "/restored", "/restarts", "/rebooted", "/reverts", "/rollbacks",
		"/killer-features", "/killed", "/setups", "/setting", "/settings", "/setupguide",
		"/shutdowns", "/api/v1/users", "/products", "/about", "/search",
	} {
		if got := OfURL("http://h" + p); got != "" {
			t.Errorf("OfURL(%s) = %q, want none", p, got)
		}
	}
}

// The query values that name no action, and the values that are no path, say
// nothing, whatever words they hold.
func TestQueryValuesThatNameNothing(t *testing.T) {
	for _, q := range []string{
		"q=run", "q=start", "sort=stop", "name=install", "title=upload", "next=home", "lang=en",
		"action=running", "action=view", "action=list", "action=runner",
		"url=http://h/run", "ref=https://h/logout", "redirect=home/logout", "s=user/logout",
		"img=/static/logo.png", "file=/a/b/run.js", "path=/etc/passwd", "page=/about", "r=/",
		"x=%zz", "x=/%zz/run",
	} {
		if got := OfURL("http://h/index.php?" + q); got != "" {
			t.Errorf("OfURL(?%s) = %q, want none", q, got)
		}
	}
	for q, want := range map[string]string{
		"s=/user/logout":            "logout",
		"r=/api/x/run":              "run",
		"redirect=/admin/restart":   "restart",
		"a=1&r=/api/x/run&b=2":      "run",
		"next=/x?action=stop":       "stop", // the value's own query is read too
		"s=/user/logout#top":        "logout",
		"cmd=run":                   "run",
		"ajax_action=Install":       "install",
		"task=sync_all":             "sync",
		"do=start%20over":           "start_over",
		"action=startOver":          "start_over",
		"action=stopall":            "stop",
		"action=restarts":           "restart", // an action value that was a word before: still its forms
		"w=/api/x/create":           "create",
		"w=/api/x/deleted":          "delete",
		"w=/api/x/restarts":         "",
		"w=/api/x/clear.gif":        "",
		"p=/css/delete-icon.svg":    "",
		"p=/a/b?sort=created&q=run": "",
	} {
		got := OfURL("http://h/index.php?" + q)
		if got != want {
			t.Errorf("OfURL(?%s) = %q, want %q", q, got, want)
		}
	}
	if w, where := Of("http://h/server/index.php?s=/user/logout"); w != "logout" || where != "query" {
		t.Errorf("Of = %q in %q, want logout in query", w, where)
	}
	if w, where := OfTarget("index.php?r=/api/x/run"); w != "run" || where != "query" {
		t.Errorf("OfTarget = %q in %q, want run in query", w, where)
	}
}

// start_over is read as a phrase of its own, whatever its case; the parts
// apart are start, a word of the list too.
func TestStartOverIsAPhrase(t *testing.T) {
	for p, want := range map[string]string{
		"/start_over": "start_over", "/start-over": "start_over", "/startOver": "start_over", "/StartOver": "start_over",
		"/START_OVER": "start_over", "/startover": "start_over", "/api/start over": "start_over", "/wizard/start_over.php": "start_over",
		"/start/over": "start_over", "/over-start": "start", "/start-overs": "start", "/startovers": "",
	} {
		if got := OfURL("http://h" + p); got != want {
			t.Errorf("OfURL(%s) = %q, want %q", p, got, want)
		}
	}
}

// An API description's operation is named by its operationId in the same words.
func TestOperationIDsUseTheList(t *testing.T) {
	for _, c := range []struct{ path, id, summary, word string }{
		{"/jobs/{id}", "runJob", "", "run"},
		{"/server", "restartServer", "", "restart"},
		{"/db", "importData", "", "import"},
		{"/db", "uploadBackup", "", "upload"},
		{"/jobs", "listRuns", "List the runs", ""},
		{"/jobs", "getInstalledPlugins", "Installed plugins", ""},
	} {
		if w, _ := OfOperation(c.path, c.id, c.summary); w != c.word {
			t.Errorf("OfOperation(%q, %q, %q) = %q, want %q", c.path, c.id, c.summary, w, c.word)
		}
	}
	// A word of the list is read as written, in a summary too.
	if w, _ := OfOperation("/jobs", "triggers", "Triggers of a job"); w != "" {
		t.Errorf("a summary that says Triggers names nothing: %q", w)
	}
}

// The documented list is the code's: run.md names every word, and the pages
// say a GET outside the list is sent.
func TestDocsNameEveryWord(t *testing.T) {
	run, err := os.ReadFile(filepath.Join("..", "..", "docs", "commands", "run.md"))
	if err != nil {
		t.Fatal(err)
	}
	section := string(run)
	if i := strings.Index(section, "### State-changing requests"); i >= 0 {
		section = section[i:]
		if j := strings.Index(section[5:], "\n### "); j >= 0 {
			section = section[:j+5]
		}
	}
	for _, w := range append(append([]string{}, Verbs...), ActionVerbs...) {
		if !strings.Contains(section, w) {
			t.Errorf("docs/commands/run.md does not name %q among the state-changing words", w)
		}
	}
	concepts, err := os.ReadFile(filepath.Join("..", "..", "docs", "CONCEPTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"docs/commands/run.md": section, "docs/CONCEPTS.md": string(concepts)} {
		if !strings.Contains(text, "A GET whose name is outside the list is sent") {
			t.Errorf("%s does not say a GET outside the list is sent", name)
		}
	}
}
