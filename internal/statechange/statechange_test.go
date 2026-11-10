package statechange

import "testing"

func TestWord(t *testing.T) {
	for _, c := range []struct {
		texts []string
		want  string
	}{
		{[]string{"/createdb"}, "createdb"},
		{[]string{"Creates and populates the database"}, "create"},
		{[]string{"creates a user"}, "create"},
		{[]string{"Deleting the item"}, "delete"},
		{[]string{"/users/{id}", "Reset a password"}, "reset"},
		{[]string{"createCustomerOrder"}, "create"},
		{[]string{"/rest/user/logout"}, "logout"},
		{[]string{"Logs out the current user"}, "logout"},
		{[]string{"signs out"}, "logout"},
		{[]string{"/api/cache/clear"}, "clear"},
		{[]string{"/users/v1"}, ""},
		{[]string{"List users"}, ""},
		{[]string{"created_at of the user"}, "create"}, // a word of the set, whole
		{[]string{"accredited deletions"}, ""},         // no substring match
		{[]string{"population statistics"}, ""},
	} {
		if got := Word(c.texts...); got != c.want {
			t.Errorf("Word(%q) = %q, want %q", c.texts, got, c.want)
		}
	}
}

// A path is named by its own words: not by its query, not by a static file,
// and not by prose.
func TestOfPathAndOfURL(t *testing.T) {
	for _, c := range []struct{ raw, want string }{
		{"http://h/createdb", "createdb"},
		{"http://h/logout.php", "logout"},
		{"http://h/user/delete?id=1", "delete"},
		{"http://h/reset", "reset"},
		{"http://h/", ""},
		{"http://h/users/v1", ""},
		{"http://h/list?sort=created", ""},      // the query is not the path
		{"http://h/images/clear.gif", ""},       // a static file
		{"http://h/static/delete-icon.svg", ""}, // a static file
		{"http://h/js/seed.min.js", ""},         // a static file
		{"http://h/app/clear", "clear"},
	} {
		if got := OfURL(c.raw); got != c.want {
			t.Errorf("OfURL(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// An operation is named by its path, operationId and summary, never by its
// description or the API's.
func TestOfOperation(t *testing.T) {
	for _, c := range []struct{ path, id, summary, word, where string }{
		{"/", "home", "VAmPI home", "", ""},
		{"/createdb", "", "", "createdb", "path"},
		{"/users/v1", "deleteUser", "", "delete", "operationId"},
		{"/users/v1", "", "Resets the password", "reset", "summary"},
		{"/books/v1", "listBooks", "List books", "", ""},
		// It lists: "deleted" says what, not what the GET does.
		{"/api/recording-rules", "listRecordingRules", "Lists all rules in the database: active or deleted.", "", ""},
		{"/api/rules", "", "Returns the rules a user created", "", ""},
		{"/logout", "getLogout", "", "logout", "path"}, // the path still decides first
	} {
		w, where := OfOperation(c.path, c.id, c.summary)
		if w != c.word || where != c.where {
			t.Errorf("OfOperation(%q, %q, %q) = %q in %q, want %q in %q", c.path, c.id, c.summary, w, where, c.word, c.where)
		}
	}
}

// A query parameter that names an action, with a value that is a verb,
// names the request (a process control page's ?action=stop); any other
// parameter says nothing, whatever its value.
func TestOfQuery(t *testing.T) {
	for _, c := range []struct{ raw, want string }{
		{"http://h/index.html?processname=x&action=stop", "stop"},
		{"http://h/index.html?processname=x&action=restart", "restart"},
		{"http://h/index.html?action=clear", "clear"},
		{"http://h/p?cmd=delete", "delete"},
		{"http://h/p?cmd=delete_user&id=1", "delete"},
		{"http://h/p?op=reset", "reset"},
		{"http://h/p?do=shutdown", "shutdown"},
		{"http://h/p?task=purge", "purge"},
		{"http://h/p?ajax_action=Stop", "stop"},
		{"http://h/p?action=log%20out", "logout"},
		{"http://h/p?a=1&action=stop%20all", "stop"},
		{"http://h/p?action=view", ""},                 // not a verb
		{"http://h/p?action=list&sort=delete", ""},     // not an action parameter
		{"http://h/p?q=delete", ""},                    // a search
		{"http://h/p?reaction=stop", ""},               // not the word action
		{"http://h/p?processname=stop", ""},            // not an action parameter
		{"http://h/p?action", ""},                      // no value
		{"http://h/logo.png?action=delete", "delete"},  // the query names it
		{"http://h/user/delete?action=view", "delete"}, // the path first
		{"http://h/p?action=%zz", ""},                  // a bad escape names nothing
		{"http://h/stop", ""},                          // stop is no path verb
	} {
		if got := OfURL(c.raw); got != c.want {
			t.Errorf("OfURL(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
	if w, where := OfTarget("p?action=stop"); w != "stop" || where != "query" {
		t.Errorf("OfTarget query: %q %q", w, where)
	}
	if w, where := OfTarget("delete?id=1"); w != "delete" || where != "path" {
		t.Errorf("OfTarget path: %q %q", w, where)
	}
}
