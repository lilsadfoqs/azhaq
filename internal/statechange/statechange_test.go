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
