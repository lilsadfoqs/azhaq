package normalize

import "testing"

func TestTokenShaped(t *testing.T) {
	for v, want := range map[string]bool{
		"d243c53758192467":                 true,  // 16 hex
		"3d567aa69a92b5bb879821706feb67fc": true,  // a Joomla token
		"eAHTj7jOHbp8hjQADb0DGQ__":         true,  // base64url with digits, lower and upper case
		"0123456789012345":                 true,  // digits are hex
		"7490ae30":                         false, // short
		"hostinventoriesoverview":          false, // a word
		"sortorder_description":            false, // no digit, no upper case
		"conversationId":                   false,
		"name=value1234567890":             false, // outside both alphabets
		"":                                 false,
	} {
		if got := TokenShaped(v); got != want {
			t.Errorf("TokenShaped(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestIdentityIgnoresTheOrderOfQueryNames(t *testing.T) {
	same := [][2]string{
		{"http://h/latest.php?sort=name&sortorder=ASC&filter_rst=1", "http://h/latest.php?filter_rst=1&sort=name&sortorder=ASC"},
		{"http://h/a.php?x=1&y=2", "http://h/a.php?y=2&x=1"},
		{"http://h/a.php?x=1&x=2&y=3", "http://h/a.php?y=3&x=1&x=2"},
		{"http://h/a.php?flag&x=1", "http://h/a.php?x=1&flag"},
		{"http://h/p;jsessionid=AB12?x=1&y=2", "http://h/p?y=2&x=1"},
		{"http://h/a?sid=d243c53758192467&x=1", "http://h/a?x=1&sid=93d091eaefd9d037"},
		{"http://h/a?x=1#top", "http://h/a?x=1"},
	}
	for _, c := range same {
		if a, b := Identity(c[0], nil), Identity(c[1], nil); a != b {
			t.Errorf("%s and %s are two identities: %s | %s", c[0], c[1], a, b)
		}
	}
	different := [][2]string{
		{"http://h/a.php?x=1&x=2", "http://h/a.php?x=2&x=1"}, // the order of one name's values is kept
		{"http://h/a.php?x=1", "http://h/a.php?x=2"},
		{"http://h/a.php?x", "http://h/a.php?x="},
		{"http://h/a.php?sortorder=ASC", "http://h/a.php?sortorder=DESC"},
		{"http://h/a.php?x=1", "http://h/a.php?x=1&y=1"},
		{"http://h/a?token=short", "http://h/a?token=other"},
	}
	for _, c := range different {
		if a, b := Identity(c[0], nil), Identity(c[1], nil); a == b {
			t.Errorf("%s and %s are one identity: %s", c[0], c[1], a)
		}
	}
	// A name measured to change between runs has no value in the identity.
	a := Identity("http://h/login.seam?conversationId=7", map[string]bool{"conversationId": true})
	b := Identity("http://h/login.seam?conversationId=2", map[string]bool{"conversationId": true})
	if a != b {
		t.Errorf("a per-visit number is part of the identity: %s | %s", a, b)
	}
}
