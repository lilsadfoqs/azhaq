package webextract

import (
	"net/url"
	"strings"
	"testing"
)

func TestFuncKeyAt(t *testing.T) {
	for _, tc := range []struct {
		js, lit string
		want    bool
	}{
		{`{"/a":function(t,e){}}`, `"/a"`, true},
		{`{x:1,"/a": function (t){}}`, `"/a"`, true},
		{`{"/a":async function(){}}`, `"/a"`, true},
		{`{"/a":(t,e,n)=>{}}`, `"/a"`, true},
		{`{"/a":t=>t}`, `"/a"`, true},
		{`{"/a"(t,e){}}`, `"/a"`, true},
		{`{"/a":1}`, `"/a"`, false},
		{`{"/a":"/b"}`, `"/b"`, false},
		{`{"/a":functionality}`, `"/a"`, false},
		{`n("/a",function(){})`, `"/a"`, false},
		{`x?"/a":function(){}`, `"/a"`, false},
		{`{"/a":b}`, `"/a"`, false},
	} {
		i := strings.Index(tc.js, tc.lit)
		if got := FuncKeyAt(tc.js, i, i+len(tc.lit)); got != tc.want {
			t.Errorf("%s: %s is a function key: %v, want %v", tc.js, tc.lit, got, tc.want)
		}
	}
}

// A function key is a Ref with Key set, so JSURLs leaves it out; the same
// string written as an argument is still there.
func TestFunctionKeysAreOutOfJSURLs(t *testing.T) {
	base, _ := url.Parse("http://app.test/")
	got := JSURLs(`var m={"/a":function(){},"/b":function(){}};f("/b");g("/c")`, base)
	want := map[string]bool{"http://app.test/b": true, "http://app.test/c": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("%s is a route? %v", u, got)
		}
	}
}

// Candidates: a string katana's patterns take that is a function key
// everywhere it is written is rejected as a module key; one also written as
// an argument is judged on its own.
func TestCandidatesRejectFunctionKeysOnly(t *testing.T) {
	page, _ := url.Parse("http://app.test/")
	js := `var m={"admin/users/":function(t,e){},"api/orders/":function(){}};load("api/orders/");`
	reasons := map[string]string{}
	for _, c := range Candidates(js, page, page, true) {
		reasons[c.Text] = c.Reason
	}
	if reasons["admin/users/"] != ReasonModuleKey {
		t.Errorf("a key everywhere: %q", reasons["admin/users/"])
	}
	if reasons["api/orders/"] == ReasonModuleKey {
		t.Errorf("a key and an argument is kept: %q", reasons["api/orders/"])
	}
}
