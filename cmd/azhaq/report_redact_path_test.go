package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A write from a history file fills a route the run found (/users/v1/{username}/password):
// the row names that route, so report -redact masks the user name in the URL,
// the title, the file name and the curl lines.
func TestReportRedactMasksTheValueOfAPathParameterOfAWrite(t *testing.T) {
	spec := `{"openapi":"3.0.1","info":{"title":"x","version":"1"},"paths":{
	 "/me":{"get":{}},
	 "/users/v1/{username}":{"get":{"parameters":[{"name":"username","in":"path","required":true,"schema":{"type":"string"}}]}},
	 "/users/v1/{username}/password":{"put":{"parameters":[{"name":"username","in":"path","required":true,"schema":{"type":"string"}}]}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		switch {
		case r.URL.Path == "/openapi.json":
			fmt.Fprint(w, spec)
		case user == "":
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"sign in"}`)
		case r.Method == http.MethodPut:
			w.WriteHeader(204)
		case r.URL.Path == "/me":
			fmt.Fprintf(w, `{"data":{"username":%q}}`, user)
		default:
			fmt.Fprintf(w, `{"username":%q}`, strings.TrimPrefix(r.URL.Path, "/users/v1/"))
		}
	}))
	defer srv.Close()
	put := func(file, user string) string {
		return writeHAR(t, file, harEntry("2026-10-29T10:00:00.000Z", "PUT", srv.URL+"/users/v1/"+user+"/password", `{"password":"n3w"}`, 204,
			"Authorization", "Bearer tok-"+user, "Content-Type", "application/json"))
	}
	dir := t.TempDir()
	if _, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", dir, "-role", "anon", "-role", "ra=Authorization: Bearer tok-zed1", "-role", "rb=Authorization: Bearer tok-zed2",
			"-har", "ra=" + put("ra.har", "zed1"), "-har", "rb=" + put("rb.har", "zed2"), "-replay-writes", "put", "--", "-url", srv.URL + "/", "-sources", "none", "-depth", "1"})
	}); err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	out := filepath.Join(dir, "out")
	if _, _, err := captureBoth(t, func() error { return cmdReport([]string{"-dir", dir, "-redact", "-o", out + "/"}) }); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(out, "*"))
	puts := 0
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(filepath.Base(f)+string(b), "zed1") || strings.Contains(filepath.Base(f)+string(b), "zed2") {
			t.Errorf("%s names a user though the report was redacted:\n%s", f, b)
		}
		if strings.Contains(filepath.Base(f), "put-users-v1") {
			puts++
		}
	}
	if puts != 2 {
		t.Errorf("want a report for each write, got %v", files)
	}
}

// The masks hold only for what they name: report -redact's host does not
// rewrite a word or a path segment that holds the host's name, and a kept
// body keeps the word before a credential ("Bearer"), masking the credential.
func TestRedactionKeepsWordsAndPathsThatHoldAHostOrAScheme(t *testing.T) {
	m := newMasker(true, nil)
	m.addHost("http://app:8080/x")
	m.addHost("https://shop.example.com/")
	got := m.text("the application at http://app:8080/x and /app/queues, myshop.example.com, app.other.net; api.shop.example.com via https://shop.example.com/ at @app; app is down")
	for _, keep := range []string{"the application at", "/app/queues", "myshop.example.com", "app.other.net"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q was rewritten: %s", keep, got)
		}
	}
	for _, gone := range []string{"http://app:8080", "https://shop.example.com", "api.shop.example.com", "@app;", "app is down"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q is left in: %s", gone, got)
		}
	}
	rd := newRedactor([]role{{name: "alice", session: http.Header{"Authorization": {"Bearer alice-secret-token"}}}})
	body := string(rd.body([]byte(`{"error":"Bearer token required","echo":"Bearer alice-secret-token"}`)))
	if !strings.Contains(body, "Bearer token required") || strings.Contains(body, "alice-secret-token") || !strings.Contains(body, "[redacted ") {
		t.Errorf("kept body: %s", body)
	}
}
