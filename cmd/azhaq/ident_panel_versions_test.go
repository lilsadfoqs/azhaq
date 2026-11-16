package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An admin panel that gives its version in the links of its assets, and a
// broker console behind nginx that has a copyright range before its version,
// are named with that version: the template's path is asked, and the version
// is the value shaped like one.
func TestRunNamesTheVersionOfAnAdminPanelAndABrokerConsole(t *testing.T) {
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.25 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/7.2.5")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<!DOCTYPE HTML><html lang='en' dir='ltr'><head><meta charset="utf-8" />` +
			`<meta name="robots" content="noindex,nofollow" /><link rel="icon" href="favicon.ico" type="image/x-icon" />` +
			`<link rel="stylesheet" type="text/css" href="./themes/pmahomme/jquery/jquery-ui.css" />` +
			`<link rel="stylesheet" type="text/css" href="js/vendor/codemirror/lib/codemirror.css?v=4.8.1" />` +
			`<link rel="stylesheet" type="text/css" href="phpmyadmin.css.php?nocache=6648795120ltr&amp;server=1" />` +
			`<title>127.0.0.1:8080 / mysql | phpMyAdmin 4.8.1</title>` +
			`<script data-cfasync="false" type="text/javascript" src="js/vendor/jquery/jquery.min.js?v=4.8.1"></script>` +
			`</head><body><div id="pmalogo"><img src="./themes/pmahomme/img/logo_left.png" alt="phpMyAdmin" id="imgpmalogo" /></div></body></html>`))
	}))
	t.Cleanup(panel.Close)
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.31.8")
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		if r.URL.Path != "/admin/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("<html><head><title>localhost : ActiveMQ Console</title></head><body>\n" +
			"<table><tr><td>Version</td>\n<td><b>6.1.1</b></td></tr></table>\n" +
			"Copyright 2005-2024 The Apache Software Foundation.</body></html>"))
	}))
	t.Cleanup(broker.Close)

	t.Chdir(t.TempDir())
	_, stderr, code := cli(t, "run", "-url", panel.URL+"/", "-url", broker.URL+"/", "-allow", "127.0.0.1",
		"-no-favicon", "-sources", "none", "-db", "w.db", "-ledger", "w.ledger")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	g, err := readGraph("w.db")
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]string{}
	for _, r := range huntRows(g, "w.db", nil, 7*24*time.Hour) {
		if r.Ident != nil {
			named[strings.ToLower(r.Product)] += r.Version + ";"
		}
	}
	for product, version := range map[string]string{"phpmyadmin": "4.8.1", "apache activemq": "6.1.1"} {
		if !strings.Contains(named[product], version+";") {
			t.Errorf("hunt names %q with versions %q, want %s (all: %v)", product, named[product], version, named)
		}
	}
}
