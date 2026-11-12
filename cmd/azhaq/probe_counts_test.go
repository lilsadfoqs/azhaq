package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// probe's counts partition its rows: each row is answered or without an
// answer, once, and a host with no web port is a note, not a count.
func TestProbeCountsPartitionTheRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<title>ok</title>")) }))
	defer srv.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	l.Close()
	_, errOut, _ := cli(t, "probe", "-u", srv.URL+"/", "-u", "http://"+closed+"/", "-json")
	rep := sumMap(t, errOut)
	counts, _ := rep["counts"].(map[string]any)
	if counts["answered"] != float64(1) || counts["without an answer"] != float64(1) || counts["hosts without a web service"] != nil {
		t.Errorf("counts %v", counts)
	}
	if !strings.Contains(errOut, "results") {
		t.Errorf("no summary: %s", errOut)
	}
}
