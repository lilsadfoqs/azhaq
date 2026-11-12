package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// A server that sends Content-Length: 4096 and 234 bytes, then closes, is a
// failure that says how much came, retryable; the URL's row keeps the status
// the server sent, and show keeps its headers and the bytes.
func TestRunKeepsWhatACutBodySent(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	body := "<title>cut</title>" + strings.Repeat("x", 216)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Read(make([]byte, 4096))
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: cutsrv\r\nContent-Length: 4096\r\n\r\n" + body))
			}()
		}
	}()
	egress.Reset()
	t.Cleanup(egress.Reset)
	url := "http://" + l.Addr().String() + "/"
	db := filepath.Join(t.TempDir(), "c.db")
	_, errOut, _ := captureBoth(t, func() error {
		return run([]string{"run", "-url", url, "-sources", "none", "-quiet", "-json", "-no-paths", "-no-favicon", "-db", db, "-ledger", "off"})
	})
	rep := lastReport(t, errOut)
	const want = "closed after 234 of 4096 bytes (HTTP 200, text/html)"
	if len(rep.Failed) != 1 || rep.Failed[0].Error != want || !rep.Failed[0].Retryable {
		t.Fatalf("failed %+v, want one retryable %q", rep.Failed, want)
	}
	if rep.Complete || rep.Exit != 3 {
		t.Errorf("complete %v, exit %d: a cut body is a failure", rep.Complete, rep.Exit)
	}
	out, _, err := captureBoth(t, func() error {
		return run([]string{"query", "-db", db, "-type", "URL", "-json", "-match", "127.0.0.1:"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"coverage":"error"`) || !strings.Contains(out, "status=200") || !strings.Contains(out, want) {
		t.Errorf("the row lost the status or the reason:\n%s", out)
	}
	shown, _, err := captureBoth(t, func() error { return run([]string{"show", "-db", db, "-json", url}) })
	if err != nil {
		t.Fatal(err)
	}
	var sh struct {
		Observations []struct {
			Kind    string         `json:"kind"`
			Payload map[string]any `json:"payload"`
		} `json:"observations"`
	}
	if err := json.Unmarshal([]byte(shown), &sh); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range sh.Observations {
		if o.Kind != "error" || o.Payload["cut"] != true {
			continue
		}
		found = true
		hs, _ := o.Payload["headers"].(map[string]any)
		if o.Payload["status"] != float64(200) || o.Payload["received"] != float64(234) || o.Payload["length"] != float64(4096) ||
			o.Payload["body"] != body || hs["Server"] != "cutsrv" {
			t.Errorf("kept %v", o.Payload)
		}
	}
	if !found {
		t.Errorf("no observation marked cut: %s", shown)
	}
}
