package fetch

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// cutServer writes head and then body, and closes, for every connection.
func cutServer(t *testing.T, head, body string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(head + "\r\n\r\n" + body))
			}()
		}
	}()
	return "http://" + l.Addr().String() + "/"
}

// A server that promises 4096 bytes and sends 234 is a failure that says how
// much came and what it was, and keeps the status, the headers and the bytes.
func TestCutBodyNamesWhatCameAndKeepsIt(t *testing.T) {
	Reset()
	defer Reset()
	body := "<title>cut</title>" + strings.Repeat("x", 216)
	u := cutServer(t, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nServer: cutsrv\r\nContent-Length: 4096", body)
	_, _, err := Do(context.Background(), Client(nil), u)
	if err == nil {
		t.Fatal("a cut body is a failure")
	}
	if want := "closed after 234 of 4096 bytes (HTTP 200, text/html)"; err.Error() != want {
		t.Errorf("error %q, want %q", err, want)
	}
	var cb *CutBody
	if !errors.As(err, &cb) {
		t.Fatalf("%T is no CutBody", err)
	}
	if cb.Status != 200 || string(cb.Body) != body || cb.Header.Get("Server") != "cutsrv" {
		t.Errorf("kept status %d, %d bytes, Server %q", cb.Status, len(cb.Body), cb.Header.Get("Server"))
	}
	p := cb.Partial()
	if p["cut"] != true || p["received"] != 234 || p["length"] != int64(4096) || p["status"] != 200 || p["body"] != body {
		t.Errorf("partial %v", p)
	}
	if !retryable(err) {
		t.Error("a cut body is not retryable")
	}
}

// A body with no length that ends early (chunked, cut) says how much came.
func TestCutBodyWithoutALength(t *testing.T) {
	Reset()
	defer Reset()
	u := cutServer(t, "HTTP/1.1 500 Oops\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked", "10\r\n0123456789abcdef\r\n")
	_, _, err := Do(context.Background(), Client(nil), u)
	if want := "closed after 16 bytes (HTTP 500, application/json)"; err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

// A connection closed before any answer keeps its old failure.
func TestClosedBeforeAnAnswerIsNoCutBody(t *testing.T) {
	Reset()
	defer Reset()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, _, err = Do(context.Background(), Client(nil), "http://"+l.Addr().String()+"/")
	var cb *CutBody
	if err == nil || errors.As(err, &cb) {
		t.Errorf("error %v", err)
	}
}
