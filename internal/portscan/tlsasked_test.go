package portscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// dualListener serves a TLS-only service: a ClientHello gets a handshake and
// an HTTPS answer, any other first byte gets plain(port, method).
func dualListener(t *testing.T, plain func(port int, method string) string) int {
	t.Helper()
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS()
	cert.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				first, err := br.Peek(1)
				if err != nil {
					return
				}
				if first[0] == 0x16 {
					tc := tls.Server(&prefixed{c, br}, &tls.Config{Certificates: cert.TLS.Certificates})
					if tc.Handshake() != nil {
						return
					}
					rd := bufio.NewReader(tc)
					_, _ = rd.ReadString('\n')
					_, _ = tc.Write([]byte("HTTP/1.0 200 OK\r\nServer: MiniServ/2.105\r\nContent-Length: 0\r\n\r\n"))
					return
				}
				line, _ := br.ReadString('\n')
				_, _ = c.Write([]byte(plain(port, strings.Fields(line)[0])))
			}()
		}
	}()
	return port
}

type prefixed struct {
	net.Conn
	r *bufio.Reader
}

func (p *prefixed) Read(b []byte) (int, error) { return p.r.Read(b) }

func scanTLSAsked(t *testing.T, port int) Open {
	t.Helper()
	s := &Scanner{Rate: 1000, Banner: 300 * time.Millisecond, Timeout: time.Second}
	open, err := s.Scan(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(open) != 1 {
		t.Fatalf("open %+v err %v", open, err)
	}
	return open[0]
}

// A plain answer that says the port wants TLS is re-probed with a handshake
// and listed as https with the certificate facts, whatever the status.
func TestPlainAnswerAskingForTLSIsHTTPS(t *testing.T) {
	ssl := "<h1>Error - Bad Request</h1>This web server is running in SSL mode. Try the URL https://127.0.0.1:%d/ instead."
	cases := map[string]func(port int, method string) string{
		"webmin 200 page": func(port int, _ string) string {
			return "HTTP/1.0 200 Document follows\r\nServer: MiniServ/2.105\r\nContent-Type: text/html; Charset=iso-8859-1\r\n\r\n" + fmt.Sprintf(ssl, port)
		},
		"redirect to https on this port": func(port int, _ string) string {
			return fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:%d/\r\nContent-Length: 0\r\n\r\n", port)
		},
		"426 upgrade tls": func(int, string) string {
			return "HTTP/1.1 426 Upgrade Required\r\nUpgrade: TLS/1.2, HTTP/1.1\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n"
		},
		"nginx 400": func(int, string) string {
			return "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html><body><center><h1>400 Bad Request</h1></center><center>The plain HTTP request was sent to HTTPS port</center></body></html>"
		},
		"apache 200 body": func(int, string) string {
			return "HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\n\r\nYou're speaking plain HTTP to an SSL-enabled server port."
		},
		"tomcat 200 body": func(int, string) string {
			return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nThis combination of host and port requires TLS."
		},
		"tls alert": func(int, string) string { return "\x15\x03\x01\x00\x02\x02\x46" },
	}
	for name, plain := range cases {
		t.Run(name, func(t *testing.T) {
			o := scanTLSAsked(t, dualListener(t, plain))
			if o.Service != "https" || !o.TLS || o.Cert == nil || !slices.Contains(o.SubjectAN, "example.com") {
				t.Errorf("%+v", o)
			}
		})
	}
}

// The body is asked for when the HEAD came back without one.
func TestGetBodyAskingForTLS(t *testing.T) {
	port := dualListener(t, func(port int, method string) string {
		if method == "HEAD" {
			return "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"
		}
		return "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nThis web server is running in SSL mode."
	})
	if o := scanTLSAsked(t, port); o.Service != "https" || !o.TLS || o.Cert == nil {
		t.Errorf("%+v", o)
	}
}

// A plain answer that only mentions https elsewhere stays http.
func TestPlainAnswerNotAskingForTLS(t *testing.T) {
	for name, resp := range map[string]string{
		"redirect to 443":    "HTTP/1.1 301 Moved\r\nServer: nginx\r\nLocation: https://127.0.0.1/\r\nContent-Length: 0\r\n\r\n",
		"page links https":   "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<a href=\"https://example.com/\">use https for the docs</a>",
		"redirect elsewhere": "HTTP/1.1 302 Found\r\nServer: nginx\r\nLocation: https://example.com:8443/\r\nContent-Length: 0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						_, _ = c.Read(make([]byte, 512))
						_, _ = c.Write([]byte(resp))
						c.Close()
					}()
				}
			}()
			o := scanTLSAsked(t, ln.Addr().(*net.TCPAddr).Port)
			if o.Service != "http" || o.TLS || o.Cert != nil {
				t.Errorf("%+v", o)
			}
		})
	}
}
