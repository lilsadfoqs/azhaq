package contract

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures are small servers shaped like a real case, which the reference
// tools and azhaq are both pointed at.

// tlsClass is a TLS handshake class an `openssl s_server` offers alone.
type tlsClass struct {
	name string
	args []string
}

var tlsClasses = []tlsClass{
	{"tls12-rsa-kex", []string{"-no_tls1_3", "-cipher", "AES128-GCM-SHA256"}},
	{"tls12-dhe", []string{"-no_tls1_3", "-cipher", "DHE-RSA-AES256-GCM-SHA384"}},
	{"tls12-ecdhe", []string{"-no_tls1_3", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"}},
	{"tls13", []string{"-tls1_3"}},
}

// freePort is a TCP port nobody listens on.
func freePort(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no TCP: %v", err)
	}
	defer ln.Close()
	return portOf(ln.Addr().String())
}

// opensslServer starts `openssl s_server -www` offering only the class, and
// returns its host:port; the test is skipped where there is no openssl.
func opensslServer(t *testing.T, c tlsClass) string {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl on this machine")
	}
	dir := t.TempDir()
	key, crt := filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem")
	if out, err := exec.Command(bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=localhost", "-days", "1").CombinedOutput(); err != nil {
		t.Skipf("openssl req: %v\n%s", err, out)
	}
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, append([]string{"s_server", "-accept", port, "-cert", crt, "-key", key, "-www"}, c.args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Skipf("openssl s_server: %v", err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	addr := "127.0.0.1:" + port
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			return addr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Skipf("openssl s_server did not start with %v: %s", c.args, stderr.String())
	return ""
}

// getOnly is a port whose HTTP handler answers GET and holds anything else
// until it times out, as the Jenkins agent listener does.
func getOnly(t *testing.T) string {
	t.Helper()
	return listenCounted(t, newWire(), func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		head := make([]byte, 4)
		if _, err := readFull(c, head); err != nil {
			return
		}
		if string(head) != "GET " {
			time.Sleep(time.Second)
			return
		}
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain;charset=UTF-8\r\n\r\n" +
			"Jenkins-Agent-Protocols: JNLP4-connect, Ping\nJenkins-Version: 2.462\nRemoting-Minimum-Version: 3.4\n\n"))
	}).Addr
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := c.Read(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// jdwp answers the debug wire protocol's handshake with itself.
func jdwp(t *testing.T) string {
	t.Helper()
	return listenCounted(t, newWire(), func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		got := make([]byte, 14)
		if _, err := readFull(c, got); err == nil && string(got) == "JDWP-Handshake" {
			_, _ = c.Write(got)
		}
	}).Addr
}

// rmi answers a JRMI stream header with ProtocolAck and the address the
// registry gives for itself.
func rmi(t *testing.T) string {
	t.Helper()
	var addr string
	l := listenCounted(t, newWire(), func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		head := make([]byte, 4)
		if _, err := readFull(c, head); err != nil || string(head) != "JRMI" {
			return
		}
		buf := make([]byte, 16)
		_, _ = c.Read(buf)
		host, port, _ := net.SplitHostPort(addr)
		var p uint32
		fmt.Sscan(port, &p)
		var out bytes.Buffer
		out.WriteByte(0x4e)
		_ = binary.Write(&out, binary.BigEndian, uint16(len(host)))
		out.WriteString(host)
		_ = binary.Write(&out, binary.BigEndian, p)
		_, _ = c.Write(out.Bytes())
		_, _ = c.Read(buf)
	})
	addr = l.Addr
	return addr
}

// webpackSite is a single-page app: its bundle holds a module map whose keys
// look like paths, and one route that is real.
func webpackSite(t *testing.T) *Site {
	t.Helper()
	mux := http.NewServeMux()
	s := &Site{Wire: newWire()}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.Wire.addHTTP(r.Method, s.URL+r.RequestURI)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>app</title></head><body><div id=root></div><script src="/static/assets/main.entry.js"></script></body></html>`)
		case "/static/assets/main.entry.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `var m={"./components/locale/zh_CN":0,"./components/locale/zh_TW":1,"./AdhocFilter":2,"./AdhocMetric":3};var q="/api/v1/dashboards";`)
		case "/api/v1/dashboards":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"result":[]}`)
		default:
			http.NotFound(w, r)
		}
	})
	s.Server = httptest.NewUnstartedServer(mux)
	s.Server.Start()
	t.Cleanup(s.Server.Close)
	return s
}

func lookTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("no %s on this machine: the reference comparison runs where it is installed", name)
	}
	return p
}

// output runs a command and returns what it printed.
func output(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, name, args...).Output()
	return string(out)
}

func lines0(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

var _ = os.Getenv
