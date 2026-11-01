package httpcol

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

// listen answers each connection with banner (when set) and counts them.
func listen(t *testing.T, banner string) (port int, conns *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	conns = new(atomic.Int32)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				if banner != "" {
					_, _ = c.Write([]byte(banner))
				}
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, conns
}

type countWriter struct{ n *atomic.Int32 }

func (w countWriter) Write(p []byte) (int, error) { w.n.Add(1); return len(p), nil }

type outcome struct {
	kinds []string
	last  types.Observation
	meta  types.RunMeta
	err   error
}

func runSeed(c *Collector, raw, fallback string) outcome {
	var o outcome
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw, FallbackKey: fallback}}
	o.meta, o.err = c.Run(context.Background(), seed, func(ob types.Observation) error {
		o.kinds = append(o.kinds, ob.Kind)
		if ob.Kind != "dropped" {
			o.last = ob
		}
		return nil
	})
	return o
}

// A port that answers something other than HTTP is open and not a web
// service: it ends as a "nothttp" observation, not as a failure. Asked
// over plain HTTP first, its banner shows it is not TLS either, so the
// second scheme is not asked.
func TestNotHTTPPortIsNotAFailure(t *testing.T) {
	for name, banner := range map[string]string{"ftp": "220 FTP ready\r\n", "ssh": "SSH-2.0-OpenSSH_9.0\r\n"} {
		for _, order := range []struct{ first, fallback string }{{"https", "http"}, {"http", "https"}} {
			t.Run(name+"-"+order.first, func(t *testing.T) {
				fetch.Reset()
				port, conns := listen(t, banner)
				o := runSeed(New(nil), order.first+"://127.0.0.1:"+strconv.Itoa(port)+"/", order.fallback)
				if o.err != nil || o.meta.Status != types.StatusOK {
					t.Fatalf("status %q err %v", o.meta.Status, o.err)
				}
				if len(o.kinds) != 1 || o.kinds[0] != KindNotHTTP {
					t.Fatalf("observations %v", o.kinds)
				}
				var p struct {
					Host string `json:"host"`
					Port int    `json:"port"`
				}
				_ = json.Unmarshal(o.last.Payload, &p)
				if p.Host != "127.0.0.1" || p.Port != port {
					t.Errorf("payload %s", o.last.Payload)
				}
				if want := map[string]int32{"http": 1, "https": 2}[order.first]; conns.Load() != want {
					t.Errorf("%d connections, want %d", conns.Load(), want)
				}
			})
		}
	}
}

// A server that closes the connection without answering is a failure, not
// a port that speaks something else.
func TestSilentPortStaysAFailure(t *testing.T) {
	fetch.Reset()
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
	o := runSeed(New(nil), "https://"+l.Addr().String()+"/", "http")
	if o.err == nil || len(o.kinds) != 0 {
		t.Errorf("err %v observations %v", o.err, o.kinds)
	}
}

// A TLS port asked over plain HTTP first answers 400 and is asked again
// over TLS: it is not taken for a port that is not web.
func TestHTTPFirstFindsATLSPort(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>tls</title>"))
	}))
	defer srv.Close()
	var plain atomic.Int32
	srv.Config.ErrorLog = log.New(countWriter{&plain}, "", 0)
	o := runSeed(New(srv.Client()), "http://"+srv.Listener.Addr().String()+"/", "https")
	if o.err != nil || len(o.kinds) == 0 || o.kinds[0] != "application" {
		t.Fatalf("err %v observations %v", o.err, o.kinds)
	}
	if n := plain.Load(); n != 1 {
		t.Errorf("%d plain requests reached the TLS port, want 1", n)
	}
	var row struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
	}
	_ = json.Unmarshal(o.last.Payload, &row)
	if row.Status != 200 || row.URL != "https://"+srv.Listener.Addr().String()+"/" {
		t.Errorf("row %+v", row)
	}
}
