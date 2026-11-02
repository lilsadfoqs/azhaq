package portscan

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// -detect banner reads and sends nothing: a bare 220 stays ftp-or-smtp with
// its banner, and an FTP greeting without a product is not asked SYST.
// -detect all asks.
func TestDetectBannerSendsNothing(t *testing.T) {
	for _, greeting := range []string{"220 hello\r\n", "220 FTP server ready\r\n"} {
		var got atomic.Int64
		port := listen(t, func(c net.Conn) {
			c.Write([]byte(greeting))
			c.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			got.Add(int64(n))
		})
		s := &Scanner{Detect: DetectBanner, Banner: 150 * time.Millisecond, Timeout: time.Second}
		r, err := s.ScanEach(t.Context(), "", "127.0.0.1", []int{port})
		if err != nil || len(r.Open) != 1 {
			t.Fatalf("%q: %v %+v", greeting, err, r)
		}
		time.Sleep(700 * time.Millisecond)
		if n := got.Load(); n != 0 {
			t.Errorf("%q: -detect banner wrote %d bytes", greeting, n)
		}
		if want := bannerService(printable([]byte(greeting))); r.Open[0].Service != want {
			t.Errorf("%q: service %q, want %q", greeting, r.Open[0].Service, want)
		}

		got.Store(0)
		s = &Scanner{Detect: DetectAll, Banner: 150 * time.Millisecond, Timeout: time.Second}
		if _, err := s.ScanEach(t.Context(), "", "127.0.0.1", []int{port}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(700 * time.Millisecond)
		if got.Load() == 0 {
			t.Errorf("%q: -detect all sent nothing", greeting)
		}
	}
}
