package pathscol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/detect"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// spaPage is one application page of about size bytes that names no product.
func spaPage(size int) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><title>Shop</title><script src="/main.js"></script></head><body><app-root></app-root>`)
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, `<div class="row"><a href="/#/item-%d">Latest headlines and weekly reports %d</a><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>`, i%50, i)
	}
	b.WriteString(`</body></html>`)
	return b.String()
}

// standIn is a site that answers every path with one application page
// (catch-all, as Juice Shop does) or 404 to an unknown path; real maps a
// path to the page it truly serves. Each request waits delay, as a network does.
func standIn(catchAll bool, delay time.Duration, real map[string]string) (*httptest.Server, *atomic.Int64) {
	page := []byte(spaPage(50 << 10))
	var n atomic.Int64
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		time.Sleep(delay)
		if body, ok := real[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		if catchAll || r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(page)
			return
		}
		http.NotFound(w, r)
	})), &n
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// BenchmarkProductChecks is one root sweep of a site, with and without the
// product checks: requests, wall time, CPU of the process (the stand-in
// server's included), allocations and the peak heap. The templates are
// loaded before the first run, so their load cost is not in the numbers.
func BenchmarkProductChecks(b *testing.B) {
	detect.Load()
	for _, site := range []string{"catchall", "notfound"} {
		for _, delay := range []time.Duration{0, 2 * time.Millisecond} {
			for _, checks := range []bool{false, true} {
				name := fmt.Sprintf("%s/delay=%v/checks=%v", site, delay, checks)
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					var peak uint64
					var reqs int64
					var wall, cpu time.Duration
					for i := 0; i < b.N; i++ {
						srv, n := standIn(site == "catchall", delay, nil)
						fetch.Reset()
						runtime.GC()
						stop, done := make(chan struct{}), make(chan struct{})
						go func() {
							defer close(done)
							var m runtime.MemStats
							for {
								runtime.ReadMemStats(&m)
								peak = max(peak, m.HeapInuse)
								select {
								case <-stop:
									return
								case <-time.After(2 * time.Millisecond):
								}
							}
						}()
						col := &Collector{Client: srv.Client(), Wordlist: DefaultWordlist, ProductChecks: checks}
						c0, t0 := cpuTime(), time.Now()
						_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(types.Observation) error { return nil })
						wall += time.Since(t0)
						cpu += cpuTime() - c0
						close(stop)
						<-done
						reqs += n.Load()
						srv.Close()
						if err != nil {
							b.Fatal(err)
						}
					}
					b.ReportMetric(float64(reqs)/float64(b.N), "requests")
					b.ReportMetric(float64(wall.Milliseconds())/float64(b.N), "ms/sweep")
					b.ReportMetric(float64(cpu.Milliseconds())/float64(b.N), "cpu-ms/sweep")
					b.ReportMetric(float64(peak>>20), "peakheapMB")
				})
			}
		}
	}
	fetch.Reset()
}
