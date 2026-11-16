package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// catchAllSite answers every path 200 with one application page of about
// size bytes, as a single-page app does (Juice Shop); apiSite answers a
// few paths and 404s the rest. n counts the requests each got.
func catchAllSite(size int) (*httptest.Server, *atomic.Int64) {
	var page strings.Builder
	page.WriteString(`<!doctype html><html><head><title>Shop</title><link rel="icon" href="/assets/favicon_js.ico"><script src="/main.js"></script></head><body><app-root></app-root>`)
	for i := 0; page.Len() < size; i++ {
		fmt.Fprintf(&page, `<div class="row"><a href="/#/item-%d">Latest headlines and weekly reports from the editorial desk %d</a><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>`, i%50, i)
	}
	page.WriteString(`</body></html>`)
	body := page.String()
	var n atomic.Int64
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		switch r.URL.Path {
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `var routes=["/rest/products","/api/Users"];`)
		case "/rest/products":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":[]}`)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, body)
		}
	})), &n
}

func apiSite() (*httptest.Server, *atomic.Int64) {
	var n atomic.Int64
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><title>API</title><a href="/users">u</a></html>`)
		case "/users", "/books/v1":
			fmt.Fprint(w, `{"users":[{"id":1}]}`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"not found"}`)
		}
	})), &n
}

// BenchmarkRunOneApp is `azhaq run -url SITE` on one app, with and without
// -no-tech: wall time, requests and the peak heap of the process.
func BenchmarkRunOneApp(b *testing.B) {
	for _, site := range []string{"catchall", "api"} {
		for _, flag := range []string{"", "-no-tech"} {
			name := site + "/tech"
			if flag != "" {
				name = site + "/no-tech"
			}
			b.Run(name, func(b *testing.B) {
				devnull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
				defer devnull.Close()
				var peak uint64
				for i := 0; i < b.N; i++ {
					var srv *httptest.Server
					var n *atomic.Int64
					if site == "catchall" {
						srv, n = catchAllSite(50 << 10)
					} else {
						srv, n = apiSite()
					}
					fetch.Reset()
					runtime.GC()
					dir := b.TempDir()
					b.Setenv("AZHAQ_DATA_DIR", dir)
					args := []string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-db", dir + "/r.db", "-json"}
					if flag != "" {
						args = append(args, flag)
					}
					stop := make(chan struct{})
					done := make(chan struct{})
					go func() { // sample the heap while the run goes
						defer close(done)
						var m runtime.MemStats
						profiled := false
						for {
							if f := os.Getenv("BENCH_HEAPPROF"); f != "" && !profiled && n.Load() > 1100 {
								profiled = true // live heap near the end of the sweep
								runtime.GC()
								if out, err := os.Create(f); err == nil {
									_ = pprof.WriteHeapProfile(out)
									out.Close()
								}
							}
							runtime.ReadMemStats(&m)
							peak = max(peak, m.HeapInuse)
							select {
							case <-stop:
								return
							case <-time.After(5 * time.Millisecond):
							}
						}
					}()
					oo, oe := os.Stdout, os.Stderr
					os.Stdout, os.Stderr = devnull, devnull
					start := time.Now()
					_ = run(args)
					el := time.Since(start)
					os.Stdout, os.Stderr = oo, oe
					close(stop)
					<-done
					srv.Close()
					b.ReportMetric(float64(el.Milliseconds()), "ms/run")
					b.ReportMetric(float64(n.Load()), "requests")
				}
				b.ReportMetric(float64(peak>>20), "peakheapMB")
			})
		}
	}
}
