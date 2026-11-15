package detect

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// page builds an HTML body of about size bytes that names no product.
func page(size int) []byte {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><title>Welcome</title></head><body>")
	for i := 0; b.Len() < size; i++ {
		b.WriteString(`<div class="row"><a href="/news/item-`)
		b.WriteString(strings.Repeat("x", i%7+1))
		b.WriteString(`.html">Latest headlines and weekly reports from the editorial desk</a><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.</p></div>`)
	}
	b.WriteString("</body></html>")
	return []byte(b.String())
}

func BenchmarkMatchRoot(b *testing.B) {
	Load()
	r := Response{Path: "/", Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: page(64 << 10)}
	b.SetBytes(int64(len(r.Body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Match(r)
	}
}

// BenchmarkMatchRootTypical is a WordPress home page: a handful of products
// named, so a few dozen matchers reach their full check.
func BenchmarkMatchRootTypical(b *testing.B) {
	Load()
	head := `<html><head><meta name="generator" content="WordPress 6.4.2"><title>Blog</title>` +
		`<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">` +
		`<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.css">` +
		`<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css">` +
		`<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>` +
		`<script src="/assets/bootstrap.min.js"></script></head><body>`
	body := append([]byte(head), page(60<<10)...)
	r := Response{Path: "/", Status: 200, Header: http.Header{"Server": {"nginx/1.24.0"}, "X-Powered-By": {"PHP/8.2"}}, Body: body}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Match(r)
	}
}

// BenchmarkMatchRootBusy pads the page with the needles of many templates, so
// the prefilter passes hundreds of candidates to their full matchers.
func BenchmarkMatchRootBusy(b *testing.B) {
	var d Data
	decode(&d)
	var needles []string
	for _, u := range d.Units {
		if len(u.Paths) > 0 && u.Paths[0] == "/" {
			for j, m := range u.Matchers {
				if len(m.Lits) > 0 && j%400 == 0 {
					needles = append(needles, strings.Join(m.Lits[0], " "))
				}
			}
		}
	}
	body := append(page(48<<10), []byte(strings.Join(needles, " "))...)
	Load()
	r := Response{Path: "/", Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: body}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Match(r)
	}
}

func BenchmarkLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		start := time.Now()
		var d Data
		decode(&d)
		build(&d)
		b.ReportMetric(float64(time.Since(start).Milliseconds()), "ms/load")
	}
}
