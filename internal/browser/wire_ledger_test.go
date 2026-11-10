package browser

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A plain HTTP request is listed and counted as the guard saw it on the
// wire, which Chrome's events cannot tell: a retry that reached the server
// is two requests, one that did not is one, a cache hit revalidated is one,
// and a request no pause held is one.
func TestPlainHTTPIsListedAsTheWireSawIt(t *testing.T) {
	const u = "http://x.test/a.css"
	for _, c := range []struct {
		name  string
		steps func(b *Browser, let func())
		want  int
	}{
		{"a retry, both tries on the wire", func(b *Browser, let func()) {
			let()
			b.pausedAgain("1", u)
			let()
			b.wireSent("GET", u)
			b.wireSent("GET", u)
		}, 2},
		{"a retry, one try on the wire", func(b *Browser, let func()) {
			let()
			b.pausedAgain("1", u)
			let()
			b.wireSent("GET", u)
			b.unheard(nil)
		}, 1},
		{"a cache hit revalidated", func(b *Browser, let func()) {
			let()
			b.fromCache("1")
			b.wireSent("GET", u)
			b.unheard(nil)
		}, 1},
		{"a cache hit", func(b *Browser, let func()) {
			let()
			b.fromCache("1")
			b.unheard(nil)
		}, 0},
		{"let go, never on the wire", func(b *Browser, let func()) {
			let()
			b.unheard(nil)
		}, 0},
		{"on the wire, no pause held it", func(b *Browser, let func()) {
			b.wireSent("GET", u)
		}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			egress.Reset()
			defer egress.Reset()
			path := filepath.Join(t.TempDir(), "l.jsonl")
			l, err := ledger.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			ledger.Use(l)
			defer ledger.Use(nil)
			g, err := egress.NewChromeGuard(func(string) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			b := &Browser{guard: g}
			let := func() {
				if err := egress.Take(); err != nil {
					t.Fatal(err)
				}
				b.sending("1", letGo{ctx: context.Background(), method: "GET", url: u})
			}
			c.steps(b, let)
			l.Close()
			n := 0
			_ = ledger.Read(path, func(e ledger.Entry) error {
				if e.Counted() {
					n++
				}
				return nil
			})
			if n != c.want || egress.Sent() != int64(c.want) {
				t.Errorf("ledger %d, counted %d; want %d of each", n, egress.Sent(), c.want)
			}
		})
	}
}
