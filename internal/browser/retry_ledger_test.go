package browser

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/chromedp/cdproto/network"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A request Chrome pauses again under its network ID with the same URL (a
// retry) may have reached the server the first time: both tries are listed
// and counted, when Chrome says each went out or when the page ends, never
// given back. A redirect's next hop lists the hop before it.
func TestARetriedRequestIsListedForEveryTry(t *testing.T) {
	for _, c := range []struct {
		name  string
		steps func(b *Browser, g func(string) letGo)
		want  int
	}{
		{"both tries heard leaving", func(b *Browser, g func(string) letGo) {
			b.sending("1", g("/a.css"))
			b.pausedAgain("1", "http://x.test/a.css")
			b.sending("1", g("/a.css"))
			b.sentOff("1")
			b.sentOff("1")
		}, 2},
		{"the first try not heard of", func(b *Browser, g func(string) letGo) {
			b.sending("1", g("/a.css"))
			b.pausedAgain("1", "http://x.test/a.css")
			b.sending("1", g("/a.css"))
			b.sentOff("1")
			b.unheard(nil) // the page ended: the first try may have left
		}, 2},
		{"a redirect", func(b *Browser, g func(string) letGo) {
			b.sending("1", g("/old"))
			b.pausedAgain("1", "http://x.test/new")
			b.sending("1", g("/new"))
			b.sentOff("1")
		}, 2},
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
			b := &Browser{}
			g := func(p string) letGo {
				if err := egress.Take(); err != nil {
					t.Fatal(err)
				}
				return letGo{ctx: context.Background(), method: "GET", url: "http://x.test" + p}
			}
			c.steps(b, g)
			l.Close()
			n := 0
			_ = ledger.Read(path, func(e ledger.Entry) error {
				if e.Target != "" {
					n++
				}
				return nil
			})
			if n != c.want || egress.Sent() != int64(c.want) || len(b.out[network.RequestID("1")]) != 0 {
				t.Errorf("ledger %d lines, counted %d, left pending %d; want %d listed and counted", n, egress.Sent(), len(b.out["1"]), c.want)
			}
		})
	}
}
