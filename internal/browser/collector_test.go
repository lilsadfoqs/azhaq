package browser

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// The requests Chrome sends for a page carry the name of the collector that
// loaded it, so a run counts them in that collector's stage, not in "other".
func TestChromeRequestsCarryTheCollectorOfTheLoad(t *testing.T) {
	srv := newRecorder(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><title>t</title><link rel=stylesheet href=/a.css><script src=/a.js></script><img src=/i.png>`))
			return
		}
		_, _ = w.Write([]byte("x"))
	})
	defer srv.Close()
	b := startChrome(t)
	egress.Reset()
	defer egress.Reset()
	before := ledger.Account()
	ctx, cancel := context.WithTimeout(ledger.WithCollector(context.Background(), "azhaq-shots"), 40*time.Second)
	defer cancel()
	if _, err := b.Load(ctx, srv.URL+"/", true); err != nil {
		t.Fatal(err)
	}
	var named, unnamed int64
	for k, n := range ledger.Account() {
		if k.Kind != "chrome" {
			continue
		}
		switch d := n - before[k]; k.Collector {
		case "azhaq-shots":
			named += d
		case "":
			unnamed += d
		}
	}
	if named < 2 || unnamed != 0 {
		t.Errorf("Chrome's requests: %d under azhaq-shots, %d with no collector; want the page and its assets under azhaq-shots", named, unnamed)
	}
}
