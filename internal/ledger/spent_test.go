package ledger

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

// What a command sent is counted by collector and stage whether or not a
// ledger is open, from any number of goroutines.
func TestAccountCountsWithoutALedger(t *testing.T) {
	Use(nil)
	then := Account()
	ctx := WithCollector(context.Background(), "azhaq-ports")
	end := SetStage("scan")
	defer end()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				TCP(ctx, "", "192.0.2.1:80")
			}
			TCPBatch(ctx, "", []string{"192.0.2.1:81", "192.0.2.1:82"})
			req, _ := http.NewRequestWithContext(WithCollector(context.Background(), "azhaq-http"), http.MethodGet, "http://192.0.2.1/", nil)
			HTTP(req)
			DNS(ctx, "example.com", "A", "192.0.2.53")
		}()
	}
	wg.Wait()
	got := func(k SpentKey) int64 { return Account()[k] - then[k] }
	for k, want := range map[SpentKey]int64{
		{ClassTarget, "tcp", "azhaq-ports", "scan"}:  8 * 102,
		{ClassTarget, "http", "azhaq-http", "scan"}:  8,
		{ClassDNS, "dns", "azhaq-ports", "scan"}:     8,
		{ClassTarget, "tcp", "azhaq-ports", "other"}: 0,
	} {
		if g := got(k); g != want {
			t.Errorf("%+v: %d, want %d", k, g, want)
		}
	}
	if k := LastSender(); k.Collector == "" || k.Stage != "scan" {
		t.Errorf("the last sender is %+v", k)
	}
	end()
	if Stage() != "" {
		t.Errorf("the stage is %q after it ended", Stage())
	}
}
