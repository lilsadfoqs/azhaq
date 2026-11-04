package dirscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// An event stream is cut as probe cuts it, its row says so, and the other
// rows are whole.
func TestSweepCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	fetch.Reset()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			chunk := []byte(strings.Repeat("data: tick\n", 1500))
			for {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-done:
					return
				case <-r.Context().Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	defer close(done)
	c := New(srv.Client(), Options{Words: []string{"admin", "events"}, Rate: 1000, Threads: 1})
	rows := map[string]map[string]any{}
	start := time.Now()
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		if u, ok := m["url"].(string); ok && o.Kind != "dirs" {
			rows[strings.TrimPrefix(u, srv.URL)] = m
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the stream held the sweep for %v", took)
	}
	ev := rows["/events"]
	if ev == nil || ev["truncated"] != true {
		t.Fatalf("/events: row %v, want one with truncated true", ev)
	}
	if n, _ := ev["length"].(float64); n < 60<<10 || n > 70<<10 {
		t.Errorf("/events length %v, want about 64 KiB (what was read)", ev["length"])
	}
	if ad := rows["/admin"]; ad == nil || ad["truncated"] != nil || ad["status"].(float64) != 403 {
		t.Errorf("/admin: %v, want a whole 403 row", ad)
	}
}
