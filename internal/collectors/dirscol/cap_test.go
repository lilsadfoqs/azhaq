package dirscol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/types"
)

func capped(t *testing.T, c *Collector, base string) (types.RunMeta, error, []types.Observation) {
	t.Helper()
	var rows []types.Observation
	batch := func(o []types.Observation) error { rows = append(rows, o...); return nil }
	ctx := types.WithBatchEmit(context.Background(), batch)
	meta, err := c.Run(ctx, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": base}}, func(o types.Observation) error {
		rows = append(rows, o)
		return nil
	})
	return meta, err, rows
}

// Calibration the budget cut short is not an answered calibration: with no
// word left to ask (all held back) the sweep used to end done, its filter
// half learned. It is capped, and azhaq resume makes it whole.
func TestCalibrationCutByTheBudgetLeavesTheSweepUndone(t *testing.T) {
	fetch.Reset()
	egress.Reset()
	t.Cleanup(func() { fetch.Reset(); egress.Reset() })
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	egress.SetDenyPath(scope.Rules{DenyPath: []string{`^/logout`}}.Compile().DeniedPath)
	egress.SetMaxRequests(2) // two of the four shapes
	c := New(srv.Client(), Options{Words: []string{"logout"}, Rate: 1000, Threads: 1})
	meta, err, _ := capped(t, c, srv.URL+"/")
	if !errors.Is(err, neterr.ErrBudget) || meta.Status != types.StatusCapped {
		t.Errorf("status %q, error %v: a sweep with half its calibration is not done", meta.Status, err)
	}
}

// The requests of a task the budget stopped that were sent and failed are
// kept (Keep) as error rows, one for each cause: the engine drops the
// task's own error, and a resume redoes the sweep.
func TestRequestsThatFailedBeforeTheCapAreKeptAsErrorRows(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	for _, tc := range []struct {
		name string
		opts Options
		max  int64
	}{
		{"calibrated, one request", Options{Threads: 8}, 1},
		{"calibrated, two requests", Options{Threads: 8}, 2},
		{"calibrated, three requests", Options{Threads: 8}, 3},
		{"no calibration, one request", Options{NoCalibration: true, Threads: 8}, 1},
	} {
		for i := 0; i < 10; i++ { // threads race the cap: every order keeps the failure
			fetch.Reset()
			egress.Reset()
			egress.SetMaxRequests(tc.max)
			tc.opts.Words, tc.opts.Rate = []string{"one", "two", "three"}, 1000
			c := New(http.DefaultClient, tc.opts)
			meta, err, rows := capped(t, c, "http://"+addr+"/")
			var kept []map[string]any
			for _, o := range rows {
				if o.Kind == "error" && o.Keep {
					var m map[string]any
					_ = json.Unmarshal(o.Payload, &m)
					kept = append(kept, m)
				}
			}
			if !errors.Is(err, neterr.ErrBudget) || meta.Status != types.StatusCapped || len(kept) != 1 || kept[0]["url"] != "http://"+addr+"/" {
				t.Fatalf("%s: status %q, error %v, kept %v", tc.name, meta.Status, err, kept)
			}
		}
	}
	egress.Reset()
	fetch.Reset()
}
