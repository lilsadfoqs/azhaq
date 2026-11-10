package main

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/types"
)

// wrote names the screenshots and their HTML this run took, not those an
// earlier run of the workspace took.
func TestShotFilesAreThisRunsScreenshots(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	shot := func(at time.Time, row map[string]any) types.StoredObservation {
		raw, _ := json.Marshal(row)
		var o types.StoredObservation
		o.Collector, o.Kind, o.Payload, o.ObservedAt = "azhaq-shots", "screenshot", raw, at
		return o
	}
	obs := []types.StoredObservation{
		shot(start.Add(-time.Hour), map[string]any{"file": "old/a.png"}),
		shot(start, map[string]any{"file": "shots/b.png", "html_file": "shots/b.html"}),
		shot(start.Add(time.Second), map[string]any{"file": "shots/c.jpg"}),
	}
	got := shotFiles(obs, start)
	if want := []string{"shots/b.png", "shots/b.html", "shots/c.jpg"}; !slices.Equal(got, want) {
		t.Errorf("shotFiles = %q, want %q", got, want)
	}
}
