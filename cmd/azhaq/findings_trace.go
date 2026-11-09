package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// traceFindingsOf reads the answers whose body held a stack trace, from the
// url rows the web collectors stored (the `stack_trace` of a probe or dirs
// row): one record per URL, kind error-disclosure, proved because the
// answer itself shows the trace, severity low because it shows no more than
// an error does. Nothing is asked again.
func traceFindingsOf(obs []types.StoredObservation, command string) []findingRecord {
	var out []findingRecord
	seen := map[string]bool{}
	for _, o := range obs {
		if !bytes.Contains(o.Payload, []byte(`"stack_trace"`)) {
			continue
		}
		var row struct {
			URL    string           `json:"url"`
			Status int              `json:"status"`
			Trace  webextract.Trace `json:"stack_trace"`
		}
		if json.Unmarshal(o.Payload, &row) != nil || row.URL == "" || row.Trace.Frames == 0 {
			continue
		}
		key := row.URL + "|" + row.Trace.Exception
		if seen[key] {
			continue
		}
		seen[key] = true
		rec := findingRecord{
			Kind: "error-disclosure", Label: "proved", Severity: "low", URL: row.URL, Command: command,
			Evidence:  fmt.Sprintf("HTTP %d: %s (%d %s frames)", row.Status, row.Trace.Exception, row.Trace.Frames, row.Trace.Runtime),
			Collector: o.Collector,
		}
		if u, err := url.Parse(row.URL); err == nil {
			rec.Host = u.Hostname()
			if p, err := strconv.Atoi(u.Port()); err == nil {
				rec.Port = p
			}
		}
		out = append(out, rec)
	}
	return out
}
