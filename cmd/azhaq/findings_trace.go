package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/lilsadfoqs/azhaq/internal/proof"
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
	at := map[string]int{} // URL and exception → its place in out
	for _, o := range obs {
		if !bytes.Contains(o.Payload, []byte(`"stack_trace"`)) {
			continue
		}
		var row struct {
			URL         string           `json:"url"`
			Status      int              `json:"status"`
			ContentType string           `json:"content_type"`
			Trace       webextract.Trace `json:"stack_trace"`
			Excerpt     string           `json:"trace_excerpt"`
			Offset      *int             `json:"trace_offset"`
		}
		if json.Unmarshal(o.Payload, &row) != nil || row.URL == "" || row.Trace.Frames == 0 {
			continue
		}
		key := row.URL + "|" + row.Trace.Exception
		excerpt := row.Excerpt
		if excerpt == "" {
			excerpt = proof.Printable([]byte(row.Trace.Exception), proof.MaxExcerpt)
		}
		rec := findingRecord{
			Tier: proof.TierFinding, Kind: "error-disclosure", Label: "proved", Severity: "low", URL: row.URL, Command: command,
			Request:   "GET " + row.URL,
			Evidence:  fmt.Sprintf("HTTP %d: %s (%d %s frames)", row.Status, row.Trace.Exception, row.Trace.Frames, row.Trace.Runtime),
			Collector: o.Collector,
			Proof:     traceProof(row.URL, o.Collector, row.Status, o.ObservedAt, excerpt, row.Offset, row.ContentType),
		}
		rec.Host, rec.Port = hostPort(row.URL)
		if i, seen := at[key]; seen {
			// One record per URL and exception: the answer that kept the bytes wins.
			if row.Excerpt != "" && out[i].Proof.ExcerptOffset == nil {
				out[i] = rec
			}
			continue
		}
		at[key] = len(out)
		out = append(out, rec)
	}
	return out
}
