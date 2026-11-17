package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/lilsadfoqs/azhaq/internal/collectors/jscol"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/types"
)

// mapRow is what the js collector kept of a source map it read
// (jscol.MapKind): the answer's status, every source and the app's own code.
type mapRow struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	BodyLength  int    `json:"body_length"`
	Sources     int    `json:"sources"`
	WithCode    int    `json:"with_code"`
	SourceFiles []struct {
		Name    string `json:"name"`
		Code    bool   `json:"code"`
		Bytes   int    `json:"bytes"`
		Library bool   `json:"library"`
	} `json:"source_files"`
	Contents []struct {
		Name string `json:"name"`
		Text string `json:"text"`
	} `json:"contents"`
	NamesCut int  `json:"source_files_cut"`
	CodeCut  int  `json:"contents_cut"`
	Guessed  bool `json:"guessed"`
}

// withoutMapCode is a source map's payload without its code: a row listing
// is read for what it names, and the code is shown with -body.
func withoutMapCode(o types.StoredObservation) json.RawMessage {
	if o.Kind != jscol.MapKind {
		return o.Payload
	}
	var m map[string]any
	if json.Unmarshal(o.Payload, &m) != nil {
		return o.Payload
	}
	if c, ok := m["contents"].([]any); ok {
		delete(m, "contents")
		m["contents_omitted"] = len(c)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return o.Payload
	}
	return raw
}

// printSourceMap prints what the run kept of the source map behind obs: the
// answer's status, each source with whether the map carries its code, and
// with body the code kept. Every line is escaped, as an answer's is.
func printSourceMap(obs []types.StoredObservation, body bool) {
	var m *mapRow
	for _, o := range obs {
		if o.Kind != jscol.MapKind {
			continue
		}
		var r mapRow
		if json.Unmarshal(o.Payload, &r) == nil {
			m = &r
		}
	}
	if m == nil {
		printOldSourceMap(obs)
		return
	}
	line := func(s string) string { return proof.Printable([]byte(s), 4*fetch.ExcerptBytes) }
	lib := 0
	for _, f := range m.SourceFiles {
		if f.Library {
			lib++
		}
	}
	fmt.Printf("source map: status %d, %s (%d of a library), %d of the app's own with their code, %d bytes\n", m.Status, plural(m.Sources, "source"), lib, m.WithCode, m.BodyLength)
	for _, f := range m.SourceFiles {
		what := "no code"
		if f.Code {
			what = fmt.Sprintf("code, %d bytes", f.Bytes)
		}
		tag := ""
		if f.Library {
			tag = "  [library]"
		}
		fmt.Printf("  %s  %s%s\n", line(f.Name), what, tag)
	}
	if m.NamesCut > 0 {
		fmt.Printf("  … %d more sources, in the map and not listed here\n", m.NamesCut)
	}
	if lib > 0 {
		fmt.Printf("  the code of a [library] source is not kept; only the app's own is\n")
	}
	if len(m.Contents) == 0 {
		return
	}
	if !body {
		kept := 0
		for _, c := range m.Contents {
			kept += len(c.Text)
		}
		fmt.Printf("  the code of %s is kept (%d bytes): show -body prints it\n", plural(len(m.Contents), "file"), kept)
		return
	}
	for _, c := range m.Contents {
		fmt.Printf("code of %s (%d bytes)\n", line(c.Name), len(c.Text))
		for _, l := range bytes.SplitAfter([]byte(c.Text), []byte("\n")) {
			fmt.Printf("    %s\n", proof.Printable(bytes.TrimRight(l, "\r\n"), 4*len(l)+8))
		}
	}
	if m.CodeCut > 0 {
		fmt.Printf("  %s of the app's own with code did not fit the %d bytes kept for a map and are not shown\n", plural(m.CodeCut, "file"), fuzz.MaxBody)
	}
}

// printOldSourceMap says what a workspace made before the map's own row
// kept: the counts and the names of the app's own files, no code.
func printOldSourceMap(obs []types.StoredObservation) {
	for _, o := range obs {
		var p struct {
			Role     string   `json:"role"`
			Sources  int      `json:"sources"`
			WithCode *int     `json:"with_code"`
			Files    []string `json:"files"`
		}
		if o.Kind != "url" || json.Unmarshal(o.Payload, &p) != nil || p.Role != "sourcemap" {
			continue
		}
		fmt.Printf("source map: %s; this workspace kept the count and the app's own names, not the map's status or code\n", plural(p.Sources, "source"))
		for _, f := range p.Files {
			fmt.Printf("  %s\n", proof.Printable([]byte(f), 4*fetch.ExcerptBytes))
		}
		return
	}
}
