package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/collectors/jscol"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/types"
)

// mapRow is what the js collector kept of a source map it read
// (jscol.MapKind): the answer's status and every source, not the code.
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
	NamesCut int  `json:"source_files_cut"`
	Guessed  bool `json:"guessed"`
}

// mapCode is the code of one of the app's own sources.
type mapCode struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

// mapCodeFrom reads the code of the app's own sources from the answer -sr
// wrote for the map (its header block, a blank line, the body). The reason
// is "" when the code was read.
func mapCodeFrom(file string) ([]mapCode, string) {
	if file == "" {
		return nil, "the code was not kept: a run with -sr keeps it"
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, "the code was not kept: the -sr file " + file + " is gone (" + err.Error() + ")"
	}
	parts := strings.SplitN(string(raw), "\n\n", 4)
	if len(parts) < 4 || strings.TrimSpace(parts[3]) == "" {
		return nil, "the code was not kept: the -sr file " + file + " holds no body (-ob)"
	}
	var m struct {
		Sources        []string  `json:"sources"`
		SourcesContent []*string `json:"sourcesContent"`
	}
	if json.Unmarshal([]byte(parts[3]), &m) != nil {
		return nil, "the code was not kept: the -sr file " + file + " holds no source map"
	}
	var out []mapCode
	for i, name := range m.Sources {
		if i < len(m.SourcesContent) && m.SourcesContent[i] != nil && !jscol.Library(name) {
			out = append(out, mapCode{name, *m.SourcesContent[i]})
		}
	}
	return out, ""
}

// printSourceMap prints what the run kept of the source map behind obs: the
// answer's status and each source with whether the map carries its code, and
// with body the code of the app's own files, read from file, the answer -sr
// wrote ("" when the run kept none). Every line is escaped, as an answer's is.
func printSourceMap(obs []types.StoredObservation, file string, body bool) {
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
	if !body {
		if file != "" && m.WithCode > 0 {
			fmt.Printf("  the map's answer is kept in %s: show -body prints the app's own code\n", file)
		}
		return
	}
	code, why := mapCodeFrom(file)
	if why != "" {
		fmt.Printf("  %s\n", why)
		return
	}
	for _, c := range code {
		fmt.Printf("code of %s (%d bytes)\n", line(c.Name), len(c.Text))
		for _, l := range bytes.SplitAfter([]byte(c.Text), []byte("\n")) {
			fmt.Printf("    %s\n", proof.Printable(bytes.TrimRight(l, "\r\n"), 4*len(l)+8))
		}
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
