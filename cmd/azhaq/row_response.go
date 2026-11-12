package main

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/proof"
)

// responseFields are the fields of a row that its stored answer gives. They
// are not in the default row: a user asks for them.
var responseFields = []string{"headers", "body_excerpt", "body_length", "body_cut", "body_url", "asked_at"}

func wantsResponse(cols []string) bool {
	return slices.ContainsFunc(cols, func(c string) bool { return slices.Contains(responseFields, c) })
}

// addResponse sets the row's stored answer in row. oneLine writes the body
// as one printable line (a cell of a table), else it is the text as is.
func addResponse(row map[string]any, r engine.MapEntry, oneLine bool) {
	ev, ok := r.Response()
	if !ok {
		return
	}
	if len(ev.Headers) > 0 {
		row["headers"] = ev.Headers
	}
	if len(ev.Excerpt) > 0 {
		if oneLine {
			row["body_excerpt"] = proof.Printable(ev.Excerpt, 4*fetch.ExcerptBytes)
		} else {
			row["body_excerpt"] = string(ev.Excerpt)
		}
	}
	row["body_length"] = ev.BodyLength
	if ev.Cut {
		row["body_cut"] = true
	}
	if ev.BodyURL != "" {
		row["body_url"] = ev.BodyURL
	}
	if !ev.AskedAt.IsZero() {
		row["asked_at"] = ev.AskedAt.Format("2006-01-02T15:04:05Z")
	}
}

// printResponse prints a row's stored answer for show: headers, then the
// body's start. Every line is escaped: a target's bytes never reach the
// terminal as they came.
func printResponse(ev fetch.Evidence) {
	when := ""
	if !ev.AskedAt.IsZero() {
		when = " asked " + ev.AskedAt.Local().Format("2006-01-02 15:04:05")
	}
	fmt.Printf("answer%s\n", when)
	for _, l := range ev.HeaderLines() {
		fmt.Printf("  %s\n", proof.Printable([]byte(l), 4*fetch.ExcerptBytes))
	}
	if len(ev.Excerpt) == 0 {
		fmt.Printf("  body: %d bytes\n", ev.BodyLength)
		return
	}
	of := ""
	if ev.BodyURL != "" {
		of = " of " + ev.BodyURL
	}
	if ev.Cut {
		fmt.Printf("  body%s: first %d of %d bytes\n", of, len(ev.Excerpt), ev.BodyLength)
	} else {
		fmt.Printf("  body%s: %d bytes\n", of, ev.BodyLength)
	}
	for _, line := range bytes.SplitAfter(ev.Excerpt, []byte("\n")) {
		fmt.Printf("    %s\n", proof.Printable(bytes.TrimRight(line, "\r\n"), 4*fetch.ExcerptBytes))
	}
}

// answerText is a row's stored headers as text for the HTML report, "" when
// it kept none. The body's start is not in the report: a page can name hosts
// outside the scope.
func answerText(r engine.MapEntry) string {
	ev, ok := r.Response()
	if !ok || len(ev.Headers) == 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range ev.HeaderLines() {
		b.WriteString(proof.Printable([]byte(l), 4*fetch.ExcerptBytes) + "\n")
	}
	return b.String()
}
