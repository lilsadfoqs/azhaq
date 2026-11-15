// Command detectgen compiles nuclei's detection templates into the embedded
// data that internal/detect matches against responses.
//
//	go run ./scripts/detectgen -src DIR -out internal/detect -tag v10.5.2 -commit SHA
//
// DIR is an unpacked nuclei-templates release. Only http/technologies and
// http/exposed-panels are read, and only the requests the engine can honour
// are kept; the rest is counted by reason in SOURCE.md.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/lilsadfoqs/azhaq/internal/detect"
)

var sourceDirs = []string{"http/technologies", "http/exposed-panels"}

func main() {
	src := flag.String("src", "", "unpacked nuclei-templates release")
	out := flag.String("out", "internal/detect", "output directory")
	tag := flag.String("tag", "", "release tag")
	commit := flag.String("commit", "", "release commit")
	flag.Parse()
	if *src == "" {
		fmt.Fprintln(os.Stderr, "detectgen: -src is required")
		os.Exit(2)
	}
	if err := run(*src, *out, *tag, *commit); err != nil {
		fmt.Fprintln(os.Stderr, "detectgen:", err)
		os.Exit(1)
	}
}

func run(src, out, tag, commit string) error {
	res, err := compileTree(src)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res.data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "templates.json.gz"), buf.Bytes(), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "SOURCE.md"), []byte(sourceDoc(res, tag, commit)), 0o644); err != nil {
		return err
	}
	lic, err := os.ReadFile(filepath.Join(src, "LICENSE.md"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "LICENSE.md"), lic, 0o644); err != nil {
		return err
	}
	fmt.Printf("compiled %d units from %d templates, skipped %d, %d bytes\n",
		len(res.data.Units), res.templates, total(res.data.Skipped), buf.Len())
	return nil
}

type result struct {
	data             detect.Data
	templates        int // templates with at least one compiled unit
	extractorsDroped int
}

func total(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

type template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name string `yaml:"name"`
	} `yaml:"info"`
	HTTP     []map[string]any `yaml:"http"`
	Requests []map[string]any `yaml:"requests"`
	Flow     any              `yaml:"flow"`
	Self     bool             `yaml:"self-contained"`
	Vars     any              `yaml:"variables"`
}

func compileTree(src string) (*result, error) {
	var files []string
	for _, d := range sourceDirs {
		root := filepath.Join(src, d)
		err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !e.IsDir() && strings.HasSuffix(p, ".yaml") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)

	res := &result{data: detect.Data{Version: 1, Skipped: map[string]int{}}}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var t template
		if err := yaml.Unmarshal(raw, &t); err != nil {
			res.data.Skipped["yaml does not parse"]++
			continue
		}
		blocks := append(t.HTTP, t.Requests...)
		if len(blocks) == 0 {
			res.data.Skipped["no http request"]++
			continue
		}
		kept := 0
		for _, b := range blocks {
			u, dropped, reason := compileBlock(&t, b)
			res.extractorsDroped += dropped
			if reason != "" {
				res.data.Skipped[reason]++
				continue
			}
			res.data.Units = append(res.data.Units, *u)
			kept++
		}
		if kept > 0 {
			res.templates++
		}
	}
	sort.SliceStable(res.data.Units, func(i, j int) bool { return res.data.Units[i].ID < res.data.Units[j].ID })
	return res, nil
}

var blockKeys = map[string]bool{
	"method": true, "path": true, "matchers": true, "matchers-condition": true,
	"extractors": true, "stop-at-first-match": true, "redirects": true,
	"host-redirects": true, "max-redirects": true,
}

// blockReasons name the keys that change what is requested or how.
var blockReasons = map[string]string{
	"raw": "raw request", "payloads": "payloads", "attack": "payloads", "threads": "payloads",
	"body": "request body", "headers": "custom request headers",
}

func compileBlock(t *template, b map[string]any) (u *detect.Unit, dropped int, reason string) {
	if t.Flow != nil {
		return nil, 0, "flow"
	}
	if t.Self {
		return nil, 0, "self-contained"
	}
	if t.Vars != nil {
		return nil, 0, "template variables"
	}
	keys := make([]string, 0, len(b))
	for k := range b {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if blockKeys[k] {
			continue
		}
		if r, ok := blockReasons[k]; ok {
			return nil, 0, r
		}
	}
	for _, k := range keys {
		if !blockKeys[k] {
			return nil, 0, "unsupported request key " + k
		}
	}
	if m, ok := b["method"]; ok && !strings.EqualFold(str(m), "GET") {
		return nil, 0, "method " + strings.ToUpper(str(m))
	}
	if v, ok := b["redirects"]; ok && v == false {
		return nil, 0, "redirects disabled"
	}

	unit := &detect.Unit{ID: t.ID}
	paths, reason := compilePaths(b["path"])
	if reason != "" {
		return nil, 0, reason
	}
	unit.Paths = paths

	switch c := strings.ToLower(str(b["matchers-condition"])); c {
	case "", "or":
	case "and":
		unit.And = true
	default:
		return nil, 0, "matchers-condition " + c
	}
	ms, _ := b["matchers"].([]any)
	if len(ms) == 0 {
		return nil, 0, "no matchers"
	}
	names := map[string]bool{}
	for _, raw := range ms {
		m, reason := compileMatcher(raw)
		if reason != "" {
			return nil, 0, reason
		}
		if m.Name != "" {
			names[m.Name] = true
		}
		unit.Matchers = append(unit.Matchers, *m)
	}
	xs, _ := b["extractors"].([]any)
	for _, raw := range xs {
		x, internal, ok := compileExtractor(raw)
		if internal {
			return nil, 0, "internal extractor"
		}
		if !ok {
			dropped++
			continue
		}
		unit.Extractors = append(unit.Extractors, *x)
	}

	title := t.Info.Name
	if title == "" {
		title = t.ID
	}
	unit.Product = detect.Product(title)
	unit.Multi = !unit.And && len(names) >= detect.MatcherNamed
	return unit, dropped, ""
}

func compilePaths(v any) ([]string, string) {
	list, _ := v.([]any)
	if len(list) == 0 {
		return nil, "no path"
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range list {
		p := str(raw)
		var rest string
		switch {
		case strings.HasPrefix(p, "{{BaseURL}}"):
			rest = strings.TrimPrefix(p, "{{BaseURL}}")
		case strings.HasPrefix(p, "{{RootURL}}"):
			rest = strings.TrimPrefix(p, "{{RootURL}}")
		default:
			return nil, "path is not relative to the base URL"
		}
		if strings.Contains(rest, "{{") {
			return nil, "path uses variables"
		}
		if !strings.HasPrefix(rest, "/") {
			rest = "/" + rest
		}
		if !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
	}
	return out, ""
}

var matcherKeys = map[string]bool{
	"type": true, "name": true, "part": true, "words": true, "regex": true, "status": true,
	"dsl": true, "condition": true, "negative": true, "case-insensitive": true,
}

func compileMatcher(raw any) (*detect.Matcher, string) {
	mm, _ := raw.(map[string]any)
	if mm == nil {
		return nil, "malformed matcher"
	}
	if mm["internal"] == true {
		return nil, "internal matcher"
	}
	typ := str(mm["type"])
	if typ != "word" && typ != "regex" && typ != "status" && typ != "dsl" {
		return nil, "matcher type " + typ
	}
	keys := make([]string, 0, len(mm))
	for k := range mm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !matcherKeys[k] {
			return nil, "unsupported matcher key " + k
		}
	}
	m := &detect.Matcher{Type: typ, Name: str(mm["name"])}
	switch c := strings.ToLower(str(mm["condition"])); c {
	case "", "or":
	case "and":
		m.And = true
	default:
		return nil, "matcher condition " + c
	}
	m.Neg = mm["negative"] == true
	m.CI = mm["case-insensitive"] == true
	if typ == "status" {
		for _, s := range list(mm["status"]) {
			n := 0
			if _, err := fmt.Sscanf(str(s), "%d", &n); err != nil {
				return nil, "malformed status matcher"
			}
			if n >= 300 && n < 400 {
				return nil, "status 3xx needs an unfollowed redirect"
			}
			m.Status = append(m.Status, n)
		}
	} else {
		field := map[string]string{"word": "words", "regex": "regex", "dsl": "dsl"}[typ]
		for _, v := range list(mm[field]) {
			s := str(v)
			if strings.Contains(s, "{{") {
				return nil, "matcher uses variables"
			}
			m.Vals = append(m.Vals, s)
		}
	}
	if typ != "status" && typ != "dsl" {
		part, ok := detect.NormalizePart(str(mm["part"]))
		if !ok {
			return nil, "part " + str(mm["part"])
		}
		m.Part = part
	}
	if err := detect.Prepare(m); err != nil {
		reason := err.Error()
		if typ == "dsl" && !strings.HasPrefix(reason, "empty") {
			reason = "dsl " + reason
		}
		return nil, reason
	}
	return m, ""
}

// compileExtractor reports internal extractors, which feed other requests,
// and ok=false for ones the engine cannot run; those are dropped and only
// cost the version.
func compileExtractor(raw any) (x *detect.Extractor, internal, ok bool) {
	mm, _ := raw.(map[string]any)
	if mm == nil {
		return nil, false, false
	}
	if mm["internal"] == true {
		return nil, true, false
	}
	typ := str(mm["type"])
	x = &detect.Extractor{Type: typ}
	switch typ {
	case "regex":
		for _, v := range list(mm["regex"]) {
			x.Vals = append(x.Vals, str(v))
		}
		fmt.Sscanf(str(mm["group"]), "%d", &x.Group)
	case "kval":
		for _, v := range list(mm["kval"]) {
			x.Vals = append(x.Vals, str(v))
		}
	default:
		return nil, false, false
	}
	part, pok := detect.NormalizePart(str(mm["part"]))
	if !pok {
		return nil, false, false
	}
	x.Part = part
	if detect.PrepareExtractor(x) != nil {
		return nil, false, false
	}
	return x, false, true
}

func list(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case nil:
		return nil
	}
	return []any{v}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func sourceDoc(res *result, tag, commit string) string {
	var b strings.Builder
	b.WriteString("# Detection templates\n\n")
	b.WriteString("`templates.json.gz` is compiled from the MIT-licensed nuclei-templates\n")
	b.WriteString("(`http/technologies` and `http/exposed-panels`); see `LICENSE.md`.\n\n")
	fmt.Fprintf(&b, "- Release tag: %s\n- Commit: %s\n", orNone(tag), orNone(commit))
	fmt.Fprintf(&b, "- Compiled: %d requests from %d templates\n", len(res.data.Units), res.templates)
	fmt.Fprintf(&b, "- Skipped: %d\n", total(res.data.Skipped))
	fmt.Fprintf(&b, "- Extractors dropped (unsupported type or part, only the version is lost): %d\n\n", res.extractorsDroped)
	b.WriteString("## Skipped by reason\n\n")
	type kv struct {
		k string
		n int
	}
	var rs []kv
	for k, n := range res.data.Skipped {
		rs = append(rs, kv{k, n})
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].n != rs[j].n {
			return rs[i].n > rs[j].n
		}
		return rs[i].k < rs[j].k
	})
	for _, r := range rs {
		fmt.Fprintf(&b, "- %s: %d\n", r.k, r.n)
	}
	b.WriteString("\n## Semantics kept and relaxed\n\n")
	b.WriteString("- The caller supplies the response, so `redirects`, `host-redirects` and `max-redirects` are ignored;\n")
	b.WriteString("  templates that need an unfollowed redirect (`redirects: false`, a 3xx status matcher) are skipped.\n")
	b.WriteString("- `stop-at-first-match` only limits which paths a scanner requests, so every path is matched on its own.\n")
	b.WriteString("- Extractors of other types than regex and kval, or on an unknown part, are dropped; the match stays.\n\n")
	b.WriteString("## Regenerate\n\n")
	b.WriteString("Unpack a nuclei-templates release, then run from the repository root:\n\n")
	b.WriteString("```\ngo run ./scripts/detectgen -src DIR -out internal/detect -tag TAG -commit SHA\n```\n\n")
	b.WriteString("The output is deterministic: the same release gives the same bytes.\n")
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "(not given)"
	}
	return s
}
