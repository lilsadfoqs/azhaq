package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// The kinds of finding a route's own answer shows besides a path check's file
// or panel and a stack trace. `hunt` ranks the same records (hunt.Input.Measured),
// so both read one population of them.
const (
	sqlErrorKind   = "sql-error"
	debugPageKind  = "debug-page"
	listingKind    = "directory-listing"
	gqlSchemaKind  = "graphql-schema"
	gqlIDEKind     = "graphql-ide"
	crossRoleKind  = "cross-role-access"
	graphqlSchemaQ = `{__schema{queryType{name}}}`
)

// webMeasuredKinds are the kinds of record hunt shows as a row of its own, by URL.
var webMeasuredKinds = map[string]bool{
	traceKind: true, sqlErrorKind: true, debugPageKind: true, listingKind: true,
	gqlSchemaKind: true, gqlIDEKind: true, crossRoleKind: true,
}

// errAnswer is what a 5xx answer's body gave away, from the row that stored it.
type errAnswer struct {
	kind, sample, collector string
	status                  int
	contentType             string
	at                      time.Time
}

func errAnswersOf(obs []types.StoredObservation) map[string]errAnswer {
	out := map[string]errAnswer{}
	for _, o := range obs {
		if o.Collector != "azhaq-http" {
			continue
		}
		if p, err := httprow.ParseRow(o.Payload); err == nil && p.ErrorText != "" {
			out[o.EntityID] = errAnswer{p.ErrorText, p.ErrorSample, o.Collector, p.Status, p.ContentType, o.ObservedAt}
		}
	}
	return out
}

// schemaAnswer is the GraphQL schema read of an endpoint: the newest answer wins.
type schemaAnswer struct {
	url       string
	status    int
	queries   []string
	mutations []string
	types     []string
	recovered bool
	at        time.Time
	collector string
}

func schemaAnswersOf(obs []types.StoredObservation) map[string]schemaAnswer {
	out := map[string]schemaAnswer{}
	for _, o := range obs {
		if o.Collector != "azhaq-graphql-schema" || o.Kind != "graphql" {
			continue
		}
		var p struct {
			URL       string   `json:"url"`
			Status    int      `json:"status"`
			Queries   []string `json:"queries"`
			Mutations []string `json:"mutations"`
			Types     []string `json:"types"`
			Recovered string   `json:"recovered"`
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		out[o.EntityID] = schemaAnswer{p.URL, p.Status, p.Queries, p.Mutations, p.Types, p.Recovered != "", o.ObservedAt, o.Collector}
	}
	return out
}

// webFindings are the findings a route's own answer shows, read from the map's
// rows by hunt's predicates: SQL error text or a debug page in a 5xx, a
// directory listing, a GraphQL schema read or IDE. One record for each URL and
// kind. answers and verdicts are the path checks' (proof.AnswersOf and Judge).
func webFindings(rows []engine.MapEntry, obs []types.StoredObservation, answers map[string]proof.Answer, verdicts map[string]proof.Verdict, command string) []findingRecord {
	errs, schemas := errAnswersOf(obs), schemaAnswersOf(obs)
	var out []findingRecord
	add := func(rec findingRecord) {
		rec.Tier, rec.Label, rec.Command = proof.TierFinding, "proved", command
		rec.Host, rec.Port = hostPort(rec.URL)
		rec.Request = rec.Proof.Method + " " + rec.URL
		out = append(out, rec)
	}
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL || r.Role == "sourcemap" || !hunt.Considered(r, verdicts) {
			continue
		}
		raw := r.Entity.Key
		a := answers[raw]
		page := func(status int, ct string, at time.Time, via, excerpt string) *proof.Proof {
			if via == "" {
				via = "azhaq-http"
			}
			return &proof.Proof{ObservedAt: stamp(at), Method: "GET", Target: raw, Status: status, ContentType: ct, Excerpt: excerpt,
				ExcerptPart: "body", How: via, Reproduce: proof.Curl("GET", raw)}
		}
		if e, ok := errs[r.Entity.ID]; ok && r.Status >= 500 && hunt.ProvedErrorText(e.kind) {
			kind, what, sev := sqlErrorKind, "the body has SQL error text", "medium"
			if e.kind == webextract.ErrDebug {
				kind, what = debugPageKind, "the body is a framework's debug page"
			}
			add(findingRecord{Kind: kind, Severity: sev, URL: raw, Collector: e.collector,
				Evidence: fmt.Sprintf("HTTP %d: %s: %s", e.status, what, e.sample),
				Proof:    page(e.status, e.contentType, e.at, e.collector, first(e.sample, "(the error text)"))})
		}
		if hunt.Served(r) && hunt.IsListing(r.Title) {
			add(findingRecord{Kind: listingKind, Severity: "low", URL: raw, Collector: viaOf(a),
				Evidence: fmt.Sprintf("HTTP %d: the page's title is a directory listing: %s", r.Status, r.Title),
				Proof:    page(r.Status, a.ContentType, a.Observed, a.Via, "title: "+proof.Printable([]byte(r.Title), proof.MaxExcerpt))})
		}
		switch what, partial := hunt.GraphQLRead(r); what {
		case hunt.GraphQLSchema:
			if s, ok := schemas[r.Entity.ID]; ok {
				add(schemaRecord(raw, s, partial))
			}
		case hunt.GraphQLIDE:
			if v := verdicts[raw]; v.Tier == proof.TierFinding {
				break // the path check's panel record is this finding
			}
			add(findingRecord{Kind: gqlIDEKind, Severity: "low", URL: raw, Collector: viaOf(a),
				Evidence: fmt.Sprintf("HTTP %d: a GraphQL IDE answers: %s", r.Status, r.Title),
				Proof:    page(r.Status, a.ContentType, a.Observed, a.Via, "title: "+proof.Printable([]byte(first(r.Title, "GraphiQL")), proof.MaxExcerpt))})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func viaOf(a proof.Answer) string {
	if a.Via == "" {
		return "azhaq-http"
	}
	return a.Via
}

func first(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// schemaRecord is the finding for a GraphQL endpoint whose schema was read:
// the root fields and types the answer listed, and a POST that asks the same.
func schemaRecord(raw string, s schemaAnswer, partial bool) findingRecord {
	names := func(label string, xs []string) string {
		if len(xs) == 0 {
			return ""
		}
		shown := xs[:min(len(xs), 8)]
		more := ""
		if len(xs) > len(shown) {
			more = fmt.Sprintf(", and %d more", len(xs)-len(shown))
		}
		return label + " " + strings.Join(shown, ", ") + more
	}
	var parts []string
	for _, p := range []string{names("queries", s.queries), names("mutations", s.mutations)} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(s.types) > 0 {
		parts = append(parts, plural(len(s.types), "object type"))
	}
	excerpt := proof.Printable([]byte(strings.Join(parts, "; ")), proof.MaxExcerpt)
	query, how := graphqlSchemaQ, "the schema was read by introspection"
	if partial {
		how = "introspection is off: the root fields were recovered from the server's validation errors"
		query = "query { __typename }"
		if len(s.queries) > 0 {
			query = "query { " + s.queries[0] + " }"
		}
	}
	body, _ := json.Marshal(map[string]string{"query": query})
	p := &proof.Proof{ObservedAt: stamp(s.at), Method: "POST", Target: raw, RequestBytes: proof.EscapeBytes(body), Status: s.status,
		Excerpt: first(excerpt, "(no names listed)"), ExcerptPart: "body", How: s.collector,
		Reproduce: strings.Replace(proof.Curl("POST", raw), "-X POST", "-X POST -H 'Content-Type: application/json' --data "+proof.Quote(string(body)), 1)}
	return findingRecord{Kind: gqlSchemaKind, Severity: "low", URL: raw, Collector: s.collector, Proof: p,
		Evidence: fmt.Sprintf("HTTP %d: %s: %s", s.status, how, p.Excerpt)}
}
