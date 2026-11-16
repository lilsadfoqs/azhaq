package hunt

import (
	"net/url"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
)

// What a route's own answer proves, and what a roles verdict proves, are
// decided here, once: `hunt` ranks the findings and `report -findings` records
// them from the same predicates, so a workspace has one population of them.

// Considered says a map row's answer is one to read: not a catch-all or a gone
// route, not an asset, and not an answer that equals a baseline of its host.
func Considered(r engine.MapEntry, verdicts map[string]proof.Verdict) bool {
	if r.Coverage == "catchall" || r.Coverage == "gone" || staticURL(r) {
		return false
	}
	v, judged := verdicts[r.Entity.Key]
	return !(judged && v.Dropped())
}

// Served says a row was fetched and answered 2xx.
func Served(r engine.MapEntry) bool {
	return r.Coverage == "visited" && r.Status >= 200 && r.Status < 300
}

// IsListing says a page title is a web server's directory listing.
func IsListing(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	return strings.HasPrefix(t, "index of") || strings.Contains(t, "listing directory") || strings.HasPrefix(t, "directory listing for")
}

// ProvedErrorText says the error text of a 5xx body (webextract's kinds) is a
// finding by itself: an SQL error or a framework's debug page. A stack trace
// is a finding by its own record (three frames, any status).
func ProvedErrorText(kind string) bool {
	return kind == webextract.ErrSQL || kind == webextract.ErrDebug
}

// What GraphQLRead finds.
const (
	GraphQLSchema = "schema" // the schema was read by introspection or recovered from the server's errors
	GraphQLIDE    = "ide"    // a GraphiQL or Playground page answers
)

// GraphQLRead says what a route's answer shows of GraphQL: its schema read
// (partial: recovered from validation errors, introspection being off), an IDE
// page, or "" (nothing, or only an answer that looks like GraphQL).
func GraphQLRead(r engine.MapEntry) (what string, partial bool) {
	for _, op := range r.Ops {
		if op.Source == "graphql" {
			return GraphQLSchema, op.Partial
		}
	}
	p := ""
	if u, err := url.Parse(r.Entity.Key); err == nil {
		p = strings.ToLower(u.Path)
	}
	if strings.Contains(r.Proof, "role=graphql") && strings.Contains(p, "graphiql") || strings.Contains(strings.ToLower(r.Title), "graphiql") {
		return GraphQLIDE, false
	}
	return "", false
}

// Proved says a roles verdict shows one role reaching another's data: a verdict
// that counts for the ranking, from a row whose owner is proved (or has no
// confidence, as older roles output has none).
func (r RoleRow) Proved() bool {
	_, ok := verdictWeight[r.Verdict]
	return ok && (r.Confidence == "" || r.Confidence == "proved")
}

// Weight is the rank a roles verdict has, scaled by its confidence.
func (r RoleRow) Weight() int {
	w := verdictWeight[r.Verdict]
	if s, ok := confidenceScale[r.Confidence]; ok {
		w = w * s / 100
	}
	return w
}

// Route is the template a roles row is of, or its URL.
func (r RoleRow) Route() string {
	if r.Template != "" {
		return r.Template
	}
	return r.URL
}

// ProvedScore is the rank of a finding of a kind `report -findings` records
// from a route's answer, as the ranking weighs it.
func ProvedScore(kind string) int {
	switch kind {
	case "sql-error":
		return serverErrorSQL
	case "debug-page":
		return serverErrorDebug
	case "directory-listing":
		return weights["listing"]
	case "graphql-schema", "graphql-ide":
		return graphqlStrong
	}
	return 0
}
