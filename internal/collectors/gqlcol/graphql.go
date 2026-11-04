// Package gqlcol recognises GraphQL endpoints and, behind -graphql, reads
// their schema through introspection. Recognising one takes a plain GET;
// introspection is a POST, so it is an active technique. The schema is
// kept whole (types, fields, arguments, input objects, enums) for the map
// and the graphql, sdl and openapi exports.
package gqlcol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/gqlschema"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

const (
	Name       = "azhaq-graphql"
	SchemaName = "azhaq-graphql-schema"
	maxFields  = 500
)

// graphqlPath: where GraphQL servers usually listen.
var graphqlPath = lazyre.New(`(?i)(^|/)(graphql|graphiql|gql|playground|altair|v\d+/graphql|graphql/v\d+|api/graphql)/?$`)

// signature: what a GraphQL server or its IDE answers to a bare GET.
var signature = lazyre.New(`(?i)must provide (a )?query|graphql operations must contain|query (is )?(missing|required)|no query (string )?(was )?(present|provided)|"errors"\s*:\s*\[\s*\{\s*"message"\s*:\s*"[^"]*(query|graphql)|<title>\s*(graphiql|graphql playground|apollo|altair)|graphiql\.(min\.)?(js|css)|embeddable-sandbox|graphql-playground`)

// Collector marks URLs that answer like a GraphQL endpoint.
type Collector struct {
	Client *http.Client
}

func New(client *http.Client) *Collector { return &Collector{Client: fetch.Client(client)} }

func (c *Collector) Name() string { return Name }

// Info: one GET to the target.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http"}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"graphql"} }

// Skip declines URLs whose path is not a usual GraphQL location.
func (c *Collector) Skip(seed types.Seed) bool { return !looksGraphQL(seed.Keys["url"]) }

func looksGraphQL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && graphqlPath.MatchString(u.Path)
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	ctx = ledger.WithPurpose(ctx, ledger.PurposeDescriptions)
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	res, _, err := fetch.Do(ctx, c.Client, raw)
	if err != nil {
		if neterr.Quiet(err) {
			return types.RunMeta{Status: types.StatusOK, Drop: true}, nil
		}
		return types.RunMeta{Status: types.StatusError, Error: err.Error(), Drop: true}, err
	}
	postOnly := refusesGET(res)
	switch {
	case res.Status == http.StatusNotFound || res.Status == http.StatusMethodNotAllowed && !postOnly || res.Status < 400 && !signature.Match(res.Body):
		// Nothing here, or an answer that is not GraphQL's: the schema query is not sent.
		return types.RunMeta{Status: types.StatusOK, Drop: true}, nil
	case !signature.Match(res.Body) && !postOnly:
		// The GET was refused in words that do not say GraphQL (401, 403, a
		// 500): not named here, but the schema query (-graphql) is still
		// sent, as the server may answer a POST.
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	row := map[string]any{"url": raw, "role": "graphql", "status": res.Status}
	if from := seed.Keys[types.ExposedByKey]; from != "" {
		row[types.ExposedByKey] = from
	}
	if postOnly {
		row["post_only"] = true // the GET was refused: queries go in a POST
	} else if ide := ideName(res.Body); ide != "" {
		row["ide"] = ide
		fetch.Learn(ideFact(raw), ide)
	} else if answersGET(ctx, c.Client, raw) {
		// It runs queries sent with GET: they can be asked as any GET is,
		// by every session, with no POST.
		row["get_queries"] = true
	}
	return one(emit, raw, "graphql", row)
}

// answersGET asks the endpoint {__typename} with GET, the cheapest query
// there is, which changes nothing: a server that answers it runs queries
// sent with GET.
func answersGET(ctx context.Context, client *http.Client, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	q := u.Query()
	q.Set("query", "{__typename}")
	u.RawQuery = q.Encode()
	res, _, err := fetch.Do(ctx, client, u.String())
	return err == nil && res.Status == http.StatusOK && typename.Match(res.Body)
}

var typename = lazyre.New(`"data"\s*:\s*\{\s*"__typename"\s*:\s*"`)

// postOnlyRE is what a GraphQL server says when it takes no GET.
var postOnlyRE = lazyre.New(`(?i)only supports POST|supports only POST|POST (method )?(only|is required|required)|(GET|this) method is not (allowed|supported)|must (use|be) POST`)

// refusesGET says whether a GET answer is a GraphQL endpoint's refusal to
// take one: a 405 that allows POST, or a message that says POST only.
func refusesGET(res fetch.Result) bool {
	if res.Status == http.StatusMethodNotAllowed {
		allow := strings.ToUpper(res.Header.Get("Allow"))
		return allow == "" || strings.Contains(allow, "POST")
	}
	return res.Status >= 400 && postOnlyRE.Match(res.Body)
}

func ideName(body []byte) string {
	b := bytes.ToLower(body)
	for _, n := range []string{"graphiql", "graphql-playground", "embeddable-sandbox", "altair"} {
		if bytes.Contains(b, []byte(n)) {
			return strings.TrimPrefix(n, "embeddable-")
		}
	}
	return ""
}

// Schema reads a GraphQL schema with the standard introspection query, and
// with a shorter one when the server refuses that for its depth. Active
// (-graphql): it POSTs to the target.
type Schema struct {
	Client   *http.Client
	Wordlist []string // -graphql-wordlist: extra probe words for a recovery without introspection
}

func NewSchema(client *http.Client) *Schema { return &Schema{Client: fetch.Client(client)} }

func (s *Schema) Name() string { return SchemaName }

func (s *Schema) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "graphql", After: Name}
}

func (s *Schema) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (s *Schema) Outputs() []string { return []string{"graphql"} }

func (s *Schema) Skip(seed types.Seed) bool { return !looksGraphQL(seed.Keys["url"]) }

// short asks for the operation fields and type names only: what is read
// from a server that refuses the full query for its depth.
const short = `query AzhaqSchema { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name } } } }`

// maxSchema bounds the schema kept in the observation; a larger one loses
// its descriptions, then is not kept (its operation names still are).
const maxSchema = 8 << 20

// introOff: what a server says when introspection is turned off.
var introOff = lazyre.New(`(?i)introspection[^"]{0,60}(disabled|not allowed|forbidden|blocked|not permitted|turned off)|(not allowed|disabled)[^"]{0,40}introspection`)

// introspectionOff says whether an answer refuses introspection itself.
func introspectionOff(data []byte) bool { return introOff.Match(data) }

func (s *Schema) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	// A GraphiQL or Playground page is a client of the origin's endpoint:
	// once another URL of the origin gave the whole schema it is not asked.
	ide := s.isIDE(raw)
	if ide {
		if from := schemaElsewhere(raw); from != "" {
			ideSkipped(raw, from)
			return types.RunMeta{Status: types.StatusOK}, nil
		}
	}
	status, data, err := s.post(ctx, raw, gqlschema.Query)
	if err != nil {
		return failed(err)
	}
	full, sc, ok := gqlschema.Read(data)
	if !ok && !introspectionOff(data) {
		// Refused for its depth or cost, cut short, blocked for its size or
		// one of its fields: the names are still worth a second ask. A
		// server that turned introspection off is not asked again.
		firstStatus, firstData := status, data
		if status, data, err = s.post(ctx, raw, short); err != nil {
			return failed(err)
		}
		_, sc, ok = gqlschema.Read(data)
		full = nil
		if !ok && refusedAlike(firstStatus, firstData, status, data) {
			// A refusal that does not depend on the query is the page's, not
			// a schema's: more queries would get it again.
			fetch.Note(fmt.Sprintf("GraphQL %s: refused the schema query twice the same way (%d %s): dropped, nothing more was sent to it", raw, status, snippet(data)))
			return types.RunMeta{Status: types.StatusOK}, nil
		}
	}
	if !ok {
		// Introspection is off or refused: the fields the server's errors
		// name are what can still be read.
		return s.recoverSchema(ctx, raw, status, ide, emit)
	}
	row := summary(sc)
	if full != nil {
		fetch.Learn(schemaFact(raw), raw)
		if kept, fits := gqlschema.Bound(full, maxSchema); fits {
			row["schema"] = kept
		} else {
			row["schema_bytes"] = len(full)
		}
	}
	row["url"], row["role"], row["status"] = raw, "graphql", status
	return one(emit, raw, "graphql", row)
}

// refusedAlike says whether two refusals of different queries are one: the
// same status (an error) and the same body, which says nothing of GraphQL's
// own validation or of introspection (a server that blocks introspection says
// which field or feature it blocks). It is a gate in front of the endpoint.
func refusedAlike(s1 int, b1 []byte, s2 int, b2 []byte) bool {
	if s1 < 400 || s1 != s2 || !bytes.Equal(bytes.TrimSpace(b1), bytes.TrimSpace(b2)) {
		return false
	}
	low := bytes.ToLower(b1)
	return !bytes.Contains(low, []byte("__schema")) && !bytes.Contains(low, []byte("introspection")) && !bytes.Contains(low, []byte("cannot query field"))
}

// snippet is the start of an answer, for a note.
func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return fmt.Sprintf("%q", s)
}

// MaxRecoveryPOSTs is how many validation queries recovering a schema may
// send to one endpoint whose introspection is off: up to maxRecover for the
// query type and as many for the mutation type.
const MaxRecoveryPOSTs = 2 * maxRecover

// schemaFact is where a run keeps that an origin's schema was read whole.
func schemaFact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return "graphql schema " + strings.ToLower(u.Scheme+"://"+u.Host)
}

// schemaElsewhere is the URL on raw's origin that gave its schema whole, or
// "" when none has, as far as the run knows.
func schemaElsewhere(raw string) string {
	from, ok := fetch.Learned(schemaFact(raw))
	if !ok || from == raw {
		return ""
	}
	return from
}

func ideSkipped(raw, from string) {
	fetch.Note("GraphQL " + raw + ": an IDE page, not asked for its schema: " + from + " on the same origin gave it whole")
}

// ideFact is where a run keeps that a GET of raw answered with a GraphiQL
// or Playground page.
func ideFact(raw string) string { return "graphql ide " + raw }

// isIDE says whether the recognising stage saw raw answer with an IDE page.
func (s *Schema) isIDE(raw string) bool {
	_, ok := fetch.Learned(ideFact(raw))
	return ok
}

// recoverSchema reads the root fields of the query and mutation types
// from the server's validation errors, when introspection gave nothing.
func (s *Schema) recoverSchema(ctx context.Context, raw string, status int, ide bool, emit func(types.Observation) error) (types.RunMeta, error) {
	clientWords := harvestClientWords(raw)
	// An IDE page's recovery stops once the origin's schema is read whole.
	var halt func() bool
	if ide {
		halt = func() bool { return schemaElsewhere(raw) != "" }
	}
	q, err := s.recoverType(ctx, raw, "query", clientWords, s.Wordlist, nil, halt)
	if err != nil {
		return failed(err)
	}
	if q == nil {
		if halt != nil && halt() {
			ideSkipped(raw, schemaElsewhere(raw))
		}
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	m, err := s.recoverType(ctx, raw, "mutation", clientWords, s.Wordlist, q.names(), halt)
	if err != nil {
		return failed(err)
	}
	if halt != nil && halt() {
		ideSkipped(raw, schemaElsewhere(raw))
	}
	row := map[string]any{"url": raw, "role": "graphql", "status": status, "introspection": false, "recovered": "suggestions",
		"queries": q.names(), "types": typeNames(q, m), "errors": q.errors, "query_type": q.name,
		// Recovery never proves a type has no more fields than it found.
		"complete": false}
	sigs := map[string]any{"queries": q.signatures()}
	recovery := map[string]any{"queries": recoveryCounts(q)}
	if m != nil {
		row["mutations"] = m.names()
		row["errors"] = q.errors + m.errors
		row["mutation_type"] = m.name
		sigs["mutations"] = m.signatures()
		recovery["mutations"] = recoveryCounts(m)
	}
	if len(clientWords) > 0 {
		row["client_words"] = len(clientWords)
	}
	row["signatures"] = sigs
	row["recovery"] = recovery
	return one(emit, raw, "graphql", row)
}

// recoveryCounts is how many of a root type's fields were found each way
// (client, probe or suggestion) and how many words were tried to find
// them: never proof that the type has no more.
func recoveryCounts(rt *recoveredType) map[string]any {
	return map[string]any{"fields": len(rt.fields), "by": rt.counts(), "words_tried": rt.tried}
}

// harvestClientWords reads the GraphQL operations already in the map for
// raw's origin -- HTML and scripts fetch.CachedOrigin holds from earlier
// in the run -- so a field, argument or type name the client code already
// asks for is tried before a guess.
func harvestClientWords(raw string) []string {
	seen := map[string]bool{}
	var out []string
	for _, body := range fetch.CachedOrigin(raw) {
		for _, w := range webextract.GraphQLWords(string(body)) {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}

// failed is what a query that got no answer leaves: capped by the request
// budget, nothing for a host that does not resolve, else an error.
func failed(err error) (types.RunMeta, error) {
	switch {
	case errors.Is(err, neterr.ErrBudget):
		return types.RunMeta{Status: types.StatusCapped}, err
	case neterr.Quiet(err):
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
}

// post sends one GraphQL query and reads the answer.
func (s *Schema) post(ctx context.Context, raw, query string) (int, []byte, error) {
	body, _ := json.Marshal(map[string]string{"query": query})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, vs := range fetch.CurrentExtra() {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", fetch.UserAgent)
	}
	if err := egress.Spend(ctx); err != nil {
		return 0, nil, err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, fetch.MaxScriptBody))
	return resp.StatusCode, data, nil
}

// summary lists the fields of the query, mutation and subscription types
// and the names of the other object types.
func summary(sc *gqlschema.Schema) map[string]any {
	root := map[string]string{}
	for key, t := range map[string]*gqlschema.Named{"queries": sc.QueryType, "mutations": sc.MutationType, "subscriptions": sc.SubscriptionType} {
		if t != nil {
			root[t.Name] = key
		}
	}
	row := map[string]any{"introspection": true}
	var objects []string
	for _, t := range sc.Types {
		if key, ok := root[t.Name]; ok {
			var names []string
			for _, f := range t.Fields {
				if len(names) < maxFields {
					names = append(names, f.Name)
				}
			}
			sort.Strings(names)
			row[key] = names
			continue
		}
		if t.Kind == "OBJECT" && !strings.HasPrefix(t.Name, "__") && len(objects) < maxFields {
			objects = append(objects, t.Name)
		}
	}
	sort.Strings(objects)
	row["types"] = objects
	return row
}

func one(emit func(types.Observation) error, source, kind string, row map[string]any) (types.RunMeta, error) {
	payload, _ := json.Marshal(row)
	if err := emit(types.Observation{
		Collector: kindName(row), Source: source, Kind: kind,
		Payload: payload, Confidence: 0.9, ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
}

func kindName(row map[string]any) string {
	if row["introspection"] == true || row["recovered"] != nil {
		return SchemaName
	}
	return Name
}
