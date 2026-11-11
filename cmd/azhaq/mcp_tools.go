package main

import (
	"encoding/json"
	"strings"

	"github.com/lilsadfoqs/azhaq/scope"
)

func scopeRules(allow, deny []string) scope.Rules {
	return scope.Rules{Allow: allow, Deny: deny}
}

// Schema helpers for the tool list. The schemas are also what a call's
// arguments are checked against (mcp_schema.go).
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(typ, desc string) map[string]any { return map[string]any{"type": typ, "description": desc} }

// whole is an integer argument of at least min.
func whole(min int, desc string) map[string]any {
	return map[string]any{"type": "integer", "minimum": min, "description": desc}
}

func strs1(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

// strsN is a list of strings with a bound: an unbounded list is refused
// by the schema check before any network activity.
func strsN(desc string, max int) map[string]any {
	return map[string]any{"type": "array", "maxItems": max, "items": map[string]any{"type": "string"}, "description": desc}
}

func with(s map[string]any, k string, v any) map[string]any {
	s[k] = v
	return s
}

// queryColumns are the fields of a query row, what fields picks from.
var queryColumns = []string{"key", "type", "role", "coverage", "status", "answer", "evidence", "evidence_from", "response_file", "title", "state", "names", "service", "product", "version", "methods", "params", "body", "ops", "forms", "found_in", "watch", "guard", "protocol", "namespace", "template", "count", "not_asked", "capped", "folded", "proof", "scope", "first_seen"}

var (
	pWorkspace = prop("string", "workspace name (a database in the server's directory); default \"default\". Runs into the same workspace can be compared with azhaq_diff.")
	pLimit     = whole(1, "rows at most in the result: default 100, at most 1000 (narrow the question for more)")
	pURL       = prop("string", "a URL to map, such as https://app.example.com/")
	pDomain    = prop("string", "a domain whose names to enumerate and map, such as example.com")
	pTargets   = strs1("targets, each a URL, host, host:port or IP address")
	pScope     = prop("boolean", "seed from the program scope the server was started with")
	pPassive   = prop("boolean", "send nothing to the targets: third-party sources and DNS only")
	pBrowser   = prop("boolean", "also load pages in Chrome to see the requests their scripts make (needs Chrome on the machine); Chrome sends GET, HEAD and OPTIONS only, and maps the writes pages would send without sending them")
	pGraphQL   = prop("boolean", "also ask each GraphQL endpoint found for its schema: an introspection query, which is a POST and counts against the budget; where introspection is off, the schema is recovered from the endpoint's validation errors (marked partial). Sent only when the server was started with -allow-writes: without it the call is refused before anything is sent")
	pDepth     = whole(0, "how many steps from the targets to follow; 0 maps the targets alone (default 4)")
	pTimeout   = whole(1, "stop after this many seconds and keep what was found")
	pHeaders   = strs1("request headers for every request, \"Name: value\" (a session cookie, an Authorization token, a bug bounty identification header)")
	pLogin     = with(with(obj(map[string]any{"url": prop("string", "the login page"), "user": prop("string", "user name or email"), "password": prop("string", "password")},
		"url", "user", "password"),
		"description", "sign in with Chrome before mapping; the session goes with every request. The sign-in is the one POST a call may send without -allow-writes: the page's own sign-in form, submitted with the user and password given"),
		"examples", []any{json.RawMessage(`{"url":"https://app.example.com/login","user":"alice@example.com","password":"…"}`)})
	// A role is anonymous, sends headers, or signs in: user and password
	// go together.
	pRole = with(with(obj(map[string]any{"name": prop("string", "role name"), "header": strs1("headers its requests carry, \"Name: value\""),
		"user": prop("string", "user to sign in as at login_url"), "password": prop("string", "its password")}, "name"),
		"dependentRequired", map[string][]string{"user": {"password"}, "password": {"user"}}),
		"examples", []any{json.RawMessage(roleAnon), json.RawMessage(roleHeader), json.RawMessage(roleLogin)})
)

// The examples of a role, as written (raw, so the name comes first), in
// the schema, its errors and the tool's description alike.
const (
	roleAnon   = `{"name":"anon"}`
	roleHeader = `{"name":"user","header":["Authorization: Bearer …"]}`
	roleLogin  = `{"name":"alice","user":"alice@example.com","password":"…"}`
)

func annotations(readOnly, openWorld bool, title string) map[string]any {
	return annotationsD(readOnly, openWorld, title, false)
}

// annotationsD is annotations for a tool that can send writes: its
// destructiveHint says so, as its readOnlyHint says it is no read.
func annotationsD(readOnly, openWorld bool, title string, destructive bool) map[string]any {
	return map[string]any{"title": title, "readOnlyHint": readOnly, "destructiveHint": destructive, "idempotentHint": readOnly, "openWorldHint": openWorld}
}

func mcpTools() []map[string]any {
	planProps := map[string]any{"url": pURL, "domain": pDomain, "targets": pTargets, "program_scope": pScope,
		"passive": pPassive, "browser": pBrowser, "graphql": pGraphQL, "depth": pDepth, "timeout_seconds": pTimeout, "headers": pHeaders, "login": pLogin}
	mapProps := map[string]any{"workspace": pWorkspace, "limit": pLimit}
	for k, v := range planProps {
		mapProps[k] = v
	}
	return []map[string]any{
		{"name": "azhaq_scope", "title": "Scope and budget",
			"description": "What this server may touch (the scope fixed at start), the run options fixed with it (resolvers, sources, skipped collectors, takeover check: run_options), its request budget and how much of it is used. Call it first on a program.",
			"inputSchema": obj(map[string]any{}), "annotations": annotations(true, false, "Scope and budget")},
		{"name": "azhaq_plan", "title": "Plan a run",
			"description": "What azhaq_map would take, leave out of the scope (and why), run and send for these targets, without sending anything: collectors per target, built-in paths, active techniques, limits, and state_changing: the GET requests among the targets whose own path or query declares a state change (create, delete, reset, populate, logout, action=stop and the other words of the documented set), each with the -deny-path rule that would keep it out, and its status: a target you name is held back like a GET a run finds on the way, and the server's -send-state-changing at start sends it. A word of a wordlist is held back the same way, and one found on the way the plan cannot know. With graphql the plan is refused unless the server was started with -allow-writes, as the call is. Built by the same code path that builds azhaq_map's call, so the plan is what the call would send.",
			"inputSchema": obj(planProps), "annotations": annotations(true, false, "Plan a run")},
		{"name": "azhaq_map", "title": "Map a target",
			"description": "Map a URL, a domain or a list of targets into a workspace: names and their addresses, web services, pages, routes the JavaScript calls (method, query and body fields), API descriptions and their operations, forms, parameters, what needs a session (401) or is refused (403). Without a flag every request to a target is a GET (with graphql, also the introspection POST, which a server started without -allow-writes refuses), and a GET can change data or end a session: every URL found in scope is requested, a GET operation of an API description and a GET form included, except a GET found on the way whose own path, query or API operation declares a state change (create, delete, reset, populate, logout, action=stop and the other words of the documented set): a link, a script's route, an API operation or a GET form's action like that is held back and listed as skipped, and only the server's -send-state-changing at start sends it. A URL you gave as a target is held back the same way: the server's -send-state-changing sends it, not the call. With graphql a POST goes to each GraphQL endpoint, so a server started without -allow-writes refuses the call. Besides that, only the -deny-path rules the server was started with keep a URL out, and a call cannot add one. Returns the summary (failures, skipped targets, limits hit, and state_changing: the GETs whose own name or API description declares a state change, each with the -deny-path rule that would keep it out, and whether it was sent or held back) and the highlights: auth-gated, forbidden and API routes. Read the rest with azhaq_query. A run the budget, timeout_seconds or a cancellation stopped continues with azhaq_resume; mapping again starts over.",
			"inputSchema": obj(mapProps), "annotations": annotations(false, true, "Map a target")},
		{"name": "azhaq_resume", "title": "Resume a run",
			"description": "Continue the run of a workspace that a limit (the request budget, timeout_seconds) or a cancellation stopped, where it stopped: the answers it got are not asked for again. Holds to the server's scope and pace and spends what is left of its budget. Returns the summary and the highlights, like azhaq_map. A workspace keeps no session: give headers or login again if the run had them.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "headers": pHeaders, "login": pLogin, "timeout_seconds": pTimeout, "limit": pLimit}),
			"annotations": annotations(false, true, "Resume a run")},
		{"name": "azhaq_subdomains", "title": "Find subdomains",
			"description": "Subdomains of domains from passive sources (certificate transparency, archives, DNS datasets), each with the sources that gave it; with live, only names that resolve (wildcard answers left out). Nothing is sent to the targets. Not available when the server was started with -sources none.",
			"inputSchema": obj(map[string]any{"domain": strs1("domains such as example.com"), "live": prop("boolean", "only names that resolve"),
				"workspace": prop("string", "also keep the names in this workspace (a database in the server's directory), to map or query later; none by default"), "limit": pLimit}, "domain"),
			"annotations": annotations(true, true, "Find subdomains")},
		{"name": "azhaq_probe", "title": "Probe web services",
			"description": "Which targets serve the web, like httpx: URL, status, title, technologies, web server, CDN, the address connected to. One GET per service.",
			"inputSchema": obj(map[string]any{"targets": pTargets, "limit": pLimit}, "targets"), "annotations": annotations(false, true, "Probe web services")},
		{"name": "azhaq_ports", "title": "Scan ports",
			"description": "Open TCP ports of hosts inside the locked scope (connect scan, no root), with banners; with udp_ports, UDP ports too: a reply is open, an ICMP unreachable closed, neither open|filtered. Only when the server was started with -allow or -scope.",
			"inputSchema": obj(map[string]any{"hosts": strsN("hosts or addresses, at most 100", 100), "ports": prop("string", "TCP ports: default (the top 100 and the usual ports of the services azhaq names and checks), top-100, top-1000, full, or a list such as 22,80,8000-8100"), "udp_ports": prop("string", "UDP ports to ask too: top (about 25 common ones), full, or a list such as 53,123,161,1-1024; when ports names no TCP port, no TCP port is asked"), "limit": pLimit}, "hosts"),
			"annotations": annotations(false, true, "Scan ports")},
		{"name": "azhaq_dirs", "title": "Discover paths",
			"description": "Paths on web services from a wordlist, like ffuf with auto-calibration: a GET for each word (and each extension) under each target, calibrated on paths that cannot exist so a catch-all answer is not listed. The server's scope, deny-path rules, pace and budget hold; a target outside the scope is refused before anything is sent. words is the wordlist (at most 5000); without it the built-in common list is used. A word that declares a state change by its own path or query (logout, reset, delete, action=stop and the like) is held back and listed as skipped, whether it is a word of the built-in list or one of the words you give; the server's -send-state-changing at start sends every word. With workspace the results are kept in that workspace, else the call writes the server's ledger.",
			"inputSchema": obj(map[string]any{"targets": strsN("web services such as https://app.example.com/, at most 100", 100), "words": strsN("path words to guess, at most 5000 (default: the built-in common list)", 5000), "extensions": strsN("also try each word with these extensions, such as php or bak, at most 20", 20), "workspace": pWorkspace, "limit": pLimit}, "targets"),
			"annotations": annotations(false, true, "Discover paths")},
		{"name": "azhaq_params", "title": "Discover parameters",
			"description": "Query parameters the pages read, from a wordlist, like arjun: the names the pages themselves hold first, then batches of the wordlist. method GET (the default) sends names in the query and no body; POST, JSON and XML send names in a body, which may change data, and are refused unless the server was started with -allow-writes. The server's scope, deny-path rules, pace and budget hold; a target outside the scope is refused before anything is sent. words is the wordlist (at most 5000); wordlist names a built-in one instead.",
			"inputSchema": obj(map[string]any{"targets": strsN("page URLs, at most 100", 100), "words": strsN("parameter names to try, at most 5000", 5000), "wordlist": with(prop("string", "a built-in wordlist instead of words"), "enum", []string{"small", "medium", "large"}), "method": with(prop("string", "how names are sent: GET (query, the default), POST (form body), JSON or XML (a body; needs -allow-writes at server start)"), "enum", []string{"GET", "POST", "JSON", "XML"}), "workspace": pWorkspace, "limit": pLimit}, "targets"),
			"annotations": annotationsD(false, true, "Discover parameters", true)},
		{"name": "azhaq_dns_brute", "title": "Brute-force DNS names",
			"description": "Subdomains by resolving guesses: WORD.domain for each word under each domain, through the server's resolvers (wildcard answers left out). Nothing is sent to the targets: the queries go to the resolvers, paced at the server's rate and refused when its budget is spent. A domain outside the scope is refused before any query. words is required and bounded (at most 5000), domains at most 20. With workspace the names are kept in that workspace, else the call writes the server's ledger.",
			"inputSchema": obj(map[string]any{"domain": strsN("domains such as example.com, at most 20", 20), "words": strsN("words to guess under each domain, at most 5000", 5000), "workspace": pWorkspace, "limit": pLimit}, "domain", "words"),
			"annotations": annotations(true, true, "Brute-force DNS names")},
		{"name": "azhaq_query", "title": "Query a workspace",
			"description": "The rows of a workspace's map that match, best first: by entity type (URL, Hostname, IPAddress, Domain), role (app, auth, forbidden, api, page, client-route, websocket, live, sibling, unresolved, dead), coverage (visited, hint, catchall, error, skipped), status (200, 401, 4xx), method (GET, POST), host, text, what the last run saw first (new). fields picks the columns: " +
				strings.Join(queryColumns, ", ") + " (default " + strings.ReplaceAll(queryFields, ",", ", ") + ").",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "type": strs1("entity types"), "role": strs1("roles"), "coverage": strs1("coverage values"),
				"status": strs1("statuses: 200, 401, 4xx"), "method": prop("string", "routes with this method"), "host": prop("string", "on this host or under this domain"),
				"match": prop("string", "keys that contain this text"), "scope": with(prop("string", "target (what was asked about) or fanout (found on the way)"), "enum", []string{"target", "fanout"}),
				"new":    prop("boolean", "only what the last run saw first"),
				"fields": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": queryColumns}, "description": "columns to return"}, "limit": pLimit}),
			"annotations": annotations(true, false, "Query a workspace")},
		{"name": "azhaq_show", "title": "Show one entity",
			"description": "Everything a workspace knows about one URL, hostname, address or domain: its row, what found it, what it leads to, every observation (status, headers, title, technologies, parameters, the calls that reach it).",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "key": prop("string", "the URL, hostname, address or domain")}, "key"),
			"annotations": annotations(true, false, "Show one entity")},
		{"name": "azhaq_roles", "title": "Compare sessions",
			"description": "Map the target once per role, ask every endpoint any role reached with every other role, fill path parameters with identifiers the roles' answers held (each role's own objects first), and list where the answers differ, worst first: anyone reads sensitive fields (passwords, secrets, keys), a role reads another role's object, an object every signed-in role reads alike, the same answer for a session that never found the URL, signed-in only, only one role reads it, some roles refused, different fields. Each role is an object: " +
				roleAnon + " is anonymous, " + roleHeader + " sends those headers, " + roleLogin + " signs in at login_url with Chrome. A GET found on the way, or a target you named, whose own path, query or API operation declares a state change is held back in each role's map and listed as skipped, as azhaq_map holds it, unless the server's -send-state-changing at start sends it.",
			"inputSchema": obj(map[string]any{"url": pURL, "targets": pTargets, "program_scope": pScope,
				"workspace": prop("string", "where the roles' maps are kept: a database per role in <workspace>-roles in the server's directory; default \"default\""),
				"roles":     map[string]any{"type": "array", "description": "two or more sessions", "minItems": 2, "items": pRole},
				"login_url": prop("string", "the login page, for roles that sign in"), "all": prop("boolean", "also list endpoints that answer every role alike"),
				"ids":     strs1("identifiers to fill routes with, [ROLE:]NAME=VALUE: alice:book_title=aliceBook says that book is alice's, so another role reading it is reported"),
				"browser": pBrowser, "depth": pDepth, "timeout_seconds": pTimeout, "limit": pLimit}, "roles"),
			"annotations": annotations(false, true, "Compare sessions")},
		{"name": "azhaq_roles_writes", "title": "Replay role writes",
			"description": "Like azhaq_roles, and replay the writes with every other role's session: the writes each role's own map or routes name (PUT and PATCH with an empty object, DELETE, and the POSTs a route takes), of the methods replay_writes names. Writes change data on the target, so the call is refused before anything is sent unless the server was started with -allow-writes; dry_writes lists the writes it would send and sends none, and needs no opt-in. A cross-role write is listed only when the owner's object, read as the owner before and after, changed the way the write asks. Each role is an object: " +
				roleAnon + " is anonymous, " + roleHeader + " sends those headers, " + roleLogin + " signs in at login_url with Chrome.",
			"inputSchema": obj(map[string]any{"url": pURL, "targets": pTargets, "program_scope": pScope,
				"workspace":     prop("string", "where the roles' maps are kept: a database per role in <workspace>-roles in the server's directory; default \"default\""),
				"roles":         map[string]any{"type": "array", "description": "two or more sessions", "minItems": 2, "items": pRole},
				"replay_writes": prop("string", "the write methods to replay, such as post,put,patch (add delete to delete objects)"),
				"dry_writes":    prop("boolean", "list the writes it would send, with whose and why, and send none"),
				"canary":        prop("boolean", "with a PUT or PATCH, change one short string field of the body to a value unique to each role it is replayed with, so an otherwise invisible change can be proved (it changes data; restoring the field is not done)"),
				"login_url":     prop("string", "the login page, for roles that sign in"), "all": prop("boolean", "also list endpoints that answer every role alike"),
				"ids":     strs1("identifiers to fill routes with, [ROLE:]NAME=VALUE: alice:book_title=aliceBook says that book is alice's, so another role reading it is reported"),
				"browser": pBrowser, "depth": pDepth, "timeout_seconds": pTimeout, "limit": pLimit}, "roles", "replay_writes"),
			"annotations": annotationsD(false, true, "Replay role writes", true)},
		{"name": "azhaq_export", "title": "Export a workspace",
			"description": "A workspace in another tool's format: openapi (the target's own description where it serves one, plus what scripts call and forms send), graphql (introspection JSON, for InQL or Burp), sdl (GraphQL schema), burp (scope), targets (web services, for nuclei -l), urls, hosts, names, html, graphml, secrets, jsonl. Writes the whole export to a file next to the workspace on the server's machine (juice.openapi.json, juice.html) and returns it a page of about 16 KB at a time, each page a document of its own: an OpenAPI description with some of the paths, an introspection result or SDL with some of the definitions, whole lines. The result says how many paths, definitions or lines there are, which ones the page holds, and the offset of the next page.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "format": map[string]any{"type": "string", "enum": exportFormats, "description": "default openapi"},
				"offset": whole(0, "the first unit of the page, counted as the result counts them: paths for openapi, definitions for graphql and sdl, scope entries for burp, rows for html, nodes and edges for graphml, lines for the others")}),
			"annotations": annotations(true, false, "Export a workspace")},
		{"name": "azhaq_diff", "title": "What changed",
			"description": "What the last run into a workspace saw that the run before it did not, and what it no longer saw.",
			"inputSchema": obj(map[string]any{"workspace": pWorkspace, "limit": pLimit}), "annotations": annotations(true, false, "What changed")},
		{"name": "azhaq_workspaces", "title": "List workspaces",
			"description": "The workspaces this server has written.",
			"inputSchema": obj(map[string]any{}), "annotations": annotations(true, false, "List workspaces")},
		{"name": "azhaq_status", "title": "Server and workspace status",
			"description": "A compact status of this server and every workspace it has written: the scope (locked, the allow and deny rules), the request budget (limit, used, left), the pace, the path of the ledger of the calls that name no workspace, and each workspace's state as its database records it -- complete, or stopped by a limit with tasks_left, the requests the run has sent and the azhaq_resume call that continues it; failed, when this session's last map, resume or roles call for it failed outright. Sends nothing and starts no command.",
			"inputSchema": obj(map[string]any{}), "annotations": annotations(true, false, "Server and workspace status")},
	}
}
