# azhaq export

Write a database in another tool's format.

## Synopsis

```
azhaq export [-db FILE] [-format jsonl|urls|hosts|names|targets|openapi|graphql|sdl|burp|html|graphml|secrets|findings|findings-md] [-origin ORIGIN|URL] [-safe] [-coverage LIST] [-json] [-run ID]
```

## Examples

```
# OpenAPI 3 description of the origin with the most API routes
azhaq export -db app.db -format openapi > app.openapi.json

# The introspection JSON of one GraphQL endpoint
azhaq export -db app.db -format graphql -origin https://app.example.com/graphql > schema.json

# The same schema in GraphQL SDL
azhaq export -db app.db -format sdl > schema.graphql

# A run's scope, as Burp Suite project options
azhaq export -db h1.db -format burp > scope.json

# Web services, for nuclei
azhaq export -db h1.db -format targets | nuclei -l -

# The findings records of a run, one JSON object per record
azhaq export -db app.db -format findings > findings.jsonl

# Only the URLs a request answered, for another tool
azhaq export -db app.db -format urls -coverage visited > answered.txt

# Every URL with how the run knows it
azhaq export -db app.db -format urls -json > urls.jsonl
```

## What it does

`azhaq export -db FILE -format F` writes the newest run of a workspace in one format on stdout. Without `-db` it uses the last run's database. `-format` defaults to `jsonl`. `-run ID` writes an earlier run instead: the `run_id` of its summary, or the start of it (at least 4 characters), as `query -run` takes it; `azhaq query -db FILE -runs` lists them. `jsonl` without `-run` writes every run of the workspace.

## Output

The output is the format you chose, on stdout.

| Format | Output |
| --- | --- |
| `jsonl` | Everything: one object per map row (`"kind":"entity"`, with `evidence` and `evidence_from`, and for a web row that was answered the `headers`, `body_length`, `body_cut`, `body_url` and `asked_at` of its answer: see [query](query.md#the-answer-a-row-kept)), observation and edge. The body's start is in the answering observation's payload, as base64 in `body_excerpt`: a page can name hosts outside the scope, which no row of an export does. |
| `urls` | Every URL the workspace learned, one per line: the map's URL rows, and every URL the archives gave for the run, which the workspace keeps in `DB.urls.jsonl` beside it (the graph holds one example for each URL shape, 200 a domain). Each URL once. A workspace made before the list was kept holds only the examples, and stderr says how many archived URLs they stand for. `-coverage` and `-json` say which were visited and which were only named: see [Lists with coverage](#lists-with-coverage). |
| `hosts` | One per line: names that resolve, and addresses given as targets or serving the web. |
| `names` | Every name, one per line. `-coverage` and `-json` as for `urls`. |
| `targets` | Web services, one per line, for `nuclei -l` and `httpx`. See Details. |
| `openapi` | OpenAPI 3 JSON of one origin. See [openapi](#openapi). |
| `graphql` | The introspection result of each GraphQL endpoint read with `-graphql`. See [graphql and sdl](#graphql-and-sdl). |
| `sdl` | The same schemas in the GraphQL schema language. See [graphql and sdl](#graphql-and-sdl). |
| `burp` | Burp Suite project options with the run's target scope. See [burp](#burp). |
| `html` | One self-contained page. See [html](#html). |
| `graphml` | The graph for Gephi, yEd or Cytoscape. |
| `secrets` | Credentials found in scripts, tab-separated: severity, kind, value, script, name it was assigned to, rule that listed it. |
| `findings` | The rows of the workspace in three tiers, as JSON Lines, one object per row, each with its `type`: `{"type":"finding", …}` for a proven row (a stack trace, a data store's answer to a read with no credential, an exposed file or panel whose answer shows it, a secret of a known format, a takeover the service's own page shows), then `{"type":"identification", …}` for a product and version a service stated, with the advisory match where there is one (`proved`, `version-only` and `conditional` kept distinct), then `{"type":"lead", …}` for what is inferred from a name, a path or a guess, with the check that would prove it, and one `{"type":"folded", …}` per class of the hints its default view folds, with their count. Each finding and identification has the host, port, product, version, advisory id, kind, severity and the proof fields: `observed_at`, `method` and `target` (the request), `request_bytes` for a probe that is not HTTP, `status` and `content_type`, `excerpt`, `excerpt_part` and `excerpt_offset`, `how` (the stage that found it) and `reproduce` (one command that shows the same without azhaq): see [report](report.md#findings-records--findings). A workspace with no qualifying rows writes one explicit line, `{"type":"findings","findings":0,"identifications":0,"leads":0}`. An advisory record is one line for each advisory, with the `lead` it belongs to (`host:port Product`); the counts of the three tiers are of issues, not lines: the records of one lead that no read settled (`version-only` and `conditional`) are one identification. The counts of the three tiers are said on stderr. The same as `azhaq report -findings -format jsonl`. |
| `findings-md` | The same records in Markdown: a section for each tier with its count (the identifications by label), the request, the excerpt and the `reproduce` command under each finding and identification, and the check under each lead; an empty workspace writes a sentence saying there are no qualifying rows. |

## Summary and exit codes

A format that finds nothing writes nothing and says why on stderr; `openapi` writes a description with no paths instead (below), and `findings`/`findings-md` write an explicit empty record set. The exit code is 0, except for `graphql` and `sdl`: when no GraphQL schema was read they write nothing, fail with `no GraphQL schema in DB: map with -graphql …` and exit 1.

```
azhaq export: nothing to write: the workspace holds no host names (a run of a URL or an address has none: …)
```

The summary and the other exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Lists with coverage

A bare `urls` or `names` list does not say which entries were requested and which were only named: a URL a request answered, one a script only names, one a rule kept out and one beyond the depth look alike. Two flags say it. The plain list, with neither, is unchanged.

- `-coverage visited,hint,…` keeps the entries of those coverages, as [query](query.md) `-coverage` does: `visited`, `catchall`, `error`, `gone`, `hint`, `skipped`, `capped`. A value that is not one is a usage error, so a typo does not give an empty list. Both flags are for `-format urls` and `names` only; with another format they are a usage error.
- `-json` writes one JSON object per line: `{"url", "coverage", "status", "source"}` for `urls`, `{"name", …}` for `names`. `status` is the answer's status (0 when nothing answered). `source` is the collectors that found the entry, comma-separated: for a URL the archives gave and the graph does not hold, the archive.

For `urls`, the coverage is the map row's. A URL that only an archive gave is a `hint`: no request was made for it. The count of a coverage is what `azhaq query -type URL -coverage C` lists, except that `query` folds URLs of one shape into a template row and the export lists each URL.

A name has no coverage of its own. It takes that of the URLs the run holds on it, the best one first: `visited`, `catchall`, `gone`, `error`, `skipped`, `capped`; a name no URL was asked on is a `hint` (named by a source, a list or a certificate). Its `status` is that URL's, its front page's when there is a tie.

When `-coverage` matches nothing, stderr says `nothing to write: no entry has coverage C` and the exit code is 0.

### targets

`targets` lists the front pages that answered. They are azhaq's own, or taken in from httpx, katana or ffuf.

### html

- The page holds web services, names, screenshots, secrets, API routes (with an Evidence column) and the map.
- Screenshots are embedded, 560 pixels wide. The page opens from any directory.
- A picture file missing from where the run named it and from beside the database is listed as not found.
- For thousands of pictures use the interactive view, [gallery](gallery.md).

### openapi

`openapi` describes one origin: `-origin`, default the one with the most API routes. It holds:

- the description the target serves, as it is
- the routes that scripts call
- forms
- the pages found with a query string of their own (a GET taking those names)
- what answered

The address a description was read from (`/openapi.json`) is not a path of the API it describes: it is left out unless the description lists it.

It is a valid OpenAPI document whatever went into it:

- A workspace with no API route gives one too, such as a run whose target did not answer. Its `paths` is `{}`, stderr says `azhaq export: no API routes found on ORIGIN: wrote a description with no paths`, and the exit code is 0.
- Every `operationId` is unique. A served description's keep theirs. A repeat gets `_2`, `_3` in path order: `/blog` and `/blog/` are both `get_blog`.
- Templates that differ only by their parameter names are one path: the served description's, else the first.
- Every `{name}` in a path is a declared path parameter, and a parameter is listed once.
- Component names that OpenAPI does not allow are renamed, with their references.

#### Routes the run did not request

A route the run did not request (`skipped`, kept out by `-deny-path`) has no GET or HEAD of azhaq's making in it. A tool importing the description would send one.

- The served description may list such a route anyway, such as VAmPI's `GET /createdb`. Or azhaq may have guessed its POST.
- Each such operation carries `x-azhaq-skipped: true` and `x-azhaq-skipped-reason`, for example `-deny-path ^/createdb`.
- `-safe` leaves those operations out, for a tool that must not touch them.
- An API route kept out whose callers do not say the method is described as a POST. `x-azhaq.method` says it is a guess. It is never described as a GET.

#### Forms

- A GET form's fields are query parameters of its action's GET.
- A POST form's fields are its request body: `application/x-www-form-urlencoded` or `multipart/form-data`, as its `enctype` says. A file input is `"format":"binary"`.
- A form adds the fields that an operation the export made lacks. A served description's operations are left as they are.

#### The x-azhaq fields

- `x-azhaq` on each operation holds `source`, `coverage`, `status` and `needs_credentials`.
- `x-azhaq-evidence` beside it is the evidence level of the route: `described` for a served description's operations, `linked` for a form's.

#### GraphQL in openapi

A GraphQL endpoint is one `POST` taking `{"query","operationName","variables"}`, not a made-up REST mapping. Its operations are in `x-azhaq-graphql`:

```json
"x-azhaq-graphql":{"operations":[
  {"type":"query","name":"pastes","arguments":[{"name":"public","type":"Boolean"},{"name":"limit","type":"Int"}],"returns":"[PasteObject]"},
  {"type":"mutation","name":"createPaste","arguments":[{"name":"burn","type":"Boolean","default":"false"}],"returns":"CreatePaste"}]}
```

- `type` is `query`, `mutation` or `subscription`.
- `default` is a GraphQL literal. `deprecated` is set on deprecated fields.
- A schema kept by names only gives `type` and `name`.
- A schema recovered from validation errors (see [show](show.md#recovering-a-schema-when-introspection-is-off)) adds `"introspection": false, "recovered": "suggestions", "partial": true, "complete": false` beside `operations`.
- The text map puts `GraphQL: introspection disabled, schema recovered (partial, may lack types and fields)` above the endpoint's operations.

### graphql and sdl

`graphql` prints `{"data":{"__schema":{…}}}`: the server's answer to the standard introspection query. Tools such as InQL, Burp, Postman, graphql-voyager and clairvoyance read it.

- With several endpoints it prints one object keyed by endpoint URL: `{"https://app/graphql":{"data":{"__schema":…}},…}`.
- `-origin` keeps the endpoints of one origin, or the one at a URL (`-origin https://app/graphql`). Use it to get a file that a tool loads as it is.

`sdl` prints each endpoint's schema under a `# URL` comment:

- It holds types, interfaces, unions, enums, input objects, custom scalars and directives, with descriptions, defaults and `@deprecated`.
- It leaves out the built-in scalars and directives.
- It adds a `schema { … }` block when the root types are not simply `Query`, `Mutation` and `Subscription`.
- Concatenated schemas of several endpoints are not one schema. Pick one with `-origin`.

#### A schema recovered from validation errors

When a server has introspection turned off, the schema is recovered from its validation errors. It is partial. `show` explains how it is recovered: see [show](show.md#recovering-a-schema-when-introspection-is-off).

- In `graphql`, `"x-azhaq": {"introspection": false, "recovered": "suggestions", "partial": true, "complete": false}` sits beside `data`. With several endpoints it sits inside each endpoint's object.
- Beside it are `validation_errors`, `client_operations`, `client_words` and `untyped_fields`, when known.
- `complete` is always `false` on a recovery: it cannot prove that a type has no more fields.
- In `sdl`, the schema starts with this comment:

```
# introspection disabled on URL; recovered from N validation errors and M client operations: partial, may lack types and fields; recovery does not prove there are no others
```

- Next comes a `# recovered fields: …` line. It gives each root type's field count, how the fields were found (client, probe, suggestion) and how many words were tried.
- Then come the root types, as far as they were recovered.
- Fields whose type was not recovered, and the client operations found in scripts, are listed in comments.

### burp

`burp` writes `{"target":{"scope":{"advanced_mode":true,"include":[…],"exclude":[…]}}}`.

- When the run had a scope, `include` holds its allow rules (`-scope` and `-allow`). `exclude` holds its deny rules: the program's out-of-scope entries and `-deny`.
- Each rule is for any protocol, port and path.
- The scope is read back from the run's options. A scope file is read again (it is stored by its full path). A platform's program (`-scope hackerone -program x`) is read as it stands now, from bounty-targets-data.
- A run without allow rules includes every web service it found. So does a run whose scope file is gone, and a note on stderr says so.
- `azhaq run -scope` reads the file back.

Rules look like this:

| Rule for | Looks like |
| --- | --- |
| A domain, and its subdomains | `{"enabled":true,"protocol":"any","host":"^(.*\\.)?example\\.com$"}` |
| One host | `^api\\.example\\.com$` |
| An address | `^192\\.0\\.2\\.7$` |
| A range, as Burp takes it | `10.0.0.0/24` |
| A web service, when there are no allow rules | `{"enabled":true,"protocol":"https","host":"^app\\.example\\.com$","port":"^443$","file":"^/.*"}` |

## Flags

<!-- flags:begin export -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | sqlite path (default: last run) |
| `-format` | string | `jsonl` | jsonl (everything), urls, hosts (names that resolve), names (every name), targets (web services, for nuclei -l), openapi, graphql (introspection JSON), sdl (GraphQL schema), burp (the run's scope), html, graphml, secrets, findings (one record per qualifying stored row in three tiers, JSON Lines; an empty workspace writes an explicit empty record set), findings-md (the same records in Markdown) |
| `-origin` | string |  | openapi: the origin to describe (default: the one with most API routes); graphql, sdl: the endpoints of an origin, or one endpoint's URL |
| `-safe` | bool |  | openapi: leave out the routes the run did not request, such as those -deny-path kept out (otherwise they carry x-azhaq-skipped: true) |
| `-coverage` | string |  | urls, names: only these coverages, comma-separated: visited, catchall, error, gone, hint, skipped, capped |
| `-json` | bool |  | urls, names: one {url\|name, coverage, status, source} object per line |
| `-run` | string |  | the run to write, by the run_id of its summary (default: the newest run of the workspace; jsonl: every run) |
<!-- flags:end -->
