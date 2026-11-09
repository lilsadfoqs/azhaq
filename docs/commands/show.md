# azhaq show

Everything known about one URL, host or name: what found it, what it leads to, every observation.

## Synopsis

```
azhaq show -db FILE [-json] [-run ID] KEY
```

## Examples

```
# A URL
azhaq show -db app.db https://app.example.com/api/users

# A host, as JSON
azhaq show -db app.db -json app.example.com

# A page an earlier run of the workspace saw (the run_id of its summary, or its first 4 characters)
azhaq show -db app.db -run 3883752b https://app.example.com/
```

## What it does

`azhaq show` looks up KEY in a workspace (`-db`, default the last run's) and prints the entity's row, its links and its observations. KEY is a URL, a host or a name.

A workspace keeps every run, and `show` reads the newest. A KEY the newest run did not see is looked up in the earlier runs, newest first: the run it read is named on stderr and in `-json` (`run`). `-run ID` reads that run only, by the `run_id` of its summary (at least 4 characters); `azhaq query -db FILE -runs` lists them.

## Output

The text form prints the entity's row, its links and its observations.

`show -json` prints one object:

| Field | Meaning |
| --- | --- |
| `row` | The map row, with `found_in`. |
| `links` | Each link: `rel`, `dir` (`in` or `out`), `type` and `key`. |
| `observations` | Each observation: `collector`, `kind`, `source`, `observed_at` and `payload`. |
| `run` | The `run_id` of the run read. |
| `services` | For a hostname: its front pages, with `coverage`, `status`, `title` and the `error` of one that failed. |

An `azhaq-js` observation's payload holds the `found_in` of the page it read.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### GraphQL endpoints

- An endpoint found by a run has an `azhaq-graphql` observation. Its `get_queries` is true when the endpoint answers `{__typename}` sent with GET.
- An endpoint read with `-graphql` has an `azhaq-graphql-schema` observation. Its payload holds `queries`, `mutations`, `subscriptions` and `types` (names), and `schema`.
- `schema` is the whole `__schema` object of the introspection. A schema over 8 MB is kept without its descriptions. If it is still over 8 MB, `schema` is left out and `schema_bytes` holds its size.
- A server that refuses the full introspection query for its depth is asked for the names only. `schema` is then absent.

### Recovering a schema when introspection is off

A server with introspection turned off is asked for root fields by name, as clairvoyance does. Its validation errors name the fields that exist:

```
Cannot query field "pastez" on type "Query". Did you mean "pastes"?
Field "paste" of type "PasteObject" must have a sub selection
```

Errors about required arguments give the arguments. The payload then holds `queries`, `mutations`, `types` and `signatures`, with `"recovered":"suggestions"`. A signature looks like `uploadPaste(content: String!, filename: String!): UploadPaste`.

Three kinds of word are tried, in this order:

1. `client`: the field, argument and type names of GraphQL operations that the map already found in the HTML and scripts on the endpoint's origin. `client_words` counts them.
2. `probe`: the built-in wordlist of verbs and nouns, the words of `-graphql-wordlist`, and the parts of names already recovered.
   - The wordlist holds `get`, `list`, `all`, `create`, `update`, `delete`, `import`, `upload`, `system`, `health`, `diagnostics`, `user`, …
   - The parts are recombined pairwise and with an "All" infix for CRUD conventions: `delete` + `all` + `pastes` tries `deleteAllPastes`. At most 4000 words are made, taking the parts in alphabetical order.
3. `suggestion`: a name that a validation error names outright.

- The payload's `recovery` object gives each root type's field count, how many fields were found each way (`"by":{"client":1,"probe":6}`) and how many words were tried (`words_tried`).
- `complete` is always `false`: recovery cannot prove that a type has no more fields than it found.
- A recovered schema is not the server's schema. It lacks types, fields the server never suggested, and the types of fields whose errors did not name them.
- The exports mark it as partial (see [export](export.md#graphql-and-sdl)). A whole schema read by introspection is not marked.
- Every document asked carries a field no schema has, so none passes validation and nothing runs.
- Recovery sends at most 96 documents to one endpoint: 48 for the query type and 48 for the mutation type. `azhaq plan -graphql` says so.
- A candidate whose answers to the introspection query and to its shorter form are the same refusal (the same error status and the same body, which names neither `__schema` nor introspection) is a gate in front of the endpoint, not a schema: it is sent those two POSTs and no more, dropped, and the summary names it (`refused the schema query twice the same way (400 "…"): dropped, nothing more was sent to it`). A server that blocks introspection by a rule of its own (its error names `__schema` or introspection, or says `Cannot query field`) is recovered as below.
- Endpoints a script or a description names are asked before the ones only a path sweep found (`/graphql` before `/graphiql`), so a budget reads their schemas first.
- A GraphiQL or Playground page (one whose GET served the IDE) is not asked for a schema once another URL of its origin gave one whole by introspection: no POST goes to it, or its recovery stops before the next document, and the summary notes `an IDE page, not asked for its schema`. With no such schema on its origin, the page is recovered as any endpoint is, unless it refuses twice the same way (above). A resume keeps what the run it continues learned.

## Flags

<!-- flags:begin show -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | the database (default: the last run's) |
| `-json` | bool |  | one JSON object |
| `-run` | string |  | the run to read, by the run_id of its summary (default: the newest run of the workspace that has it) |
<!-- flags:end -->
