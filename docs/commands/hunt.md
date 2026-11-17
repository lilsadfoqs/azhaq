# azhaq hunt

Where to look first: the mapped routes, hosts and files ranked, and what the run named on each listener, each with its evidence and the next command.

A map of thousands of routes does not say where to start. `hunt` ranks the mapped routes, hosts and files by what a tester should open first. It gives one row per route template and one per listener the run named, each with its score, the reasons for it and the command to run next. It reads the workspace and sends nothing. It reads a workspace a `run` is still writing, too: the rows stored so far, without holding the run up ([a workspace whose run is still going](#a-workspace-whose-run-is-still-going)).

## Synopsis

```
azhaq hunt -db FILE [-roles roles.jsonl] [-limit 25] [-since 168h] [-json]
```

## Examples

```
# rank what the map holds
azhaq hunt -db app.db

# add what roles proved: rows where one role reached another's data rank first
azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app.example.com/ > roles.jsonl
azhaq hunt -db app.db -roles roles.jsonl

# show only the ten best rows
azhaq hunt -db app.db -roles roles.jsonl -limit 10
```

## What it does

1. Reads the workspace, and the JSONL files of `-roles` if you give any. It sends nothing.
2. Folds URLs into route templates, so `/rest/basket/6` and `/rest/basket/7` are one row.
3. Raises signals on each row, such as an identifier in the path, a backup file or a role reading another role's object. [Signals](#signals) lists them.
4. Scores each row as the sum of its signals, and drops rows with no signal.
5. Adds a row for each listener the run named: the product, the version or `no version seen`, the top advisory with its label, the proof and the command that shows it again. [Listeners](#listeners) says which.
6. Puts each row in a tier: a **finding** when a signal of it is shown by the answer (see [Findings and leads](#findings-and-leads)), an **identification** for a listener the run named, a **lead** otherwise.
7. Sorts the findings first, then the identifications, then the leads, each by score, and prints the best `-limit` rows (default 25). A lead names the check that would prove it, and every row a command to run next.

## Output

Text form: one row per line, the findings first under `findings (N)`, the identifications under `identifications (N)` and the leads apart under `leads (N)`.

```
findings (N): what the answer itself shows, as measured
rank  score  key  reason; reason  → next: COMMAND
identifications (N): what the run named on each listener; the label says how far a read settled the advisory
rank  score  host:port  identified: PRODUCT VERSION; advisory: ID LABEL; proof: EXCERPT  → next: COMMAND
leads (N): inferred from a name, a path or a guess; each names the check that would prove it
rank  score  key  reason; reason  → check: WHAT WOULD PROVE IT  → next: COMMAND
```

A reason is `signal: detail`. With `-json`, stdout holds one object per row. The summary goes to stderr, as JSON with `-json`, and counts `rows` and, apart, the `tiers` of the rows printed: `findings`, `identifications` and `leads`. When `-limit` cut the list, a note says how many rows had a signal, counts them by tier, says how many the limit left out and gives the `-limit` that prints them all.

The tier counts are `report -findings`' own function, run on hunt's rows, so a finding is one in both and a row both list has the same tier; every finding is a row of a record `report -findings` lists, one for each (a stack trace, SQL error text or a debug page in a 5xx, a directory listing, a GraphQL schema read, a dangling name, a `-roles` verdict), so the run's summary, its `next` line, `hunt` and `report -findings` count the same findings on one workspace, each with the same severity, excerpt, `reproduce` command and tier. A `-roles` verdict is in the count when `report -findings -roles` is given the same file. The three counts are not of the same rows: `hunt` counts listeners (one for each product) and the routes and hosts with a signal, and `report -findings` counts issues (an advisory a read settled, a service's unchecked matches) and the hints and checks it lists, including scripts and routes that hunt never ranks. The summary says which in `identifications_of` and `leads_of`, and the text summary in a `counted:` line, so 889 leads in one and 671 in the other are not a disagreement. `hunt` prints one row for each listener it counts, so its counts have no second number; the headline of `report -findings` gives the issues and, in brackets, the records its JSONL lists where a tier has more (`2 identifications (17 records)`), and does not call a count a stored row.

```
$ azhaq hunt -db app.db
identifications (2): what the run named on each listener; the label says how far a read settled the advisory (version-only: the version is in range, nothing checked)
  1   79  192.0.2.12:8161  identified: ActiveMQ 5.15.0; advisory: CVE-2023-46604 version-only, known exploited (CISA KEV), CVSS 10.0; 14 advisories match this version, then CVE-2022-41678 (version-only, CVSS 8.8), CVE-2021-26117 (conditional, CVSS 7.5) and 11 more: 9 version-only, 2 conditional; azhaq report -findings -db app.db lists them; proof: Server: Jetty(9.4.z-SNAPSHOT)  → next: curl -sS -i --max-time 10 'http://192.0.2.12:8161/'
  2   10  192.0.2.14:3000  identified: Express (no version seen); proof: HTTP/1.0 200 OK  → next: curl -sS -i --max-time 10 'http://192.0.2.14:3000/'
leads (2): inferred from a name, a path or a guess; each names the check that would prove it
  3   57  http://app/api/orders/{id}  object-id: {id} in the path; path-data: "orders" in /api/orders/{id}, named, not requested; unauth-write: DELETE: nothing that names it asks for credentials (not tried)  → check: GET it with the sessions of two roles (azhaq roles): one's data must not come back to the other  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
  4   33  http://app/api/v2/export  object-id: identifier parameter userId; unauth-write: POST: nothing that names it asks for credentials (not tried); input: takes format, userId  → check: GET it with the sessions of two roles (azhaq roles): one's data must not come back to the other  → next: azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url http://app/
```

| Field (`-json`) | Meaning |
| --- | --- |
| `rank` | Position in the list, best first. |
| `score` | The sum of the row's signal weights. |
| `key` | A route template, host, file or listener. A template folds several URLs and holds `{n}`, `{uuid}`, `{hex}` or `={v}`. A key seen once is the URL. A listener is `host:port`, which `azhaq show` opens (see [show](show.md)). |
| `type` | `URL`, `Hostname` or `Service` (a listener). |
| `reasons` | An array of `{signal, detail}`, one per signal. |
| `tier` | `finding`, `identification` or `lead`: see [Findings and leads](#findings-and-leads). |
| `check` | On a lead, the check that would prove it: what an answer must show. |
| `proof` | On a finding of a path check, and on a listener, the proof fields of [report](report.md#what-a-finding-carries): the request, the excerpt of the answer with its offset, the command that shows it again. |
| `kind` | Only on the row of a listener: `identification`, or `finding` when a read proved something on it. |
| `what` | On a listener: the kind of the record in `report -findings` (`advisory-precondition`, `software-version`, `unauthenticated-read`…). |
| `also_at` | On a route that answered the same body at other host names of its address and port: their URLs. |
| `also_named` | On a listener also reached under other host names (its address, a name that resolves to it) whose own answer named the same product and version: those names. Names on the address that named another product, or none, are not listed. |
| `host`, `port`, `product`, `version` | On a listener. `version` is `""` when no version was seen. |
| `source` | On a listener a name's root page gave: what named the product, `page title`, `generator`, `header X-Powered-By`, `header Server`, `header WWW-Authenticate realm` or `technology`. A title is not a version: `version` is only what one of them stated. |
| `advisory_id`, `advisory_url`, `advisories`, `kev`, `cvss` | On a listener with an advisory match: the top advisory, how many advisories match the version, whether CISA lists the top one as exploited, and its score. |
| `next_advisories`, `other_advisories` | With more than one advisory: the two that follow the top one (`id`, `label`, `kev`, `cvss`), and the count of all the others by label. The text row names these and counts the rest. |
| `label`, `severity`, `evidence`, `command` | On a listener: the record's own `proved`, `version-read`, `version-only` or `conditional` label and severity, what the record says, and the command that produced it. |
| `next` | The command to run next. [The next command](#the-next-command) says how it is chosen. |
| `template` | Only on the row of an input the pages of an origin carry in common: `{"input", "pages", "of"}`, the input and how many of the origin's fetched pages carry it. |

### Signals

| Signal | Raised by |
| --- | --- |
| `cross-role-access` | A proved `-roles` verdict that one role reached another's data: a finding, one row for each route and method, the heaviest signal: see [Cross-role rows](#cross-role-rows). |
| `cross-role` | A `-roles` verdict of `likely` or `guess` confidence: a lead of the route. |
| `takeover` | A name another party may take over, on a service's own page or a domain nobody holds. |
| `dangling-dns` | A CNAME chain that ends at a name that answered `NXDOMAIN`: a finding of severity low, ranked with the other findings. It says what was measured, and nothing about who may create the name: the `takeover-candidate` lead for the same name stays a lead. |
| `error-disclosure` | An answer whose body holds a stack trace (three or more frames, any status, from `probe`, `run` or `dirs`): a finding of severity low, one row for each record `report -findings` lists, keyed by its URL and ranked with the other findings. The route's own 5xx lead is not repeated beside it. See [Server errors](#server-errors). |
| `takeover-candidate` | A CNAME to a cloud name that does not resolve (`dangling`). It rests on NXDOMAIN alone: `unverified who can claim TARGET: NXDOMAIN does not show the name is free`. The unverified part is who can claim the name, not the dangling record, which is the `dangling-dns` row. See [Takeover candidates](../CONCEPTS.md#what-a-dangling-row-rests-on). |
| `secret` | A credential a script carries. The reason names the file and gives the evidence: the name it was assigned to, the value redacted, the rule that listed it and, for a generic secret, its entropy. See [Secret candidates](#secret-candidates). |
| `sourcemap` | The source maps azhaq read on a host, one row for the host: it weighs more when the maps carry the app's own code (`sourcesContent`) than when they only name its files. |
| `exposed-file` | A backup, key, database or archive file, or a `.git` directory, whose path is requested: a finding when its answer is the file's own, a lead otherwise: see [Exposed files](#exposed-files). |
| `exposed-panel` | An admin panel, dashboard, console, actuator, phpinfo, Swagger UI or GraphQL IDE whose own page answered, shown by its title or its content: see [Exposed files](#exposed-files). |
| `directory-listing` | A page whose title is a directory listing: a finding of severity low, ranked 55, a record of `report -findings`. |
| `sql-error`, `debug-page` | The body of a 5xx shows SQL error text (ranked 50) or a framework's debug page (35): findings of severity medium, records of `report -findings`. |
| `api-description` | An API description served. |
| `graphql-schema`, `graphql-ide` | A GraphQL endpoint whose schema was read, or whose IDE answers: findings of severity low, ranked 45, records of `report -findings`. |
| `graphql` | A GraphQL endpoint that answers like GraphQL: a lead. |
| `object-id` | `{name}` in the path, or an `id` parameter. |
| `unauth-write` | A POST, PUT, PATCH or DELETE that no description asks credentials for, on a route that did not turn the plain request away. |
| `upload` | A file field in a form, or an operation whose body is `multipart/form-data` or a file. |
| `xml` | An operation whose body is XML (`application/xml`, `text/xml`): a parser that may read entities. |
| `password-in-url` | A GET form with a password field: the password lands in logs and history. |
| `gated` | A 401: the server asked for authentication, so a target for `azhaq roles`. A bare 403 says only `forbidden` and weighs less (5, against 15): nothing in it shows that a session would change the answer. |
| `server-error` | A 5xx, weighed by what shows beside it: see [Server errors](#server-errors). |
| `input` | The route takes query, body or form names. |
| `new` | First seen within `-since`. |
| `unconfirmed` | A route that only a script names, whose GET answered 404 or 410. It adds no weight: see [Routes only a script names](#routes-only-a-script-names). |
| `path-auth`, `path-search` | A word in the path says it signs in or issues a session, or that it searches and filters: see [Words in paths](#words-in-paths). |
| `param-command`, `param-url`, `param-file`, `param-debug`, `param-redirect`, `param-query`, `param-callback` | A parameter name that says what it takes. |
| `path-admin`, `path-debug`, `path-config`, `path-env`, `path-doc`, `path-function`, `path-data` | A word in the path says what the route is for. The first five also read the labels of a host name that resolves. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Which rows appear

- A row with no signal of its own is left out.
- A row whose only signal is `new` never ranks.
- Static assets, scripts, catch-all pages and pages that are gone are never rows.
- A route that answered the same at several host names of one address and port is one row, not one for each name. The names must resolve to the same address, and every answer must have been read, with the same status and the same body hash. The row lists the other URLs in `also_at` and in a `same-answer` reason, and the tier counts count it once. A route whose answer was read at only one of the names is not folded: nothing shows the answers equal.
- An input name that most pages of an origin carry belongs to the site's template, such as a search box or a sign-in form in every page's header. The rule: at least 5 of the origin's fetched pages carry the name, and at least 40% of them. The numbers come from the v0.12 hunter evidence, where one search box was 77 of the top 100 rows. The pages that only carry it have no signal for it and are left out. The input is not lost, since it can be the injection point: it is one row for each origin and name, on the page it was first seen on, with a reason such as `input q on 312 of 340 pages of http://host:8080 (the site's template)`, ranked by its own signals like any other input. Its `-json` row has `template: {input, pages, of}`. A route that takes the name in its own query keeps it as its own signal.

### Listeners

A listener row is what the run named on one `host:port`. The rows come from the same records as [`azhaq report -findings`](report.md#what-a-finding-carries), so the two agree. There is one row for each listener and product:

- The product and the version a service stated, or `(no version seen)` when a stage named the product and nothing named its version.
- The top advisory the version matches, with its label as `report -findings` says it (`proved`, `version-read`, `version-only`, `conditional`) and how many advisories match in all. The text row names the next two and counts the rest by label (`and 11 more: 9 version-only, 2 conditional`); every advisory is in `report -findings`. A `conditional` advisory says what it waits on, with the words of the record it was read from (`CVE-2023-44487 conditional; precondition: needs HTTP/2: "The HTTP/2 protocol allows…"`; in the next ones, `conditional: needs HTTP/2`), and ranks below the matches with nothing open; a row says `settled: HTTP/2 offered (ALPN h2)` where a probe saw the listener speak HTTP/2. A product with no version has no advisory: there is nothing to match.
- The proof: the banner or the header that stated it, and the command that shows it again, which is the row's `next`.
- A name that shares its listener with others (name-based virtual hosts) has a row of its own, keyed `name:port`, for the application its root page names about itself: see [Applications of a name](#applications-of-a-name).
- A listener reached under its address and under a name that resolves to it, with the same product and version, is one row, which lists the other host names in `also_named` and in its `identified` reason. Only a name whose own answer named that product and version is listed; a name on the same address whose answer named another product or version, or none, is not folded into the row, and a name whose root page answered differently is a row of its own, whatever the product.
- A read that proved something on a listener (`-verify`: a data store that answered without a password) is a finding row, one for each address, port and protocol: a listener reached by its address and by names that resolve to it is read once and is one row, which lists the other names in `also_named`. The first name keys the row, a name before an address. A read that depends on the name (a service read inside TLS) is a row for each name, folded into one only when the answers are the same.

An identification is never softened: `version-only` says the version is in the advisory's range and nothing more was checked.

### A workspace whose run is still going

`hunt -db PATH` reads a workspace a `run` is still writing: the rows committed so far, a listener named and a proof answered included, as another reader of the file would see them. It opens the file as a reader of its WAL database does, so the run's writes are not held back and the run does not fail: a batch the run has open is not in the rows until it commits. The rows grow as the run goes, and the rank of a row changes with them. `hunt` does not say the run is going: the progress line of the run does, and names `azhaq hunt -db PATH` once its first listener row is stored; `run -stream` prints each listener row as `found  identified …` and `found  finding …` when it is stored ([run](run.md#streaming-found-lines)).

### Applications of a name

When several names share an address and port, the root page of each name can name a different application. A name's row is read from that page, by the sources `page title` (the title rules `azhaq ports` reads a page's title with), `generator` (the meta tag), `header X-Powered-By`, `header Server`, `header WWW-Authenticate realm` (the realm of a `401`'s challenge, which a console names itself by: `ActiveMQRealm`) and `technology` (the technologies found in the page). The `source` field says which; a title or a realm names a product and no version. There is one row for each name, port and product, and none for a product the listener's row already names for the same name.

Only an application is a row: a product wappalyzer's data holds under a category such as CMS, wiki, CI, database manager, webmail, issue tracker or web framework. A library, a font, a CDN or an analytics script is not. A web server, a proxy or a cache is left out when the listener already names it. A product the data does not hold, named by a page's own title, generator or `X-Powered-By`, is kept as the page names it. These rows go through the same advisory matching and labels as the listeners'.

### Findings and leads

A row is a **finding** when one of its signals is shown by what was received, and a **lead** when none is. A path or a name is never proof. The `findings` header says what the tier is, not a verdict on each row: a row under it states what its own answer showed and nothing more. A `dangling-dns` row, for one, says the CNAME chain ended at a name that answered `NXDOMAIN` and, in its own line, that whether anyone can create that name was not tested.

- Shown by the answer: `cross-role-access` (a `-roles` verdict of `proved` confidence, or with none), `takeover` of strength `strong`, a `secret` whose own format names it (a key with a known shape, severity above `info`), `exposed-file` and `exposed-panel` when the answer shows the file or the panel ([Exposed files](#exposed-files)), `directory-listing` (the page's own title is a directory listing), `graphql-schema` when its schema was read and `graphql-ide` when its IDE answers, `error-disclosure` when the answer holds a stack trace of three or more frames, `sql-error` when the body of a 5xx shows SQL error text and `debug-page` when it shows a framework's debug page. Each of these is a row of the record `report -findings` lists for it: the route has no lead that repeats it.
- Leads: every other signal, such as a word in a path, `input`, a `param-*`, `object-id`, `gated`, `unauth-write`, `upload`, `sourcemap`, `takeover-candidate`, `api-description` (a served API description: a service that publishes it has not shown a flaw), a generic or bundler secret, a role's 5xx that differs from another's, and a `named` route no server confirmed.

An **identification** is a listener the run named: a product, and a version or none. It is not proven: the label says how far a read settled its advisory.

A product named only by the hash of an icon is not an identification but a lead (`favicon: favicon matches X or Y (hash …); asked: X: GET /path answered 404 …`), keyed `host:port`, with no version and no advisory. It ranks below every identification, and its `check` says what would settle it. [Product checks](run.md#product-checks) says what makes it one.

`hunt` lists the findings first, then the identifications, then the leads, each group by score. In the identifications, a version seen comes before none seen, and a `proved` label before `version-read`, and that before `version-only`. Each lead carries `check`, what an answer must show for it to be a finding.

### Score and order

- The score is the sum of the row's signals. Each signal counts once, at its highest weight.
- Rows only a script names and the server did not confirm, and a `takeover-candidate` that is the row's only signal, come after every other row, whatever their score: see [Routes only a script names](#routes-only-a-script-names).
- A path whose answer is also its prefix's catch-all (the map row's `answer` says `the answer of /api/<random> too: this prefix's catch-all`) comes after the rows the server answered for themselves, before the ones only a script names: it says least of whether the route behind it exists, and it is a row all the same.
- Ties go to the target before fan-out, then to the row with more distinct signals, then by key. [Concepts](../CONCEPTS.md#reading-a-map-row) explains target and fan-out.
- `-limit` (default 25) keeps the best rows. The summary counts what it left out.

### Weights

- `dangling-dns`: weighs 30, a finding of severity low: below the other findings that have more weight, above every identification and lead.
- `takeover`: `strong` weighs more than `page`. `dangling` is its own signal, `takeover-candidate`, weighing 20.
- `secret`: weighed by the credential's severity.
- `object-id`: a route with no GET weighs less.
- `unauth-write`: weighs less when no GET showed that the route answers.
- `input`: weighs more when a write sends named fields.
- `graphql`: a lead weighs 40; the `graphql-schema` and `graphql-ide` findings weigh 45.

### Secret candidates

- A `secret` reason reads `generic-secret (medium) in URL; name apiToken, value Zx81Qp…7Ks, rule: name says secret, value looks random, entropy 4.3`.
- The rule is `known key format` (an AWS, GitHub, Stripe, Slack or similar key, a private key, a JWT), `variable a bundler inlined` (a `VITE_` or `NEXT_PUBLIC_` variable, severity `info`) or `name says secret, value looks random`.
- A private key is a secret only as a whole block: the begin line, a base64 body that decodes (to DER, OpenSSH's key format or an OpenPGP packet, or ciphertext under a `Proc-Type: 4,ENCRYPTED` header) and the end line of the same type. A begin line without them (help text, a pattern, a line joined to a variable) is a `private-key-marker` of severity `info` with the rule `begin line only, no key body after it`: a lead, never a finding.
- The last rule needs a property whose name holds `secret`, `token`, `password`, `apikey` and similar words, assigned a string of 8 characters or more with entropy of 3.2 bits per character or more. It leaves out placeholders, a parser's token tables, values with much punctuation, a class name a CSS module made (`_tokensUsage_dypaw_41`) a value that repeats its own name (`secretName: "secretName-input"`) and a translation key or a reference to one: two or more words of letters only, joined by `_` or `-`, each with a vowel and no capital after its first letter, and an optional leading `@` (`@Button_Cancel`, `Enter_Your_Password`). A value with a digit or a capital inside a word is still listed.
- A value that names a header or a field is a label, not a secret: one whose property name ends in `Name`, `Header`, `Field`, `Label` or `Param` (`tokenHeaderName`), or that is shaped as a header name, capitalised words joined by `-` (`X-Api-Token`).
- A file with several candidates is ranked by its strongest: the highest severity, then the most random value.
- A `medium` candidate needs a human: read the value in `azhaq export -format secrets` before acting on it.

### Cross-role rows

`-roles FILE` reads the JSONL that `azhaq roles -json` printed. It is repeatable, and `azhaq report -findings -roles` and `azhaq export -format findings -roles` read the same files. A row of a proved verdict (`proved` confidence, or none) is a `cross-role-access` finding, one for each route and method, which `report -findings` lists as a record; a `likely` or `guess` verdict is a `cross-role` lead of the route. A verdict is one of these:

- `reads another role's object`
- `writes another role's object`
- `anyone writes another role's object`
- `anyone reads sensitive fields`

The reason quotes the row's evidence and its confidence.

These rows have the heaviest weights, 95 to 110. The row's confidence scales the weight: `proved` whole, `likely` 85%, `guess` 60%.

### New rows

`-since` is how long ago a row is first seen to count as new. The default is 7 days (`168h`). `new` adds a little, and only when the workspace also holds URLs older than `-since`.

### Exposed files

`exposed-file` covers a `.kdbx`, `.pem`, `.key`, `.env`, `.sql`, `.db`, `.bak`, `.old`, `.orig`, `.swp`, `.zip` or `.tar.gz` file, or a `.git` directory. A file that is named or refused weighs less than one that is served.

A path that names a file or a panel is judged by its answer, which azhaq already holds (nothing is asked again), the same way `azhaq report -findings` judges it ([Path checks](report.md#path-checks)): the row is a finding when the answer holds the file's own bytes or the panel's own title; a lead when it does not (a redirect, a 401 or 403, a login form, a page that is not the file); and it is not a row at all when its answer equals the host's baselines: the answer a path that does not exist gets, its index page, one body that answers three or more paths, its login page. A served file whose bytes were not judged (a workspace made before the answers were kept) is a lead.

### Server errors

A 5xx alone is a lead, not a finding; the body showing SQL error text or a framework's debug page is a finding of its own (`sql-error`, `debug-page`), a record of `report -findings`, and the route then has no `server-error` lead for it. A stack trace of three or more frames in the answer, at any status, is an `error-disclosure` row of its own (a finding, as `report -findings` lists it), and the route then has no `server-error` lead for it. The weight of a 5xx depends on what shows beside it:

Every rule here reads the body of the row's own URL: a URL that answers a redirect has the redirect's body, and the page it ends at is a row of its own. A route that folds two URLs (`/assets` and `/assets/`) names, in the reason, the URL that gave a 5xx when it is not the first of the row.

- SQL error text in the body: 50, the rank of the `sql-error` finding.
- Another role's answer to the same route, a 5xx for one role and an answer for another: 40.
- A framework's debug page: 35, the rank of the `debug-page` finding.
- A parameter whose value came back: 30.
- A stack trace the body names but `report -findings` has no record of (fewer than three frames): a lead of 25, or 15 when the request lacked the input the route takes.
- Alone: 10.
- Alone, when the plain request carried none of the input the route takes: 3. The map row's `answer` is then `500 without input`; see [Evidence](../CONCEPTS.md#evidence-how-azhaq-knows-a-url).

### Words in paths

- `path-auth`: a word that says the route signs in or issues a session, such as `login`, `signin`, `auth`, `oauth`, `sso`, `token`, `reset`, `forgot`, `register`, `2fa`. Weight 45. A sign-in, sign-up or password reset page (`login`, `signin`, `signon`, `logon`, `reset`, `forgot`, `recover`, `register`, `signup`; a route that is not an API) is an asset to note, not a weakness by itself: it weighs 10, and a data word beside it (`/user/login`, `/reset_password`) adds at most 10. It stays in the list, low. An API route with the same words, and `auth`, `oauth`, `sso`, `saml`, `token`, `mfa`, `2fa`, keep 45.
- `path-search`: a word that says the route searches or filters: `search`, `find`, `filter`, `query`, `lookup`. Weight 35.
- A route that a script or a description gives methods for counts in full, even when it was not asked.
- A named route that nobody calls weighs half.
- A route whose GET answered 405, 400, 415 or 422 counts in full: the server has it, it only refused this request.

### Routes only a script names

A script that names a route says the client calls it, not that the server has it, and a GET that answers 404 or 410 shows nothing of a POST-only route either. A row of such a route (`hint` coverage, status 404 or 410) is not an answer to anything:

- Its path words and an exposed-file name weigh nothing, and its reasons say `unconfirmed: named by a script, not confirmed: GET 404`, not `answers 404`.
- It still keeps the signals the script gives it (the fields it sends, a write without credentials), and it comes after every row the server confirmed (200, 401, 403, 405 and other 4xx that are not 404 or 410, 5xx), whatever their scores.
- A route template where one instance is confirmed is a confirmed row.
- When nothing else is known of the route the row is left out.

### The next command

`next` is a real command, chosen by the signal that weighs most in the row.

| Row | `next` |
| --- | --- |
| `cross-role` | `azhaq roles show -dir /abs/azhaq-roles-… URL`, with `-method` for a write |
| `object-id` | `azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url ORIGIN/` |
| `input` | `azhaq params -u URL -w WORDLIST` |
| everything else | `azhaq show -db FILE URL` |

For a `cross-role` row, the `-dir` is that of the roles run that listed it. `hunt` looks in this order:

1. The `dir` of the roles row.
2. The folder of the `-roles` file, when it holds `roles.db`.
3. The newest `azhaq-roles-*` folder of the current directory.

When none is found, the row's command is `azhaq show`.

## Flags

<!-- flags:begin hunt -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | workspace database; a run that is still going may be writing it (default: the last run's) |
| `-roles` | string, repeatable |  | the JSONL azhaq roles -json printed: rows where one role reached another's data rank first |
| `-limit` | int | `25` | rows at most, best first |
| `-since` | duration | `168h0m0s` | first seen within this long is new: a bonus, never the reason a row ranks |
| `-json` | bool |  | one JSON object per row, and the summary as JSON on stderr |
<!-- flags:end -->
