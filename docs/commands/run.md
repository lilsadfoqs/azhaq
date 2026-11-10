# azhaq run

Map a target: names, services, pages, scripts, APIs, forms, parameters, in one graph.

## Synopsis

```
azhaq run (-url URL | -domain D | -list FILE | -scope FILE|PLATFORM -program P | -asn AS | -cidr NET | -in seeds.jsonl | -allow NET -sweep) [flags]
```

## Examples

```
# Map one app into a workspace
azhaq run -url https://app.example.com/ -db app.db

# Map a program's scope, capped and paced
azhaq run -scope hackerone -program security -db h1.db -max-requests 5000 -rate 5

# Names only: nothing is sent to the targets
azhaq run -domain example.com -passive -json > map.jsonl

# Sign in with Chrome first, then map as that user
azhaq run -url https://app.example.com/ -browser -login https://app.example.com/login -login-user me@x.test -login-pass '…'
```

## What it does

1. Takes your seeds: a URL, a domain, a list, a program's scope, an AS number, an address range, or a seeds file.
2. Resolves names, probes web services, crawls pages and scripts, and reads API descriptions.
3. Follows what it finds in waves, as far as `-depth` allows. `-permute` still varies the names `-dns-brute` found, whatever `-depth` is: DNS answered them, and a variation asks DNS only. A name found past `-depth` and not resolved is not varied, and a note says how many.
4. Asks each web service for the built-in paths unless `-no-paths` says not to ([Path checks](#path-checks-stop-at-their-answer)).
5. Requests every GET URL it finds in scope, except a GET found on the way (or a word of a `-dirs` or `-paths` wordlist) whose own path, query or API operation declares a state change (a word like create, delete, reset or logout, or `?action=stop`): that one is held back, listed as `skipped` with the flag that sends it, `-send-state-changing`, and counted in the summary's `state_changing_held` ([State-changing requests](#state-changing-requests)). A target you give is never held back; the targets among those that declare one are printed before the run starts. A GET can change data or end a session under any other name, and azhaq asks it: every other URL in a link, a script, an API description or a GET form is requested (a GET form is filled with neutral values with `-fill-forms`). A write, a request with a method other than GET, HEAD or OPTIONS, goes only with its flag. `-deny-path REGEX` keeps any path out (it gets the coverage `skipped`). See [what azhaq sends](../CONCEPTS.md#what-azhaq-sends-and-what-it-cannot-know).
6. Sends nothing to a host outside the scope, Chrome's requests included. `-passive` sends nothing to the targets at all. `-sources none` asks no third party at all: no subdomain source, archive, RDAP, RIPEstat or search engine. Only the resolvers and the targets get requests, and `azhaq plan` says so. `-urls-sources`, `-urls-archive` and `-asn` ask a third party, so with `-sources none` they are a usage error.
7. Prints the ranked map when it ends and the summary on stderr.

`-probe` turns off every collector but DNS and HTTP: the crawl, scripts, path checks, TLS and the third-party sources, at depth 1. A flag that asks for a collector by name still runs it: `-dirs`, `-params`, `-ports`, `-ports-udp`, `-screenshots`, `-browser`, `-dns-brute`, `-permute` and `-graphql`. A flag that only a collector `-probe` turns off reads (`-fill-forms`, `-submit-forms`, `-path-climb`, `-known-files`) is a usage error that names both, never a flag that is dropped.

`-url`, `-domain`, `-cidr` and `-asn` repeat, and each value is a seed. `-list`, `-in` and `-org` take one value: a second, different one is a usage error (exit 2), never the last one kept silently. The same holds for `-l` and `-dL` of the commands that read targets from a file.

[What azhaq sends](../CONCEPTS.md#what-azhaq-sends) lists every request by kind. `azhaq plan` prints what a run would do and send before anything goes out.

## Output

The map has one row per entity, best first: the target's own pages and APIs, then what they led to. The summary goes to stderr.

- Plain: one row per line, with forms and parameters indented below ([The text map](#the-text-map)).
- `-json`: one JSON object per row, and the summary as one JSON object on stderr.
- `-quiet`: no map and no progress lines, only the summary.
- `-o FILE`: also writes the rows to FILE, as they are printed (JSON lines with `-json`, the text map without), replacing it, as `crawl`, `probe` and `ports` do. The file is made before anything is sent, so a path that cannot be written fails at once with exit 1, and a directory is a usage error. With `-quiet` nothing is printed and the file still gets the rows. The summary lists the file under `wrote`.
- `-stream`: also prints each name, address, URL and open port as it is found, before the map ([Streaming found lines](#streaming-found-lines)).

```json
{"type":"URL","key":"http://127.0.0.1:3001/api/Users","scope":"target","coverage":"visited","role":"auth",
 "status":401,"title":"UnauthorizedError: No Authorization header was found","methods":["GET","POST"],
 "params":["email","password"],"proof":"status=401 …","first_seen":"2026-10-26T14:23:40Z"}
{"type":"URL","key":"http://127.0.0.1:3001/rest/2fa/verify","scope":"target","coverage":"hint","role":"api",
 "methods":["POST"],"body":["tmpToken","totpToken"],"ops":[{"method":"POST","body":["tmpToken","totpToken"],"source":"js-call"}],
 "found_in":[{"script":"http://127.0.0.1:3001/main.js","line":6472,"col":88,
              "snippet":"this.http.post(`${F$.hostServer}/rest/2fa/verify`,{tmpToken:localStorage.getItem(`totp_tmp_token`),totpToken:t})"}]}
{"type":"URL","key":"http://127.0.0.1:3001/#/administration","scope":"target","coverage":"hint","role":"client-route",
 "guard":"canActivate","proof":"guard=canActivate","found_in":[{"script":"http://127.0.0.1:3001/main.js","line":6622,"col":727,
 "snippet":"…AboutComponent});var pN=[{path:`administration`,component:Su,canActivate:[cs]},{path:`accounting`,"}]}
{"type":"URL","key":"ws://127.0.0.1:3001/socket.io","scope":"target","coverage":"hint","role":"websocket","protocol":"socket.io"}
```

| Field | Meaning |
| --- | --- |
| `type` | `URL`, `Hostname`, `Domain`, `IPAddress`, `Port`, `Organization`, … |
| `key` | The URL, name or address. For a port, `address:port/tcp` (`/udp`): one row for each endpoint, however many names point to the address. For a folded page, its `{n}` template. |
| `scope` | `target`: what you asked about. `fanout`: found on the way (other hosts, CNAME targets). |
| `coverage` (URLs) | What azhaq did with the URL: `visited`, `catchall`, `error`, `gone`, `hint`, `skipped` or `capped`. See [Coverage](#coverage). |
| `evidence` (URLs) | How azhaq knows the row: the strongest level of its sources, from `answered` to `given`. See [Evidence](#evidence). |
| `evidence_from` | The collectors behind the evidence, sorted. |
| `answer` (URLs) | Set when the status says less than it looks, such as `500 without input`. See [Evidence](#evidence). |
| `role` (URLs) | What the URL is: `app` (a front page), `auth` (401), `forbidden` (403), `api`, `page`, `script`, `asset`, `sourcemap`, `manifest`, `client-route`, `websocket`. |
| `role` (names) | The status of a name: `live`, `sibling`, `unresolved`, `dead` or `wildcard`. [CONCEPTS](../CONCEPTS.md#names) defines them. |
| `names` (ports) | The names that point to the port's address, sorted; the row's key is the address. |
| `proof` | Why the row is as it is, in one line: `status=401 …`, `guard=canActivate`. |
| `first_seen` | When the workspace first saw the entity. |
| `guard` | What a client route's router checks before it draws the view. See [Client routes](#client-routes). |
| `protocol`, `namespace` | `protocol` is `socket.io` for a socket.io endpoint; `namespace` is its namespace, when the app names one. See [WebSockets](#websockets). |
| `service`, `product`, `version` | A port's row (`-ports`, `-ports-udp`): what answered on it, as `azhaq ports` prints it. `role` is `service`; `state` is `open` or `open\|filtered` (a UDP port that neither answered nor was refused); `proof` repeats it with `extrainfo`, `tls` and the title or banner when no product was named. |
| `status`, `title` | The URL's own answer: the first hop of a redirect. See [Redirects](#redirects). |
| `methods`, `params` | From API descriptions and call sites in scripts. See [Methods and parameters](#methods-and-parameters). |
| `ops` | Each operation on the route: `method`, `query`, `path`, `header`, `body`, `body_type`, `auth`, `summary`, `operation_id`, `source`. See [Operations](#operations). |
| `body` | The body field names of all the route's operations, whatever described them. See [Operations](#operations). |
| `forms` | One object per form on the page: `method`, `action`, `enctype`, `fields`, `files`. See [Forms](#forms). |
| `found_in` | Up to three places where scripts name the route, calls first. See [found_in](#found_in). |
| `watch` | Names worth trying first, by what each says it takes: `returnUrl (redirect)`, `url (url)`, `file (file)`, `cmd (command)`, `isAdmin (debug)`, `userId (id)`, `callback (callback)`. |
| `folded` | On a summary row of names: how many dead, wildcard or unresolved names it holds. |
| `template`, `count`, `not_asked`, `capped` | A page that differs only by an ID is folded: its `{n}` template, how many URLs it holds, how many were not requested, and how many of those a limit kept from being asked (`coverage: capped`). See [Templates](#templates). |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). Three things are specific to `run`:

- `-max-time` ends the whole run, the DNS brute force and the permutations included: it exits 4, `stopped` names the flag, what was answered is kept and `azhaq resume` asks the rest.
- The summary's `counts` are disjoint and add up to `stored`, the map rows in the database: `pages`, `api`, `auth`, `forbidden`, `catchall` (URLs that answered with the page every unknown path gets), `skipped` (URLs named and not asked: a `-deny-path` rule, or a catch-all origin, see [Catch-all origins](#catch-all-origins)), `client routes`, `websockets`, `scripts`, `assets`, `source maps` and `manifests` for URLs, `hostnames`, `dead hostnames` and `wildcard hostnames` for names, `ports`, and `open|filtered ports` for the UDP ports that neither answered nor were refused, never counted as open. `results` is smaller than `stored` by the rows folded into templated rows, dead or wildcard name rows and, in the text view, the lines of the [folded classes](#folded-rows), and the text summary says how many. Each key is a `query` filter: see [run counts](../OUTPUT.md#run-counts). A port is one row for each host, port and protocol, however many scans listed it.
- Under `-max-requests`, a port sweep leaves the requests that mapping each web service it found open needs (about N per service, as `plan` says), so a budget smaller than the sweep still maps the services found; the summary's notes say how the budget went by stage (`request budget N, spent by stage: ports …`).
- A target given with no port (a name or an address) is asked on 443, then 80, or on `-web-ports`. So is the name of a URL given with its own port, and a name found on the way. A guess nothing listens on, refused, is a note (`no web service on 443 or 80`), not a failure, and so is a refused connection on 443 to read a name's certificate; a `-web-ports` port that refuses is one, and so is a URL given that refuses. A refused URL is one failed target: the other targets of the run are mapped as usual, and the exit code is 0 while another target answered, 3 when none did.
- A port the scan found open that answers the HTTP stage with something other than HTTP (an FTP or SSH banner) is a service, not a failed target: it keeps its `Port` row and the run names it in a note (`open, but not a web service`). Its plain-HTTP request is its only one when the reply is not TLS either. A port the scan found open and did not name as HTTP that closes or resets at once on the request is an answer too, as `tcpwrapped` is in `ports`: no failure, the same note, exit 0. A timeout, a refused connect after the port was seen open, a TLS error, and a port named `http` or `https` that resets or closes without answering are still failures.
- It counts the path checks it skipped, as a note ([Path checks](#path-checks-stop-at-their-answer)).
- `cost` is what the run was estimated to send, stage by stage, beside what each stage sent (`sign-in`, `sources`, `names`, `web`, `ports`, `fuzz`, `shots`, `verify`, …, each with its collectors): the text summary has a `cost:` line for each stage. The estimate is `plan`'s ([The estimate](plan.md#the-estimate)) and `run` prints it on stderr before it sends when it is more than 1000 requests, connects and DNS queries together. The stages' `actual` add up to `requests` and `dns_queries`. A resumed run has no estimate, only what it sent.
- A run that finished, with no limit stopping it, ends its `next` with the wider passes it did not make that its flags and findings point to, each a command to copy with what it would send beyond this run, marked `next pass, not run`: after `-ports` with fewer than all 65535 ports, the rest of the range (`azhaq ports -host … -p full`: the ports not asked, the addresses scanned, the connects it would send, and the open ports found in the range asked). It is a line, never a request; see [Next in the summary](#next-in-the-summary).
- A run stopped by `-max-requests` says in `stopped` which stage the last request of the budget was sent by, which collector was refused first when that is another, and what each stage had sent; `resume` is the command that continues it.

## Details

### The text map

- Rows are the JSON rows, one per line, best first. Forms and parameters are indented below the row.
- A GraphQL endpoint's operations are listed by their signatures: the first 50. The rest are in `-json` and the exports.
- A row that is not `answered` ends with its evidence: `[browser]`, `[described]`, `[called]`, `[linked]`, `[archived]`, `[guessed]` or `[given]`.
- A row that has an `answer` shows `500 without input` after its proof.

### Folded rows

The text map lists the rows that answer for themselves and counts the others in one line of their class each. A row folds only for what the run's own requests measured; no name decides it:

| Class | The rows | The line says |
| --- | --- | --- |
| `catchall` | URLs whose answer is the very page the origin gives a path that cannot exist (`catchall` rows, with the page equal byte for byte once the requested path is taken out of both; a page that only has its shape, title, size and lines, may be a route of its own and stays listed), and the URLs not asked because the origin had answered other paths so; and a path `-dirs` found in a directory that answers every unknown name alike: its answer is the control `-dirs` asked in that directory byte for byte ([dirs](dirs.md#a-catch-all-inside-a-directory)), 403 and 404 answers too. | The origin, how many URLs, and the control: the request for a path that cannot exist and its answer (`GET /xq3 → 200 text/html, 3748 bytes, "OWASP Juice Shop"`). One line for each origin. |
| `not-found` | URLs the server answered with 404 or 410, and routes only scripts name whose GET got one. | How many, and the templates they fall into (`/api/Feedbacks/{n} ×12`), the five largest. |
| `beyond-depth` | Images, fonts, media, source maps and manifests a page holds that no request asked for (past `-depth`, a limit, or fetched by no step). | How many. |
| `unrequested` | Hints only scripts name, with no call, method, form, description or page link, that nothing requested. | How many. |

A route a script calls with a method, a description lists, a page links or a request answered with anything else stays listed, as does every row under `-deny-path`: those are leads or the effect of a setting you chose. Each line counts as one result, and `results + folded + left_out = stored` as before.

- `-all-rows` prints one line for each row, as `run` did.
- `-json` prints every row, each folded one with its class as `fold`. The summary's `folds` has one entry for each line of the text view: `class`, `count`, and for a catch-all origin its `origin` and the `controls` it was compared with.
- Folded rows stay in the workspace: `query` lists them, `-all-rows` and `-json` print them.
- Parameter and body names worth trying first are on a `watch:` line under the row.
- A folded template shows its count: `(30 urls, 27 not asked)`.
- Client routes and websockets come after the server's routes of the same rank. Their proof is `guard=…`, `protocol=…` and `namespace=…`.
- `azhaq show URL` prints where scripts name a route, under `found in`, one place per line as `script:line:col  snippet`:

```
found in
  http://127.0.0.1:3001/main.js:6472:88  this.http.post(`${F$.hostServer}/rest/2fa/verify`,{tmpToken:localStorage.getItem(`totp_tmp_token`),totpToken:t})
```

### Streaming found lines

- With `-stream`, `run` prints each URL, name that resolves, address and open port as it is found. They come before the map.
- One line for each key the map has a row for: a URL found by the crawl and answered later, or the front page found twice, prints once, as the first way it was found (its status is in the map). The address of an IP host is a row and a line too (`found  address 127.0.0.1`).
- An open port is a line of its own, under its row's key: `address:port/protocol`, printed once, when a scan reports the port (`found  port    127.0.0.1:3001/tcp  open http`). A later scan that lists the same port does not print it again.
- Not streamed: names that do not resolve, which the map folds into a summary row.
- An answer line looks like `found  answer http://app/openapi.json  [200]`. An answer that is the page every unknown path gets ends with `(catch-all: the page any unknown path gets)`.
- With `-json`, each is an object with `"type":"found"` and these fields:

| Field | Meaning |
| --- | --- |
| `kind` | `name`, `url`, `answer`, `address` or `port`. |
| `key` | The name, the URL, the address, or `address:port/protocol` of a port: the key of the map row. |
| `collector` | The collector that found it. |
| `status`, `title` | For an answer. |
| `catchall` | For an answer: `true` when it is the page every unknown path gets. |
| `ip`, `host`, `port`, `protocol`, `state`, `service` | For a port: the address, the name it was scanned under (empty for an address given as such), the port number, `tcp` or `udp`, `open` (UDP also `open\|filtered`) and the service when one was named. |

### Coverage

[CONCEPTS](../CONCEPTS.md#coverage-what-azhaq-did-with-a-url) defines `visited`, `catchall`, `error`, `gone`, `hint`, `skipped` and `capped`. What follows is what is specific to `run`.

- `gone` is a URL found in an archive or a link that answered 404 or 410: it is not there now.
- A path a `-dirs` or `-paths` sweep asked is `visited` (or `gone`, or what its answer makes it) with the status the sweep read, even when `-depth` leaves no step for fetching it again. It is never `capped` for that.
- `hint` means found, in a script, an API description or an archive, but not requested. It also covers these cases:
  - An archive's static assets, such as images and fonts, are never requested, whatever hides their extension.
  - A route that scripts call only with POST or PUT.
  - A route that only a page in Chrome writes to. A GET that answers 404 or the catch-all page says nothing about such a route, and it stays `hint`; a GET that answers 405 makes it `visited`, with the 405.
  - A route named only in scripts, with no GET call among them, while a GET answers 404. Its `proof` says `GET answers 404; found only in scripts, method unknown`.
- `skipped` means found by a link, a script's call, an API description or an archive, and not requested because a `-deny-path` rule of yours keeps its path out, because its own name declares a state change and `-send-state-changing` is not given ([State-changing requests](#state-changing-requests)), or because its origin answers every path alike: see [Catch-all origins](#catch-all-origins).
  - The row's `skipped` field and the summary say which rule: `-deny-path ^/admin/`.
  - Nothing else makes a row `skipped`. A URL on a host `-allow` lists with another port only has no row: the summary's `skipped` names it, with the reason `outside the scope: -allow lists this host with another port only`. A word of a wordlist (`dirs -w`, `-dirs FILE`, `-paths FILE`, `fuzz`) that names a state change is held back like a found link: it is listed in the summary's `skipped`, a guess nobody saw exist is no row of the map, and `-send-state-changing` asks it.
- `capped` means left when a limit was hit, or when its origin stopped answering.
  - An origin has stopped answering after 5 connects or timeouts in a row with no answer between them.
  - The rest of that origin's work is left for `azhaq resume`. It is listed under `skipped` as `ORIGIN stopped answering after 5 timeouts`, and `stopped` names the origin.
- A version prefix alone that only a script's strings name (`/v3`) is left out of the map when it answers 404 or the catch-all page.

### Catch-all origins

An origin that answers every path with the same page (a single-page app's shell) says nothing about a route by a 200. `run` tells the page from a real one by a control request for a path that cannot exist, in the same directory.

- Once 3 of a directory's script-named paths have answered with that page, before 3 of them answered anything else, `run` stops asking the directory's other script-named paths, when the control of the directory (the answer for a path that cannot exist there) is that page too. 3 is the number the summary's note has always used. The directory's own paths decide: one nothing was asked in is no exception azhaq knows of, so its first path is asked alone, and that asks the control; its paths then go one at a time until it is decided, so a loaded machine sends the same requests as an idle one. A directory whose control is another answer (an API that answers JSON, an error page, a folder of real pages), or whose own paths answer for themselves, is asked whole: an API whose unknown paths answer the app's shell is asked, route by route, for the routes answer something else. Beyond the 24 directories an origin gets a control for, the nearest directory above stands for the control, as in the catch-all check; the directory's own paths still decide. Nothing is decided by a path's name.
- The links of a page, the root, the scripts the run loaded to read and everything you give are always asked. Paths lent to workers (`-serve`) are asked too: the rule needs the answers in one process.
- A resumed run goes on from what the stopped run had learned, kept with its answers: it holds what the first held, and does not ask again the paths the first had settled.
- Their rows stay in the map with coverage `skipped`. The summary names how many and the origin (`http://app: 600 URLs that scripts name were not asked, because it had answered paths with the one page every unknown path gets`), the `skipped` list has one line for the origin, and `counts` has `skipped` for them (and `catchall` for the answers), each row counted once.
- `-catchall-after N` sets the number (0 asks every path). `crawl` asks every path, as katana does, and keeps the catch-all answers as rows of coverage `catchall`, which its default list folds into a line.
- A held path that is a real page of its own in a directory the catch-all covers would have answered a different page: this is an inference from the controls, not a request. Ask it with `-catchall-after 0`, or by hand.
- The text view counts the catch-all rows in one line, with the control ([Folded rows](#folded-rows)); `-all-rows` lists them. `-no-catchall` leaves the rows that answered with the catch-all page, and those not asked for that reason, out of the rows printed and out of `results`. `stored` and `counts` still hold them, and `left_out` says how many, so what `run` prints is what `results` counts: `results + folded + left_out = stored`.

### Evidence

- [CONCEPTS](../CONCEPTS.md#evidence-how-azhaq-knows-a-url) defines the levels, `evidence_from` and `answer`. It also lists where evidence shows: `query`, the text map and the exports.
- `azhaq query -fields key,evidence,evidence_from` shows the level. `azhaq query -evidence answered,described` keeps the rows with those levels.
- `answer` is `500 without input` for a 5xx that azhaq's plain request got from a route that takes names, in the query or the body. The request sent none of them.

### Roles of a URL

- `manifest` is a bundler's build manifest: Vite's `.vite/manifest.json`, Create React App's `asset-manifest.json`, Angular's `ngsw.json`, Nuxt's build meta.
- `client-route` and `websocket` are below.

### Client routes

A client route is a view that a single-page app's router draws.

- It is read from the app's route table: Angular's `RouterModule`, React Router's `<Route>` and `createBrowserRouter`, or Vue Router.
- Its key is `http://host/#/administration` for an app that routes by the hash, else its path, `http://host/admin`.
- Parameters are written `{name}`. Nested routes are joined to their parents'.
- A view after the hash is never requested: the server answers every one with the app's shell.
- A view in the path is asked for once with a GET, as the server may answer it itself.
  - A sign-in's 401 makes the row `auth`. A page the server renders makes it `page`. The guard stays on the row and in its `proof`.
  - A view the shell answers stays `client-route`, with coverage `catchall`.
  - A template such as `/reports/{id}` is not requested.
- A string in a script that names a view is that view's, listed in its `found_in`, not a page of its own. A router link and `router.navigate(['/order-completion', id])` are examples.
- With `-browser`, Chrome opens a view in the path like any page the run found, once; it does not open a view after the hash.

`guard` is what the router checks before it draws the view. A parent's guard holds for its children.

- Angular: `canActivate`, `canMatch`, `canLoad` or `canActivateChild`, with the guard's name when the build keeps it, such as `canLoad AdminGuard`.
- Vue: `meta.requiresAuth`, or another meta key about sessions or roles, or `beforeEnter`.
- React: a wrapper such as `RequireAuth` or `PrivateRoute`.

### WebSockets

- A `websocket` row is an endpoint a script opens: `new WebSocket(…)`, `SockJS`, a `ws://` or `wss://` URL, or a socket.io client's `io(url, {path})`.
- Its key is `ws://` or `wss://`: the page's scheme when the script builds the URL from `location.host`.
- It is never requested.
- `protocol` is `socket.io` for a socket.io endpoint. `namespace` (`/chat`) is given when the app's call names one.
- When the app's call cannot be read, the library's default path, `/socket.io`, stands.
- Third parties' sockets, such as chat widgets and analytics, are left out.

### Operations

- `ops` has an entry for each operation on the route. `auth` means the description asks for credentials. `body` lists field names.
- `source` is `js-call`, `openapi`, `graphql` or `browser`. `browser` is a write that a page in Chrome sent or was refused. It carries the names its query and body held, never their values.
- The route's `body` is the body field names of all its operations, whatever described them:
  - a script's call;
  - an API description, served or found;
  - a GraphQL schema, as argument names;
  - a request taken in from katana.
- A GraphQL endpoint whose schema was read with `-graphql` has one op per query, mutation and subscription:
  - `method` is `POST`.
  - `summary` is its signature: `mutation login(username: String, password: String): Login`.
  - `operation_id` is the field name, `body` the argument names, and `source` is `graphql`.

### Redirects

- `status` and `title` are the URL's own answer: the first hop of a redirect.
- Without a scope, a redirect is followed only within the site: the same registrable domain or address. With a scope, it is followed only inside it.
- Chrome is held to the same rule for everything a page asks for.

### Methods and parameters

- `methods` and `params` come from API descriptions and call sites in scripts.
- `params` also holds the names in the URL's own query string.
- The query names of the links on a page are on the links' rows, not the page's.

### Forms

- Each form is `{"method","action","enctype","fields","files"}`.
- A form whose action is empty or `#` submits to the page itself. Its `action` is the page's URL with its query.
- `enctype` is a POST form's encoding: `application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain`.
- `files` are the fields that are file inputs.
- A GET form is a request like a link: with `-fill-forms` its action is asked once with neutral values, unless its own path declares a state change (a form that posts to `/logout` is held back; `-send-state-changing` sends it). `-deny-path` keeps its action out. A POST form is not sent without `-submit-forms`.

### found_in

- It lists where scripts name the route: up to three places, calls first.
- For a route on another host than the page whose script named it, it lists the script on that host. `show` links the route to that script too.
- Each place has:
  - `script`: its URL. For a script inside the page, the page's URL, with `inline` true and the page's line numbers.
  - `line` and `col`: in bytes, from 1.
  - `snippet`: up to 120 bytes, the call as written or the string with the code around it.
  - `source`: the original file, when the route was read from a source map's sources. `line` and `col` are then that file's.
- Credentials in a snippet read `[redacted]`: JSON Web Tokens, bearer tokens, secrets set to a literal or in a query string, and long keys.

### Templates

- Pages that differ only by an ID are folded: `/product?id={n}`.
- `count` is the number of URLs folded. `not_asked` is how many of them were found and not requested. `capped` is how many of those a limit (`-depth`, a budget) kept from being asked. The row's own `coverage` is that of its first URL, so `azhaq query -coverage capped` also returns a templated row that holds a capped URL.
- Pages of one route that differ in which ID-like names they carry are one row: `/product?id={n}` and `/product?id={n}&store={n}`. Its `params` lists every name.
- A query value that names a page, such as `index.jsp?content=about.htm` or `view=grid`, is not an ID. Each is a page of its own.
- Every URL of a template is requested, as `crawl` and katana do. `-per-template N` limits it to N; the others are listed with `coverage: hint`.
- The others are listed with `coverage: hint`, as rows of their own in `crawl`, in text and `-json`.

### Strings that are not routes

- A string in a script that is only the start of a path, `"/rest/user/" + id`, is not a route.
- Nor is a base that calls are built on, such as `this.hostServer + "/rest/web3"`, whose calls are `/rest/web3/submitKey`.
- It has no row and is never requested. It is kept as a rejected string with the reason `the start of a path a script joins more to`. `crawl -rejected` lists it.
- A string with a query, `"/search?q=" + q`, names its route and stays.
- A `./name` that is a key of an object or a `case` label, as in a webpack module map (`{"./components/locale/zh_CN": 1}`), is a module id in the bundler's source tree, not a path of the app. It is never requested and is kept as a rejected string with the reason `a key of a module map or a case label`. A `./name` written as a value, `"./redirect?to="`, is still a route. A string that is only the key of an object whose value is a function (`{"/21U":function(t,e,n){…}}`, the module table of a bundle) is the same: never requested, rejected with that reason. A string that is also a call argument, a link or a part of a URL somewhere else in the script is kept.

### Where the requests go

- The summary splits `requests` by purpose, in `requests_by_purpose` and in a text line: `requests by purpose: description checks 42, path checks 19, pages 11, scripts 9, controls 6, assets 1`. The numbers add up to `requests` and to the ledger's lines to targets, and each line of the ledger names its `purpose`.
- `controls` are the requests for a path that cannot exist, whose answers the others are compared with. `description checks` are the places an API description or a GraphQL endpoint is guessed at, and a description that is read. `path checks` are the built-in paths. `crawl` has the same line.
- A page is asked once whichever way its URL is written when the standard says the spellings name one resource: the case of the scheme and host, the case of the hex digits of an escape, an escaped letter or digit (`/%61bout` for `/about`), the default port, an empty path and a fragment, which is never sent. A trailing slash, an empty query (`/about?`), the order of the parameters and a dot segment are other requests, and are sent.

### Routes under a client's base

- A script that gives its HTTP client a base, `axios.create({baseURL: "/api/v2"})`, `axios.defaults.baseURL = ...` or a `baseURL`/`prefixUrl` set to a constant, sends its routes through that base. A route `/orders/list` it calls is `/api/v2/orders/list`, and that is the route's row and the URL asked.
- A base that is a query-string dispatcher, `baseURL: "server/index.php?s="`, keeps the route as its query: `/server/index.php?s=/item/list`. A base without a leading slash is the page's, as a browser resolves it.
- The row names the base it came from in `base`. A call joins the base given to the client it is made on; a call on a client the script gives no base by name joins the only base the script declares, and none when it declares several. `fetch`, `XMLHttpRequest`, `$.ajax` and a call to an absolute URL take no base.
- The route as the script writes it is not a route of the site's root, and the base itself is not a route. Neither has a row or is requested; each is kept as a rejected string, `the start of a path a script joins more to` for the base and `a route a script's client asks under the base the script declares` for the route. A route the script also asks without any base, `fetch("/orders/list")`, stays a route at the root.

### Path checks stop at their answer

- The checks that guess where an API description sits are asked one at a time, likeliest first.
- The names include `openapi.json`, `swagger.json`, `api-docs` and `v3/api-docs`. The same names are asked again under each API base the run found, such as `/rest/` or `/v3/`.
- They stop at the first answer that is an OpenAPI or Swagger document with paths. A Swagger UI or ReDoc page that loads one counts too.
- Once an origin has served a description, here or through `azhaq-openapi`, its other locations are not asked. The summary counts them: `note: path checks: 28 skipped (an API description was already found)`.
- Whenever the plan lists the built-in path checks (`azhaq plan`: `built-in path checks on each web service (51 …)`), the summary's `path_checks` has a row for each web service: the checks `listed`, how many were `sent`, how many a request sent before had already `answered` (the favicon), and the `skipped` with the reason for each count. A limit that refused a check is the reason (`the request budget is spent`, `-host-guesses reached for this host`), and a service whose sweep left no record says so in a note. See [OUTPUT](../OUTPUT.md#the-summary).
- Every other check is still asked: `robots.txt`, `login`, `admin`, `graphql`, `.git/HEAD` and more.
- A Swagger UI whose script holds the document (Juice Shop's `/api-docs/`) is read from the script. The names next to it are not guessed.
- A page that is byte for byte what the site root answers for a made-up path is a single-page app's shell. That makes it the catch-all answer of a directory whose own baseline was not asked, so that baseline is not requested. A directory with answers of its own is still asked.

### Sweeping the scope
`-allow` and `-scope` fence a run; they do not add targets. `-url http://10.0.0.5/ -allow 10.0.0.0/24` maps 10.0.0.5 only, and a note says how much of the range that leaves. `-sweep` adds the IPv4 ranges and addresses `-allow` and `-scope` hold to the targets, as `-cidr` does for each: with `-ports` they are scanned in blocks with no size limit, and without it a range is expanded up to `-max-ips` (the summary says when it is cut). `-sweep` needs no target named alongside it. For example `azhaq run -allow 10.0.0.0/24 -sweep -ports top-100`. The sweep asks what the named targets are asked and holds to `-deny`, `-deny-path`, `-rate`, `-max-requests` and the kill file. A tighter `-allow` bounds it. The ledger holds a connect to every address the scan asked, and the summary says how many that is (`addresses_scanned`) and how many had a port open (`addresses_open`); `counts.addresses` is another number, the address rows of the map. IPv6 ranges are left alone, with a note. See [scope](../CONCEPTS.md#scope).

### Notes in the summary
Examples of what `notes` holds for a run:

- `the scope (-allow, -scope) holds 256 addresses and the targets name 1 of them: -sweep covers the other 255, …; it would send at least 255 requests`: see [Sweeping the scope](#sweeping-the-scope).

- `path checks: 28 skipped (an API description was already found)`: see [Path checks](#path-checks-stop-at-their-answer).
- `screenshot of URL not taken: the page needs about 26 requests and 8 were left (raise -max-requests)`, or `the budget was spent before the page loaded`: see [shots](shots.md#screenshots-and-the-budget).
- `GraphQL URL: introspection disabled: schema recovered (partial: query Query: 2 fields (1 client, 1 probe), 140 words tried; not proof there is nothing more)`, or `introspection: full schema`. `GraphQL URL: an IDE page, not asked for its schema: URL on the same origin gave it whole` says why a GraphiQL page got no POST: see [show](show.md#recovering-a-schema-when-introspection-is-off).

### State-changing requests

A GET azhaq sends can itself change state: follow its link and a database is created, or a session ends. azhaq cannot know from the method, so it reads the request's own name. The words are read whole, never as substrings: create, createdb, delete, remove, reset, populate, logout, signout, clear, wipe, drop, truncate, purge, destroy, erase, seed (and their forms: `creates`, `created`, `creating`), in the URL's path, or in the query parameters that name an action, or, for an operation of an API description, in its path, its `operationId` or its summary. A query parameter names an action when its name has one of these as a word (`action`, `act`, `cmd`, `command`, `op`, `operation`, `do`, `task`; `ajax_action` too), and then its value is read for the verbs above and for `stop`, `start`, `restart`, `kill`, `shutdown`, `reboot`, `halt`, `terminate`, `flush`, `disable` and `enable`: `index.html?processname=x&action=stop` and `?cmd=delete_user` are named, `?q=delete`, `?sort=created` and `?action=view` are not. The path is read for the first list only: `/stop` names nothing. A description's prose is never read: an API whose `info.description` says the app "was created" names nothing, and neither does a root operation's long description. A path whose last segment is a static file (`clear.gif`, `delete-icon.svg`, a script or a stylesheet) names nothing.

A GET that declares one and was found on the way (a link, a script's route, an API description's operation, a GET form's action), or is a word of a wordlist (`dirs -w`, `-dirs FILE`, `-paths FILE`, `fuzz -w`: the built-in lists too), is **held back**: it is not sent, it is listed under `skipped` with the word and the flag that sends it, and the summary counts it in `state_changing_held`. `-send-state-changing` sends them (on `run`, `crawl`, `dirs`, `fuzz`, `params`, `urls -live` and `azhaq mcp`); with it every word is sent, as ffuf sends every word. Before the first request a run names how many words of a `-dirs` or `-paths` list are held (a note, and a line on stderr), and `fuzz` how many words of each list. Each held word is a row of `state_changing` with the status `held back`. Not held back: a URL you gave as a target (and, in `fuzz`, a URL you typed that names one by itself: no word is held then), a write you asked for with its flag, and anything a `-deny-path` rule covers, which stays a deny and is listed under that rule.

The summary's `state_changing` lists each one with its `status`: `sent` only when a request for it is in the run's ledger, `held back` for one listed as skipped, `not requested` for one found and not asked for another reason, and, in a plan, `given as a target`. Before a run starts, the targets among them are printed (first lines on stderr, all of them in the summary's `state_changing` and `notes`); `azhaq plan` prints the same list for the targets, and cannot know the ones found on the way, since it sends nothing. Each entry names the `-deny-path` rule that would keep it out of every later run.

### Next in the summary
`next` suggests a command in these cases. The first three are measured from the run; the next-pass lines follow from the flags it was given:

- A run without `-browser` whose target pages leave their links to their scripts gets `azhaq run -url ORIGIN/ -browser …`, with the page that showed it. The signs are three or more `{{templates}}` in the text, or Markdown in the text whose links are read as text, or an empty shell of a front page. The last two count only when fewer than 10 routes were found on the page's origin. Example: `(/learn/vulnerability/a1_injection and 11 more pages: Markdown its scripts turn into links; read as text here, Chrome sees the page as rendered)`.
- A run that found a GraphQL endpoint and did not read its schema gets `azhaq run -url ORIGIN/ -graphql -allow HOST …   (/graphql and /graphiql answer like GraphQL; -graphql reads the schema by introspection)`. That is a run with no `-graphql`, or with the endpoint's host outside the scope.
- A run without a session (`-login`, `-cookie`, `-header`) whose target site shows a sign-in form gets `azhaq run -url ORIGIN/ -login PAGE -login-user USER -login-pass PASS -allow HOST …`. A sign-in form is a form that takes a password.
- A run that named a service with a read-only check (see [Read-only verification](#read-only-verification)) and was not given `-verify` gets `azhaq run … -verify -db DB   (next pass, not run: N services found with a read-only check; -verify sends INFO server to redis; …, no credential, one connect a service: N connects more)`. Each check is named once, with what it sends. No line when no service found has a check.
- A run that scanned a list of TCP ports (`-ports top-100`, a list) that leaves out ports of the default set (the top 100 and the usual ports of the services azhaq names and checks) gets, before the line below, `azhaq ports -host HOSTS -p LIST,default -db DB   (next pass, not run: N ports of the default set … were not asked on A addresses: C connects)`, with `-ports LIST,default` for the run's own line as below. `N` counts the ports of the default set the scan did not ask, and `C` is `N` times the addresses the scan asked. A scan of the whole default set suggests nothing.
- A run that scanned some TCP ports (`-ports top-100`, `-ports top-1000`, a list) and not all 65535 gets `azhaq ports -host HOSTS -p full -db DB   (next pass, not run: the other N of the 65535 TCP ports were not asked on A addresses: C connects; O open ports found in the K asked)`. `C` is `N` times the addresses the scan asked, counted as [plan](plan.md#the-estimate) counts connects, and the banner and protocol probes of any new open port come on top. With more than 8 target names, or a scan of names found on the way, the command is the run's own line with `-ports full`. Nothing is run for it, and a finished scan of every port suggests nothing.

### Known-issue matching

With `-advisories -advisory-source FILE`, every product and version the run confirmed (a port scan's services, a web answer's `Server` header) is matched against the advisory records of that source, and each match is printed as a lead after the map: `advisory: nginx 1.18.0 on app.example.com:443 is affected (range >=1.0.0 <1.20.0) — CVE-… https://…`. With `-json` each lead is one object with `"type":"advisory"`, and the summary holds them in `advisories`, one per line printed; the summary's note counts them by label from those rows, and the map's own counts are unchanged. Part 1 sends nothing to any target. `-advisories-confirm` adds the one benign read of each lead, within the run's scope, and labels it `observed`, `inferred` or `claimed`, with what was read. The boundary, the labels and the data-source decision are in [Known-issue matching](../CONCEPTS.md#known-issue-matching--advisories).

```
azhaq run -url https://app.example.com/ -ports top-100 -advisories -advisory-source osv.json -db app.db
azhaq run -url https://app.example.com/ -ports top-100 -advisories -advisories-confirm -advisory-source osv.json -allow app.example.com
```

### Read-only verification

With `-verify`, each service the run named that has a check gets at most one more read, from a fixed list of checks — there is no way to name another request. Each check sends only what a client with no credentials sends to read what the service already gives anyone:

| Check | Sends exactly | Settles |
| --- | --- | --- |
| Redis | `INFO server` | whether the data store answers a read with no credential, and the version it states |
| MongoDB | an `isMaster` OP_MSG (`{$db: "admin"}`) | whether the server answers a hello with no credential, and the version it states |
| memcached | `version` | whether the service answers with no credential, and the version it states |
| ZooKeeper | `srvr` | whether it answers its state command with no credential, and its version |
| PostgreSQL | a StartupMessage of protocol version 1.0, no user | the protocol versions it speaks, which bound its major version |
| Kafka | `ApiVersions` v0 | whether the broker answers its first request with no credential |
| SQL Server | a TDS PRELOGIN | the version token of the answer |
| Cassandra | an `OPTIONS` frame | what the server supports |
| Oracle TNS | a Connect with `(COMMAND=ping)` | the listener's version |
| LDAP | an anonymous search of the root DSE, no bind | the vendor, version and naming contexts it states |
| DNS | `version.bind` CHAOS TXT, length-prefixed over TCP | the version a BIND, dnsmasq or Unbound server states |
| RTSP | `OPTIONS * RTSP/1.0` | the methods it supports and its `Server` header |
| SIP | an `OPTIONS` request over TCP | what it supports and its `Server` header |
| SOCKS5 | the method selection (version 5, one method, no authentication) | the method the proxy accepts |
| SMB | an SMB2 `NEGOTIATE`, no session | the dialect and the signing it requires |
| NetBIOS session | a session request to `*SMBSERVER` | whether the service takes a session |
| RDP | an X.224 connection request with a negotiation request | the protocol it selects |
| X11 | a connection setup with no authorization | an open server's vendor and release, or its refusal |
| JDWP | `JDWP-Handshake` | whether a debug port answers the handshake |
| Java RMI | the stream header `JRMI`, version 2, StreamProtocol | whether a registry acknowledges it, and the host it sees the asker as |
| Elasticsearch transport | the keep-alive ping (`ES` and a length of -1) | whether a node of 7.x or later answers it |
| AFP | a DSI `GetStatus`, no login | the server's status block |
| Minecraft | a handshake and a status request | the version and players the status states |
| MQTT | a `CONNECT` without user name or password | whether the broker accepts an anonymous connection |
| AMQP | the protocol header `AMQP 0-9-1` | the product and version in Connection.Start |
| STOMP | a `CONNECT` frame without credentials | whether the broker accepts it, and the server it states |
| XMPP | the opening of a stream | whether the server answers with its own stream |

Every other service the scan names has no check, and the reason is stated once, in [the services with no check](../CONCEPTS.md#services-with-no-check). A check reads the service on the port it was found on, inside TLS when the scan found it there; a service seen over UDP has none, since the scan's own datagram is its read.

With `-advisories`, each advisory lead is labelled from its one confirmation read as well (the read itself is `-advisories-confirm`'s; `-verify` sends nothing more for a lead). Every result is labelled exactly one of:

- `proved` — the read answered with no credential sent, or an advisory's version and named precondition were both settled by its confirmation read. Proved names that read only, never exploitability, which is never tested.
- `version-only` — only the product and version identification stands: the service asked for authentication, or no confirmation read settled more. No unauthenticated read is claimed.
- `conditional` — the result depends on a precondition the read did not show, which the result names.

Each result carries the exact request sent and an excerpt of the answer, is printed after the map (one `{"type":"verify", …}` object with `-json`), held in the summary's `verify`, and stored as one `verify` observation (azhaq `show` lists them), so every count derives from the stored rows. The severity printed is a stated ranking of how directly the read shows the fact (an unauthenticated read of a data store's state, which are Redis `INFO`, MongoDB `isMaster`, memcached `version` and ZooKeeper `srvr`, is `high`; any other proved read, such as a version a protocol states, is `info`; a settled advisory is `medium`, a conditional `low`, the rest `info`); it is not a CVSS score. Every read goes through the scope, `-deny-path`, the kill file, `-max-requests` and the pace, and is a ledger line of the collector `azhaq-verify`. A read the scope refuses, a rule keeps out or a limit stops is a note, not a failure; a read that gets no answer is a failure (exit 3). Never a payload, never a write or state change, never a credential or a guessed password, never a request that tries to trigger a flaw. The boundary is stated once, in [Read-only verification](../CONCEPTS.md#read-only-verification--verify).

```
azhaq run -url https://app.example.com/ -ports top-1000 -verify -db app.db
```

## Flags

<!-- flags:begin run -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-url` | string, repeatable |  | seed URL |
| `-domain` | string, repeatable |  | seed Domain, for subdomain discovery |
| `-list` | string |  | targets, one per line: URL, host, host:port or IP (- for stdin) |
| `-in` | string |  | JSONL seeds |
| `-asn` | string, repeatable |  | seed an autonomous system: its announced prefixes |
| `-cidr` | string, repeatable |  | seed an address range such as 192.0.2.0/24 |
| `-org` | string |  | seed Organization name |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-exec` | string |  | connector command (seeds on stdin, facts on stdout) |
| `-demo` | bool |  | run against the built-in fixture server (no internet) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-probe` | bool |  | resolve and fetch each target once, print one line per web service and per path -dirs found: no crawl, scripts, path checks, TLS, subdomain or archive sources, and depth 1; a flag that asks for a collector (-dirs, -params, -ports, -ports-udp, -screenshots, -browser, -dns-brute, -permute, -graphql) still runs it, and a flag for what -probe turns off (-fill-forms, -submit-forms, -path-climb, -known-files) is a usage error |
| `-passive` | bool |  | skip HTTP/crawl/JS/paths/TLS (no handshake to the target) |
| `-skip` | string |  | collectors not to run, comma-separated: azhaq-ports or ports, subs for the subdomain collector (azhaq plan lists them); a name that is none is an error; azhaq resume leaves out the tasks the run kept for them |
| `-dirs` | string |  | guess paths on each web service from this wordlist, or @common for the built-in one (active; the targets given are the scope unless -allow) |
| `-params` | string |  | find query parameters pages read, from this wordlist or small, medium or large for a built-in one (active; the targets given are the scope unless -allow) |
| `-ports` | string |  | scan TCP ports: default (the top 100 and the usual ports of the services azhaq names and checks), top-100, top-1000, full or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888 (active; the targets given are the scope unless -allow) |
| `-ports-on` | string, repeatable |  | scan only these ports on a host: HOST=22,80 |
| `-ports-udp` | string |  | ask UDP ports (active): top (about 25 common ones), full or a list of ports, ranges and these names, such as 53,123,161,1-1024 or top,5354; a reply is open, an ICMP unreachable closed, neither open\|filtered (-ports none: UDP only) |
| `-dns-brute` | string |  | resolve WORD.domain for each word in this file (active; the targets given are the scope unless -allow) |
| `-permute` | bool |  | resolve variations of found names (active; the targets given are the scope unless -allow) |
| `-no-takeover` | bool |  | do not check CNAMEs for a takeover: no question is asked about the domain of a CNAME target (without it, a domain outside the scope is not asked either, and the summary says so) |
| `-graphql` | bool |  | read the schema of GraphQL endpoints with an introspection query (active; the targets given are the scope unless -allow) |
| `-graphql-wordlist` | string |  | extra probe words (one per line), tried and recombined with the built-in ones when a GraphQL endpoint's introspection is off and its schema has to be recovered from validation errors |
| `-known-files` | string |  | ask each web service only for its robots.txt and sitemaps and read every entry (all, robotstxt or sitemapxml); replaces the 51 built-in paths |
| `-paths` | string |  | extra path wordlist (one path per line) |
| `-no-paths` | bool |  | do not ask each web service for the 51 built-in paths (robots.txt, sitemaps, API descriptions, .git/HEAD, backup, admin, …): some programs count that as scanning |
| `-path-climb` | bool |  | also list and ask the parent directories of each link a page names (/a/b/c: /a/b/ and /a/) |
| `-fill-forms` | bool |  | ask the action of each GET form with neutral values in its fields (a search box gets a word): one GET request per form, unless the action's own path declares a state change (it is held back, and -send-state-changing sends it); -deny-path keeps its action out; a form that posts is not sent unless -submit-forms; crawl does this by default (-no-form-fill turns it off) |
| `-per-template` | int |  | URLs of one template (/product?id={n}) to request; the rest are listed (default: all) |
| `-catchall-after` | int | `3` | stop asking the paths scripts name in a directory once this many of them have answered with the page every unknown path gets, before as many have answered anything else; they stay in the map as skipped (0: ask them all) |
| `-web-ports` | string |  | ports to probe on each hostname or address of the list, comma-separated (default: 443, falling back to 80; a target given with no port and nothing there is a note, not a failure) |
| `-web-scheme` | string |  | try a name or an address over this scheme only, http or https (default: https, then http) |
| `-no-favicon` | bool |  | do not hash the favicon of front pages (one or two requests less per web service) |
| `-no-tech` | bool |  | skip technology fingerprints (saves about 30 MB of memory) |
| `-no-map-guess` | bool |  | do not ask for main.js.map next to a script that names no source map (a map a script or a header names is still read) |
| `-no-follow` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-advisories` | bool |  | match the products and versions this run already confirmed against the advisory records of -advisory-source, as labelled leads (affected, not affected or conditional, each with its advisory id and URL): a pure lookup over what the run already holds, nothing more is sent to a target |
| `-advisories-confirm` | bool |  | with -advisories: for each affected or conditional lead, also make the one benign read the advisory names (a GET of its documented version or info path, or of / to read the version it states): no payload, no login, no state change, never a request that could trigger the issue; each read is in the ledger and counts against -max-requests, and each lead is labelled observed, inferred or claimed (with -advisories; reads only within the run's scope: the targets given, -allow or -scope) |
| `-advisory-source` | string |  | the advisory records to match against, OSV JSON (a record, a list, {"vulns": [...]}, or JSON lines): a file the user downloaded (works offline), or an http(s) URL asked once as a third-party source; azhaq vendors no snapshot and fetches none it was not given |
| `-verify` | bool |  | with the services this run confirmed: make each enumerated safe read-only verification (one fixed request a client with no credentials sends, listed by plan: Redis INFO server, MongoDB isMaster, memcached version, ZooKeeper srvr and so on; with -advisories, each advisory lead is labelled from its confirmation read) and label the results proved, version-only or conditional, each with the exact request sent and an excerpt of the answer; every read goes through the scope, -deny-path (for the advisory GET), -max-requests, the pace, the kill file and the ledger; no payload, no credential, no write and no request that tries to trigger an issue |

**Crawl scope**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-crawl-scope` | string |  | the hosts a crawl follows links to: rdn (the start host's registrable domain and its subdomains), fqdn (the host only), dn (hosts that name its domain keyword) or a regex on the host (default: rdn for a name, the origin itself for an address) |
| `-crawl-any-host` | bool |  | follow links to any host, within -allow and -deny (katana's -ns) |
| `-crawl-in` | string, repeatable |  | follow only URLs that match this regex |
| `-crawl-out` | string, repeatable |  | never follow URLs that match this regex |

**Names and sources**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-sources` | string |  | subdomain sources to run, comma-separated (default: the default set; none: no source, and no archive, RDAP, search engine or RIPEstat lookup either: only the resolvers and the targets are asked) |
| `-all-sources` | bool |  | also run slower subdomain sources outside the default set |
| `-exclude-sources` | string |  | subdomain sources never to run, comma-separated |
| `-providers` | string |  | API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-source-proxy` | string |  | send every subdomain source request through this proxy URL, as subfinder -proxy (else HTTP_PROXY and HTTPS_PROXY) |
| `-source-rate` | float |  | requests per second to each subdomain source, as subfinder -rl (0: each source's own pace); a source's lower own pace stays |
| `-source-rates` | string |  | pace single subdomain sources, as subfinder -rls: name=N/unit, comma-separated, unit s, m or h (hackertarget=10/m,crtsh=1/s) |
| `-source-timeout` | duration | `30s` | give each subdomain source this long, 30s as subfinder does (any duration: 800ms holds to the millisecond for every source); a slower one (crt.sh) is abandoned, listed as failed, and the names the others gave are kept; -source-timeout 60s or more waits for crt.sh on a large domain (not -timeout, the run's bound) |
| `-extra-wait` | duration | `5s` | how long the sources azhaq adds to subfinder's default set (commoncrawl, hudsonrock, rapiddns, sitedossier, thc, waybackarchive) may go on after every source of that set has answered; one still running then is cut, listed as failed, and its names so far are kept; 0 waits for them as long as -source-timeout; a source named with -sources is not cut |
| `-max-time` | duration |  | how long the run may take: it stops after this long, in any phase (the sources, subdomain.center's guesses, the DNS checks of -live, the brute force and the permutations, probing), exits 4 and keeps what was answered for azhaq resume; it also bounds the wait for the sources of a domain (0: -source-timeout and a short grace bound the wait; -timeout bounds a run), as subfinder -max-time |
| `-max-body` | int |  | largest response body read from a subdomain source, in bytes (default 33554432), as subfinder -rsr |
| `-max-results` | int |  | most names one paging subdomain source gives (0: no cap), as subfinder -mr |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |
| `-no-history` | bool |  | do not read or write the name history (the names earlier runs found, kept in $AZHAQ_DATA_DIR if set, else azhaq-data/ beside -db (the current directory for a run with a temporary database); with -live each is checked by DNS in the run) |
| `-history-dir` | string |  | keep the name history under DIR/names, shared by every run that names it (default $AZHAQ_DATA_DIR, else azhaq-data/ in the workspace's folder: beside -db, or the current directory) |

**Browser**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-browser` | bool |  | also load pages in Chrome: the requests their scripts send and the links of the rendered page (needs Chrome) |
| `-interact` | bool |  | with -browser: click the buttons, links and menus of each page (up to -interact-clicks) to find what only a click brings; a click is made whatever its label says, and the writes it would send are refused by their method and mapped, not sent |
| `-interact-clicks` | int | `12` | clicks -interact makes on each page |
| `-screenshots` | string |  | save a screenshot of each web service's front page in this directory (needs Chrome) |
| `-chrome` | string |  | the Chrome or Chromium to run (default $AZHAQ_CHROME, else the first found) |
| `-chrome-profile` | string |  | a Chrome user data directory to use and keep: sessions it holds go with the pages (default: a temporary one) |
| `-chrome-proxy` | string |  | send Chrome's own connections through this http or socks5 proxy (default: -proxy, else the environment's); a plain http:// request reaches an http proxy as a proxy request, a page over TLS as a CONNECT tunnel |
| `-chrome-no-sandbox` | bool |  | let Chrome run without its sandbox where the system gives it none (no user namespaces, AppArmor, a container): it is started once more without, and the summary says so. The pages it loads are the targets' and untrusted: use a throwaway environment. By default Chrome does not start then |
| `-chrome-require-sandbox` | bool |  | never run Chrome without its sandbox (the default since v0.15.0, so this changes nothing: kept for scripts that pass it; it cannot go with -chrome-no-sandbox) |
| `-tabs` | int | `6` | Chrome tabs open at once for screenshots and -browser (gowitness -t) |
| `-unsafe-ports` | bool | `true` | let Chrome open the ports it refuses by default (6000, 6666, 10080 and others); -unsafe-ports=false keeps its refusal |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; HOST:PORT allows that host on that port only; with any -allow, nothing else is requested |
| `-sweep` | bool |  | cover the whole scope: the IPv4 ranges and addresses -allow and -scope hold are targets too, not only the ones named (without it a note says how much of a range the targets leave); -deny, -deny-path, -rate, -max-requests and the kill file hold as for any target, and a range is expanded up to -max-ips unless -ports scans it |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself) |
| `-send-state-changing` | bool |  | send the GETs whose own path or query declares a state change (create, delete, reset, logout, and the other words of the documented set; a query's action=stop and the like): a crawl's link, a script's route, an API description's operation, a word of a -dirs or -paths wordlist (ffuf sends every word). By default they are held back and listed as skipped; a target you give and -deny-path rules are not affected |
| `-kill-file` | string |  | stop all sending when this file exists, so that no request starts after it, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-seal-to` | string |  | when the run ends, append the ledger's seal as one JSON line ({"time","ledger","seal","entries"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact |
| `-submit-forms` | bool |  | also submit POST forms with neutral values (crawl): CHANGES DATA on the target, each submission counts as a request and is in the ledger, the summary says how many; held to -allow, -deny and the crawl's scope |
| `-browser-writes` | bool |  | let pages in Chrome send their writes (POST, PUT, DELETE…, beacons, forms posted on load) as a user's browser would: they change data on the target; by default Chrome sends only GET, HEAD and OPTIONS outside signing in, and maps the writes it does not send |
| `-params-writes` | bool |  | let -params-method POST, JSON or XML send bodies (they may change data on the target); needs -allow or -scope, or a single target |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-host-rate` | float |  | requests per second to each host, besides -rate over all (0: none) |
| `-host-parallel` | int |  | requests in flight per host (default 10, as katana) |
| `-parallel` | int |  | work items in flight (default 16) |
| `-delay` | duration |  | pause before each uncached fetch |
| `-backoff` | bool |  | when a host answers 429 or 503, wait (1 s doubling to 30 s, or its Retry-After) and ask again, up to 3 times; the summary says which hosts did |
| `-retry` | int |  | ask again this many times when a host that answered before gives no answer (a timeout, a reset) |
| `-request-timeout` | duration |  | time one request gets, headers and body (default: 10 s for headers, 30 s in all; not -timeout, the run's bound) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-max-host-requests` | int |  | requests one host may be sent (0: no cap); the rest of its work is left for azhaq resume |
| `-host-guesses` | int |  | most guesses one host is sent (0: no cap): requests for the built-in paths, a -dirs or -params wordlist or GraphQL field names; the rest are not asked and the summary lists them, the run exits 4 and azhaq resume asks them with a larger value |
| `-daily-requests` | int |  | requests a day to the program's targets (-program, else this run's targets), counted over the runs in -db |
| `-max-items` | int |  | most collector tasks (a name, a URL, an address each, per collector) this run starts (default: no cap, katana's and httpx's); the work left is for azhaq resume, which starts as many more |
| `-max-names` | int |  | most hostnames this run resolves (default 200000, as many as subs keeps for a domain); the names left are for azhaq resume. A value you give also caps the names -dns-brute and -permute ask, together: the guesses past it are not asked, the run exits 4 and says how many, and azhaq resume asks them |
| `-max-ips` | int | `4096` | addresses expanded from -asn and -cidr prefixes, for the whole run |
| `-max-response-size` | int |  | bytes read of a page or document (default 2097152; scripts and JSON get 16 MiB) |
| `-depth` | int | `4` | max fan-out waves (0 = seed wave only, not unlimited) |
| `-retry-failed` | bool |  | with azhaq resume: ask again the failed targets the summary marks retryable (a timeout, a closed connection, a 429 or 5xx); only those run again |
| `-retry-run` | string |  | with -retry-failed: the run to ask again, by the run_id of its summary (default: the newest run of the workspace) |

**Session**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-cookie-jar` | bool |  | carry the cookies targets set (Set-Cookie) on the requests that follow, as a browser does; -cookie and -header values go first |
| `-header` | string, repeatable |  | extra request header K: V |
| `-login` | string |  | sign in on this page with Chrome before the run; its cookies and token go with every request (needs -login-user and -login-pass) |
| `-login-user` | string |  | user name or email for -login |
| `-login-pass` | string |  | password for -login (default $AZHAQ_LOGIN_PASS) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY, except for loopback targets, which stay direct) |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | the workspace, a SQLite file (default: workspace.db in the run's folder under $AZHAQ_HOME/runs, ~/.azhaq/runs unless set; with AZHAQ_HOME=none a new azhaq-TIME-PID.db in the current directory; or $AZHAQ_DB; query, show and export read it afterwards) |
| `-json` | bool |  | print the map as JSON lines, and the summary as one JSON object on stderr |
| `-o` | string |  | also write the rows to this file, as printed (JSON lines with -json), replacing it; with -quiet the file still gets them |
| `-quiet` | bool |  | print no map and no progress lines (a line every 10 s while the run works), only the summary (on stderr) |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-stream` | bool |  | also print each name, address, URL and open port as it is found, once per map row (found lines, before the ranked map) |
| `-sr` | bool |  | also write each answer a target gave, headers and body as read, to the -srd directory as DIR/HOST/SHA1.txt with an index.txt (katana's -sr); query -fields response_file says where a row's is |
| `-srd` | string | `azhaq_response` | directory for -sr |
| `-no-catchall` | bool |  | leave out URLs that answer with the page every unknown path gets (client-side routes of a single-page app) from the rows printed |
| `-all-rows` | bool |  | list every row, as run printed before: by default the rows that answer as the control request for a path that cannot exist does, the 404s, the assets no request asked for and the hints only scripts name are counted in one line of their class each (-json lists every row with its fold class) |
| `-fail-on-errors` | bool |  | the same as -strict-exit |
| `-fail-on-capped` | bool |  | exit 4 also when the run hit -depth with hints left |
| `-strict-exit` | bool |  | exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures |

<details>
<summary>Other names, flags accepted with no effect and rarely used flags (81)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-H` | string, repeatable |  | same as -header | other name |
| `-port-cdn-full` | bool |  | accepted: CDN and WAF addresses are scanned in full by default | accepted, no effect |
| `-dirs-ac` | bool | `true` | calibrate on paths that cannot exist, as ffuf's -ac does, so a catch-all answer is not listed even with a filter of your own; -dirs-ac=false sends no guesses and lists what the filters leave | rarely needed |
| `-dirs-depth` | int | `1` | directory levels to sweep; 2 also sweeps directories found | rarely needed |
| `-dirs-ext` | string |  | also try each word with these extensions, comma-separated (php,bak) | rarely needed |
| `-dirs-fc` | string |  | hide these statuses | rarely needed |
| `-dirs-fl` | string |  | hide these line counts | rarely needed |
| `-dirs-fr` | string |  | hide answers whose headers or body match this regular expression | rarely needed |
| `-dirs-fs` | string |  | hide these response sizes | rarely needed |
| `-dirs-fw` | string |  | hide these word counts | rarely needed |
| `-dirs-ic` | bool |  | ignore the lines of the wordlist that start with # (and a trailing ' # note'), as ffuf's -ic does; without it they are asked like any word | rarely needed |
| `-dirs-mc` | string |  | report only these statuses (comma-separated, ranges, or all; default ffuf's: 200-299,301,302,307,401,403,405,500) | rarely needed |
| `-dirs-ml` | string |  | report only these line counts | rarely needed |
| `-dirs-mr` | string |  | report only answers whose headers or body match this regular expression | rarely needed |
| `-dirs-ms` | string |  | report only these response sizes (values and ranges, 100-200) | rarely needed |
| `-dirs-mw` | string |  | report only these word counts | rarely needed |
| `-dirs-rate` | float |  | path guesses per second per host (0: no limit but -dirs-threads, as ffuf) | rarely needed |
| `-dirs-threads` | int | `40` | path guesses in flight per service (as ffuf) | rarely needed |
| `-facts` | string |  | JSONL connector facts to ingest before native collectors | rarely needed |
| `-ob` | bool |  | with -sr: write the status line and headers only | rarely needed |
| `-obs` | bool |  | also print the observation log | rarely needed |
| `-params-all` | bool |  | with -params, also search the pages a request of the run showed to read no name: one that answered as a path that cannot exist does, or refused (401, 403, 405); by default a note lists them | rarely needed |
| `-params-chunk` | int |  | names per parameter request at most (0: 500, and about 7.6 KB in a query; fewer where the server refuses a long query) | rarely needed |
| `-params-delay` | duration |  | wait before each parameter request, one at a time (arjun -d) | rarely needed |
| `-params-include` | string |  | sent with every parameter request: a query for GET; for a body a form, a JSON object or XML, or a template with $arjun$ where the names go | rarely needed |
| `-params-method` | string | `GET` | how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target: -params-writes must say it is wanted | rarely needed |
| `-params-per-host` | int | `20` | pages searched for parameters per host | rarely needed |
| `-params-rate` | float |  | parameter requests per second per host (0: no limit, as arjun) | rarely needed |
| `-params-stable` | bool |  | one parameter request at a time, 3 to 9 s apart, and 30 s after a refused connection (arjun --stable) | rarely needed |
| `-params-targets` | string |  | file of JSON: pages that are asked otherwise ({"URL":{"method":"POST","include":"a=1","header":["Name: value"]}}), as params -i writes it | rarely needed |
| `-params-threads` | int | `5` | parameter requests in flight per page (as arjun -t); 1 with -params-delay and -params-stable | rarely needed |
| `-params-timeout` | duration | `15s` | wait for each parameter request; one that times out is asked again with 5 s more, up to 20 s (arjun -T) | rarely needed |
| `-port-all-ips` | bool |  | scan every address of a name, not the first two of each family | rarely needed |
| `-port-detect` | string | `all` | what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection, several at once while the scan has workers free: at most 25 connects after the first), banner (what it says on the one connection; nothing is sent, so a bare 220 stays ftp-or-smtp) or none (connect and close). UDP ports: all and banner ask every request a port's protocol has (4 datagrams to a silent port); none asks one | rarely needed |
| `-port-discover` | string |  | ask first whether an address is up, by a connect to 80 and 443: first (scan the ones that answer) or only (list them, scan nothing) | rarely needed |
| `-port-exclude-cdn` | bool |  | ask a CDN or WAF address only ports 80, 443, 8080 and 8443 (naabu -ec asks 80 and 443; this adds 8080 and 8443) | rarely needed |
| `-port-ip` | string |  | the address families of a name to scan: 4 or 6 (default both) | rarely needed |
| `-port-min-rate` | float |  | port connection attempts per second at least, as nmap's --min-rate: raises the pace to this when the pace (-port-rate, or the default 1500) is lower, and never lowers it | rarely needed |
| `-port-order` | string | `random` | the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc | rarely needed |
| `-port-payload` | string |  | send this to each open TCP port before reading what it says (\r and \n are CR and LF) | rarely needed |
| `-port-proxy` | string |  | connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent | rarely needed |
| `-port-proxy-auth` | string |  | user:password for -port-proxy | rarely needed |
| `-port-rate` | float |  | port connection attempts per second, a ceiling (0: 1500, as naabu's connect scan, and 127.0.0.1 unpaced) | rarely needed |
| `-port-retries` | int | `-1` | more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer) | rarely needed |
| `-port-seed` | int |  | make the random port order repeat (0: a new one each run) | rarely needed |
| `-port-source-ip` | string |  | connect from this local address, one of this machine's (any other is refused) | rarely needed |
| `-port-threshold` | int |  | stop asking a host after this many open ports: it answers every port (0: no limit) | rarely needed |
| `-port-timeout` | duration |  | wait this long for one port to accept or refuse a connect (0: 1.5s) | rarely needed |
| `-port-unnamed` | int |  | after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6; -1: no limit; each probe is a connect) | rarely needed |
| `-port-workers` | int |  | port connects in flight at once, over all hosts (0: as many as the rate allows, up to 20000) | rarely needed |
| `-serve` | string |  | let azhaq worker processes take this run's work, at this address (127.0.0.1:7777) | rarely needed |
| `-shot-codes` | string |  | take only pages that answer with these statuses, comma-separated (default: any); the others are listed as skipped | rarely needed |
| `-shot-format` | string | `png` | screenshot format: png or jpeg | rarely needed |
| `-shot-fullpage` | bool |  | screenshot the whole page, not only the first screen (up to 16384 pixels tall) | rarely needed |
| `-shot-html` | bool |  | keep each page's rendered HTML beside its screenshot | rarely needed |
| `-shot-js` | string |  | a file of JavaScript to run on each page before its screenshot (it runs on the target's page) | rarely needed |
| `-shot-quality` | int | `80` | jpeg quality, 1 to 100 | rarely needed |
| `-shot-size` | string | `1440x900` | screenshot size in pixels, WIDTHxHEIGHT | rarely needed |
| `-shot-timeout` | duration | `30s` | time a page gets: with -rate, how long it may go without a request let go or an answer, not in all | rarely needed |
| `-shot-wait` | duration | `1.5s` | wait after a page's load event for scripts that draw after it, before the screenshot: a value is waited out whatever the page does (0: none); by default a page with no script, frame or refresh is taken once painted, and one with a script after 1.5 s | rarely needed |
| `-urls` | string |  | write every archived URL of the run's domains to this file, one per line | rarely needed |
| `-urls-archive` | string, repeatable |  | ask NAME's archive at this address instead of its own, as NAME=URL (a mirror or a test server; repeatable) | rarely needed |
| `-urls-blacklist` | string |  | leave out URLs whose path ends in these extensions, comma-separated (png,jpg,svg) | rarely needed |
| `-urls-fc` | string |  | leave out URLs the archive recorded with these HTTP status codes, comma-separated; a URL whose status the archive did not record is kept | rarely needed |
| `-urls-fp` | bool |  | keep one URL for each host and path, dropping the variants that differ by parameters | rarely needed |
| `-urls-from` | string |  | only captures from this time on: YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss; OTX, which dates no capture, is asked all the same and its URLs kept, with a note | rarely needed |
| `-urls-ft` | string |  | leave out URLs the archive recorded with these MIME types, comma-separated; OTX, which keeps no type, is asked all the same and its URLs kept, with a note | rarely needed |
| `-urls-keep-junk` | bool |  | list the archived URLs left out as junk too, each labelled with its class and reason (-json), instead of only counting them | rarely needed |
| `-urls-max` | int | `500000` | URLs kept for each domain (0: no cap); the summary counts the ones past it | rarely needed |
| `-urls-mc` | string |  | keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); OTX and urlscan.io record a status for most URLs, and a URL with none is not kept | rarely needed |
| `-urls-mt` | string |  | keep only URLs the archive recorded with these MIME types, comma-separated (text/html); OTX, which keeps no type, is asked all the same and its URLs kept, with a note | rarely needed |
| `-urls-pages` | int |  | stop reading an archive after this many pages for a domain (default 0: no cap, as gau reads every page); an archive that stops at the cap says so in the summary | rarely needed |
| `-urls-pause` | duration |  | pause between the requests of one archive (default: none, as gau asks; an archive that answers 429 or 503 is waited out) | rarely needed |
| `-urls-proxy` | string |  | send the archive requests through this proxy: http://HOST:PORT, https:// or socks5:// | rarely needed |
| `-urls-raw` | bool |  | print the archived URLs exactly as the archives gave them: no normalising, junk filter or deduplication | rarely needed |
| `-urls-retries` | int |  | times an archive request is asked again after a 429, 503 or network error, after its Retry-After (seconds or a date, however long) or 2, 5, 10, 20, then 30 s; 0 makes the first refusal final (default: a 429 or 503 is asked again until the archive's time, -urls-timeout, or the run's is spent, a network error 3 times; a wait longer than the time left ends the request at once, with the reason) | rarely needed |
| `-urls-source` | bool |  | with -urls: each line is the URL, then after tabs the archive that gave it, when it captured it, and the junk class and reason of a URL that looks like noise | rarely needed |
| `-urls-sources` | string |  | ask only these archives, comma-separated: wayback, commoncrawl, otx, urlscan, arquivo (default: all) | rarely needed |
| `-urls-subs` | bool | `true` | ask the archives for the subdomains of each domain too (false: only the name itself, as gau does without --subs) | rarely needed |
| `-urls-to` | string |  | only captures up to this time, in the same form | rarely needed |
| `-worker-token` | string |  | the token workers give (default $AZHAQ_WORKER_TOKEN, else a new one) | rarely needed |

</details>
<!-- flags:end -->
