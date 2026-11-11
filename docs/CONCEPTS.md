# Concepts and terms

What the words in azhaq's output mean, each defined once. Other pages link here instead of explaining them again. `azhaq docs concepts` prints this page.

In this page:

- Results: [map row](#reading-a-map-row), [coverage](#coverage-what-azhaq-did-with-a-url), [evidence](#evidence-how-azhaq-knows-a-url), [kinds of URL](#kinds-of-url), [names](#names)
- Safety: [scope](#scope), [budget, pace and the kill switch](#budget-pace-and-the-kill-switch), [the ledger and its seal](#the-ledger-and-its-seal), [what azhaq sends](#what-azhaq-sends)
- Runs: [workspaces, runs and resuming](#workspaces-runs-and-resuming), [failures](#failures-fan-out-partial-and-degraded), [takeover candidates](#takeover-candidates)
- Testing access: [roles](#access-control-azhaq-roles)

## Reading a map row

The map is what `azhaq run` and `azhaq crawl` print: one row for each thing found.

```
URL http://localhost:3000/rest/2fa/verify  target  hint  api  POST
    POST  body tmpToken totpToken
```

| Part | Here | Meaning |
| --- | --- | --- |
| type | `URL` | What the row is: `URL`, `Hostname`, `Domain`, `IPAddress`, `Port`, … |
| key | `http://localhost:3000/rest/2fa/verify` | The URL, name or address. A template such as `/api/Users/{id}` stands for URLs that differ by an identifier. |
| scope | `target` | `target` is what you asked about. `fanout` was found on the way. |
| coverage | `hint` | What azhaq did with the URL: see [Coverage](#coverage-what-azhaq-did-with-a-url). |
| kind | `api` | What the URL is: see [Kinds of URL](#kinds-of-url). |
| methods | `POST` | The methods its callers and descriptions use. |
| indented | `POST  body …` | One line for each operation or form, with the names it sends. |

`azhaq show -db W URL` prints everything known about one row, and where a script named it (`found in main.js:6472:88`).

A row's `scope` (`target` or `fanout`) is not the request [scope](#scope) that `-allow` and `-scope` set.

## Coverage: what azhaq did with a URL

| State | Meaning | What to do next |
| --- | --- | --- |
| `visited` | Requested; it answered as a page of its own (any status but 404 and 410). | Read it. |
| `catchall` | Requested; it answered with the page every unknown path gets (an app shell, a soft 404). Not proof the route exists. A summary note names an origin that answered three or more URLs this way, `run` then stops asking the paths scripts name in a directory that answered three of them this way (`-catchall-after`), `counts` has `catchall` for them, apart from the kinds of URL, and for a bare address says that the site's name may be served differently (`-H 'Host: NAME'`). | Look at it in a browser, or use `-browser`. |
| `error` | Requested; no answer: timeout, refused, reset or TLS failure. | `azhaq query -db W -failed`, then try again. |
| `gone` | Requested; it answered 404 or 410, usually a URL found in an archive or a link. Nothing read says it takes another method. | Try older API versions near it. |
| `hint` | Known from a script, a description, an archive or a link, not proven by a GET. See below for the cases. | Send the method in its operations yourself. |
| `skipped` | Found, and not requested for a stated reason: a `-deny-path` rule of yours keeps its path out, or `run` held a script-named path because its origin answers every path with one page. Listed under `skipped` with the rule or the reason. | Change the rule, or `-catchall-after 0`, if you want it requested. |
| `capped` | Not requested: a limit (budget, depth, items) ran out first. | `azhaq resume -db W`. |

A `skipped` row says why in its `skipped` field, for example `-deny-path ^/admin/`. azhaq decides nothing by a URL's name: what a GET does on the server cannot be known from it.

A `hint` row is one of these:

- It was not requested, because it takes a path parameter.
- Scripts call it only with another method, such as POST or PUT, and a GET would prove nothing.
- A GET answers 404 while scripts call it. Its `proof` says `GET answers 404; found only in scripts, method unknown`.

A `capped` row also covers the work left for an origin that stopped answering, after 5 connects or timeouts in a row. [`run`](commands/run.md#coverage) has the cases of each state.

## Evidence: how azhaq knows a URL

Coverage says what azhaq did with a URL. Evidence says how azhaq knows the URL at all, and so what its status and size are worth. An `answered` row's status and size are what the server returned to azhaq's own request. Every other level is something a script, a description or a page said, never asked. Every URL row has an `evidence` field, and `evidence_from` lists the collectors behind it, sorted.

A row takes the strongest level any of its sources reaches, in this order:

| Level | Meaning |
| --- | --- |
| `answered` | This run requested it and the server answered: a status, not the origin's any-path answer, not a 404 or 410. |
| `browser` | Chrome, loading the page (`-browser`), sent the request itself, or the write it would have sent. Seen on the wire, not only written in a script. |
| `described` | An API description the run read lists it: OpenAPI or Swagger. |
| `called` | A script calls it, with a `fetch` or XHR call and its method. Not asked, and not seen to happen. |
| `linked` | A page links to it, a form submits to it, or a script names it in a string or as a route. |
| `archived` | Only archive sources hold it: Wayback, Common Crawl, OTX, urlscan, Arquivo. |
| `guessed` | Only a wordlist guess found it, and the answer was a 404 or the origin's any-path answer. |
| `given` | You named the URL and nothing else holds it. It did not answer, so the row is `error`. |

### Rules

- A 404 does not make a row `answered`. The server said it is not there, so the row keeps the level of whatever named it.
- A row folded into a template (`/product?id={n}`) takes the strongest level of its instances and lists the collectors of all of them.
- Only URL rows have a level. Coverage still says what was done: `skipped` is a URL kept out by a rule of yours, with the level it was named at.

### A 5xx without input

A 5xx that azhaq's plain request got from a route that takes names (query or body) carries `answer`: `500 without input`. The request carried none of the names, so the failure says little about the route. It is a lead only with something more, such as an error text in the body or a different answer for another session.

### Where evidence shows

- `azhaq query -fields key,evidence,evidence_from` shows it. `azhaq query -evidence answered,described` keeps the rows with those levels.
- At the end of a map row that is not `answered`: `[browser]`, `[described]`, `[called]`, `[linked]`, `[archived]`, `[guessed]` or `[given]`.
- In `export -format jsonl`: `evidence`, `evidence_from` and `answer`.
- In `export -format openapi`: `x-azhaq-evidence` on each operation.
- In the Evidence column of `export -format html`.

## Kinds of URL

- `app`: a front page.
- `auth`: it answered 401.
- `forbidden`: it answered 403.
- `api`, `page`, `script`, `asset`, `sourcemap`.
- `manifest`: a bundler's build manifest.
- `client-route`: a view a single-page app's router draws, such as `http://host/#/administration`, with the `guard` that keeps it.
- `websocket`: an endpoint scripts open a WebSocket to.

Views after the hash and sockets are never requested, so they stay `hint`. A view in the path (`http://host/admin`) is asked for once. If the server answers it (`auth`, `page`), that answer stands, with the guard noted beside it. If the app's shell answers instead, it stays a `client-route`.

## Names

| Status | Meaning |
| --- | --- |
| `live` | Resolves. A host you gave, or a name under a domain you gave. |
| `sibling` | Resolves. Found on the way, under another domain. |
| `unresolved` | From a source or a list, not looked up (a name that was asked and did not exist is `dead`), and named by no DNS answer of the run that held its address. A name a stopped `subs -live` listed and did not ask says `not checked:` and why in its `proof`; `azhaq resume` asks it. A name that is the target of a CNAME in an answer holding its address is `live` or `sibling` at any `-depth`, with that address in `proof`. |
| `dead` | Does not resolve: NXDOMAIN, no address, or SERVFAIL from every resolver. |
| `wildcard` | Resolves only because its zone answers for any name. |

Rows of the kinds `domain` (a domain you gave) and `addr` (an address) carry no status. [Which DNS answers are failures](#which-dns-answers-are-failures) says when a name counts as dead.

## Scope

The scope is the set of hosts, and ports where an entry names one, a run may send to. No request to a target goes outside it, and Chrome's requests are included.

- `-allow` names the domains, hosts or address ranges a run may touch. With any `-allow`, nothing else is requested.
- `-deny` names what the run must not touch, even when given as a target.
- `-scope` reads a program's scope: a file, or `hackerone`, `bugcrowd`, `intigriti` or `yeswehack` with `-program`. `azhaq scope` prints what a run would take, exclude and skip.
- With no rule, the scope is the targets you named, and Chrome stays on the site.
- A scope is a fence, not a list of targets: a run (and `ports`) given targets scans those, and `-allow 10.0.0.0/24` with one address named does not scan the other 253. The summary says so in a note (`the scope (-allow, -scope) holds 256 addresses and the targets name 1 of them: -sweep covers the other 255`). `-sweep` makes the IPv4 ranges and addresses `-allow` and `-scope` hold targets as well. It adds no request type: they are asked what the named ones are asked, within `-deny`, `-deny-path`, `-rate`, `-max-requests` and the kill file, and the ledger holds every address the scan asked, which the summary's `addresses_scanned` counts. The note counts what the scope allows less what it denies, and names an address as a target only when it is an address, a URL on one or a range: a name is not resolved for it. IPv6 ranges are left alone, with a note.
- `-deny-path REGEX` keeps paths out (repeatable): a URL whose path, or path and query, matches is never requested, by any collector or by Chrome, and is listed under `skipped` as `-deny-path REGEX`. It is the only rule azhaq has about a path, and it has no default: see [what azhaq sends](#what-azhaq-sends).
- Options that send more than the map does are held to the targets given, or to `-allow` and `-scope`: see [what azhaq sends](#what-azhaq-sends).

A scope entry, in `-allow`, `-deny` and a scope file, is one of:

- a domain with its subdomains: `example.com` or `*.example.com`;
- one host and no subdomains: `=api.example.com`;
- an address range: `10.0.0.0/8`;
- a host with a port, `127.0.0.1:3001`, `app.example.com:8443` or `[::1]:80`: that host, subdomains of a domain included, on that port only.

An `-allow` entry without a port allows every port of its host. With a port, a connection to any other port of the host is refused before it is made: a request, a redirect, a link, a script's URL, Chrome, an MCP tool, a port scan's connect. Each URL left out for its port is listed under `skipped` as `outside the scope: -allow lists this host with another port only`, and a port scan says how many ports it left out. A URL without a port has its scheme's: `http://127.0.0.1/` is port 80. A name you give as a target with no port (`-l hosts.txt`) is asked on ports 80 and 443, so under `-allow HOST:3001` give the target as `-url http://HOST:3001/`.

A port in `-deny` is dropped: the host is kept out on every port. Looking a name up, or asking about a subdomain, is judged by the host alone. [`scope`](commands/scope.md) shows how a scope file is read.

Requests the scope refuses are listed in the summary under `skipped`: see [OUTPUT](OUTPUT.md#the-summary). Targets that are all outside the scope exit 2: see [exit codes](OUTPUT.md#exit-codes).

### Hosts named in headers

A header that names a host is held to the scope too, because a front end routes by it. The headers are `Host`, `X-Forwarded-Host`, `X-Host` and `X-Original-Host`.

- With no `-allow`, `-deny` or `-scope`, a host you name in a header joins the targets you named.
- With a rule, a header that names a host outside it is refused before anything is sent. The command exits 2.
- A header that names a port is held to the rule's port like a URL: with `-allow 127.0.0.1:3001`, `Host: 127.0.0.1:5002` is refused and `Host: 127.0.0.1:3001` is sent. A header with no port is judged by its host.
- A request file, an import (`params -i`), a `-vi` line and a `-role-cmd` bring headers you did not type. They are held to the targets.

## Sessions

A run with a session (`-login`, `-cookie`, `-header` carrying a token) sends it with every request. Any URL it requests may end that session: a `/logout` link, an expiry. azhaq does not guess which; it measures.

- **The check.** At the start the run asks a page with its session and without it (the page `-login` ended on, else a target) and keeps one whose answers differ: a 200 against a redirect to the sign-in page, say. The page `-login` ended on has already answered with the session, in Chrome, and that answer is the "with" side: when Chrome got a 2xx for it and the run's own first request for it, with the session, is a 401 or a redirect to the sign-in page, the session ended right after the sign-in. The check fails at once, with no request without the session, and the run goes on as below. If none differs, the summary says so, and the run looks on: a JSON answer of 200 that a visitor without the session is refused (such as `/api/me`) becomes the check as soon as the run gets one (up to 6 are measured). With none, a 401 or a redirect to the sign-in page is tested by signing in again (`-login`) and asking that URL once more: if it now answers differently, the session had ended, and it becomes the check; if alike, it was the page's own answer. At most 3 such sign-ins; with `-cookie` or `-header` there is no test, and a lost session is noticed only when a response clears the session cookie.
- **When it is asked.** Every 50 requests, once more at the end, and right after an answer that looks like the end of the session: a 401, a redirect to the sign-in page, or a response that expires a cookie the run sends (that response names the URL that ended it), or one that sets a cookie the user gave to another value (the run goes on with the user's value, and the check says whether it still holds). A route tried as the check page is measured without the session only when no other request of the run is in the air and none starts meanwhile, so a logout that is on its way cannot meet it. Once such an answer was read, the run measures nothing without the session: a route it would have tried as the check page is not asked, since its answer with a session that already ended would be taken for the live one. The sign-in page is the one `-login` used; a run given `-cookie` or `-header` takes the page a visitor without the session is sent to from the check page (the `/login` that `/` redirects to), so a `/logout` that only redirects there is noticed too. The check is made before the next request is sent, so after such an answer nothing more is sent without the session except the requests already in flight (at most `-parallel`), and the failure counts those: the GETs answered after the first such answer, named in the summary's `session_lost` (`in_flight`, `in_flight_urls`). The same holds while the run signs in again: a request that starts meanwhile waits for the new session. A redirect is read against the URL that was asked, so `Location: login.php` from `/vulnerabilities/` is a redirect to `/vulnerabilities/login.php`, and `../login.php` one to `/login.php`. The answers of the pages Chrome loads (`-browser`) count too: a 401 or a redirect to the sign-in page sets the check, which asks with the run's own session. What is not promised: a session that ends with no such answer (an expiry that answers like the page itself, a logout that redirects somewhere else) is noticed at the next check, up to 50 requests later, and the requests sent in between may be answered without it; the failure says how many GETs were asked since the last good check.
- **A session that failed its check, with `-login` (or a `-role-login`).** The run signs in again, asks again the pages requested since the last good check (counted and entered in the ledger as any request) and says so in a note: `the session ended after /logout was requested; signed in again; 37 requests asked again`. The URL that ended the session is not asked again: when it is not named (a response cleared no cookie), a session that ends again right after signing in sends the requests since the sign-in once more, one at a time with a check after each, finds the one that ends it, and the note names it (`/logout ended the new session when asked again and is not asked again`). A session that ends 5 times stops the run as below. A run that cannot sign in again (`-max-requests` leaves no room for a sign-in, or the sign-in fails) stops sending at that check, whatever else a limit says: the summary's `session_lost` and a failure naming why it could not exit 3, never a run that goes on as an anonymous visitor. The failure counts the requests sent since the sign-in, or since the last good check, that may have been answered without the session. The same holds when a 401 or a redirect to the sign-in page is tested by signing in again (no check page) and that sign-in cannot be made: the failure is `the session may have ended: …`.
- **A session that failed its check, given with `-cookie` or `-header`.** The run cannot sign in again. From the check that finds it ended, it refuses every later request with `the session ended: …`, lists the failure (naming the first answer that looked like the end, `/logout answered 302 to /login`), and exits 3, a failure that names no target. The failure says what is true of the requests sent meanwhile: with an answer that looked like the end, `N GETs answered after that answer, already in flight, may have been answered without it` (or `no GET was in flight when that answer was read`); with none, `the N GETs asked since the last good check may have been answered without it`. Treat those answers as an anonymous visitor's. Give a fresh session and `azhaq resume`.
- **With workers (`-serve`).** The same holds. A worker that sees a 401, a redirect to the sign-in page or a cleared session cookie tells the run, and the run makes the check; the requests of every worker count toward the 50. After a new sign-in the workers take the new headers with their next task, and the pages they asked since the last good check are asked again. With a session that cannot be renewed the run lends no more work and ends with the failure above.
- **Sweeps and page tasks.** The `-dirs` and `-params` tasks, and the `-browser` page loads and `-screenshots`, that ran since the last good check run again after the new sign-in: what they reported is dropped and they ask again with the new session. The note counts the requests they sent in the same stretch. A task that ran again and met a session that ended once more is not run a third time; `azhaq resume` runs it.
- **`roles`.** Each signed-in role's session has its own check (a page only a live session reads), every `-canary-every` requests; see [roles](commands/roles.md). A role's logout is requested like any other URL, and the check says when it mattered.

## Budget, pace and the kill switch

Three controls bound what a run sends. They hold for every request to a target, Chrome's included.

- **Budget.** `-max-requests` is how many requests to targets a run may send. Port connects and UDP datagrams count too, and so does each redirect a command follows (`fuzz -r`, `probe -fr`): the budget can stop a run before a hop it does not cover. `0` means no cap.
- **Pace.** `-rate` is requests per second to targets, over all hosts. Chrome's requests count too.
- **Kill switch.** `-kill-file PATH` names a file that stops all sending when it exists. The default is `DB.stop`.

The budget holds for each run: `azhaq roles` is one run whose budget (the run options' `-max-requests`) covers every role's run, the history reads and the replay together; `azhaq resume` sends up to as many more as its own `-max-requests` says. Other limits end a run the same way: [exit code 4](OUTPUT.md#exit-codes) lists them. `azhaq plan` prints what a run would send before anything goes out.

### The kill file

- Create the file. Every request, connection and query looks for it at the moment it is sent, so none starts after the file exists. That includes a request already waiting for `-rate`: its wait ends within 100 ms and it is not sent.
- Chrome is held the same way for each request it makes: a request Chrome was already let send before the file existed is not recalled, and neither are the frames of a WebSocket it had open or the rest of a response it was reading. Those end when the run closes Chrome.
- The run exits 4. Its `stopped` says `the kill switch: kill file PATH exists, N tasks known and not done (remove it, then azhaq resume)`.
- Remove the file, then run `azhaq resume -db DB` to continue.
- A drop-in command without `-db` has no default kill file.
- `azhaq roles` uses `roles.stop` in its `-dir`. It stops the runs of the roles and the history reads and replay after them, and `roles` exits 4.

### Signals

Ctrl-C, `kill` and a hangup (SIGINT, SIGTERM and SIGHUP) all stop a command the same way. It exits 4, prints its summary and seals its ledger.

## Proxies

One rule holds for every command that sends HTTP to a target: `run`, `crawl`, `probe`, `dirs`, `fuzz`, `params`, `shots`, `roles` and the commands `watch` and `resume` repeat.

- `-proxy URL` (an `http://`, `https://` or `socks5://` URL; `fuzz` also takes `-x`) sends every request of the command through it. The proxy sees each one, and the ledger counts the same.
- `-proxy` sends everything through the proxy, loopback targets (`127.0.0.1`, `localhost`, `::1`) included: that is how to put a local lab in Burp.
- Through an HTTP proxy a plain-HTTP request names its URL in the request line (`GET http://127.0.0.1:3001/path`) and sends a `Host` header you set as you set it, as curl does. The proxy connects to the URL's host, never to the one the `Host` header names.
- Without `-proxy`, the environment's `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` apply by Go's rule, as in ffuf, httpx and katana: a loopback target always stays direct, so a company proxy in the environment never gets your local labs.
- `azhaq mcp` has no `-proxy`: its commands read the environment the server starts with.
- Not target requests, so not covered: `subs -proxy` and `-source-proxy` (the name sources), `urls -proxy` (the archives), `notify -proxy`, `dns -proxy` and `ports -proxy` (SOCKS5 for DNS and for connects).

## Workspaces, runs and resuming

The summary's `next` lists commands worth running after a run: see [OUTPUT](OUTPUT.md#next).

- A **workspace** is one SQLite file, set with `-db`. Every run into it adds to it, and keeps every run: a later run does not replace the graph of an earlier one. `query`, `show`, `export`, `diff` and `watch` read it, the newest run by default. `azhaq query -db FILE -runs` lists the runs by their `run_id` (the one a run's summary has); `query`, `show` and `diff` take `-run ID` to read another.
- A **run** is one pass into a workspace. `azhaq resume` continues a run that a limit stopped.
- A run keeps the answers it got in its workspace until nothing is left to resume. A run stopped by a limit, Ctrl-C or a signal that it handles (SIGTERM, SIGHUP) is resumed without asking again what it already asked.
- A run that was **killed** (SIGKILL, a crash, a power cut) is different: the [ledger](#the-ledger-and-its-seal) has a request as it leaves, so the last ones may have gone out with no answer stored. `azhaq resume` reads the ledger lines after its last seal. A read (GET, HEAD, OPTIONS) whose answer was lost is asked again, and the summary counts them: `N requests sent before the run was killed had no stored answer and were asked again`. A port scan keeps the ports it has finished (and, for a range, its finished addresses) about every second, so the resume asks the ports after them; the connects made after the last of these and before the kill are asked again, and the summary counts them (`N connects made before the run was killed had no stored answer ... and were asked again`). A write (any other method, a GraphQL POST included) is never sent again: it is held back by its method, URL and body, listed under `skipped` (`sent before the run was killed, its answer was not stored: not sent again (POST URL)`) and counted in a note, and what it belonged to continues without it. Chrome's writes (`-browser-writes`) are held by method and URL. The hold stays for every later resume of that run. It needs the ledger: with `-ledger off`, nothing says what was in flight. `fuzz` with `-db` keeps the inputs it asked every second, so what is asked again is what the last second held ([fuzz](commands/fuzz.md#stopping-and-resuming))
- The requests of a run that was stopped and resumed add up to a few more than those of one uninterrupted run, not twice as many.

File names and the runs that have no `-db` are in [OUTPUT](OUTPUT.md#the-workspace).

### Partial port scans

A port scan that the budget or the kill file cut short keeps the open ports it found. It also keeps the ports it asked, in a row marked `"partial":true` with `asked_ports`.

- `azhaq resume` asks only the other ports.
- It prints the open ports it finds as `ports` does: `-json` for objects, `-quiet` for the summary only.
- Ports an earlier run printed are not printed again, so the rows of the runs add up to the scan's.
- Its row, and `query` and `show` after it, hold every open port.

## The ledger and its seal

The ledger is the record of what a run sent: a line for each request, connection or query that left, and none for one a stop (`-timeout`, the kill file, Ctrl-C) cancelled before it did. [What a line means](OUTPUT.md#what-a-line-means) says it for each kind. It has one JSON line for each, with its class:

- `target`: a host the run was pointed at.
  - HTTP requests.
  - Chrome's requests, each once it has left, and its WebSocket handshakes with their path.
  - TCP connects and TLS handshakes.
  - UDP datagrams.
- `source`: a third party asked about the targets: the subdomain sources, the archives of `urls`, RDAP and RIPEstat, search engines, a scope platform, the services `notify` posts to, crt.sh's database and a mail server.
- `dns`: each query sent to a resolver.

Each line has its time, its class, the URL or `ip:port`, the host, the scope rule that allowed it (a target's) and the collector. [OUTPUT](OUTPUT.md#the-ledger) lists the fields. The ledger lists everything a run sends: the code that sends is `internal/egress`, and no other code can open a connection.

- **Chain.** Each line carries the hash of the one before, so an edited, removed or reordered line is caught.
- **Seal.** A run that ends writes a `seal` line, so lines cut from the end are caught too. The summary names the seal (`sealed 3f9c…`), and `ledger -verify` prints the last one.
- **Limit.** The chain alone cannot tell a ledger from one with lines removed and the rest re-chained. A seal kept apart from the file can: see [What `-verify` proves](commands/ledger.md#what--verify-proves), [Checking against a kept seal](commands/ledger.md#checking-against-a-kept-seal) and [Keeping the seal elsewhere](commands/ledger.md#keeping-the-seal-elsewhere).
- **Not listed.** The user's own endpoints: a `-replay-proxy`, the link of a worker to its run, and where `-seal-to` posts the seal. They are not requests about a target. Chrome's own background services are refused, not sent.
- **File.** `DB.ledger.jsonl` sits next to the workspace. Later runs into the workspace, and `azhaq resume`, append to it.
- **Options.** `-ledger FILE` writes it elsewhere, and `-ledger off` writes none. A drop-in command without `-db` writes one only with `-ledger FILE`.
- **Roles.** `azhaq roles` keeps one ledger, `roles.ledger.jsonl`, in its `-dir`.
- **Helpers.** The ledger records what azhaq sends. A `-role-cmd` command's own requests are not azhaq's and are not in the ledger or held to the scope; give tokens directly or use `-role-login` to keep every request in the ledger.

`azhaq ledger -verify FILE` checks the chain and the seal. `-summary FILE` counts the lines. `-csv FILE` exports them for a client report or a blue team's deconfliction. The [`ledger` page](commands/ledger.md) has the details, including exit 3.

## Failures: fan-out, partial and degraded

A failure is work that did not get its answer. The summary lists each one and counts them in `failures`. Exit code 3 says the run did not do its job; exit 0 says it did, with the failures it names: see [Exit 3](OUTPUT.md#exit-3) for the rule. Fan-out and partial failures are counted like any other and do not alone make a run fail. `-strict-exit` (and `-fail-on-errors`) makes any failure exit 3.

### Fan-out

Fan-out is what you did not ask about. It is a name found on the way, and the third-party lookups (subdomain sources, archives, RDAP) of a domain that is only the domain of a URL you mapped.

- A failure there is listed with `"fanout": true`, so you can see it is not your target. It is counted in `failures`, and does not make the run fail by itself: the lookup is not what you asked for. `-strict-exit` makes it exit 3.
- Ask for the domain itself (`-domain`, `subs -d`, `urls -d`) and its failures count.

### Partial

A failure is partial when one source failed while other sources answered for the same domain.

- It is listed with `"partial": true`, which says the names other sources gave stand. It is counted in `failures` and the run exits 0 when its job is done: a pipeline that wants to stop on any source that did not answer reads `failures` or passes `-strict-exit`.
- crt.sh holds the most names of any certificate log, but it is also the flakiest: gateway 5xx are common. A run that got its names from other sources should not fail a CI gate over a transient crt.sh failure. The failure is still listed.
- The summary's `sources` block and its last line say how many sources answered and which failed.
- crt.sh is among them: its transient 5xx is listed and counted, the run exits 0 while other sources answered (3 with `-strict-exit`), and a retry (`azhaq resume`) asks it again.

### Degraded

A run is degraded when every source or archive failed, so an empty answer is not an honest zero. `subs` also sets `degraded` when a source in the default set failed while others answered. Its names are listed, and the exit code is 3 only when no source answered (or with `-strict-exit`): the sources that failed are named in `failed` and counted in `failures`. The field is described in [OUTPUT](OUTPUT.md#the-summary).

### Which DNS answers are failures

- A name answered SERVFAIL on every attempt, by two resolvers or more, on two passes, is not a failure. The resolvers answered alike, so the name's own DNS is broken for everyone: a lame delegation. The name is dead, with `result` `servfail`.
- Resolvers that time out, answer REFUSED (refusing this machine), or give SERVFAIL from one resolver alone, are a failure.
- One resolver's NXDOMAIN does not make a name dead. Nor does an answer without an address: `nodata`, or a CNAME chain that ends without one.
- In those cases a second resolver is asked once, and the name is dead only when both agree. A public resolver answers NODATA now and then for a name every other one resolves.
- The second resolver is another operator's. With the default pool, 1.1.1.1 is checked with 8.8.4.4, not 1.0.0.1.
- Names under a wildcard zone and special-use names are not asked twice.

## Takeover candidates

A takeover finding is a name whose CNAME points at something gone, or whose front page is a hosting service's page for an unclaimed name. Each has a `status`:

| Status | Meaning |
| --- | --- |
| `candidate` | What was observed (the CNAME, its target, the answer for the target, the service it matched) does not show the name is free. The row says so. |
| `verified` | The service itself answered, from the name's own front page, with its documented "nothing here" page, and the name's CNAME is on that service. |

Only the services whose pages are listed below under `strong` have such an answer to read. The `dangling` services (Azure, Elastic Beanstalk, Fly.io) have none that needs no account, so a `dangling` row stays a `candidate`, and so does a domain no DNS answer shows (the check asks no registry). The summary counts the two apart (`takeover_candidates`, `takeover_verified`). Confirm each by hand before reporting it.

| Strength | Meaning |
| --- | --- |
| `strong` | The CNAME points at a hosting service whose own page says nobody claimed the name (`verified`), or at a name whose ICANN domain has no DNS answer (`candidate`: no registry was asked). |
| `dangling` | The CNAME points at a web name on Azure, Elastic Beanstalk or Fly.io that does not resolve. It rests on that one DNS answer: see [What a dangling row rests on](#what-a-dangling-row-rests-on). |
| `page` | One of those services' own pages, with no CNAME known (`candidate`: the name is not shown to be on that service). Where DNS shows the name points elsewhere, nothing is said. |

- The hosting pages that make a name `strong`: GitHub Pages' "There isn't a GitHub Pages site here.", S3's `NoSuchBucket`, Heroku's no-such-app page, Pantheon, Ghost, WordPress.com, Help Scout, ReadMe, ngrok, Bitbucket and Surge.
- A cloud's shared suffix such as `elb.amazonaws.com` is no registry and never counts as an unregistered domain.
- The Azure services for `dangling`: App Service, Cloud Services, CDN, API Management, Container Instances, HDInsight, Blob Storage and a virtual machine's public IP name.
- azhaq reads DNS answers (`subs -live`, `dns`, `run`) and front pages (`probe`, `run`). Even a plain `subs -live` flags a candidate.
- To tell a free domain from a taken one, the check asks your resolvers for the SOA of a CNAME target's registrable domain (a known hosting service is not asked). A domain outside the scope (`-allow`, `-scope`) is never asked: the row says `takeover-not-asked` and why, no free-domain finding is made for it, and the summary counts these targets in a note: `not asked: N CNAME targets on a domain outside the scope`. Add the domain to `-allow` to have it asked. `-no-takeover` (`run`, `dns`) turns the check off, and with it the question.
- How a candidate is printed: see the `takeover` field in [OUTPUT](OUTPUT.md#the-summary).

### What a dangling row rests on

A `dangling` row is a `candidate`. Its `evidence` states what was observed: the CNAME, its target, the NXDOMAIN answer and the service it matched. Its only evidence is that the CNAME target answered NXDOMAIN, and NXDOMAIN does not show the name is free: a disabled Traffic Manager profile or a deleted database answers it while its owner still holds the name. The row, the `-json` row and `hunt` say so (`unverified: NXDOMAIN does not show the name is free`), and `hunt` ranks it after every row a server answered and every `strong` row. The check sends nothing to the provider.

Each service rests on its entry in the public takeover list (can-i-take-over-xyz), which azhaq's table copies. The entries were read on 2026-10-28, the `list` field of the row names the entry and that date, and the list changes as providers change: open the entry and read its status before relying on the row.

| Suffix | List entry |
| --- | --- |
| `.azurewebsites.net` | Azure App Service |
| `.cloudapp.net` | Azure Cloud Services |
| `.cloudapp.azure.com` | Azure virtual machine public IP name |
| `.blob.core.windows.net` | Azure Blob Storage |
| `.azure-api.net` | Azure API Management |
| `.azurehdinsight.net` | Azure HDInsight |
| `.azureedge.net` | Azure CDN |
| `.azurecontainer.io` | Azure Container Instances |
| `.elasticbeanstalk.com` | AWS Elastic Beanstalk |
| `.fly.dev` | Fly.io |

To confirm one, ask the provider whether the name is available, from an account you hold and with the owner's permission: the provider's create form or its name-availability check (for Elastic Beanstalk, `aws elasticbeanstalk check-dns-availability --cname-prefix NAME`; for Blob Storage, `az storage account check-name --name NAME`). Registering the name is the takeover itself: do it only when the engagement allows, and release it afterwards.

## Known-issue matching (`-advisories`)

azhaq names a service's product and version from the wire (an SSH greeting, an HTTP `Server` header, a protocol's own answer). `-advisories` takes the step after that and no further: it matches each product and version the run *already confirmed* against public advisory records, and reports each match as a labelled lead. It is identification, and optionally read-only confirmation — never exploitation.

- **The records are yours to name.** azhaq vendors no advisory snapshot (one built into the binary would go stale and read as checked when it is months old) and fetches nothing it was not given. `-advisory-source FILE` reads OSV JSON from a file (a record, a list, `{"vulns": [...]}`, or JSON lines; the OSV bulk downloads are Apache-2.0 data) and works offline. `-advisory-source https://…` asks that URL once, as a third-party source like any other: recorded in the ledger as a source, held to the kill file, and a failed fetch is a failed source in the summary (exit 3), never silence that reads as no matches.
- **Part 1 sends nothing.** The match is a pure lookup over the products and versions held in the run's observations (the port scan's services, and the `Server` header of a web answer). No request is made to a target to decide it.
- **Labels are exact, or say they are not.** A version is compared with the advisory's own range syntax — semver, and epoch-version-release (`1:9.6p1`, `2.4.25-3ubuntu1`) where the banner gives it. A lead is `affected` (the version seen is inside the affected range), `not affected` (outside it), or `conditional` (inside it only under a precondition the match alone cannot see, which the lead names, or the comparison itself is uncertain, which the lead says rather than guessing). Every lead carries its advisory id and URL as its source, and the version seen.
- **Part 2 reads, and only reads.** `-advisories-confirm` (with `-advisories`, and a scope: `-allow`, `-scope` or the targets given) may make, for each affected or conditional lead, the one benign read the advisory names: a `GET` of its documented version, build, status or info path (`azhaq_confirm_path` in the record), or of `/` to read the version the service states in its headers when it names none. That is the kind of request nmap's default scripts make: it observes, it never actuates. Never a payload, an injection string, a login attempt, a request that changes state, or anything that tries to trigger the issue. If settling an issue would need any of those, azhaq does not confirm it: the lead stays at its Part-1 label and says why. A confirm path that is not one plain path on the service itself is refused when the records are read.
- **Confidence is not the match label.** A confirmed lead is `observed` (the read itself settles where the version stands — and, where the advisory names a precondition, that the precondition holds), `inferred` (the read narrows the match but leaves something open, which the lead names), or `claimed` (a range match only: nothing was read that settles it, or nothing could be read). A range match is never printed as a proven, exploitable finding.
- **Counts add up.** Each lead is one stored `advisory` observation (azhaq `show` lists them), one line of output, and one entry of the summary's `advisories`. The summary's note counts them by label (and by confidence, when confirmation ran) from those rows, and the run's other counts are unchanged: advisory leads are not map rows. Confirmation reads go through the same egress chokepoint as every request — scope, `-deny-path`, pace, `-max-requests`, kill file — and are ledger lines of the collector `azhaq-advisories`. A read the scope refuses is a note, not a failure; a read that gets no answer is a failure (exit 3).

## Read-only verification (`-verify`)

`-verify` (on `run` and `ports`) takes one step past naming a service, and no further: for each service the run named, it makes at most one read from a fixed, enumerated list of checks, and labels what the answer settles. There is no way to name another request, and the list is printed, with the exact request and the precondition of each check, by `azhaq plan` and in the `run` docs before anything is sent.

- **The fence is exact.** A check sends only what a client with no credentials would send to read information the service already gives anyone: a protocol info or hello command (`INFO server` to Redis, an `isMaster` OP_MSG to MongoDB, `version` to memcached, and the others in [the table of checks](commands/run.md#read-only-verification)), or the one benign read an advisory names. Never a payload, never a write or state-changing command, never a credential or a guessed password, never a request that tries to trigger a flaw. If settling a question would need any of those, azhaq does not ask it: the result stays at the label the read supports and names the precondition left open.
- **Three labels, never merged.** `proved`: the read answered with no credential sent, or an advisory's version and named precondition were both settled by its read — proved names that read only, never exploitability, which is never tested. `version-only`: only the product and version identification stands (the service asked for authentication, or no read settled more); no unauthenticated read is claimed. `conditional`: the result depends on a precondition the read did not show, which the result names. Each result carries the exact request sent and an excerpt of the answer as its evidence, so every claim in it can be checked against the row it came from.
- **Two kinds of unauthenticated result.** A check names its kind. `unauthenticated-read`: the answer holds state or information the service exposes to anyone (Redis `INFO`, MongoDB `isMaster`, memcached `version`, ZooKeeper `srvr`, an LDAP root DSE, a DNS `version.bind`, an AFP status block, a Minecraft status). `unauthenticated-handshake`: the service answers its protocol's opening with no credential (the JRMI stream header, `JDWP-Handshake`, Kafka `ApiVersions`, a TDS prelogin, an SMB negotiate, a NetBIOS session request, an X.224 request, a PostgreSQL startup, an Oracle TNS ping, an `OPTIONS`, an AMQP header, an XMPP stream and the like), which shows the service talks to a client that has proved nothing and reads no data. Both are `proved` when the answer was read; the kind says what was proved. A DNS server that refuses `version.bind` (`REFUSED`, `NOTIMP`, `SERVFAIL`, or `NOERROR` with no TXT answer) is `version-only` with the rcode as evidence. Evidence that is not text is printed with each such byte as `\xNN`. Rows stored by an older run keep the kind they were stored with.
- **Severity is a stated ranking, not a score.** An unauthenticated read of a data store's state (Redis, MongoDB, memcached, ZooKeeper) ranks `high`, an advisory settled by its read `medium`, a conditional `low`, the rest `info`, any other proved read among them: the ranking says how directly the read itself shows the fact. azhaq holds no data to rate a CVSS score and does not print one.
- **Every service the scan names has a check or a stated reason.** A check is one fixed request a client with no credentials sends: the protocol's own version, info or hello command. It is the request the scan already sends to a port that waits, read by the same reader, so a check asks nothing the scan does not. The services with none are listed [below](#services-with-no-check).
- **Like every request, and counted.** A verification read is not a side channel: it goes through egress — scope, `-deny-path` (for the advisory GET), the kill file, `-max-requests`, the pace — and is a ledger line of the collector `azhaq-verify`. Each result is one stored `verify` observation, one line of output and one entry of the summary's `verify`; the counts derive from the stored rows, as the advisory counts do. A read the scope refuses, a `-deny-path` rule keeps out or a limit stops is a note (those are the user's own settings), never a failure; a read that gets no answer is a failure (exit 3). `-verify` is off unless given: a plain run sends no verification read beyond naming the service.
- **The findings record.** `azhaq report -findings -db WORKSPACE.db` (or `azhaq export -format findings` / `findings-md`) writes one record per qualifying stored row (a verify result, an advisory lead, or a web answer that held a stack trace, kind `error-disclosure`) — kind, severity, host, port, URL, product and version where confirmed, advisory id where matched, evidence excerpt, and the command that produced it — proved first, `version-only` and `conditional` kept distinct. Rows that prove nothing (a map `hint` its default view lists) are listed as leads, separately; the hints it folds are counted by class. A workspace with no qualifying rows writes an explicit empty record set and exits 0.

### Services with no check

Every TCP service the scan names has a check (the table in [run](commands/run.md#read-only-verification)) or is in this list with its reason. A test fails when a service is in neither. A service seen over UDP has none: the scan's own datagram is its read.

| Service | Why it has none |
| --- | --- |
| `ssh` | states its software and version in its first line, which the scan reads: there is no further no-credential read |
| `ftp` | states its software in its greeting, which the scan reads; SYST and FEAT are asked only by -detect all, where the greeting names no product |
| `smtp` | states its software in its greeting, which the scan reads; its commands after it (EHLO, HELP) add a capability list, not a version |
| `ftp-or-smtp` | only a 220 greeting that names neither: there is nothing to read that the greeting did not say |
| `pop3` | states its software in its greeting, which the scan reads |
| `imap` | states its software in its greeting, which the scan reads |
| `mysql` | states its server version in its first packet, which the scan reads; any request after it is a login |
| `telnet` | opens with its option negotiation, which the scan reads; the next thing it wants is a login |
| `vnc` | states its protocol version in its first line, which the scan reads; the next message is a security handshake |
| `irc` | opens with its notice, which the scan reads; its version is read after a registration with a nick |
| `nntp` | states its software in its greeting, which the scan reads |
| `sieve` | sends its capability list, with its implementation, on connect, which the scan reads |
| `icy` | states its server in its first line, which the scan reads |
| `nping-echo` | opens with its binary handshake, which the scan reads; the next message is a client handshake that starts an echo session |
| `kerberos` | the only request without a credential is an AS-REQ that names an account, which asks the KDC about a principal; it states no version |
| `finger` | its only request lists a user or the logged-in users, data of the host rather than a version or info of the service |
| `gopher` | its only request lists the menu it serves, its content rather than a version or info of the service |
| `http` | the scan's own HEAD and GET already read its Server header and page; a version or info path belongs to a product, not to the protocol |
| `https` | the scan's own HEAD and GET already read its Server header and page; a version or info path belongs to a product, not to the protocol |
| `tls` | a handshake is the whole of what a client with no credentials says, and the scan reads its version, suite and certificate |
| `tcpwrapped` | closes the connection without a word: it answers nothing to read |

## Access control (`azhaq roles`)

| Term | Meaning |
| --- | --- |
| role | A session: anonymous, headers (`-role`), headers from a command (`-role-cmd`), or a Chrome sign-in (`-role-login`). |
| replay | Every URL any role reached, asked with every other role as a GET, unless `-replay-writes` adds writes. |
| reads | Answered 2xx, and not with an error shaped as data. |
| refused | One of the cases under "What counts as refused" below. |
| owner, `owner_by` | Whose object it is, and the evidence: a token's claim, a list only that role sees, or the object's own owner field. |
| `confidence`, `evidence` | How surely the object is the owner's, and why in one line. `confidence` is `proved`, `likely` or `guess`. |
| control | A made-up identifier of the same shape on the same route. A route that answers it like a real object answers any identifier. |
| canary | An endpoint only a role's live session reads, checked during the replay. A session that dies is renewed, or its answers are `session_suspect`. |
| evidence | The answers behind the listed rows, secrets taken out, in `roles.db`: `azhaq roles show -dir DIR URL`. |
| dead session | A role refused wherever a session matters: its token expired or is wrong. Said in a note; the exit code is 3. |
| report | `azhaq report -dir DIR` writes each listed finding up from the evidence as a Markdown report to submit. It sends nothing. |

### What counts as refused

[Reads and refusals](commands/roles.md#reads-and-refusals) has the detail.

- Any 4xx.
- An error served with a 2xx status.
- The site's own `200 Access denied` page, or what `-refusal` matches.
- A redirect to a sign-in page.
- A redirect to the front page, while another role reads the endpoint.

### Confidence

The rules are in [Confidence](commands/roles.md#confidence) on the `roles` page.

- `proved`: both the session (or the owner's own list) and the object's answer say whose it is.
- `likely`: one of those two does.
- `guess`.

### Verdicts

Worst first. What each means is in the [verdict table](commands/roles.md#verdicts) of the `roles` page.

1. anyone reads sensitive fields
2. reads another role's object
3. answers any identifier
4. every signed-in role reads the same object
5. roles read the same sensitive fields
6. same answer for a session that did not find it
7. signed-in only
8. only one role reads it
9. some roles refused
10. different fields per role
11. anyone reads the same object
12. status differs

With `-replay-writes`, three more come before them all:

- anyone writes another role's object
- writes another role's object
- writes another role's object: accepted; the change cannot be read back to confirm

## What azhaq sends

| What | Method | When |
| --- | --- | --- |
| Pages, scripts, API descriptions (at the root and under each API base), archived URL templates, the GET operations a description names that need no path or required query parameter, GET forms | GET | Every run, inside the scope. A GET can change data on the target: only `-deny-path` keeps a URL out. |
| 51 built-in path checks per web service: `robots.txt`, sitemaps, API descriptions, `.git/HEAD`, `backup`, `admin`, … | GET | Every run. `-no-paths` turns them off. |
| Path and parameter guesses | GET. `params -X` sends the names in a POST, JSON or XML body. | `-dirs`, `-params`, held to the targets given or to `-allow` and `-scope`. |
| GraphQL introspection | POST | `-graphql`, held to the targets given or to `-allow` and `-scope`. |
| A port's service | A TCP connect, then for a port that says nothing: protocol probes, one `HEAD /`, a TLS handshake. | `-ports`, `ports` |
| UDP ports | One datagram of the protocol's harmless request for each port; more when none came back. | `-ports-udp`, `ports -udp`, `-pu` |
| A wordlist in a request | The method and body you give it, with the wordlist's words in them. | `azhaq fuzz`, held to the host of `-u` or to `-allow` and `-scope`. |
| Chrome | What the page loads, inside the scope. | `-browser`, `-login`, `shots`, `-role-login` |
| Writes of other roles | POST, PUT, PATCH, DELETE | `roles -replay-writes`, held to the `-url` hosts or to `-allow` and `-scope`. |

### Ports

- For a port that says nothing, azhaq sends its own protocol's request on its usual number, one `HEAD /`, a TLS handshake, and one request of each of the other protocols until one answers, then, if nothing named it, one `GET /`. That is at most 25 more connects for each port.
- On a web port whose head names no product, azhaq sends a `GET /`.
- On 5432, 6379 and 27017–27019, it sends that database's own first request.
- A UDP port with no known protocol is asked four ways: a DNS query, an SNMP get, memcached's version, then an empty datagram.
- A UDP datagram is a protocol's harmless request, such as a DNS `. NS` or an SNMP GET of `sysDescr.0` with community `public`. When none came back, azhaq sends the next way its protocol has.

### Chrome

- Chrome sends GET, HEAD and CORS preflights (OPTIONS).
- While signing in, it sends every method the page sends: its sign-in request, and whatever the page's own scripts send meanwhile, such as a socket's polling POSTs. All of them are in the ledger.
- A page's own writes are refused and mapped, unless `-browser-writes`.
- Every download is refused and listed. Chrome saves nothing to disk.
- A page read for its requests is loaded without its images, fonts and media.

### What azhaq sends, and what it cannot know

azhaq sends a GET to every URL it finds in scope. The exception is decided and stated: a GET found on the way, or a word of a wordlist, whose own path, query or API operation declares a state change is held back ([What is held back](#what-is-held-back)). It cannot know what a GET does on the server: a name says nothing reliable (`/rest/saveLoginIp` is a GET that changes state on some apps and a read-only page on others), so no other name keeps a URL out. What azhaq promises is about the method, and nothing more:

- **Without a flag, every request azhaq sends to a target on purpose is a GET**, besides what the table above lists: HEAD and TCP or UDP probes of ports, Chrome's HEAD and OPTIONS, and a sign-in.
- **"A write" in these pages means a request with a method other than GET, HEAD or OPTIONS.** Writes (POST, PUT, PATCH, DELETE, a form submitted, a page's own writes in Chrome, a role's write replay, a parameter search with a body) are sent only when you ask for them by name: with their flag (`-submit-forms`, `-browser-writes`, `roles -replay-writes`, `run -params-writes` with `-params-method`, `-graphql` for the introspection POST) or on a command whose own option is the method (`params -X POST|JSON|XML`, `fuzz -X`, `probe -x`), which needs no second flag. Without it they are mapped, not sent. That says what the method is, not that nothing changes.
- **A GET can change data or end a session, and azhaq requests it.** It does so for the URLs in links, in forms (a GET form is filled with neutral values and asked: `crawl` does it by default, `run` with `-fill-forms`), in scripts and in API descriptions. A GET operation a description names is requested like any other URL, unless its own path, `operationId` or summary names a state change: VAmPI's `GET /createdb` drops and recreates its database, so a default crawl of its `/openapi.json` lists it as skipped and does not send it, and `-send-state-changing` sends it. A description's prose is never read: VAmPI's `GET /`, whose description says the app "was created", is requested and not named.

What keeps a URL out is known:

- **Your rule.** `-deny-path REGEX` keeps a path out of every request, Chrome's included. If a URL must not be requested whatever its name says, say so with it.
- **The decided exception.** A GET found on the way, or a word of a wordlist (`dirs -w`, `-dirs FILE`, `-paths FILE`, `fuzz -w`), whose own path, query or API operation declares a state change (the words under [State-changing requests](commands/run.md#state-changing-requests)) is held back unless `-send-state-changing` is given. A target you give is not affected.
- **A measurement.** A signed-in run checks that its session lives: see [Sessions](#sessions).

`azhaq plan` lists the kinds of request, the counts and the seeds, not the URLs a crawl will find: `/createdb` is known only after the description is read. The [ledger](#the-ledger-and-its-seal) lists every request that was sent. What is named in advance is narrower: a GET among the targets whose own path declares a state change (`plan` and, before it sends anything, a run: it is a target you gave, so it is sent), and the ones a run finds, each in the summary with what became of it: held back, or sent, said only for a request the run's ledger holds ([State-changing requests](commands/run.md#state-changing-requests)).

### What is held back

- A path a `-deny-path` rule matches is never requested. It is listed under `skipped` with the rule, and its coverage is `skipped`.
- A GET found on the way whose own path, query or API operation declares a state change is not sent. It is listed under `skipped` with the reason and the flag that sends it, and the summary counts it in `state_changing_held`. `-send-state-changing` sends them; a target you give is never held back. On an `azhaq mcp` server the targets come from a client, so a target a call names is held back too (see [MCP](MCP.md)).
- A wordlist sweep (`dirs -w`, `-dirs FILE`, `-paths FILE`, `fuzz -w`) holds back its words that name a state change in the same way, the built-in list and a list you give alike: a note before the first request says how many, each is a row with the status `held back` and is listed under `skipped`, and `-send-state-changing` asks every word, as ffuf does. The words that do not are asked, with a session or without one. A word a `-deny-path` rule matches is not sent. A sweep's plan and estimate leave the held words out.
- A URL that carries a scanner's payload in its path or query never enters the map. Examples are `<script>`, `../../etc/passwd` and `union select`, as archives often keep them. A scanner's own test file never enters either.
- No request to a target goes to a host outside the [scope](#scope), Chrome's included. Without a scope, requests stay on the site.
- Third-party sources (subdomain lists, archives, RDAP) are asked about your domains. `-passive` sends nothing to the targets.
- Every request, connection and query goes in the [ledger](#the-ledger-and-its-seal), by class: `target`, `source` or `dns`. Only the scope and `-deny-path` hold a target's; the kill file stops all three.
- `-rate` paces what is sent and `-max-requests` caps it: see [budget, pace and the kill switch](#budget-pace-and-the-kill-switch).
