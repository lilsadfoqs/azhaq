# What azhaq prints

Every command follows the same contract, so a script or an assistant can read any of them the same way. `azhaq help -json` lists every command and flag with its type and default; what `azhaq help` and `-h` leave out carries `"hidden": true` and a `"why"` (`compat:TOOL`, `alias`, `accepted`, `rare`, or the reason a command is left out of the list). Each command's own fields are on its page: the command table in the [README](../README.md) links them, and `azhaq docs COMMAND` prints one.

## stdout and stderr

- **stdout** carries results only: one per line, or one JSON object per line with `-json`.
- **stderr** carries progress, failures as they happen (the first three of each kind) and a **summary** at the end.
- With `-json`, every stderr line is JSON, and the summary is one object with `"type":"summary"`.
- With `-silent`, the summary is printed only when something failed or was cut short. A source or archive that failed counts, whatever the exit code is.
- The **exit code** says whether the work is complete: see [Exit codes](#exit-codes).

With `-json`, the drop-in commands use the field names of the tool they stand in for, so existing `jq` filters keep working.

### When results are printed

- `probe`, `dns`, `ports`, `dirs`, `fuzz`, `params` and `shots` print each result as it is found.
- `subs` without `-live` prints a domain's names when its sources have answered.
- `subs` with `-live` prints them when the run ends. A name is live only once DNS has answered for the whole run.

### Takeover lines with -silent

A takeover candidate is a finding, not a note. `-silent` prints one line for each on stderr, and stdout stays one result per line:

```
[takeover] shop.example.org -> gone.azurewebsites.net (Azure, dangling, candidate)
```

### Progress lines

A command that is still working after 10 seconds says so every 10 seconds. A run paced at a request a second is then not taken for a hung one.

```
azhaq: 1m30s, 62 requests sent (1/s), 38 tasks left; -max-requests 80 ends it in about 18 s
```

- `requests` counts what has left: a request counted and still waiting for the pace, or that Chrome did not send after all, is not in it, and the number never goes down. The pace is that of the last interval.
- The tasks are those known so far.
- The end is the sooner of the request cap and `-timeout`.
- With `-json`, the line is an object:

```json
{"type":"progress","seconds":90,"requests":62,"requests_per_second":1,"tasks_done":70,"tasks_left":38,"ends_by":"-max-requests 80","ends_in_seconds":18}
```

A run paced slowly says so as it starts: `-rate 1 paces requests to 1/s: the cap of 80 requests …`. `-quiet` and `-silent` print neither line. A run that ends within 10 seconds prints no progress line. Nothing of this goes to stdout.

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Complete: nothing failed, or the run did its job and its summary names every failure (`failures` counts them). An open port that closes or resets at once on `run`'s HTTP request, and was not named HTTP, is an answer (not a web service), not a failure. | Use the results. Read `failures` and `failed` when it is above 0. |
| 1 | Error: the command could not do its job, or its summary disagreed with its rows (an internal error). | Read the message. |
| 2 | Usage: bad flags or input. Nothing was sent. | `azhaq help COMMAND`. For a scope refusal, check the target, `-allow` or `-scope`. |
| 3 | The run's own job failed or is incomplete: nothing it was given answered, a failure names no target, or a note says the results are short or misleading. With `-strict-exit`, any failure. See [Exit 3](#exit-3). | The summary lists each failure, whether it is worth retrying, and its targets. |
| 4 | Stopped with work left, by a limit, the kill file or a signal. | `azhaq resume -db FILE` continues where it stopped. With a kill file, remove it first. |

`watch` and `ledger` add their own rules: see [watch](commands/watch.md#summary-and-exit-codes) and [ledger](commands/ledger.md#summary-and-exit-codes).

### Exit 1

- The command could not do its job: a database it cannot open, or Chrome missing for `-browser`.
- The summary disagrees with the rows it summarises or with the ledger. The message and the summary's `error` say which number: `internal error: the summary disagrees with the rows and the ledger it summarises (results, against the rows emitted: the summary says 5, the rows say 4)`. The summary has `complete: false`. This is a bug in azhaq: the rows already printed are as they were, and the numbers beside them are not to be relied on. See [what is checked](#what-the-summary-is-checked-against).

### Exit 2

- The targets are all outside the scope given: `every target is outside the scope (2 left out): 127.0.0.2, 127.0.0.3`. The message names them. A range that no allow rule touches counts. `ports` and `dns` say it too.
- A header names a host (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`) outside a scope rule. For example `-H 'Host: secret.lab'` with `-deny secret.lab`, or a request file's or import's header whose host is not a target. See [Hosts named in headers](CONCEPTS.md#hosts-named-in-headers).
- A flag that takes a value is followed by another flag of the command: `-screenshots -max-requests 50` would take `-max-requests` for the directory. Give the value, or join the flag and a value that starts with a dash with an equals sign.
- Chrome would start without its sandbox, because the system gives it none (a container, AppArmor, no user namespaces), and `-chrome-no-sandbox` was not given. The message names the flag. This holds for every command that starts Chrome: `shots`, `crawl` and `run` with `-browser` or `-screenshots`, a sign-in with `-login`, `roles` with `-role-login` (tried before the first request), and the tools of `azhaq mcp`.
- Nothing was sent.

### Exit 3

One rule decides it, for every command, in one place of the code: the step that writes the summary. A run **did its job** when at least one target it was given answered and each failure is named in the summary (`failed`, `unreachable`, or a row without an answer): it exits 0 with `complete: true`, and `failures` says how many failed. A run **failed** (exit 3, `complete: false`) when any of these holds:

1. **Nothing it was given answered.** Every target the command can count failed: a `probe` of two dead hosts, a `run` whose only URL refused, `subs` for a domain no source answered, a `dns` run in which no resolver answered any name, a `fuzz` run in which every request failed.
2. **A failure is the run's own.** It names no target: a signed-in run that lost its session (`azhaq-session`), a report that could not be written. Or it is a bug (`panic:`), or the failure of the `-exec` connector you gave.
3. **A note says the results are short or misleading.** Names cut at `-max-names`, names `-live` could not check or got no answer for, a role whose session is dead, a picture short of its page, a `fuzz` run that stopped on a target that stopped answering, a calibration that filtered nothing, wildcard answers among a sweep's paths. A count in a note cannot name each one, so these are not "done with failures".
4. **The command was given nothing it can count.** An address list, a range or a file of ports has no answer to tell from a failure, so any failure exits 3 (`ports`, `asn`, `notify`, `watch`, `roles`, and `run` with only addresses, ranges or an organisation; `gallery` and `ledger` have rules of their own).

What a command counts as a target it was given, and so as a failed one:

| Command | A target is | It failed when |
| --- | --- | --- |
| `probe` | each input row (a port or a path of an input is a row of its own) | the row has no answer (a refused connection, a timeout, a name that does not resolve): `failures` counts these rows |
| `run`, `crawl`, `dirs`, `shots`, `urls`, `params` | each URL and each domain given | the URL is `unreachable` (every request failed), or no third-party source answered for the domain. A page it found that fails is a failure, not a target |
| `subs` | each domain | no source answered for it |
| `dns` | each name asked and finished | no resolver answered (with `-axfr`, no server transferred the zone) |
| `fuzz` | each input asked | its request failed after one retry |

`failures` is the sum of `count` over `failed`, plus each `unreachable` target no entry of `failed` names (`probe` counts its rows without an answer). It is in every summary, `0` when nothing failed, under both behaviours.

`-strict-exit` restores the rule before 0.15 for one release: any failure exits 3, a target among many included. `-fail-on-errors` is the same flag. Without it the exit code is the rule above, and a script that must alarm on any failure reads `failures` or passes `-strict-exit`. The summary says which part of the rule it met on its last line. `partial` and `fanout` failures are failures of a target like any other: they are counted and listed, and do not alone make a run fail. See [Failures](CONCEPTS.md#failures-fan-out-partial-and-degraded).

An [internal error](#exit-1) comes before this rule: a summary that disagrees with its rows exits 1, whatever the outcome of the run was, and is never a run that did its job. `failures` counts what failed in the work and `error` says the summary itself is wrong; they are different fields, and a run can have either, both or neither.

### Exit 4

- A limit stopped the run: `-max-requests`, `-timeout`, `-daily-requests`, `-max-items` or `-max-names`. The `stopped` text names it with its flag. What `-depth` leaves unasked is a note, not a stop: the URLs and names found past it are counted there, and `azhaq resume -depth N` asks them. The URLs counted are those the scheduler kept because they were found past `-depth`: a URL a budget such as `-max-items` left unasked is `capped` in the map too, but the note does not count it, and a stop by `-max-items` is not blamed on `-depth`. The note is made only when a larger `-depth` has something to ask: a `dirs` run has none (its `-depth` is the sweep's own, and the paths it found are rows it asked), and a run that has finished its tasks says nothing about work it cannot do.
- The kill file stopped it: `-kill-file`, default `DB.stop`. See [the kill file](CONCEPTS.md#the-kill-file).
- A signal stopped it: Ctrl-C, `kill` or SIGHUP. All three stop a command the same way, with its summary printed and its ledger sealed.
- `gallery`, `mcp` and `watch -every` are servers, and a signal is how they end: they exit 0 ([gallery](commands/gallery.md#summary-and-exit-codes), [mcp](commands/mcp.md#summary-and-exit-codes), [watch](commands/watch.md#summary-and-exit-codes)). `mcp` first interrupts the commands in flight, which seal their ledgers.
- Work is left. `azhaq resume -db FILE` continues. See [Workspaces, runs and resuming](CONCEPTS.md#workspaces-runs-and-resuming).

## The summary

```json
{"type":"summary","command":"run","version":"0.10.0","complete":false,"exit":4,
 "results":148,"stored":160,"folded":12,"counts":{"pages":84,"api":33,"auth":12,"scripts":14,"hostnames":9,"ports":8},"seconds":7.4,"requests":195,
 "db":"app.db","run_id":"…",
 "unreachable":["http://testphp.vulnweb.com/"],
 "failed":[{"collector":"azhaq-http","error":"timeout","retryable":true,"count":34,
            "targets":["http://testphp.vulnweb.com/login.php","…"]}],
 "skipped":[{"target":"engage.tesla.com","reason":"outside the scope"}],
 "stopped":"the request budget of 500 is spent, 41 tasks known and not done (the cap holds for each run: azhaq resume sends up to 500 more, or as many as its -max-requests says, 0 for no cap)","resume":"azhaq resume -db app.db",
 "notes":["…"],"next":["azhaq query -db app.db -type Hostname"]}
```

| Field | Meaning |
| --- | --- |
| `type`, `command`, `version`, `seconds` | Always `summary`, the command, azhaq's version, and the run time in seconds. |
| `complete`, `exit` | As in the exit codes above: `complete` is true when `exit` is 0, a run that did its job and names its failures included. |
| `failures` | Always present: how many failures the run has, 0 when none. The sum of `count` over `failed`, plus the `unreachable` targets no entry of `failed` names (`probe`: its rows without an answer). It is there under `-strict-exit` too. |
| `results` | What the command printed on stdout: names, web services, map rows. |
| `counts` | A breakdown of the results, per command. For `run` the counts are disjoint and cover every stored map row: see [run's counts](#run-counts). |
| `stored` | `run` only: the map rows the database holds. The counts add up to it. `results` is smaller when templated URLs and dead or wildcard names fold into one row. |
| `folds` | `run`, `crawl` and `dirs` (its catch-all entries only, one for each directory): the URL rows by fold class (`catchall`, `not-found`, `beyond-depth`, `unrequested`), each with its `count`; a catch-all entry has its `origin` and the `controls` its answers matched (`url`, `status`, `type`, `size`, `title`), a not-found entry its `templates`. The text view prints one line for each entry in place of its rows, `-all-rows` and `-json` print the rows. See [run](commands/run.md#folded-rows). |
| `folded` | `run` only, always present: the stored rows a printed row holds (templated URLs, dead and wildcard names, and in the text view the lines of the folded classes). `results + folded + left_out = stored`, with `left_out` (`-no-catchall`) absent when 0. |
| `requests` | Requests sent to targets, port connects included. DNS queries and requests to third-party sources are not in it: the queries are in `dns_queries`, and a source's requests are in `sources` (`subs`, `urls`) and in the ledger's `source` lines. |
| `requests_by_purpose` | `run` and `crawl`: what the requests were for, by name: `pages`, `scripts` (scripts, stylesheets and source maps), `assets` (images, fonts, media), `controls` (the requests for a path that cannot exist, which answers are compared with), `description checks` (the places an API description or a GraphQL endpoint is guessed at, and the description read), `path checks` (the built-in paths: `robots.txt`, sitemaps, `.git/HEAD`, admin pages), `wordlist sweep`, `parameter probes`, `browser` (Chrome's requests), `connections`, `sent by workers` (requests another process of the run sent, which has no purpose to name here) and `other`. A name appears when it has a request. They add up to `requests`, and each line of the ledger carries its own `purpose`. |
| `dns_queries` | Queries sent to resolvers: every question, retries and wildcard probes included, and the ones to the system resolver. It is the ledger's `DNS queries` class, with or without a ledger. Absent when none was sent. |
| `cost` | `run` and `roles`: what the command was estimated to send, by stage, beside what each stage sent. `estimate` is the total (absent for a resumed run), `actual` the total sent, and each of `stages` has `stage`, `estimate`, `actual`, `collectors` and, where the estimate leaves out what answers lead to, `estimate_at_least` and `not_counted`. Each amount has `requests`, `connects`, `dns_queries` and `source_queries`: the stages' requests and connects add up to `requests`, their DNS queries to `dns_queries`. See [plan](commands/plan.md#the-estimate) and [roles](commands/roles.md#cost-by-stage). |
| `db` | The database the results are in. Absent when it was temporary. |
| `unreachable` | Targets you gave that never answered. |
| `takeover` | Names another party may take over: `host`, `service`, `target` (the CNAME target), `evidence`, `strength`, `status` (`candidate` or `verified`) and, for `dangling`, `list` (the public list's entry and when azhaq read it). See [takeover](#takeover). |
| `takeover_candidates`, `takeover_verified` | How many of the `takeover` rows have each `status`; they add up to the rows. A count of 0 is absent. |
| `failed` | Work that did not get its answer, grouped by collector, source and error, most frequent first. See [failed](#failed). |
| `skipped` | Targets and requests azhaq did not send, with the reason. See [skipped](#skipped). |
| `junk` | `urls` only: the URLs left out as junk, by reason. See [urls](commands/urls.md#junk). |
| `sources` | `subs` and `urls`: which sources answered, which failed and why, and what each gave. See [subs](commands/subs.md#the-sources-block) and [urls](commands/urls.md#summary-and-exit-codes). |
| `partial` (in `failed`) | A third-party source failed while other sources answered for the same target. |
| `degraded` | `subs` only: a source the run relies on did not answer, so the names may be incomplete; the exit code is 3 when no source answered, or with `-strict-exit`. See [subs](commands/subs.md#degraded). |
| `degraded_by` | `subs` only, with `degraded`: an array of `{source, error, domains}`, one for each failed source of the default set. |
| `stopped`, `resume` | The limit that stopped the work and the command that continues it. |
| `notes` | Caps that were hit and other things worth knowing that are not failures. See [notes](#notes). |
| `wrote` | The files the run wrote besides the database and the files you named with `-o` and the like: the ledger, the name history files, `.azhaq-last` and `.azhaq-index`, and the archived URLs. See [the workspace](#the-workspace). |
| `next` | Commands worth running next. See [next](#next). |
| `advisories` | With `-advisories`: the known-issue leads, one per lead line printed and per stored `advisory` row: `advisory_id`, `url` (its source), `target`, `product`, `version_seen`, `affected_range`, `label` (`affected`, `not affected` or `conditional`), `precondition` when one is named, and with `-advisories-confirm` also `confidence` (`observed`, `inferred` or `claimed`) and `read` (what was read, or why nothing was). They are leads, not map rows: `counts` still adds up to `stored` without them, and a note counts them by label from these rows. See [Known-issue matching](CONCEPTS.md#known-issue-matching--advisories). |

### What the summary is checked against

Before a summary is printed, azhaq recomputes what it can from the rows it emitted and from the ledger, and a number that differs ends the run with exit 1 (see above) instead of printing as complete. Each command that prints rows counts them as they go out, apart from the numbers it publishes:

| Command | The numbers that must equal the rows |
| --- | --- |
| `run` | `results` is the rows printed; `stored - left_out` is the stored rows they stand for and `folded` the ones they hold beyond themselves; the counts add up to `stored`; and, when no printed row stands for several, each count is the rows of that kind. |
| `crawl` | Every URL row of the crawl's scope is listed or left out for one reason, and the four class counts add up to the rows listed and the rows the notes say were left out (the extension list, `-em`/`-ef`/`-mr`/`-fr`, the hints and named URLs without `-hints`, and the routes with a parameter, views and sockets that plain output cannot ask); `requested + not requested + templates` is the same total; `results` is the rows listed and the other lines printed. |
| `subs` | The names the sources gave, less what was left out, plus what DNS and the guesses added, are the names printed (the note beginning `count:`). |
| `ports` | `results` is the rows handed to the output. |
| `roles` | `results` is the rows printed, and each count is the rows with that verdict. |
| every command with a ledger | `requests` is the ledger's lines to targets and `dns_queries` its lines to resolvers, for this run. |

### Run counts

`run` counts every stored map row once, so `counts` adds up to `stored`, and `results = stored - folded`, where `folded` is the stored rows that a printed row holds (the JSON summary has `"folded":12`, the text summary says `12 folded into templated rows`). A key says what it counts and what it leaves out; each is the number `azhaq query -db FILE` lists with its filter, except that `query` folds URL templates as `run` does.

| Key | Counts | `query` filter |
| --- | --- | --- |
| `pages` | URL rows that are none of the kinds below: pages and routes | `-type URL -role page,app` |
| `api`, `auth`, `forbidden` | URL rows of that role. They are not also in `pages`. | `-type URL -role api` (or `auth`, `forbidden`) |
| `catchall` | URL rows that answered with the page every unknown path gets, whatever they are named as. They are in no other key. | `-type URL -coverage catchall` |
| `skipped` | URL rows named and not asked: a `-deny-path` rule of yours, or a catch-all origin (`run` holds the paths scripts name in a directory once 3 of them answered with the catch-all page: see [run](commands/run.md#catch-all-origins)). They are in no other key. | `-type URL -coverage skipped` |
| `client routes`, `websockets` | URLs the app's router draws, and WebSocket endpoints | `-role client-route`, `-role websocket` |
| `scripts`, `assets`, `source maps`, `manifests` | The URLs of those roles. They are in the map, and in no other key. | `-role script` (`asset`, `sourcemap`, `manifest`) |
| `hostnames` | Name rows that are neither dead nor wildcard: live, sibling and unresolved names | `-type Hostname`, less the two below |
| `dead hostnames`, `wildcard hostnames` | Names that did not resolve (a dangling CNAME among them) and names a wildcard answers | `-type Hostname -role dead` (or `wildcard`) |
| `ports`, `open|filtered ports` | Port rows, one for each host, port and protocol: those the scan found open, and the UDP ports that neither answered nor were refused | `-type Port`, by `state` |
| `addresses`, `domains`, `prefixes`, `organizations`, and the other kinds | Rows of that type | `-type IPAddress`, `Domain`, `Prefix`, `Organization` |

The URL keys other than `catchall` and `skipped` count rows of the other coverages: add `-coverage visited,error,gone,hint,capped` to their filters when a run has catch-all or skipped rows. A key with no row is absent. The sum is one unit, the stored row. `results` is another, the printed row: a templated URL row holds `count` stored URLs and a names row holds `folded` names. `run -no-catchall` leaves the `catchall` rows, and the `skipped` rows a catch-all origin made, out of what it prints and out of `results`: `left_out` says how many, and `results = stored - folded - left_out`.

### takeover

- Strengths, services and what each means: see [Takeover candidates](CONCEPTS.md#takeover-candidates). Confirm each by hand before reporting.
- `status` says how far a row is shown. `verified`: the service itself answered, from the name's own front page, with its documented "nothing here" page, and the name's CNAME is on that service. `candidate`: what was observed does not show the name is free, such as a target that answered NXDOMAIN or a page with no CNAME known. `evidence` begins with what was observed.
- The text summary prints each as `! takeover candidate` or `! takeover verified`.
- With `-silent` and nothing else to report, each is printed alone on stderr as `[takeover] name -> target (service, strength, status)`.
- `dns` and `subs -live` rows carry the same object as `takeover`.

### failed

- `retryable` is true for timeouts, dropped connections, answers cut short, 429 and 5xx: a later try may work. `azhaq resume -db FILE -retry-failed` asks those targets again, and only those (see [resume](commands/resume.md#retrying-failed-targets)). Failures that are not retryable (a refused connection, a certificate error, a 4xx other than 429) are not asked again: the same request would fail the same way, so they are for you to read and fix. A plain `resume` continues only the tasks a limit or a kill left, never a failed one.
- `source` names a third-party source, such as `crtsh` or `wayback`.
- `targets` names up to 100. `azhaq query -db FILE -failed` lists every failed target of the newest run (`-run ID` reads another by its `run_id`): the list to retry.
- `azhaq-session` is a signed-in run whose session ended and could not be renewed (`the session ended: after /logout was requested …`). Every request after the check noticed the loss was refused, so nothing after that was answered as an anonymous visitor. The summary's `session_lost` has the URL whose answer first looked like the end (`first_answer`), the GETs answered after it, which were already in flight (`in_flight`, `in_flight_urls`), and the GETs asked since the last check that held (`asked_since_good_check`). The exit code is 3: see [Sessions](CONCEPTS.md#sessions).
- `partial` and `fanout` failures are counted in `failures` like any other: see [Failures](CONCEPTS.md#failures-fan-out-partial-and-degraded) and [Exit 3](#exit-3).

### skipped

- The reasons: outside the scope, a `-deny-path` rule (`-deny-path REGEX`), sent before the run was killed, or a scope entry a run cannot use. azhaq lists nothing as skipped for what a URL is called.
- Chrome's requests outside the scope are refused before they leave. They are listed without their query string as `outside the scope (Chrome)`.
- A connection Chrome's own services tried and the guard refused is not in the ledger, because nothing was sent: the summary's `notes` counts it and names the hosts. On a new Chrome profile there are none.
- Without a scope, the reason is `outside the site (Chrome)`. The site is the registrable domain or address of the pages Chrome was pointed at.
- The first 100 URLs of a run are listed. `notes` gives the number of requests when there were more.
- Chrome sends GET, HEAD and OPTIONS only, outside signing in: see [Chrome](CONCEPTS.md#chrome).
- A write a page or its scripts would send is refused before it leaves. That covers a POST, PUT, PATCH or DELETE, a beacon, and a form a script posts.
- It is listed as `a page's script would send a write`, by method and URL without its query: `POST http://127.0.0.1:3001/api/track`. Its route is mapped with that method (`ops` with `source` `browser`).
- With `-browser-writes`, pages send their writes, which change data on the target. Nothing is listed.
- A download is refused for the whole browser. A download is a URL that is a file, an `<a download>`, or a `Content-Disposition: attachment` answer. Chrome saves nothing to disk.
- It is listed as `Chrome would download it`, by URL without its query and the name Chrome would have given the file: `http://127.0.0.1:3001/ftp/incident-support.kdbx (incident-support.kdbx)`.
- The request itself was sent and counted. Only what it answered is dropped.

### notes

`notes` holds caps that were hit and other things worth knowing that are not failures. Examples:

- `ledger: 148 recorded in app.db.ledger.jsonl: 146 to targets (142 requests, 4 connections), 2 DNS queries, sealed … (azhaq ledger -verify app.db.ledger.jsonl …)`: the lines to targets are the summary's `requests`.
- `path checks: 28 skipped (an API description was already found)`: see [run](commands/run.md#notes-in-the-summary).
- `screenshot of URL not taken: …`: see [shots](commands/shots.md#screenshots-and-the-budget).
- `GraphQL URL: introspection disabled: schema recovered (…)`: see [run](commands/run.md#notes-in-the-summary).
- For `subs`, the `coverage` line: see [subs](commands/subs.md#coverage-estimate).

### next

`next` suggests a command to run after this one. `run` suggests three: see [run](commands/run.md#next-in-the-summary). In the text summary each is a line `next: COMMAND   (why)`. A suggestion is not an instruction: nothing runs it, and it may widen what azhaq sends, so read the command before you run it.

A second kind of `next:` line follows from what this run measured. It is for a person at a terminal, and it is not in the JSON summary. At most two are printed. It is not printed with `-silent`, `-json` or `-jsonl`, and not when stderr is not a terminal unless `-v` is given. `AZHAQ_NO_HINTS=1` hides it everywhere.

| Command | The line | It appears when |
| --- | --- | --- |
| `subs` | `azhaq subs -d example.com -permute   (try variations of the 412 names found, such as …)` | the run found names and did not use `-permute`. The two names it shows are two that `-permute` would ask for one of the names found. |
| `crawl`, `run` | `… -browser -interact   (3 URLs of ORIGIN answered with the page every unknown path gets; …)` | three or more URLs of one origin answered with the page every unknown path gets, the origin's front page is an empty shell its scripts draw, and `-interact` was not given. `run` says nothing when its older `-browser` line above already points to Chrome. |
| `fuzz` | `azhaq fuzz … -preflight PAGE.req -preflight-var-auto TOKEN:csrf_token   (the request sends csrf_token with a fixed value and 98 of 100 answers were 403 or 419; …)` | at least 10 answers came back, 80% or more of them 403 or 419, the request sends a field named like a token (`csrf`, `xsrf`, `_token`, `authenticity_token`, `nonce`) with a value fixed on the command line, and no `-preflight` was given. It says what was measured, not that the token is the cause. |
| `run` | `azhaq roles -role anon -role 'user=…' -- RUN FLAGS   (the run was signed in: …)` | the run had a sign-in, a cookie or an `Authorization` or `Cookie` header, and found no `auth` row (the line for those is the one in [run](commands/run.md#next-in-the-summary)). |
| `hunt` | the same | a run in the workspace was signed in, and `-roles` was not given. |
| `subs`, `probe`, `crawl`, `dirs`, `urls`, `params`, `shots`, … | `azhaq run -domain example.com   (one command: names, services, crawl, files and a ranked map, in one workspace)` | a drop-in command ran on one domain or URL. With `-db` it is shown once for the workspace, and recorded in it only when it was shown; without `-db` there is no workspace, so it is shown each time. It is the last line, and is left out when two others are printed. |

## The ledger

The ledger is one JSON line for each request, connection or query a run sends, to a target, a third-party source or a resolver. What it is, the chain of hashes and the seal are in [Concepts](CONCEPTS.md#the-ledger-and-its-seal). `azhaq ledger` checks, counts and exports it: see the [`ledger` page](commands/ledger.md). It records what azhaq sends: the requests of a helper outside azhaq, such as a `-role-cmd` command logging in, are not in it.

A line has:

| Field | Meaning |
| --- | --- |
| `seq` | The line's number, from 1. |
| `time` | When it was sent, UTC. |
| `class` | What it was sent to: `target`, `source`, `dns` or `own`. A line without one, from a ledger written before classes, is a `target`. |
| `kind` | `http`, `tcp`, `udp`, `probe`, `dns`, `chrome` or `seal`. See below. |
| `method` | The HTTP method. For `dns`, the record type (`A`). On a `probe` line, the method of an HTTP request. Not on `tcp` and `udp` lines. |
| `proto` | On a `probe` line only: `http` or `https` for an HTTP request, else the protocol the bytes speak (`redis`, `smtp`, `payload`, …), `raw` when none is named. |
| `target` | The URL as sent, query string included, for `http` and `chrome`, and for a `probe` that is an HTTP request. `ip:port` for `tcp`, `udp` and the other `probe` lines. The resolver (`ip:port`, or its URL for DoH) for `dns`. |
| `host` | The host the request was for. For `dns`, the name asked. |
| `vhost` | The `Host` header sent, when it is not the URL's. |
| `body` | The first 16 hex digits of the sha256 of the request body, on an `http` line that has one (on a `probe` line, of the bytes sent): [resume](CONCEPTS.md#workspaces-runs-and-resuming) uses it to tell two writes to one URL apart. |
| `rule` | The scope rule that allowed it (`-allow`, `-scope`). Empty when the run has no rules. |
| `collector` | What sent it, for the lines that say. |
| `purpose` | What a request to a target was for, on the lines of a run that says: `pages`, `scripts`, `assets`, `controls`, `description checks`, `path checks`… The summary's `requests_by_purpose` counts them. |
| `prev`, `hash` | The previous line's hash, and the hex sha256 of `prev` and this line's JSON without `hash`. |

- `tcp`: a connect of `ports`, or a TLS handshake of `ports` or `azhaq-tls`; for a `source`, the connection to crt.sh's database or a mail server.
- `probe`: what `ports` writes to a connection it opened to name the service on it, one line for each write, after the `tcp` line of that connection. An HTTP probe has its `method`, its `target` as `http://IP:PORT/PATH` (`https` inside TLS) and, when the `Host` header it sent is another, its `vhost`; any other has its protocol in `proto` and the start of the sha256 of the bytes in `body`. A probe is not a request or a connection of its own: the summary's `requests` counts the `tcp` line of its connection, and the run's ledger note says how many probes went on those connections. The handshake of a TLS connection is the `tcp` line, not a probe.
- `dns`: a query to a resolver, a zone transfer or a trace step. A retry or a second opinion is a line of its own.
- `source` lines are `http` or `tcp`, with no `rule`: the scope holds targets, not the third parties asked about them.
- `chrome`: a request Chrome sent, listed once it left. One that Chrome dropped before sending is not listed, and not counted.
- A Chrome WebSocket handshake is `ws://host:port/path?query`, and `wss://host:port` inside TLS.

### What a line means

A line says the request or connection left, and the summary's `requests` counts the same lines: a request counted and then cancelled before it left (by `-timeout`, the kill file, Ctrl-C or a request that failed its checks) has no line and is given back to the count. What leaving means for each kind:

| Kind | A line is made when | No line for |
| --- | --- | --- |
| `http` | The request has been written to its connection. Also when it failed with no stop to blame: a connect was attempted and failed, a TLS handshake began, the name had no address, or the other end dropped the connection before the write. | A request a stop cancelled before any of that: before a connection was tried, or on a connection that never took the write. |
| `tcp` | The socket is about to connect (`connect(2)`), so a stop that lands earlier leaves no line. A fast port scan (`-rate` of 1,000 or more) writes the lines of up to 32 connects together just before they start; those connects are not stopped by a kill file or a deadline that comes after the lines, and a stop that comes before them records none. | A connect refused by the scope or the kill file, with no address, or stopped before its socket connected. |
| `udp` | The socket to the port is open and the datagram is written at once. | A socket that could not be opened. |
| `probe` | The bytes of one probe are about to be written to a connection a port identification opened: the HEAD / it sends to a port that said nothing, a protocol's own request, the `SYST` of an FTP check. One line for each write. | A write that was never made. |
| `chrome` | Chrome says the request's headers went out. A request Chrome was let send and nothing was heard of afterwards is listed when its tab closes, since it may have left. | A request Chrome dropped or answered from its cache. |
| `dns` | The query goes to the resolver. | A query refused by the kill file or after the context ended. |

`azhaq ledger -verify` checks the chain and the seal, not this: it cannot say a line was sent, only that it was not changed afterwards.
- An `http` line is written when the request has a live connection, and a request is one line however many connections it took. One that fails to connect (refused, timed out) is a line too. A pooled connection the server had closed is not written to; a request that fails on one the server closed unseen is sent again once on a new connection, and is still one line. So the lines to targets equal the requests a proxy in front of them counts.
- A notification is a request to a third party: a `source` line, by the webhook's host. `watch` sends its notifications after its run has sealed the workspace's ledger, so they are lines after that seal, which `watch` seals again, and its own summary counts them: [watch](commands/watch.md#notifications). `notify -ledger FILE` keeps them in a file of its own.
- `seal`: the end of a run, with no target.
- A password in a `target` URL's user info is masked.

## The workspace

A workspace is one SQLite file, set with `-db`. Its files:

| File | What it is |
| --- | --- |
| `DB` | The workspace. |
| `DB.ledger.jsonl` | The [ledger](CONCEPTS.md#the-ledger-and-its-seal), next to the workspace. |
| `DB.stop` | The default [kill file](CONCEPTS.md#the-kill-file). |
| `azhaq-data/names/DOMAIN.json` | The [name history](commands/subs.md#name-history), in the folder of `DB` (the current directory when the database is temporary). |

A run writes nothing under your home or XDG directories and leaves nothing in the temporary directory. The files it writes besides the database are in the summary's `wrote`. A history shared between workspaces is one you name with `-history-dir DIR` or `$AZHAQ_DATA_DIR`.

- A drop-in command (`subs`, `probe`, `dirs`, …) without `-db` uses a temporary database and cannot be resumed.
- `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory, or uses the file `$AZHAQ_DB` names.
- A new `azhaq-TIME-PID.db` is remembered in `.azhaq-last` in the current directory, and `query`, `show`, `export`, `hunt` and `gallery` without `-db`, and `diff` without `-b`, read that file. `ingest` into a new file writes it too. A file named by `-db` or `$AZHAQ_DB` is not remembered.
- `azhaq roles` keeps its files in its `-dir`: `roles.ledger.jsonl`, `roles.stop` and `roles.db`.
