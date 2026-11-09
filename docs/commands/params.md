# azhaq params

Finds the query parameters a page reads, by trying names from a list. Names go in the query by default; `-X POST`, `-X JSON` and `-X XML` send them in a body. `-X` is the opt-in: no `-params-writes` is needed (that flag is for `run -params`), but the target must be named (`-allow` or `-scope`) or be one page. Replaces arjun (see [Migrating](../MIGRATING.md#arjun-azhaq-params)).

## Synopsis

```
azhaq params -u URL | -l FILE | -i FILE | stdin  [-w small|medium|large|FILE] [-X GET|POST|JSON|XML] [-t N] [-c N] [-d SECONDS] [-stable] [-T SECONDS] [-include DATA] [-casing STYLE] [-passive] [-rate N] [-oJ FILE] [-oT FILE] [-oB HOST:PORT] [-json]
```

## Examples

```
# one page, the built-in list of names
azhaq params -u https://app.example.com/search

# your own wordlist, 5 requests a second, arjun's JSON file
azhaq params -u https://app.example.com/search -w burp-parameter-names.txt -rate 5 -oJ params.json

# pages from a Burp export, names sent in a body (bodies may change data)
azhaq params -i burp-export.xml -allow app.example.com -X POST
```

## What it does

1. Takes pages from `-u`, `-l`, `-i` or stdin.
2. Asks each page with random names first, to get a reference answer and the page's own noise.
3. Sends the names of the list in groups and compares each answer with that reference.
4. Narrows a group that changed the answer down to the names that did it, and prints them with `why`. A name whose only evidence is `size`, `lines` or `body` is checked once more before it is kept: four names no page reads, as long as it, are asked, and each answer it gave must differ from them and from the reference by more than the page shows by itself. A page that varies from one request to the next (a token, a counter, an ad) keeps no such candidate, and what the check saw widens the noise allowed for the names that follow.
5. Tests the parameters the URL already carries (`?q=apple`), which the list skips: a name is found when asking with it renamed to a name no page reads changes the answer, or else when another value does, and the change shows twice. A name the page ignores (`utm_source`) is not reported. On a page that prints what it is sent, only the rename is judged. They are in `params` with the others and `why` says what changed.
6. When the page refuses a request without its input (400 or 422), asks the names not found again with the names found so far in every request, against a new reference taken the same way, and repeats while a pass finds more (at most 3 passes). A page that reports its required fields one at a time says nothing about the second until the first is given. A page that answers without input is not asked again.

A body method sends requests that may change data on the target.

## Output

Plain output is the URL and the parameter names, one line per page. With `-json` you get one object per page.

| Field | Meaning |
| --- | --- |
| `url` | The page. |
| `method` | `GET`, or `POST`, `JSON` or `XML` when the names were sent in a body. |
| `params` | The names found. |
| `why` | An object: each name found, with what changed in the answer. The values are below. |
| `values` | The value a name needed, such as `{"debug":"true"}`, when it answered only to that one. |

`params -json` prints only these fields. The workspace row of a page also keeps `requests`, and `writes` (the body requests sent) for a body method: `azhaq show -json` prints them. A note in the summary says how many body requests were sent.

What `why` says for a name:

| Value | The answer changed in |
| --- | --- |
| `status` | its status |
| `size` | its size, beyond what the page shows between identical requests |
| `headers` | the set of header names |
| `location` | the redirect target |
| `lines` | its line count |
| `body` | its body, on a page that gave the same body three times in a row |
| `reflected` | the name's value came back more often than random names' values do |
| `named` | the page printed the name |

A name found in step 5 has its reason followed by what was present, such as `status, once username was present`. Its requests are counted in `requests` like the others.

Two files can be written as well:

- `-oJ FILE` writes arjun's file: `{"URL": {"params": [...], "method": "GET", "headers": {...}}}`.
- `-oT FILE` writes one request per line: `URL?name=1234&other=5678`. For a body method the line is the URL, a tab and the body.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). These cases are specific to `params`.

- A page that rate-limits (429, 418, 503) fails. The failure is listed as `failed` and retryable, with a note, and counted in `failures`. A page that leaves requests unanswered fails too: listed as `failed`, not as retryable, with a note, and counted in `failures`. The run exits 3 when every page failed, and 0 when others gave their names (`-strict-exit` makes it 3).
- A page not searched has a note that says why: it changes by itself, is not text, or is past `-params-per-host`. A page a `-deny-path` rule matches is listed under `skipped` with the rule, and nothing is sent to it. In `run -params`, a page that answered the run's own request as the origin answers a path that cannot exist, or with 401, 403 or 405, is not searched either (`-params-all` searches it); `azhaq params` asks the pages you give it all.
- A page that answers names it does not read is listed in the summary's `notes`: see Details.
- A page the request budget (`-max-requests`) ends is not lost: its row has the names established so far, the summary's `notes` say how many of the names were judged (`the request budget ended the search with 4 of 8 names judged (1 found so far)`), and the exit is 4. `azhaq resume` searches the page again, from the start. Each pass costs a fixed part (4 requests to measure the page, 4 for the switch names such as `debug`) besides the names: a page that answers 400 until a required field is given is searched up to 3 more passes with the fields found, so a short list can need over 30 requests.

## Details

### Pages that answer names they do not read
- A page answers names it does not read when most names of a group, or nearly every name tried alone, change its answer. As many random names made like them change it too.
- The names of that group are dropped and the search stops there. Names found in earlier groups stay.
- The summary's `notes` list the page.

### A route that never ends
- A page that streams for ever (server-sent events, `multipart/x-mixed-replace`) is read for 64 KiB or 2 seconds and then closed, as `probe` does, not held until the timeout. An answer longer than 2 MiB is cut there.
- The page's row has `"truncated": true` and a note says an answer body was cut, so its size is of what was read.

### Names and groups
- The built-in list is 6,500 names, `-w large`. arjun's `large` is longer. Use `-w FILE` for your own list.
- Names are sent in the order given, without duplicates. Every name is sent, with a session or without one.
- A group of names the server refuses with another status than the baseline's, such as 414 for a long query, is cut down until the server answers as before. That size is then the group.
- A page that `-deny-path REGEX` matches is not searched, and the summary lists it under `skipped` with the rule.
- A page that prints the query string back or counts the names is told apart by random names of the same lengths. Reflection is told apart by a random token.

## Flags

<!-- flags:begin params -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-u` | string, repeatable |  | page URL |
| `-l` | string |  | file of page URLs (- for stdin) |
| `-i` | string |  | import pages: a file of URLs, a Burp Suite XML export (HTML, JSON and XML items) or a raw HTTP request (GET or POST) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-w` | string | `large` | parameter names: a file, one per line, or small (1,000 names), medium (3,000) or large (6,500, the default) |
| `-X` | string | `GET` | how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target, and needs -allow or -scope, or a single page |
| `-c` | int |  | names per request at most (0: 500, and about 7.6 KB in a query; fewer where the server refuses a long query) |
| `-casing` | string |  | write the names in one style: snake (like_this), camel (likeThis) or lower (likethis) |
| `-passive` | bool |  | also try the query names the archives (Wayback Machine, Common Crawl, OTX) hold for the pages' domains |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; HOST:PORT allows that host on that port only; with any -allow, nothing else is requested |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself) |
| `-send-state-changing` | bool |  | send the GETs whose own path or query declares a state change (create, delete, reset, logout, and the other words of the documented set; a query's action=stop and the like): a crawl's link, a script's route, an API description's operation, a word of a -dirs or -paths wordlist (ffuf sends every word). By default they are held back and listed as skipped; a target you give and -deny-path rules are not affected |
| `-kill-file` | string |  | stop all sending when this file exists, so that no request starts after it, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | parameter requests per second per host (0: no limit, as arjun) |
| `-t` | int | `5` | requests in flight per page (arjun -t) |
| `-d` | float |  | seconds to wait before each request, one at a time (arjun -d) |
| `-T` | float | `15` | seconds to wait for each request; one that times out is asked again with 5 s more, up to 20 s (arjun -T) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |

**Session and network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY, except for loopback targets, which stay direct) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: workspace.db in the run's folder under ~/.azhaq/runs; with AZHAQ_HOME=none a temporary one) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-o` | string |  | also write results to this file |
| `-oB` | string |  | send each page with the names found through this proxy, HOST:PORT (Burp), after the search |
| `-oJ` | string |  | write results to this file as JSON: {"URL": {"params": [...], "method": "GET", "headers": {...}}} |
| `-oT` | string |  | write results to this file as text, one request per line: URL?name=1234&other=5678 |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-strict-exit` | bool |  | exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures |

<details>
<summary>Flags familiar from arjun and other names (3)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-include` | string |  | sent with every request: a query (a=1&b=2) for GET; for a body a form, a JSON object, or XML, or a template with $arjun$ where the names go | arjun's name |
| `-stable` | bool |  | one request at a time, 3 to 9 s apart, and 30 s wait after a refused connection (arjun --stable) | arjun's name |
| `-header` | string, repeatable |  | same as -H | other name |

</details>
<!-- flags:end -->
