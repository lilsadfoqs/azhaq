# azhaq quickstart

A first map of one target, guided: the plan and its cost first, then the map, then the commands that go deeper.

## Synopsis

```
azhaq TARGET [run flags]
azhaq quickstart TARGET [run flags]
```

`TARGET` is a name such as `example.com` (`-domain`), a URL with its scheme such as `https://app.example.com/` (`-url`), or an address (`-cidr`, a single address). A host with a port is given as a URL. Any other word is an unknown command, as before. `quickstart` takes the flags of [`run`](run.md#flags).

## Examples

```
# A name: its subdomains, services, pages, scripts and APIs
azhaq example.com

# An app, kept in a workspace of your choosing
azhaq https://app.example.com/ -db app.db

# Names only: nothing is sent to the targets
azhaq quickstart example.com -passive
```

## What it does

1. Prints the [plan](plan.md) of the run on stderr: the collectors, what is sent to the targets, the source queries, and the [estimate](plan.md#the-estimate) of the requests, connects and DNS queries by stage. Nothing is sent yet.
2. Runs the map. It is `azhaq run` with `-url`, `-domain` or `-cidr` and the flags you gave, the scoped default mapping: the target given is the scope (`-allow` widens it), and no wordlist, port scan, login or Chrome is added. The rows on stdout are `run`'s, and the summary is `run`'s.
3. Ends the summary's `next` with the commands that go on in the workspace (`hunt`, `query`, `show`) and the wider passes it did not make, each a command to copy with what it would send beyond this run (`-ports top-1000`, `-dirs @common`). Nothing is run for them. The last line of the summary is `azhaq docs start`, the page that walks the four first jobs in order.

With `-quiet` or `-json` the plan is not printed: stderr holds the summary alone, as it does for `run`.

## Output

Stdout and the summary are those of [`run`](run.md#output). The plan and the lines that frame it are on stderr.

## Summary and exit codes

The summary and the exit codes are `run`'s: see [run](run.md#summary-and-exit-codes).

## Flags

<!-- flags:begin quickstart -->
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
| `-ports` | string |  | scan TCP ports: default (the top 1000 and the usual ports of the services azhaq names and checks, then every TCP port of each address that answered; what a range or an address among the targets gets when no -ports is given), top-100, top-1000, full or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888 (active; the targets given are the scope unless -allow) |
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
| `-db` | string |  | the workspace, a SQLite file (default: workspace.db in the run's folder under $AZHAQ_HOME/runs, ./.azhaq/runs in the current directory unless set; with AZHAQ_HOME=none a new azhaq-TIME-PID.db in the current directory; or $AZHAQ_DB; query, show and export read it afterwards) |
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
<summary>Other names, flags accepted with no effect and rarely used flags (82)</summary>

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
| `-port-skip` | string |  | TCP ports never asked, in any pass: a list as -ports reads it, such as 25,9000-9010 (what -ep of the ports command passes) | rarely needed |
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
| `-urls-mc` | string |  | keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); OTX and urlscan.io record a status for most URLs; a URL with none is not judged and stays, as in gau | rarely needed |
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
