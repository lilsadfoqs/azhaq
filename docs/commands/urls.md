# azhaq urls

Lists the URLs that web archives hold for a domain: the Wayback Machine, Common Crawl, OTX, urlscan.io and Arquivo. Replaces gau (see [Migrating](../MIGRATING.md#gau-azhaq-urls)).

## Synopsis

```
azhaq urls -d DOMAIN | -dL FILE | DOMAIN… | stdin  [-subs] [-providers wayback,otx,…] [-mc/-fc/-mt/-ft LIST] [-from/-to YYYYMM] [-blacklist EXT,…] [-fp] [-raw] [-keep-junk] [-live [-live-rate N] [-live-max N]] [-proxy URL] [-retries N] [-urls-threads N] [-o FILE] [-json]
```

## Examples

```
# every URL the archives hold for a domain
azhaq urls -d example.com

# with subdomains, from two archives, without static files, one URL per host and path
azhaq urls example.com -subs -providers wayback,commoncrawl -blacklist png,jpg,css,js -fp | httpx

# only 200 answers of type text/html captured since 2024, a second between the requests of an archive
azhaq urls -d example.com -mc 200 -mt text/html -from 2024 -urls-pause 1s

# rows to triage: provider, capture date, junk labels, and a spot-check of 200 URLs against the live site at 5 a second
azhaq urls -d example.com -json -keep-junk -live -live-max 200 -live-rate 5
```

## What it does

1. Takes domains from `-d`, `-dL`, arguments or stdin.
2. Asks each archive for the URLs of the domain. `-providers` chooses the archives, and `-subs` adds the subdomains. Without `-subs`, `www.DOMAIN` counts as the domain itself, as the Wayback Machine's index files it.
3. Reads pages from each archive, and asks again when an archive answers 429 or 503.
4. Applies your filters, and prints each URL once unless you give `-raw`.
5. Holds out the URLs that `-allow`, `-deny` or `-scope` (with `-program`) do not allow, as in [dns](dns.md): they are not listed, `-live` sends them no request, and the summary counts them as `held out by scope`.

## Output

By default URLs are printed as each archive page arrives, unsorted, when stdout is not a terminal. On a terminal, or with `-sort`, they are sorted and printed at the end. `-raw` prints every row of the domain the archives gave, as they gave it: no normalising, no junk filter, no deduplication (`-blacklist` and `-fp` still apply). `-o` appends to the file. With `-json` you get one object per URL. With `-db`, the workspace keeps every URL in `DB.urls.jsonl` beside it (one JSON object a line: `run`, `url`, `source`), written as the pages arrive, so a stopped run keeps what it read and `azhaq resume` adds to it. Its graph holds one example for each URL shape, 200 a domain at most: `export -format urls` writes all of them, and `query` lists the graph's rows and says how many archived URLs they stand for. The list is not kept for a run with no `-db`.

| Field | Meaning |
| --- | --- |
| `url` | The archived URL, normalised (as the archives gave it with `-raw`). |
| `normalized` | The normalised form, always there (with `-raw`, `url` is as the archive gave it and this is the normalised form). |
| `raw_url` | The URL as the archive gave it, when that is not `url`. |
| `source` | The archive that gave it first: `wayback`, `commoncrawl`, `otx`, `urlscan` or `arquivo`. When two give a URL, the one whose page arrived first is its source, and `archived` is that archive's. |
| `archived` | When the archive captured it, in UTC (RFC 3339), as the archive states it: the Wayback Machine's and Common Crawl's capture timestamp (for the Wayback Machine the first capture of the URL, as `collapse=urlkey` keeps it), arquivo.pt's timestamp, OTX's `date` and urlscan.io's scan time. Left out when the archive gives none. |
| `junk`, `junk_reason` | Why it looks like noise: a class and the rule's words. Left out for a URL that looks like a page or an API. See [Junk](#junk). |
| `verified`, `verified_status`, `verified_error` | With `-live`: see [Live spot-check](#live-spot-check). |

In plain output every row is its URL; `-json` carries the fields above.

The archive rows (in the workspace's `azhaq-urls` observation) are one for each archive:

| Field | Meaning |
| --- | --- |
| `asked` | What it was asked for: the host pattern of the Wayback Machine, Common Crawl and arquivo.pt (`example.com/*`, `*.example.com/*` with `-subs`), OTX's indicator, urlscan.io's search. |
| `count` | URLs the archive gave that are not junk and are on the domain, repeats included. |
| `read`, `kept`, `duplicates`, `junk`, `outside`, `over_cap` | Every record read, and where it went: `read` = `kept` + `duplicates` + `junk` + `outside` + `over_cap`. `kept` is a URL new to the set, `duplicates` a record of a URL already kept, `junk` a record left out as junk, `outside` one off the domain or left out by a filter, `over_cap` one past `-urls-max`. A URL found glued inside a broken record is read as a record of its own. |
| `pages` | Pages read from it. |
| `seconds` | Time spent on it. |
| `requests` | Requests sent, retries included. |
| `retried`, `waited_seconds` | Requests asked again after a 429 or 503, and the seconds waited: see Details. |
| `error` | Why the archive failed, in words: see Details. |
| `partial` | Set with `error` when the archive gave URLs before it failed: what it gave is in the set. |
| `capped` | Set when the archive stopped at `-urls-pages` with more to read. |
| `unfiltered`, `unfiltered_by` | What the archive keeps none of, and the filter that could not apply: see Details. |
| `left_out`, `no_status`, `no_type`, `filtered_by_archive` | What the filters did to its rows, and the flags the archive applied in its own query: see Details. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). These points are specific to `urls`.

- The summary has a `sources` block with a row for each archive. It reads as the one of `subs` ([The sources block](subs.md#the-sources-block)), with `urls` where `subs` has `names`.
- The summary's top-level `requests` is what reached the targets, as in every command. `urls` sends none, so it is 0, unless `-live` asks the live site: then the requests it sent are counted. The archives are third parties: their requests, retries included, are `requests` in each archive row and in the `sources` block, and a note adds them up.
- It has `junk`, the URLs left out and why: see [Junk](#junk). `counts` has `dropped as junk` (URLs left out), `static files listed` (rows labelled `asset`, which are listed): see [Static files](#static-files), and `duplicates`, the records of the archives that repeat a URL already kept.
- The summary's `sources` block says, for each archive, what it was asked (`queries`), what it gave (`urls`), whether it failed (`failed_sources`, with the archive's words, such as `127.0.0.1:8080 answered 504`) and whether it gave URLs before failing (`partial_sources`). A failed archive leaves a partial set: the URLs of the others are listed, the failure is counted in `failures`, and a note says so. It does not need stderr to be read. An archive that failed at once is named as `wayback failed and gave nothing, so the URLs only they hold are missing and those of the others are listed (complete stays true: no URL given is in doubt)`; the words `the set is partial` are kept for an archive cut after giving URLs, which is what `complete: false` means.
- `complete` and the exit code, by how the archives answered. An archive that gave URLs and then failed (a timeout, a cut connection, a 504) did not answer in full; one that failed at once gave nothing, so it left no part of the set in doubt.
  - Every archive answered: `complete` is true, exit 0.
  - One failed at once, another answered in full: `complete` is true, exit 0, and `failures` counts it.
  - One failed after giving URLs: `complete` is false, because the set holds only part of what that archive has (it is in `partial_sources`). The exit code is still 0 while another archive answered in full, and 3 with `-strict-exit`.
  - Every archive failed, or each one that gave URLs failed after giving them: `complete` is false and the exit code is 3.

## Details

### Retries
- A 429 or 503 is asked again after its `Retry-After`, or after 2, 5, 10, 20, then 30 s.
- It is asked again for as long as the archive's `-urls-timeout` and the run's `-timeout` allow.
- The summary row counts them in `retried` and `waited_seconds`.

### Errors
- `error` says why the archive failed. It reads like these:
  - `failed after 4 tries, 429 Too Many Requests`
  - `failed after 4 tries, dial tcp …: connection refused`
  - `…, Retry-After 2m0s; the 2m0s to wait is more than the 45s left (-urls-timeout or -timeout)`

The summary's `sources.records` has `read`, `kept`, `duplicates`, `junk`, `outside` and `over_cap` for each archive, summed over the domains, and a note says it: `records read by archive: wayback 19 = 1 kept + 0 duplicates + 18 junk + 0 outside the domain or filtered`. `sources.urls` is `kept` + `duplicates`. `read` is the sum of the other five.

### Junk
`urls` counts the URLs on the domains that it left out as junk, by reason. Each URL is counted once.

- `"scanner payload"`: for example 3. It covers `/../` in a query name (`?.tst5-Name/../Gen`; a value such as `next=../home` stays) and an injection glued to a value (`artist=1union select …`, `… from information_schema.…`). A boolean test is one too: `N and N=N` or `N or N=N` in a value, with spaces, `+`, `%20`, a comment or brackets between the parts (`id=1 and 1=1`, `x=1)))and(1=1`, `x=1%20AND%201=1`), as is a value of digits and one quote (`id=1'`). `name=O'Brien`, `q=rock and roll` and `year=1999 and later` stay.
- `"scanner probe"`: a scanner's own file or tag (`acunetix_xsl_inclusion_test.xsl`, a random-named executable at the root such as `/7zSo1DIz.exe`; gau lists them), a NUL byte (`%00`) in the path or query, or a query that is only punctuation or a dot and an extension (`?.`, `?.tst`, `?.bak`). A query value that is a scanner's name alone, or led into a version or a test file, is one too: `x=acunetix`, `ua=sqlmap/1.4`, `x=acunetix_wvs_test` (Acunetix, Netsparker, Invicti, sqlmap, Nikto, w3af, Wapiti, Arachni, Skipfish, Havij and Burp Suite). A word searched for stays, as does a product's name: `q=netsparker`, `vendor=nessus`.
- `"directory listing sort link"`.
- `"script placeholder (NaN, undefined, null)"`.
- `"dot segment"`.
- `"malformed link (wildcard, quote, bracket, ellipsis)"`: the ellipsis is `…` or a `...` that ends the path or is a segment of its own.
- `"fuzzing placeholder or request-line fragment"`: a path segment, or a query name or value, that is a fuzzer's keyword in capitals (`FUZZ`, `FUZ2Z`, and in a query `FUZZFUZ2Z`, with or without an extension; with a fuzzer log's number and result, `FUZZ000003:C=200`; with a capitalised word, `FUZZMultiple`; after stray symbols such as a mis-decoded arrow, `%CB%93%E2%86%92FUZZ`) or a `{payload}` or `{FUZZ}` slot, or a path that ends in a request line's `HTTP/1.0` or `HTTP/1.1` (`/HTTP/1.1`, `/index.php%20HTTP/1.1`), or a query value that ends in one after other text (`?artist=1HTTP/1.1`). `/fuzz`, `?q=fuzz`, `/FUZZY`, `/FUZZ-list.txt`, `?proto=HTTP/1.1`, `/users/{id}` and `/docs/http/1.1` stay.
- `"another URL glued into the path or query"`: a second `http://` or `https://` URL that follows a character that is not a separator, two archive records run into one (`/admin/create.sqlA01http://example.org/artists.php`). The URL it holds is listed on its own, with the same source and date, when it is on the domains and not already listed. After `/`, `=`, `?`, `&`, `;`, `,`, `|` or a space (also `+` in a query) a URL is a redirect, a parameter or a list, and stays (after a comma, only when the query value is itself a URL: `?x=1&y=2,http://example.org/other.php` is two records run together and is junk, and is not listed again): `/go/http://other.test/`, `?next=https://other.test/`, `?urls=http://a.test/,http://b.test/`. A colon is not a separator: `/x%3Ahttp://…` is glued. `-raw` keeps the URL as the archive gave it and lists nothing more.
- `"link cut at the end of its sentence"`: a path that ends in `.`, `,`, `;`, `'` or an unmatched `)` or `]`, or a query that ends in `.`.

Every source's URLs go through these rules, OTX's too.

`counts` has the total as `dropped as junk`, and a note says it: `7 URLs dropped as junk (…; -raw keeps them)`. `-raw` prints them and drops none. `-keep-junk` (with `-json`) lists them too, each row labelled with its class in `junk` and the rule's words in `junk_reason`; they stay in `dropped as junk`, and `-live` never asks one of them.

The classes, in the order of the rules above: `scanner-payload`, `scanner-probe`, `listing-sort`, `placeholder`, `dot-segment`, `malformed`, `fuzzing`, `glued-url`, `cut-link`. A row that is not junk but is a static file (an image, a font, a style sheet, or anything on a media host with an opaque name) is listed with `"junk": "asset"` and the reason `static file (by extension or media host): no route sits behind it`: a reader who wants pages filters on an absent `junk`. See [Static files](#static-files).

### Static files
A static file is listed, not dropped. `counts` has `static files listed`, the number of rows labelled `asset`, and a note says that they are in `results` and not in `dropped as junk`. The count is left out when no row is one.

- A URL is in one of the two: a junk URL is left out and counted in `dropped as junk`, a static file is a row and counted in `results`. So `results` + `dropped as junk` is the unique URLs of the domains (less what `-blacklist`, `-fp` and `-urls-max` hold back), and `static files listed` is at most `results`.
- With `-keep-junk` the junk rows are listed too, labelled with their class, and `results` counts them as rows: `results` - `dropped as junk` is then the URLs listed that are not junk.
- With `-raw` every row is printed as the archive gave it and none is dropped: `static files listed` counts the rows labelled `asset` among them.

### Live spot-check
`-live` asks the live site for each URL once, after every archive has answered: one GET, not followed (a redirect is its own answer), at `-live-rate` requests a second (10 by default; a note states it). It sends requests to the domain's hosts, so it is off unless you give it, and the rows are printed when the check is done. `-live-max N` asks only N URLs, spread evenly over the sorted list, so a long list can be spot-checked; the others are listed without `verified` and counted as `not asked (-live-max)`. `-live-proxy` sends the requests through a proxy.

- `verified` is `true` when the site answered with a status other than 404 or 410: the page is still there (a 301, 403 or 500 answers too). It is `false` for a 404 or 410 and for a URL that got no answer. `verified_status` is the status (absent with no answer), and `verified_error` says why there was none. Rows with no `verified` were not asked.
- A URL that looks like junk (a scanner's payload) is never sent: the counts say `not asked (junk)`.
- The counts are `verified live`, `gone (404, 410)` and `no answer`, and they add up to the URLs asked. A note says how many were asked, the rate and the counts.

### Filters an archive cannot apply
- A filter judges the rows that carry what it needs, and keeps the others, as gau does. gau sends `-mc`, `-fc`, `-mt`, `-ft`, `-from` and `-to` to the Wayback Machine and Common Crawl in the query and applies none to OTX or urlscan.io. azhaq sends them to those two and to arquivo.pt, and also judges the rows of the archives that record a status or a type: OTX's `httpcode` and urlscan.io's page `status` and `mimeType` (the scan's page URL and the URL that was submitted for it share them).
- A URL with no recorded status is not judged by `-mc` or `-fc`: it stays. Likewise a URL with no recorded type with `-mt` and `-ft`. This is a change from before 0.22, when `-mc` dropped it.
- `unfiltered` lists what an archive keeps none of: for OTX `type` and `date`, for none of the others.
- When you give a filter it cannot apply, `unfiltered_by` names the filter, such as `-mt` or `-from`.
- The archive is asked all the same and its URLs are kept, as gau keeps them, with no type on the row.
- The notes say the same in words: `otx has no type of its captures: its 13 URLs are not filtered by -mt`.
- The summary counts what the filters did, for each archive that is judged row by row. `left_out` in its row has the rows each flag left out (`{"-mc": 22}`) and `counts` has them as `left out by -mc`. `no_status` and `no_type` count the rows that had none to judge and stayed, with `no_status_by` and `no_type_by` naming the flags. Notes say so: `otx: -mc left out 22 URLs` and `otx: 33 URLs have no recorded status, which -mc needs: they are kept, not judged`.
- The Wayback Machine, Common Crawl and arquivo.pt apply the filters themselves and give only what passed, so what they left out cannot be counted: their row says `filtered_by_archive` with the flags, and a note says it.

## Flags

<!-- flags:begin urls -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-d` | string, repeatable |  | domain (repeatable; domains may also be given as arguments, as gau takes them) |
| `-dL` | string |  | file of domains (- for stdin) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-providers` | string |  | the archives to ask, comma-separated: wayback, commoncrawl, otx, urlscan, arquivo (default: all five). A value that names a file, or has a / in it, is the API-key file, as -providers meant before; -provider-config says that without doubt |
| `-provider-config` | string |  | API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml) |
| `-archive` | string, repeatable |  | ask NAME's archive at this address instead of its own, as NAME=URL (a mirror or a test server; repeatable) |
| `-raw` | bool |  | print the archived URLs exactly as the archives gave them: no normalising, junk filter or deduplication |
| `-subs` | bool |  | also the subdomains of each domain: the archives are asked for *.DOMAIN (default: the name given, as gau does without --subs; azhaq run keeps the broader default) |
| `-keep-junk` | bool |  | list the archived URLs left out as junk too, each labelled with its class and reason (-json), instead of only counting them |

**Matchers and filters**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-mc` | string |  | keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); OTX and urlscan.io record a status for most URLs; a URL with none is not judged and stays, as in gau |
| `-mt` | string |  | keep only URLs the archive recorded with these MIME types, comma-separated (text/html); OTX, which keeps no type, is asked all the same and its URLs kept, with a note |
| `-ft` | string |  | leave out URLs the archive recorded with these MIME types, comma-separated; OTX, which keeps no type, is asked all the same and its URLs kept, with a note |
| `-blacklist` | string |  | leave out URLs whose path ends in these extensions, comma-separated (png,jpg,svg) |
| `-fp` | bool |  | keep one URL for each host and path, dropping the variants that differ by parameters |
| `-from` | string |  | only captures from this time on: YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss; OTX, which dates no capture, is asked all the same and its URLs kept, with a note |
| `-to` | string |  | only captures up to this time, in the same form |

**Spot-check the live site**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-live` | bool |  | spot-check the URLs against the live site once every archive has answered: one GET of each (not followed) at -live-rate, and each -json row says verified, with the status it got; sends requests to the domain's hosts, so it is off by default; it prints at the end, so not with -stream |
| `-live-rate` | float | `10` | with -live, requests a second to the live site |
| `-live-max` | int |  | with -live, check at most N URLs, spread evenly over the sorted list; the rest are listed unchecked and counted (0: every URL) |
| `-live-proxy` | string |  | with -live, send the requests through this proxy (http://, https:// or socks5://; default: $HTTP_PROXY, $HTTPS_PROXY, except for loopback targets) |
| `-send-state-changing` | bool |  | with -live, also ask the URLs whose own path or query declares a state change (create, delete, reset, logout, ...); by default an archived /logout is not asked, and is counted as not asked (state-changing) |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-urls-max` | int | `500000` | URLs kept for each domain (0: no cap); the summary counts the ones past it |
| `-urls-pages` | int |  | stop reading an archive after this many pages for a domain (default 0: no cap, as gau reads every page); an archive that stops at the cap says so in the summary |
| `-urls-pause` | duration |  | pause between the requests of one archive (default: none, as gau asks; an archive that answers 429 or 503 is waited out) |
| `-urls-threads` | int |  | domains asked at once (default 16) |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |
| `-retries` | int |  | times an archive request is asked again after a 429, 503 or network error, after its Retry-After (seconds or a date, however long) or 2, 5, 10, 20, then 30 s; 0 makes the first refusal final (default: a 429 or 503 is asked again until the archive's time, -urls-timeout, or the run's is spent, a network error 3 times; a wait longer than the time left ends the request at once, with the reason) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-rate` | float |  | requests, port connects, UDP datagrams and DNS queries to the targets' name servers per second, over all hosts (0: no pace) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; HOST:PORT allows that host on that port only; with any -allow, nothing else is requested |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-seal-to` | string |  | when the run ends, append the ledger's seal as one JSON line ({"time","ledger","seal","entries"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself) |

**Network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-proxy` | string |  | send the archive requests through this proxy: http://HOST:PORT, https:// or socks5:// |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: workspace.db in the run's folder under ./.azhaq/runs; with AZHAQ_HOME=none a temporary one) |
| `-o` | string |  | also write results to this file, appending to it as gau does |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-sort` | bool |  | print once every archive has answered, sorted (the default on a terminal) |
| `-stream` | bool |  | print each URL as it arrives, unsorted (the default when stdout is not a terminal) |
| `-fail-on-capped` | bool |  | exit 4 when an archive stopped at its page cap with more to read |
| `-fail-on-errors` | bool |  | the same as -strict-exit |
| `-strict-exit` | bool |  | exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures |

<details>
<summary>Flags familiar from gau and other names (4)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-config` | string |  | a gau config file (default: ~/.gau.toml when it exists): threads, retries, subdomains, parameters, providers, blacklist, proxy, [urlscan] apikey and host, otx, and the [filters] table; flags win | gau's name |
| `-fc` | string |  | leave out URLs the archive recorded with these HTTP status codes, comma-separated; a URL whose status the archive did not record is kept | gau's name |
| `-version` | bool |  | print the version | gau's name |
| `-threads` | int |  | same as -urls-threads | other name |

</details>
<!-- flags:end -->
