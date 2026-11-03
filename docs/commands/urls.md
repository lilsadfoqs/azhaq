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

# only 200 answers of type text/html captured since 2024, with no pause between requests
azhaq urls -d example.com -mc 200 -mt text/html -from 2024 -urls-pause 0

# rows to triage: provider, capture date, junk labels, and a spot-check of 200 URLs against the live site at 5 a second
azhaq urls -d example.com -json -keep-junk -live -live-max 200 -live-rate 5
```

## What it does

1. Takes domains from `-d`, `-dL`, arguments or stdin.
2. Asks each archive for the URLs of the domain. `-providers` chooses the archives, and `-subs` adds the subdomains. Without `-subs`, `www.DOMAIN` counts as the domain itself, as the Wayback Machine's index files it.
3. Reads pages from each archive, and asks again when an archive answers 429 or 503.
4. Applies your filters, and prints each URL once unless you give `-raw`.

## Output

By default URLs are printed as each archive page arrives, unsorted, when stdout is not a terminal. On a terminal, or with `-sort`, they are sorted and printed at the end. `-raw` prints every row the archives gave, as they gave it. `-o` appends to the file. With `-json` you get one object per URL. With `-db`, the workspace keeps every URL in `DB.urls.jsonl` beside it (one JSON object a line: `run`, `url`, `source`), written as the pages arrive, so a stopped run keeps what it read and `azhaq resume` adds to it. Its graph holds one example for each URL shape, 200 a domain at most: `export -format urls` writes all of them, and `query` lists the graph's rows and says how many archived URLs they stand for. The list is not kept for a run with no `-db`.

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

The summary lists one row for each archive:

| Field | Meaning |
| --- | --- |
| `asked` | What it was asked for: the host pattern of the Wayback Machine, Common Crawl and arquivo.pt (`example.com/*`, `*.example.com/*` with `-subs`), OTX's indicator, urlscan.io's search. |
| `count` | URLs the archive gave. |
| `pages` | Pages read from it. |
| `seconds` | Time spent on it. |
| `requests` | Requests sent, retries included. |
| `retried`, `waited_seconds` | Requests asked again after a 429 or 503, and the seconds waited: see Details. |
| `error` | Why the archive failed, in words: see Details. |
| `partial` | Set with `error` when the archive gave URLs before it failed: what it gave is in the set. |
| `capped` | Set when the archive stopped at `-urls-pages` with more to read. |
| `unfiltered`, `unfiltered_by` | What the archive keeps none of, and the filter that could not apply: see Details. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). These points are specific to `urls`.

- The summary has a `sources` block with a row for each archive. It reads as the one of `subs` ([The sources block](subs.md#the-sources-block)), with `urls` where `subs` has `names`.
- The summary's top-level `requests` is what reached the targets, as in every command. `urls` sends none, so it is 0, unless `-live` asks the live site: then the requests it sent are counted. The archives are third parties: their requests, retries included, are `requests` in each archive row and in the `sources` block, and a note adds them up.
- It has `junk`, the URLs left out and why: see [Junk](#junk).
- The summary's `sources` block says, for each archive, what it was asked (`queries`), what it gave (`urls`), whether it failed (`failed_sources`, with the archive's words, such as `127.0.0.1:8080 answered 504`) and whether it gave URLs before failing (`partial_sources`). A failed archive leaves a partial set: the URLs of the others are listed, the failure is counted in `failures` (the exit code is 0 while another archive answered, 3 with `-strict-exit` or when none did), and a note says `the set is partial: wayback failed, so the URLs only they hold are missing and those of the others are listed`. It does not need stderr to be read.

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

### Junk
`urls` counts the URLs on the domains that it left out as junk, by reason. Each URL is counted once.

- `"scanner payload"`: for example 3. It covers `/../` in a query name (`?.tst5-Name/../Gen`; a value such as `next=../home` stays) and an injection glued to a value (`artist=1union select …`, `… from information_schema.…`).
- `"scanner probe"`: a scanner's own file or tag, a NUL byte (`%00`) in the path or query, or a query that is only punctuation or a dot and an extension (`?.`, `?.tst`, `?.bak`).
- `"directory listing sort link"`.
- `"script placeholder (NaN, undefined, null)"`.
- `"dot segment"`.
- `"malformed link (wildcard, quote, bracket, ellipsis)"`: the ellipsis is `…` or a `...` that ends the path or is a segment of its own.
- `"fuzzing placeholder or request-line fragment"`: a path segment, or a query name or value, that is a fuzzer's keyword in capitals (`FUZZ`, `FUZ2Z`, `FUZZFUZ2Z`, with or without an extension; with a fuzzer log's number and result, `FUZZ000003:C=200`; with a capitalised word, `FUZZMultiple`; after stray symbols such as a mis-decoded arrow, `%CB%93%E2%86%92FUZZ`) or a `{payload}` or `{FUZZ}` slot, or a path or query value that ends in `HTTP/1.0` or `HTTP/1.1` (`/HTTP/1.1`, `/index.php%20HTTP/1.1`, `?artist=1HTTP/1.1`). `/fuzz`, `?q=fuzz`, `/FUZZY`, `/FUZZ-list.txt`, `?proto=HTTP/1.1`, `/users/{id}` and `/docs/http/1.1` stay.
- `"link cut at the end of its sentence"`: a path or query that ends in `.`, `,`, `;`, `'` or an unmatched `)` or `]`.

Every source's URLs go through these rules, OTX's too.

`counts` has the total as `dropped as junk`, and a note says it: `7 URLs dropped as junk (…; -raw keeps them)`. `-raw` prints them and drops none. `-keep-junk` (with `-json`) lists them too, each row labelled with its class in `junk` and the rule's words in `junk_reason`; they stay in `dropped as junk`, and `-live` never asks one of them.

The classes, in the order of the rules above: `scanner-payload`, `scanner-probe`, `listing-sort`, `placeholder`, `dot-segment`, `malformed`, `fuzzing`, `cut-link`. A row that is not junk but is a static file (an image, a font, a style sheet, or anything on a media host with an opaque name) is listed with `"junk": "asset"` and the reason `static file (by extension or media host): no route sits behind it`: a reader who wants pages filters on an absent `junk`.

### Live spot-check
`-live` asks the live site for each URL once, after every archive has answered: one GET, not followed (a redirect is its own answer), at `-live-rate` requests a second (10 by default; a note states it). It sends requests to the domain's hosts, so it is off unless you give it, and the rows are printed when the check is done. `-live-max N` asks only N URLs, spread evenly over the sorted list, so a long list can be spot-checked; the others are listed without `verified` and counted as `not asked (-live-max)`. `-live-proxy` sends the requests through a proxy.

- `verified` is `true` when the site answered with a status other than 404 or 410: the page is still there (a 301, 403 or 500 answers too). It is `false` for a 404 or 410 and for a URL that got no answer. `verified_status` is the status (absent with no answer), and `verified_error` says why there was none. Rows with no `verified` were not asked.
- A URL that looks like junk (a scanner's payload) is never sent: the counts say `not asked (junk)`.
- The counts are `verified live`, `gone (404, 410)` and `no answer`, and they add up to the URLs asked. A note says how many were asked, the rate and the counts.

### Filters an archive cannot apply
- OTX records a status for each URL (`httpcode`) and urlscan.io for each page (`status`, with its `mimeType`). `-mc`, `-fc`, and for urlscan.io `-mt` and `-ft`, judge them. A URL with no recorded status is not kept by `-mc` and is not left out by `-fc`.
- `unfiltered` lists what an archive keeps none of: for OTX `type` and `date`, for none of the others.
- When you give a filter it cannot apply, `unfiltered_by` names the filter, such as `-mt` or `-from`.
- The archive is asked all the same and its URLs are kept, as gau keeps them, with no type on the row.
- The notes say the same in words: `otx has no type of its captures: its 13 URLs are not filtered by -mt`.

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
| `-mc` | string |  | keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); OTX and urlscan.io record a status for most URLs, and a URL with none is not kept |
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

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-urls-max` | int | `500000` | URLs kept for each domain (0: no cap); the summary counts the ones past it |
| `-urls-pages` | int | `50` | pages read from each archive for a domain (0: no cap); an archive that stops at the cap says so in the summary |
| `-urls-pause` | duration |  | pause between the requests of one archive (default: 1 s for the Wayback Machine and Common Crawl, 0.5 s for OTX, 2 s for urlscan.io; 0 for none) |
| `-urls-threads` | int |  | domains asked at once (default 16) |
| `-urls-timeout` | duration | `3m0s` | time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes) |
| `-retries` | int |  | times an archive request is asked again after a 429, 503 or network error, after its Retry-After (seconds or a date, however long) or 2, 5, 10, 20, then 30 s; 0 makes the first refusal final (default: a 429 or 503 is asked again until the archive's time, -urls-timeout, or the run's is spent, a network error 3 times; a wait longer than the time left ends the request at once, with the reason) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |

**Network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-proxy` | string |  | send the archive requests through this proxy: http://HOST:PORT, https:// or socks5:// |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
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
