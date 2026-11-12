# azhaq dirs

Sweeps a wordlist of paths and reports those that answer unlike a path that cannot exist. SecLists' `common.txt` is built in. A URL with a path is swept from that path. Replaces `ffuf -ac` (see [Migrating](../MIGRATING.md#ffuf-azhaq-fuzz-and-azhaq-dirs)).

## Synopsis

```
azhaq dirs -u URL | -l FILE | stdin  [-w WORDLIST] [-ic] [-e EXT] [-depth N] [-mc/-ms/-mw/-ml/-mr LIST] [-fc/-fs/-fw/-fl/-fr LIST] [-ac=false] [-rate N] [-proxy URL] [-json]
```

## Examples

```
# sweep a site with the built-in wordlist
azhaq dirs -u https://app.example.com/

# sweep below /api/, try two extensions, hide one size, send 20 requests a second
azhaq dirs -u https://app.example.com/api/ -w common.txt -e php,bak -fs 4242 -rate 20

# several services from a file, as JSON
azhaq dirs -l services.txt -json
```

## What it does

1. Takes each service from `-u`, `-l` or stdin. A URL with a path is swept from that path.
2. Asks every word of the wordlist, with each `-e` extension if you give any; a word that declares a state change is held back unless `-send-state-changing` is given ([Which words are asked](#which-words-are-asked)). An empty line is a word too: it asks the base URL itself, as in ffuf, and is counted like the rest.
3. Calibrates on paths that cannot exist, as ffuf's `-ac` does, and keeps it on when you give filters (`-fc`, `-fs`, `-fw`, `-fl` or `-fr`): an answer your filters hide is hidden, and an answer that looks like the catch-all is hidden as well, as with ffuf's `-ac -fs`. `-ac=false` turns calibration off: no guess is sent, the filters are yours alone, and every answer they do not remove and a matcher keeps is listed, catch-all answers included. The summary says so in a note. The summary counts the answers the calibration filtered (`2 answers matched the calibration's: the status with the size, word count or line count that names that cannot exist get in their directory, and were filtered`), so the words asked are the paths listed, folded and filtered; `run -dirs` says the same.
4. Applies the matchers and filters to the answers and prints the paths that pass.
5. Asks one more name that cannot exist in each directory that two hits are found in, when the wordlist has words with a slash (`api/users`): see [A catch-all inside a directory](#a-catch-all-inside-a-directory).

Nothing else is sent: no front page is asked first, so with `-ac=false` a sweep of N words is N requests, and `-max-requests N` is enough. The calibration guesses (or, with `-ac=false`, the first two words) double as the check that the service answers: if none of them gets an answer, the sweep stops there, the service is listed under `unreachable`, and the exit is 3.

The request is ffuf's, so a ffuf command line carries over: [Details](#details) lists what it sends.

## Output

Plain output is one URL per line with its status, size, words and lines. With `-json` you get one object for each input that matched. The sizes, words and lines are counted as ffuf counts them, so a `-fs` or `-fl` value carries over. `-mc` defaults to ffuf's `200-299,301,302,307,401,403,405,500`.

| Field | Meaning |
| --- | --- |
| `url` | The URL that answered. |
| `status` | The HTTP status. |
| `length` | The size of the whole body, as ffuf counts it, up to 64 MB. |
| `words` | The number of spaces in the whole body, plus one. |
| `lines` | The number of newlines in the whole body, plus one. |
| `position` | The place of the input among the sweep's inputs, from 1, as ffuf counts it. |
| `redirectlocation` | Where a redirect points. |
| `truncated` | `true` when the path streams for ever (server-sent events, `multipart/x-mixed-replace`): it is read for 64 KiB or 2 seconds and then closed, and `length`, `words` and `lines` are of what was read. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). Three cases end with exit 3.

- **Cut-off answers.** An answer cut off before its body ended, by a server going down or a dropped connection, is asked once more. It is never counted as a hit. The summary says how many paths still got no whole answer: `12 paths got no whole answer, after one retry: they were not judged`.
- **429 answers.** A sweep whose guesses were answered 429 says so the same way: `6 of 6 guesses were answered 429 …`. A 429 is outside the default `-mc`, so those paths were not judged.

- **Calibration that could filter nothing.** When the answers to paths that cannot exist differ in size, in word and line counts, and share no title or words either, nothing tells a wildcard answer from a path that exists, and every one is listed. The summary says so (`calibration could filter nothing in …`) and the exit is 3.

`fuzz` asks a cut-off answer once more too, then counts it as an error.

### A catch-all page that changes each time

ffuf's calibration filters one exact size, word count or line count that all its answers share. When the page changes size on every request (a nonce, a counter, a build stamp) they share none, and ffuf lists every word. `dirs` then reads what the page is, from the answers of one status: the title they all have, the tag names they use and the words they all show. An answer of that status that has the same title, uses only those tags and shows at least 80% of those words is held back as the catch-all page, and the summary counts them (`7 paths answered with the page that names that cannot exist get … and were held back`). A path that answers a page of its own (another title, other tags, other words) is listed. This needs a title or at least 3 shared words; without them the answers are listed and the exit is 3, as above. `-ac=false` lists them all.

### A catch-all inside a directory

The calibration above is of the directory the sweep starts in. A word with a slash (`api/users`, `rest/user/login`) lands in a directory the sweep did not calibrate, and that directory may answer every unknown name alike: an API that gives `500 Error: Unexpected path` for any path under `/api/`, a `/priv/` that refuses everything with the same 403. ffuf's `-ac` lists all of them, one row for each word.

When two or more hits are found in the same directory, `dirs` asks one name that cannot exist there (a random name under that directory) once the sweep is through. A hit whose answer is that control's, byte for byte (the same status and body, or the same `Location` for a redirect, once the path asked is taken out of the body), is folded: it is not listed, and the summary counts the hits of the directory in one line, with the control's URL: `folded catchall: 4 URLs of http://app/api/ answer as the control does: GET /api/k2x9 → 500, 22 bytes`. A hit that answers anything else stays listed, and so does the only hit of a directory.

- The control is a request like the others: it counts in `requests`, goes in the ledger and in `-max-requests`, and is paced by `-rate`. The cost estimate before a `run` is a floor: it says a directory two hits are found in gets one more request, and cannot say how many there will be.
- `-json` prints every row. A folded one has `"fold":"catchall"` and `"control"` (the URL of the control); the summary's `folds` lists each directory with its count and control. `results` counts the rows that are not folded.
- A path that is folded is not swept into when `-depth` asks for the directories found.
- `-ac=false` asks no control: every hit is listed. `azhaq run -dirs` folds the same hits in its map, in the line of its catch-all fold.
- Hits that answer 403 or 404 fold the same way: only when the directory's control answered them byte for byte.

## Details

### What a match is
- `length` is the whole body, as ffuf counts it, up to 64 MB.
- `words` is the number of spaces plus one, and `lines` the number of newlines plus one. Both count the whole body.
- The matchers `-ms -mw -ml -mr` and the filters `-fc -fs -fw -fl -fr` read these numbers.
- With `-mr` they read the response headers and the first MB of the body.

### A stack trace in an answer

The start of every body is checked for a runtime's stack trace as it is read: a hit whose body holds one is stored with a `stack_trace` and listed by `azhaq report -findings` as an `error-disclosure`. Nothing more is sent for it, and a page the calibration filters is not listed. The patterns are in [report](report.md#stack-traces-in-answers).

### The request
- The request is ffuf's, with no `Accept` header. An app that picks its answer by that header, such as Express's redirect body, answers with the same size as to ffuf.
- It sends `Accept-Encoding: gzip` and decodes the answer before counting.
- A `-H` of yours wins over these headers.
- The `User-Agent` is a current Chrome's, not `Fuzz Faster U Fool`. Sizes do not change with it unless the app answers by it. `-H 'User-Agent: …'` sends another.

### A blank wordlist line
- An empty line asks the base URL, as ffuf's does, and the base is judged as any word: it is not listed when it answers like a path that cannot exist (a single-page app that gives its shell for everything).
- ffuf calibrates on the size alone, so its `-ac` drops a base that answers `200` with the very page that unknown paths get with `404`. `dirs` compares the status as well, and lists that base: it answers where a missing path does not.

### A word twice
- An input that matched is a row, as in ffuf: a word that is in the wordlist twice (or two blank lines) is asked twice and listed twice, each row with its own `position`, so `results` is ffuf's count for the same list. The workspace keeps one entity for each URL, and a note says how many inputs repeated an earlier one.

### Which words are asked
- A word whose own name declares a state change is held back, from the built-in list and from a wordlist you give (`-w FILE`) alike: a path word such as `logout`, `delete`, `reset`, `create`, `populate`, … (and the same word with an extension, `logout.php`), or a query whose action parameter names one (`console?action=stop`; [the words](run.md#state-changing-requests)). Before the first request a note says how many words of the list are held and that `-send-state-changing` sends every word, as ffuf does. Each held word is a row of the summary's `state_changing` with the status `held back` and is listed under `skipped` with the flag, so no word is dropped silently; `plan` and the estimate leave them out. Each held word is also a `skipped` row of its own URL in the workspace, with the word and `-send-state-changing`, so `azhaq query -db FILE -match purge` finds it; the base URL the words were asked under is not marked. With `-depth 2` each directory found asks the list again, and a held word has a row in each; the note before the run says so. A word whose URL a `-deny-path` rule matches is not sent and is listed under `skipped` with the rule.
- A line that starts with `#` is a word like any other, as in ffuf; `-ic` ignores those lines (and a trailing ` # note`).
- With a session, the run checks it as it goes. A word that ended the session is noticed: a `-login` run signs in again, a `-cookie` or `-H` run stops with a failure and exit 3. The sweeps that ran since the last good check run again with the new session, and the note counts the words they sent: [Sessions](../CONCEPTS.md#sessions).
- `-u https://h/api/` asks `https://h/api/WORD`. A query or fragment on the URL is dropped, and a note says so.

### Words are paths
- A word is always a path below the URL, so it is encoded as a path: `#` is sent as `%23` (the word `#note` asks `/%23note`), a space as `%20` and a `%` as `%25` (`a%20b` asks `/a%2520b`). A `?` starts the query, as in ffuf (`q?a=1` asks `/q?a=1`), and in the query a space and a `#` are encoded too (`c?d e#f` asks `/c?d%20e%23f`).
- ffuf with `-u http://host/FUZZ` puts the word in the URL as written, so `#note` becomes a fragment and ffuf asks `/`. `dirs` asks the path the word names, so the rows differ from ffuf's for such a word: on a server that answers unknown paths alike, `/%23note` gets the not-found answer, which calibration filters. `-ic` drops `#` lines, as in ffuf. For ffuf's behaviour use [`fuzz`](fuzz.md), where the word goes into the URL as written.

### Proxy
- `-proxy http://127.0.0.1:8080` (or an `https://` or `socks5://` URL) sends every request through that proxy, loopback targets included: the calibration guesses and the retries too.
- Without `-proxy`, `HTTP_PROXY` and `HTTPS_PROXY` apply by Go's rule: a loopback target (`127.0.0.1`, `localhost`, `::1`) stays direct, and `NO_PROXY` keeps other hosts direct. This is the rule of every command that sends HTTP to a target: [Proxies](../CONCEPTS.md#proxies).

### Pace
- `-rate` paces every request, the calibration guesses included; ffuf sends its calibration unpaced. With `-ac=false` there are no guesses. Calibration asks 4 guesses for each directory, and one more for each extension. At a low rate a sweep takes about (guesses ÷ rate) seconds longer than ffuf's, and stays within your rate. The guesses' names are fixed for a run: `azhaq resume` asks the names the stopped sweep asked and reuses their answers, so both halves of a sweep are judged by one calibration and the resume sends none again.

## Flags

<!-- flags:begin dirs -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-u` | string, repeatable |  | web service, such as https://app.example.com/ |
| `-l` | string |  | file of services (- for stdin) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-w` | string |  | wordlist (default: SecLists' common.txt, built in: 4747 words) |
| `-ic` | bool |  | ignore the lines of the wordlist that start with # (and a trailing ' # note'), as ffuf's -ic does; without it they are asked like any word |
| `-e` | string |  | also try each word with these extensions, comma-separated (php,bak) |
| `-depth` | int | `1` | directory levels to sweep; 2 also sweeps directories found |
| `-ac` | bool | `true` | calibrate on paths that cannot exist, as ffuf's -ac does, so a catch-all answer is not listed even with a filter of your own; -ac=false sends no guesses and lists what the filters leave |

**Matchers and filters**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-mc` | string |  | report only these statuses (comma-separated, ranges, or all; default ffuf's: 200-299,301,302,307,401,403,405,500) |
| `-fc` | string |  | hide these statuses |
| `-fs` | string |  | hide these response sizes |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; HOST:PORT allows that host on that port only; with any -allow, nothing else is requested |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself) |
| `-send-state-changing` | bool |  | send the GETs whose own path or query declares a state change (create, delete, reset, logout, and the other words of the documented set; a query's action=stop and the like): a crawl's link, a script's route, an API description's operation, a word of a -dirs or -paths wordlist (ffuf sends every word). By default they are held back and listed as skipped; a target you give and -deny-path rules are not affected |
| `-kill-file` | string |  | stop all sending when this file exists, so that no request starts after it, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-seal-to` | string |  | when the run ends, append the ledger's seal as one JSON line ({"time","ledger","seal","entries"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | path guesses per second per host (0: no limit but -t, as ffuf) |
| `-t` | int | `40` | path guesses in flight per service (as ffuf) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |

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
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: workspace.db in the run's folder under ./.azhaq/runs; with AZHAQ_HOME=none a temporary one) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-o` | string |  | also write results to this file |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-strict-exit` | bool |  | exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures |

<details>
<summary>Flags familiar from ffuf and other names (8)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-fl` | string |  | hide these line counts | ffuf's name |
| `-fr` | string |  | hide answers whose headers or body match this regular expression | ffuf's name |
| `-fw` | string |  | hide these word counts | ffuf's name |
| `-ml` | string |  | report only these line counts | ffuf's name |
| `-mr` | string |  | report only answers whose headers or body match this regular expression | ffuf's name |
| `-ms` | string |  | report only these response sizes (values and ranges, 100-200) | ffuf's name |
| `-mw` | string |  | report only these word counts | ffuf's name |
| `-header` | string, repeatable |  | same as -H | other name |

</details>
<!-- flags:end -->
