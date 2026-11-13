# azhaq crawl

The URLs of an application: links, forms, scripts, routes in JavaScript, API descriptions. Replaces katana + jsluice (see [Migrating](../MIGRATING.md#katana-azhaq-crawl)).

## Synopsis

```
azhaq crawl -u URL | -l FILE | stdin | -allow NET -sweep  [-d N] [-fs rdn|fqdn|dn|REGEX] [-cs RE] [-cos RE] [-do] [-f FIELDS] [-em/-ef/-mr/-fr] [-jsonl | -json] [-hints] [-rejected] [-submit-forms] [-rl N] [-silent]
```

## Examples

```
# Crawl three link levels deep, URLs only
azhaq crawl -u https://app.example.com/ -d 3 -silent

# katana's JSON lines, for tools that read them
azhaq crawl -u https://app.example.com/ -jsonl > crawl.jsonl

# Stay on the registrable domain, list URLs found outside it, print two fields, 5 requests a second
azhaq crawl -u https://app.example.com/ -fs rdn -do -f rdn,path -rl 5

# Also the routes scripts and descriptions name that the crawl did not observe, each row marked with its class
azhaq crawl -u https://app.example.com/ -json -hints

# Load pages in Chrome in a container that gives it no sandbox (the pages are untrusted: a throwaway environment)
azhaq crawl -u https://app.example.com/ -browser -chrome-no-sandbox

# The map's rows, with the strings kept out of the URLs
azhaq crawl -u https://app.example.com/ -json -rejected
```

## What it does

1. Starts from the URLs you give and follows links to the depth `-d`: 3 link levels below the start URL by default, as katana does.
2. Reads forms, scripts and API descriptions for more URLs and routes. Library scripts are not read for routes. Every URL they give is requested, a GET operation of an API description (one that needs no path parameter and no required query parameter) and a GET form included, except one whose own path or API operation declares a state change (`/logout`, `/user/delete`, a `GET /createdb`): that one is held back, listed as skipped, and sent with `-send-state-changing`. An endpoint that resets data under another name is asked like any other. The words are the list in [State-changing requests](run.md#state-changing-requests): a GET outside it is sent. `-deny-path` keeps one out.
3. Asks only what a crawler does. The built-in path checks of `run` are off unless you add `-builtin-paths`. `-kf all`, `-kf robotstxt` or `-kf sitemapxml` asks each web service only for its `robots.txt` and sitemaps and reads every entry. `-sweep` means what it means on `run`: the IPv4 ranges and addresses `-allow` and `-scope` hold are start URLs too. A note says that the built-in paths are `-builtin-paths` when `-sweep` is given without it.
4. Tells the page every unknown path gets from a real page with one request for a path that does not exist at the root and in each top-level directory (`/api/`, `/rest/`), not in every directory: `/rest/user/` is compared with the answer of `/rest/`. A directory below the first level whose own answer to an unknown path differs from the one above it then has its generic answers listed as `visited` where they would be `catchall`. `-builtin-paths` asks every directory, as `run` does (up to 24 per origin). katana asks none.
5. Lists the URLs it requested, each distinct URL once: every page, script and stylesheet it asked, less those that answered 404 or 410 and those that answered as the control does ([Folded rows](#folded-rows) counts them in the summary; `-all-rows` lists them), and the URLs pages link to or load (anchors, forms, scripts, stylesheets), as katana lists them. A URL a page holds that the crawl did not request (past `-d`, a limit, a `-deny-path` rule, or a library script, an image or a font no step fetches) is listed too, marked `linked`, and the summary says how many.
6. Keeps apart what no page holds: routes that scripts call with POST, PUT or another method, routes with a parameter, views and sockets, and strings that scripts only name. `-hints` lists them, each marked with its class; the summary counts them apart.
7. Never drops links without a word: the summary says how many it folded, left out of the list, kept out of the URLs or found outside the scope. When a limit stops the crawl, it exits 4 and `azhaq resume` continues it.

## Output

`crawl` prints one URL per line: the URLs it requested that answer for themselves, and the URLs pages link to or load, pages, scripts and stylesheets. The URLs that answered 404 or 410 or as the control does are [folded](#folded-rows) into the summary; `-all-rows` prints them. `-hints` adds the routes no page holds; `-assets` adds the images, fonts and media that pages load, which katana's default list leaves out. [What is listed](#what-is-listed) says what that includes.

Every row has a class, and `-json` prints it as `class`:

| Class | The row is |
| --- | --- |
| `observed` | A URL the crawl requested: it got an answer or an error, or Chrome sent the request. |
| `linked` | A URL a page links or loads that the crawl did not request: it is past `-d`, a limit stopped the crawl, or a `-deny-path` rule keeps it out. Library scripts, images, fonts and media that pages load are `linked` too, as no crawl step requests them. |
| `hint` | A route a script, a description or the app's router says exists, that no GET observed: a route with a parameter (`/api/Cards/{id}`), a view or a socket, or a route given a method other than GET. |
| `named` | A URL a script or a description names and the crawl did not ask for, or one only scripts name, with no call to say how it is used (its GET fails). |

Plain output and `-json` list the `observed` and `linked` rows; `-hints` adds the `hint` and `named` ones. A `linked` row is a URL a page holds, as katana lists it, but the crawl did not ask it: it may answer 404, and the row says so by its class. The summary's `counts` has `observed routes`, `linked routes`, `hint routes` and `named strings`, which add up to every URL row, and a note says exactly how many of the listed URLs are `linked` (`-silent` prints it on stderr too). Filter them with `-json`: `jq 'select(.class=="observed")'`. A page that holds hundreds of script strings does not bury the URLs the crawl saw: those strings are `named` and wait for `-hints`. The images, fonts and media an explicit `-assets`, `-ndef` or `-em` asks for are listed as `linked` rows, requested or not.

- `-json` prints one object per row, with the map's fields and its `class`, and `fold` on a row the text list folds. `-jsonl` prints katana's lines instead.
- `-rejected` adds the strings that were kept out of the URLs, with the reason.
- `-f`, `-ot` and `-sf` print katana's field output ([Field output](#field-output)).

| Flag | Output |
| --- | --- |
| `-json` | One object per row: `url`, `class`, `coverage`, `role`, `status`, `methods`, `params`, `forms`, `found_in` and `tech` on a page. See below. |
| `-hints` | Also the `hint` and `named` rows, which are left out by default. See [Output](#output). |
| `-jsonl` (`-j`) | katana's lines, with a `request` and a `response`. See [Katana lines](#katana-lines). |
| `-f url,path,…` | Katana's URL fields, and `method`. See [Field output](#field-output). |
| `-rejected` | The strings kept out of the URLs, each with its reason. See [Rejected strings](#rejected-strings). |
| `-do` | The URLs found outside the crawl's scope, never asked. See [Links outside the scope](#links-outside-the-scope). |
| `-sr` | Each answer, written to `-srd DIR`. See [Saved responses](#saved-responses). |

The fields of a `-json` row are the map row's. [run](run.md#output) defines them. A view or a socket also has `guard`, `protocol` and `namespace`.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). The summary of a crawl:

- counts the rejected strings and the links outside the scope;
- names a host that answered 429 or 503, and what was done about it;
- counts the rows by class, `observed routes`, `linked routes`, `hint routes` and `named strings`, says how many listed URLs are `linked` (links or loads a page holds that the crawl did not request), and how many hints and named URLs were left out of the list (`-hints` lists them);
- with `-hints`, counts both kinds of listed URL, and says where to look: routes that scripts call with other methods, and strings that scripts only name;
- counts what the rows are, apart: see [What the counts compare](#what-the-counts-compare);
- says how many POST forms `-submit-forms` sent, and which POST forms it did not send and why.

A crawl never drops links without a word: the summary says what became of them (`-silent` prints the notes on the list, and not the ones on rejected strings and on links outside the scope). When `-max-items`, `-max-requests`, `-mdp` or the run's `-timeout` stops it, the run exits 4 and `azhaq resume` continues it.

## Details

### What is listed

- One URL per line: every page and script the crawl asked and whose answer is its own, and every URL a page links or loads that it did not, each distinct URL once. The folded rows are left out ([Folded rows](#folded-rows)); `-all-rows` lists them. The routes only scripts and descriptions name, and the hints, are left out unless `-hints` is given. The summary says how many URLs it listed that the crawl never requested, and how many hints and named URLs it left out (with `-silent` too: one line each on stderr, `N listed URLs are links or loads a page holds that the crawl did not request …` and `N hints and M named URLs were left out of the list`, and in the `-json` summary's notes).
- A link's URL with its query is its own line: `/item?id=7`. A route a script names, `/catalog?category=Gin` in an object on `/catalog`, is a line when the crawl asked for it: at `-d 2` it is requested, so it is `observed`; past the depth it is not requested, so it is `named` and `-hints` lists it. A link is a line either way: at `-d 1` the links of the pages at depth 1 are not requested, katana prints them with `"error":"max depth reached"` and no response, and azhaq lists them as `linked` rows.
- `-per-template N` limits how many URLs of one template (`/item?id={n}`) are asked, not how many are listed. `crawl` and `run` ask every one by default, as katana does, and neither caps the tasks a run starts unless `-max-items` says so. `-iqp` asks one URL for each path.
- Every script a page loads or a script imports is listed once the crawl has requested it, when it is in the crawl's scope. Examples are `/main.js` and a lazy `chunk-*.js`. A stylesheet a page loads (`<link rel=stylesheet>`) is requested, as a browser and katana do: a GET, in scope, paced and counted like the rest. It is an `observed` row in the default list, and the URLs it names with `url()` and `@import` are listed: an imported stylesheet is requested too, one level further down as a link is, and an image or font it names is `linked`. A library script (`jquery-3.2.1.min.js`, `bootstrap.min.js`, which azhaq does not read for routes) and an image or font a page loads are requested by no crawl step, so the library is a `linked` row in the default list; images, fonts and media are on katana's default extension list and wait for `-assets`.
- `-json` is the map's rows, the observed and linked ones, each with its `class`. The extension list leaves out only the images, fonts and media of it (`-assets` lists them): the `.pdf` and `.txt` URLs are rows. Its script and stylesheet rows are there by default.
- `run`'s map lists every row, scripts and images included.
- Views (`client-route`) and sockets (`websocket`) are `hint` rows, listed with `-json -hints` only, as routes with a parameter are. No GET gets them.

### Folded rows

The plain list holds the URLs that answer for themselves. The summary counts the others in a line of their class each, with what each class was measured against, and `-all-rows` lists every row as katana does (`-json` lists every row, a folded one marked `fold`):

- `catchall`: URLs whose answer is the control's own page, equal byte for byte once the requested path is taken out of both (a page that only has its shape, such as an item page that prints its own number, stays listed), the request for a path that cannot exist at the root or in a top-level directory. The line has the control's answer (`GET /xq3 → 200 text/html, 3748 bytes, "OWASP Juice Shop"`).
- `not-found`: URLs the crawl requested and the server answered 404 or 410, with their templates (`/api/Feedbacks/{n} ×12`).
- `beyond-depth`: images, fonts and media a page holds that no step requested. `-assets`, `-ndef` and `-em` list them, as they ask for them.

A URL a script or a description names stays out of the list unless `-hints` lists it, and is not folded then. The counts `folded catchall`, `folded not-found` and `folded beyond-depth` are the rows each class left out of the list; the rest of `counts` is of the rows printed, and the summary's `folds` says the same as `-json`'s. `-no-catchall` leaves the catch-all rows out of every view. A script address a single-page app answers with its shell page is one of them (`-browser` run too), with the control it matched.

### What the counts compare

A crawl's rows are not all URLs that were requested, so the number of rows is no number to set beside katana's. The summary's `counts` sort every URL row of the crawl's scope:

| Count | Rows |
| --- | --- |
| `requested` | URLs the crawl sent a request for, whatever the answer. These are katana's records, scripts and stylesheets included. |
| `answered` | Of `requested`, those that got an answer, a 404 too. The others failed with no answer. |
| `not requested` | URLs found in a page, a script or an API description and not asked: a linked URL past `-d` or a limit, a library script, image or font no step fetches, a hint, or a URL a `-deny-path` rule kept out. A GET operation of a description that needs no path parameter and no required query parameter is not among them unless a rule kept it out: it is requested. |
| `templates` | Routes with a placeholder, `/api/Cards/{id}`: never requested as written. |
| `observed routes`, `linked routes`, `hint routes`, `named strings` | The same rows by class: see [Output](#output). They add up to every URL row. |
| `assets` | Images, fonts, media, source maps and build manifests, requested or not. Each is also one of the three above. |
| `left out by the extension list` | Rows the default extension list (and, in the text list, `.pdf`, `.txt` and the like) kept out of the printed rows. The class counts include them. `-assets` lists the images, fonts, media, source maps and manifests, and `-ndef` all of them. The summary has a note with the number. |
| `folded catchall`, `folded not-found`, `folded beyond-depth` | Rows the default list folds (see [Folded rows](#folded-rows)); `-all-rows` lists them. The class counts include them. |
| `left out by -em, -ef, -mr, -fr` | Rows the filters the user gave kept out of the printed rows. |
| `left out as not URLs` | Plain output only: routes with a parameter, views the app draws and sockets, which no GET asks, kept out of the list with `-hints`. `-json` lists them. The summary has a note with the number. |
| `rejected strings` | Strings read from scripts and pages and kept out of the URLs, each with a reason. They are no row. `-rejected` lists them. |

`requested`, `not requested` and `templates` add up to every URL row. So do the four class counts. The rows printed and the rows left out add up to them too, and a crawl whose counts do not add up to its rows ends with exit 1 and an internal error instead of a complete summary. The rows printed with `-json -hints` are those, less the rows the extension list and the filters left out, which the two `left out` counts give: on a page with a stylesheet, an image and a link, `results` is the class counts less `left out by the extension list` (the image). The older counts, `visited` and `hint`, are of the rows that were printed, after the filters; a printed `linked` row counts under `hint`, its coverage. The note says how many printed rows are `linked`.

Which rows plain output prints, and so `-silent` too: the `observed` and `linked` rows, scripts and stylesheets included, less the default extension list (images, fonts, archives, media, `.pdf`, `.txt`, `.map`) unless `-assets`, `-ndef` or `-em` says otherwise. With `-hints` it also prints the `hint` and `named` rows that can be requested; templates, views and sockets are left out of plain output. `-json -hints` prints every row the extension list and the filters did not leave out, templates included, and `-rejected` adds the rejected strings as lines of their own, which the number of results counts.

To compare with katana, count the lines of `-silent`: the requested URLs and the links and loads of the pages read, past `-d` too, which katana prints as `max depth reached`. The note says how many were not requested. `-silent -hints` adds the routes only scripts name, which katana's `-jsl` lists too.

### Filters

These filters limit what is printed, not what is crawled.

- Katana's default list is left out: images, fonts, archives, media, `.pdf`, `.txt` and `.map`.
- `-ndef` keeps them. `-ef php,bak` adds to the list.
- `-em php,html` lists only those extensions. `none` stands for URLs without one.
- `-mr` and `-fr` match the printed URL by regex.
- `-assets` brings back the images, fonts and media a page loads (listed as `linked`: no step requests them). It also lists the source maps and build manifests azhaq reads, which no page names. Scripts and stylesheets are in the default list.

### Forms

- Every form is a `forms` entry of its page: `method`, `action`, `enctype`, `fields`, `files`.
- A GET form is asked once with neutral values in its fields, by default. A GET form can delete or log out: it is asked like any link, and `-deny-path` keeps its action out. Hidden fields, ticked boxes and selects get the page's own values. Text gets `azhaq`, an email gets `azhaq@example.org`, and a number gets `1`. `-no-form-fill` does not fill GET forms.
- A POST form is sent only with `-submit-forms`, with the same values, urlencoded. It changes data on the target.
- Each submission is one request of the budget and the pace, and is in the ledger. It is held to `-allow`, `-deny` and the crawl's scope. The same action with the same values is sent once.
- A POST form is not sent when it uploads a file (`multipart`), has nothing to send, posts outside the crawl's scope, or its address matches a `-deny-path` rule. Its name decides nothing.
- A form whose action is empty or `#` submits to its own page: its `action` is the page's URL, and it is handled like any other. See [run](run.md#forms).
- The summary says how many POST forms were sent, and names each one that was not and why, such as `a POST form to /upload was not submitted: it uploads a file or has nothing to send`.

### Routes called with other methods

- Routes that a script calls with POST, PUT or another method are `hint` rows, listed with `-hints` as katana lists them: `/snippets/fixes`, `/logger`.
- They are not pages. A GET may answer 404 or 405.
- `-json` rows carry `methods` (`["POST"]`) and a `proof`: `GET answers 404; called with POST`.
- In plain output, `-ot '{{method}} {{url}}'` or `-f method,url` prints the methods. A route gets one line for each method. A page that no script calls another way gets `GET`.
- A string that a script only names, with no call, is a `named` row when a GET fails. Its `proof` is `GET answers 404; found only in scripts, method unknown`.
- Library scripts are not read for routes: `react`, `jquery` and `angular`, also under a versioned name such as `angular_1-7-7.js`.

### Katana lines

`-jsonl` (`-j`) prints katana's line:

```json
{"timestamp", "request": {"method", "endpoint", "tag", "attribute", "source"},
 "response": {"status_code", "technologies", "forms": [{"method", "action", "enctype", "parameters"}], "content_length"},
 "error"}
```

- `tag` and `attribute` say where the URL was read: `img` `srcset`, `header` `link`, `form` `action`, `call`, `js`.
- `source` is the page.
- A URL that was found and not asked has no `response`.
- A route with other methods has a line for each.
- `azhaq ingest` reads these lines back.

### Field output

- `-f` prints these fields of the URL, as katana does: `url`, `path`, `fqdn`, `rdn`, `rurl`, `qurl`, `qpath`, `file`, `ufile`, `key`, `value`, `kv`, `dir` and `udir`.
- azhaq adds `method`: the methods the route is called with, one line each.
- `-ot '{{rdn}}{{path}}'` fills a template with the fields.
- `-sf key,dir -sfd DIR` writes the fields to `DIR/SCHEME_HOST_FIELD.txt`.
- `-lof` lists the field names.
- `-eof request.tag,tech` leaves fields out of `-json` and `-jsonl`.

### Rejected strings

- `-rejected` lists the strings read from scripts and pages and kept out of the URLs. They are never asked.
- The summary splits the crawl's `requests` by purpose (`pages`, `scripts`, `assets`, `controls`, `description checks`…): see [run](run.md#where-the-requests-go). A page already asked under another spelling of its URL is not asked again.
- The reasons include a pattern with a wildcard (a line of `robots.txt`), an expression, unquoted script code, the start of a path a script joins more to, the end of a route with a placeholder (`"/y/${id}/z.php"` and `"/y/"+id+"/z.php"` make no request for `/z.php`), a route a script's client asks under its declared base, and a key of a module map or a case label (`{"./components/locale/zh_CN": 1}` in a bundle is a module id, not a route; nor is a string that is only the key of an object whose value is a function).
- Text output is `string`, a tab, and the reason.
- `-json` output is `{"rejected", "reason", "url", "source", "via"}`. `url` is what the string makes against the page.

### Links outside the scope

- `-do` lists the URLs found outside the crawl's scope. They are never asked.
- A link to another port of a host that `-allow HOST:PORT` lists with one port is outside the scope too: it is no row of the output, `-do` lists it, and the summary's `skipped` names it.
- With no `-allow` and no `-scope`, `-u http://HOST:PORT/` holds the host to that port the same way: a link or a script's URL to another port of HOST is outside the scope, whatever `-fs` says, and the summary's `skipped` names it with the reason `outside the scope: the targets name this host with another port only`. A URL on the scheme's default port (`-u https://HOST/`) holds the host to 80 and 443.
- Text output is the URL.
- `-json` output is `{"url", "coverage":"out-of-scope", "source", "tag", "attribute"}`.

### Saved responses

- `-sr` writes each answer to `-srd DIR` (`katana_response`) as `HOST/SHA1.txt`.
- A file holds the URL, the request line, the status line, the headers and the body. `-ob` leaves the body out.
- `DIR` also gets an `index.txt`.

## Flags

<!-- flags:begin crawl -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-u` | string, repeatable |  | start URL (repeatable, or comma-separated) |
| `-l` | string |  | file of start URLs (- for stdin) |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-d` | int | `-1` | katana's -d: link levels below the start URL to visit (3 by default); -depth N is -d N-1 |
| `-paths` | string |  | extra path wordlist (one path per line) |
| `-builtin-paths` | bool |  | also ask each web service for the 51 built-in paths (robots.txt, sitemaps, API descriptions, .git/HEAD, admin, …) and for the source map next to each script, as run does; crawl asks only what a crawler does |
| `-no-form-fill` | bool |  | do not ask the action of GET forms with neutral values (by default each is asked, unless its action's own path declares a state change: it is held back, and -send-state-changing sends it; -deny-path keeps its action out) |
| `-per-template` | int |  | URLs of one template (/product?id={n}) to request; the rest are listed (default: all) |
| `-no-follow` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-no-map-guess` | bool |  | do not ask for main.js.map next to a script that names no source map (a map a script or a header names is still read) |
| `-browser` | bool |  | also load pages in Chrome: the requests their scripts send and the links of the rendered page (needs Chrome) |
| `-interact` | bool |  | with -browser: click the buttons, links and menus of each page (up to -interact-clicks) to find what only a click brings; a click is made whatever its label says, and the writes it would send are refused by their method and mapped, not sent |
| `-interact-clicks` | int | `12` | clicks -interact makes on each page |
| `-fs` | string |  | the hosts a crawl follows links to: rdn (the start host's registrable domain and its subdomains), fqdn (the host only), dn (hosts that name its domain keyword) or a regex on the host (default: rdn for a name, the origin itself for an address) |
| `-kf` | string |  | ask each web service only for its robots.txt and sitemaps and read every entry (all, robotstxt or sitemapxml); replaces the 51 built-in paths |

**What to list**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-assets` | bool |  | also list the images, fonts and media pages load (listed as linked: the crawl does not request them), and the source maps and build manifests azhaq reads (scripts and stylesheets are listed by default, as katana lists them) |
| `-hints` | bool |  | also list the hints (routes with a parameter, views and sockets, routes scripts or descriptions give a method other than GET) and the named URLs (named by scripts or descriptions, or only in scripts); by default the URLs the crawl requested and the URLs pages link to or load are listed |
| `-no-catchall` | bool |  | leave out URLs that answer with the page every unknown path gets (client-side routes of a single-page app) |
| `-all-rows` | bool |  | list every row, as katana does: by default the rows that answer as the control request for a path that cannot exist does, the 404s and the assets no request asked for are counted in the summary in one line of their class each (-json lists every row with its fold class) |
| `-rejected` | bool |  | also list the strings read from scripts and pages and kept out of the URLs, each with its reason (text: string, a tab, the reason; -json: one object each) |
| `-em` | string |  | list only URLs with these extensions, comma-separated (none: URLs without one) |
| `-ndef` | bool |  | do not leave out the default extensions |
| `-do` | bool |  | also list the URLs found and left out of the crawl's scope (never requested) |

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
| `-submit-forms` | bool |  | also submit POST forms with neutral values (crawl): CHANGES DATA on the target, each submission counts as a request and is in the ledger, the summary says how many; held to -allow, -deny and the crawl's scope |
| `-browser-writes` | bool |  | let pages in Chrome send their writes (POST, PUT, DELETE…, beacons, forms posted on load) as a user's browser would: they change data on the target; by default Chrome sends only GET, HEAD and OPTIONS, and the request that signs in, and maps the writes it does not send |
| `-chrome-no-sandbox` | bool |  | let Chrome run without its sandbox where the system gives it none (no user namespaces, AppArmor, a container): it is started once more without, and the summary says so. The pages it loads are the targets' and untrusted: use a throwaway environment. By default Chrome does not start then |
| `-seal-to` | string |  | when the run ends, append the ledger's seal as one JSON line ({"time","ledger","seal","entries"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rl` | float |  | requests, port connects, UDP datagrams and DNS queries to the targets' name servers per second, over all hosts (0: no pace) |
| `-delay` | duration |  | pause before each uncached fetch |
| `-backoff` | bool |  | when a host answers 429 or 503, wait (1 s doubling to 30 s, or its Retry-After) and ask again, up to 3 times; the summary says which hosts did |
| `-retry` | int |  | ask again this many times when a host that answered before gives no answer (a timeout, a reset) |
| `-host-rate` | float |  | requests per second to each host, besides -rate over all (0: none) |
| `-hrl` | int |  | requests per second to each host (katana's -hrl) |
| `-host-parallel` | int |  | requests in flight per host (default 10, as katana) |
| `-parallel` | int |  | work items in flight (default 16) |
| `-request-timeout` | duration |  | time one request gets, headers and body (default: 10 s for headers, 30 s in all; not -timeout, the run's bound) |
| `-ct` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-max-host-requests` | int |  | requests one host may be sent (0: no cap); the rest of its work is left for azhaq resume |
| `-host-guesses` | int |  | most guesses one host is sent (0: no cap): requests for the built-in paths, a -dirs or -params wordlist or GraphQL field names; the rest are not asked and the summary lists them, the run exits 4 and azhaq resume asks them with a larger value |
| `-max-items` | int |  | most collector tasks (a name, a URL, an address each, per collector) this run starts (default: no cap, katana's and httpx's); the work left is for azhaq resume, which starts as many more |
| `-max-response-size` | int |  | bytes read of a page or document (default 2097152; scripts and JSON get 16 MiB) |

**Session and network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-cookie-jar` | bool |  | carry the cookies targets set (Set-Cookie) on the requests that follow, as a browser does; -cookie and -H values go first |
| `-login` | string |  | sign in on this page with Chrome before the run; its cookies and token go with every request (needs -login-user and -login-pass) |
| `-login-user` | string |  | user name or email for -login |
| `-login-pass` | string |  | password for -login (default $AZHAQ_LOGIN_PASS) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY, except for loopback targets, which stay direct) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: workspace.db in the run's folder under ./.azhaq/runs; with AZHAQ_HOME=none a temporary one) |
| `-o` | string |  | also write results to this file |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-jsonl` | bool |  | katana's JSON lines: {timestamp, request{method, endpoint, tag, attribute, source}, response{status_code, technologies, forms, content_length}, error} |
| `-f` | string |  | print these fields of each URL instead of the URL, comma-separated: url,path,fqdn,rdn,rurl,qurl,qpath,file,ufile,key,value,kv,dir,udir,method (katana's -f) |
| `-ot` | string |  | print each URL through this template, {{url}} or any field name in braces ({{rdn}} {{path}} …) |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-strict-exit` | bool |  | exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures |

<details>
<summary>Flags familiar from katana, other names and flags accepted with no effect (38)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-cos` | string, repeatable |  | never follow URLs that match this regex | katana's name |
| `-cs` | string, repeatable |  | follow only URLs that match this regex | katana's name |
| `-depth` | int | `4` | max fan-out waves (0 = seed wave only, not unlimited) | katana's name |
| `-ef` | string |  | leave out URLs with these extensions, comma-separated, besides the default list (images, fonts, archives, media, .pdf, .txt, .map, …) | katana's name |
| `-eof` | string |  | leave these fields out of -json and -jsonl lines, comma-separated (request.tag, response.forms, tech, …) | katana's name |
| `-fr` | string |  | leave out URLs that match this regex (printed URLs only) | katana's name |
| `-hrlm` | int |  | requests per minute to each host (katana's -hrlm) | katana's name |
| `-iqp` | bool |  | ask one URL of each path whatever its query values (katana's -iqp; the others are listed) | katana's name |
| `-lof` | bool |  | list the fields -f, -sf and -ot take, and the fields of -jsonl lines, and exit | katana's name |
| `-mdp` | int |  | requests one host may be sent, then its work is left for resume (katana's -mdp) | katana's name |
| `-mr` | string |  | list only URLs that match this regex (regex of the printed URL; the crawl itself is not limited) | katana's name |
| `-mrs` | int |  | bytes read of a page (katana's -mrs; default 2 MiB, scripts and JSON 16 MiB) | katana's name |
| `-ns` | bool |  | follow links to any host, within -allow and -deny (katana's -ns) | katana's name |
| `-ob` | bool |  | with -sr: write the status line and headers only | katana's name |
| `-path-climb` | bool |  | also list and ask the parent directories of each link a page names (/a/b/c: /a/b/ and /a/) | katana's name |
| `-rd` | int |  | seconds to wait before each request (katana's -rd) | katana's name |
| `-rlm` | int |  | requests per minute over all hosts (katana's -rlm) | katana's name |
| `-sf` | string |  | also write these fields, one file each, to the -sfd directory: katana_field/SCHEME_HOST_FIELD.txt | katana's name |
| `-sfd` | string | `katana_field` | directory for -sf | katana's name |
| `-sr` | bool |  | also write each answer kept in the workspace to the -srd directory, DIR/HOST/SHA1.txt, with an index.txt (katana's -sr) | katana's name |
| `-srd` | string | `katana_response` | directory for -sr | katana's name |
| `-c` | int |  | requests in flight per host (default 10, as katana) | other name |
| `-dr` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) | other name |
| `-header` | string, repeatable |  | same as -H | other name |
| `-j` | bool |  | same as -jsonl | other name |
| `-p` | int |  | work items in flight (default 16) | other name |
| `-pc` | bool |  | same as -path-climb (katana's -pc) | other name |
| `-r` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked | other name |
| `-rate` | float |  | requests, port connects, UDP datagrams and DNS queries to the targets' name servers per second, over all hosts (0: no pace) | other name |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) | other name |
| `-duc` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies | accepted, no effect |
| `-fx` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies | accepted, no effect |
| `-jc` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies | accepted, no effect |
| `-jsl` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies | accepted, no effect |
| `-kb` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies | accepted, no effect |
| `-nc` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies | accepted, no effect |
| `-s` | string |  | accepted for katana's command lines; azhaq orders its work by worth within a host, not by -s depth-first or breadth-first | accepted, no effect |
| `-td` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies | accepted, no effect |

</details>
<!-- flags:end -->
