# azhaq subs

Lists the subdomains of a domain from passive sources. Replaces subfinder (see [Migrating](../MIGRATING.md#subfinder-azhaq-subs)).

## Synopsis

```
azhaq subs -d DOMAIN | -dL FILE | stdin  [-live] [-http] [-json] [-silent] [-o FILE] [-db FILE] [-m GLOB | -f GLOB | -match-regex RE | -filter-regex RE] [-source-rate N] [-ls]
```

## Examples

```
# every subdomain the passive sources know
azhaq subs -d example.com

# only names that resolve, as JSON, kept in a workspace
azhaq subs -d example.com -live -json -db example.db

# two domains, live names under dev only, DNS at 10 queries a second, sources at 2 a second
azhaq subs -d example.com,example.org -live -dns-rate 10 -source-rate 2 -m '*.dev.example.com'

# list the sources and the key each wants, as JSON
azhaq subs -ls -json
```

## What it does

1. Takes domains from `-d`, `-dL` or stdin. `-d` takes a comma list, a URL, or a name with a trailing dot or `*.`. An IP address given as a domain is left out, with a note.
2. Asks each passive source for names below the domain. The name history of earlier runs is read as one more source.
3. With `-live`, looks the names up in DNS and keeps those that resolve, with wildcard answers left out. Without `-live` nothing is looked up, and every name the sources gave is printed as a candidate: see [Tiers](#tiers). `-guesses=false` holds back the names only subdomain.center guessed.
4. With `-w WORDS` or `-permute`, also resolves guesses. That is active DNS, and the names found are live.
5. With `-http`, asks each live name's web service one request (`GET /`) and marks the names that answered.
6. Prints each name once, then the summary with its counts and a coverage estimate for each tier.

With `-db` the requests and queries go in `DB.ledger.jsonl`; without it, in the file `-ledger FILE` names, and nowhere otherwise. `azhaq mcp` gives `azhaq_subdomains` calls with no workspace one of its own.

## Output

Plain output is one name per line, as subfinder prints it. The domain you give is not printed, because subfinder keeps only the names below it. `-o` appends to a file. With `-json` you get one object per name, with subfinder's fields and azhaq's. The summary's counts add up to the names printed: see [What became of the names](#what-became-of-the-names).

| Flag | Each line is |
| --- | --- |
| `-cs` | `host,[source,source]` |
| `-live -oI` | `host,ip,source` |
| `-oD DIR` | also writes `DIR/DOMAIN.txt` for each domain, `.json` with `-json` |

| Field | Meaning |
| --- | --- |
| `host` | The name. |
| `input` | The domain you gave. |
| `source` | The first source that gave the name. |
| `sources` | Every source that gave it, with the special values below. |
| `tier` | `candidate` on a name no lookup has confirmed (without `-live`), `dns` on a name a DNS lookup confirmed (`-live`, and the names `-w` and `-permute` found), `http` on one that also answered a request. See [Tiers](#tiers). |
| `unverified` | `true` on a name no source asserted and no DNS lookup checked: one only the name history held, or one only subdomain.center guessed. See [Name history](#name-history) and [Guesses](#guesses). |
| `wildcard_certificate` | `true` on a name a certificate gave as `*.name`. |
| `a`, `aaaa` | With `-live`, the addresses, also those the name's CNAME chain ends in. |
| `cname` | With `-live`, the chain. |
| `cdn` | With `-live`, the CDN or WAF in front. |
| `ip` | With `-live -oI`. |
| `cname_only` | With `-live`, `true` on a name that is a CNAME whose chain ends without an address (`a` is empty). It exists in DNS; one whose target is gone is a takeover lead. |
| `takeover` | `service`, `target`, `evidence` and `strength`, on a name that is a takeover candidate: a CNAME to what is gone, or a page that names an unclaimed service. |

`sources` holds the names of the sources, and these values:

- `dns-brute` or `permute` for a name found by `-w` or `-permute`.
- `history` for a name an earlier run kept: see [Name history](#name-history).
- `cname` for a live name DNS met as another name's CNAME target.

Every takeover candidate is also in the summary, under `takeover`, with `host`, `service`, `target`, `evidence` and `strength`. With `-live`, a name whose CNAME chain ends without an address (a CNAME to a deleted service or domain) is listed like the others, as `dnsx -a -cname` lists it. It has `"cname_only": true` and no `a`, it is counted as `CNAME only`, and a note names how many there are. The summary's `takeover` list and the `[takeover] …` line on stderr carry it when its target is gone.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). These points are specific to `subs`. The counts themselves are in [Details](#details).

- The summary has `degraded` when `sources failed` is above 0.
- Names past `-max-names` are left out, and the run ends with exit 3. Guesses past a `-max-names` you gave are not asked, and the run ends with exit 4.
- With `-live`, names every resolver failed on (a timeout, a REFUSED) are left out as `no answer`, and the run ends with exit 3. A note names the resolver, how many names and why: `no answer from 8.8.8.8 for 512 names (timed out)`. They are not counted as `did not resolve`: the name may well exist.
- A signal (Ctrl-C, SIGTERM, SIGHUP), `-timeout` or `-max-time` while names wait for DNS stops the run: exit 4, `complete` false, `stopped` says why (`-max-time 25s reached with N tasks known and not done`). The names DNS had answered before the stop are kept and listed; the names it had not answered are counted as `not asked`, and `azhaq resume` asks only those.
- A source that answered 200 with an error and gave no names is a failed source: see [Failed sources](#failed-sources).
- `subs` ends with a `coverage:` note: see [Coverage estimate](#coverage-estimate).
- Without `-live`, `-w` or `-permute` it ends with the wider pass as its first `next:` line: `azhaq subs … -live   (next pass, not run: N names listed by the sources were not looked up, so some may not exist; -live asks about 2N DNS queries)`. The count is two queries (A and AAAA) for each name listed, before the retries and wildcard probes. It is a line: nothing is looked up for it. Like the other `next:` lines of `subs` it is for a person at a terminal: it is not in `-json`, and `AZHAQ_NO_HINTS` hides it.

## Details

### Sources in the summary
`counts` says how many sources were asked:

| Count | Meaning |
| --- | --- |
| `sources asked` | Passive sources that ran for the domains given. Not counted: skipped sources, such as a keyed one with no key, and `history`. |
| `sources answered` | Sources that returned without an error. |
| `sources failed` | Failures of sources in the default set, or named with `-sources`. |
| `off-by-default failed` | Failures of sources that ran only because of `-all-sources`. |

`sources asked` is `sources answered` plus `sources failed` plus `off-by-default failed`.

### The sources block
- `asked`, `answered`, `failed` and `off_by_default_failed` count each source once for each domain, as `counts` does.
- `failed` counts sources in the default set, or named with `-sources`. `off_by_default_failed` counts sources that ran only because of `-all-sources`.
- `asked` is `answered` plus `failed` plus `off_by_default_failed`. A source skipped for want of a key is not asked.
- `names` is what each source gave, before any DNS check or filter. For `urls` the field is `urls`: see [urls](urls.md#summary-and-exit-codes).
- `requests` is what each source was sent, retries included, summed over the domains. The summary's top-level `requests` leaves them out: they go to third parties, not to targets.
- `seconds` is how long each source took, the longest over the domains. The slowest source set the run's time. crt.sh is asked in its public PostgreSQL first, as subfinder does, and in its JSON API only when the database fails or has no names (a 500, 502, 503 or 504 of the JSON API is asked again up to 4 times, with a pause that doubles from 1 s, as far as `-source-timeout` leaves time; not asked again once every other source has answered with names and crt.sh alone is left, since subfinder asks it once and the retry would be all the run waits for, and a note says so); a note says which happened, as in `crt.sh database: connection refused; asked the JSON API`. The limited query is cut at a quarter of `-source-timeout`, which leaves the rest for the JSON API: a large domain whose query needs longer wants a longer `-source-timeout`. The database query is limited to 10000 rows, as subfinder's is; when exactly 10000 come back the rest is asked without the limit, then from the JSON API, and the note says which path gave the names. A note names it when it held the run: `crtsh took 30 s, the next slowest source 3 s, so it held the run`.
- A source outside subfinder's default set (commoncrawl, hudsonrock, rapiddns, sitedossier, thc, waybackarchive) is waited for until every source of that set has answered, then `-extra-wait` more (5 s by default): one still running is cut, its names so far are kept, and it is a failed source whose reason says `-extra-wait`. The bound is set from the time the ones that answer take (rapiddns, thc and hudsonrock answered in 1 to 3 s on 2026-11-04) against sitedossier, which pages at 8 a minute, and waybackarchive, which waits out 429 answers. `-extra-wait 0` waits for them as long as `-source-timeout`, and a source named with `-sources` is not cut.
- `failed_sources` has each failed source's reason, such as `"wayback": "web.archive.org answered 429"`. With several domains, each reason starts with its domain.
- `dns` asks resolvers, not sources, and has no such block.

The text summary ends with the same, and says why the exit code is what it is:

```
23 of 33 sources answered, 10 failed (listed above); exit 0 because the run did its job: the names the others gave stand, and a failed source's may be missing (-strict-exit makes it 3)
```

### Degraded
- True when `sources failed` ([Sources in the summary](#sources-in-the-summary)) is above 0. A source the run relies on did not answer, so the names may be incomplete.
- The text summary opens with it, naming the sources and why: `DEGRADED: 2 of 4 sources failed: crtsh (HTTP 502, 2 domains), the names may be incomplete`. Past three sources it ends with `+N more`.
- The JSON summary has `degraded_by`: one `{"source", "error", "domains"}` for each source of the default set that failed, the one that failed for most domains first.
- The exit code is 0 while a source answered for each domain, and 3 when no source answered for a domain of a run given one, or with `-strict-exit` (also `-fail-on-errors`). A failure the other sources made up for is listed as `partial`, and the names they gave stand. Each failed source is in `failed` and counted in `failures`.
- Failures of sources that ran only because of `-all-sources` never set it on their own.

### Failed sources
- A source whose answer was an error with a 200 status is a failed source when it gave no names. Examples are hackertarget's `API count exceeded`, a JSON `{"error": …}` and a challenge page.
- Its `error` holds the server's words: `api.hackertarget.com answered 200 with an error, not names: API count exceeded - Increase Quota with Membership`.
- A source that gave names first keeps them and says so in `partial`.

### What became of the names
The counts also say what became of the names, so a reader can add them up:

| Count | Meaning |
| --- | --- |
| `from sources` | The names every source gave for the domains, with the name history and subdomain.center's guesses, before any check. |
| `raw candidates` | `from sources` less `the domain itself`: the first tier. See [Tiers](#tiers). |
| `DNS-confirmed` | With `-live`, `-w` or `-permute`: the rows a DNS lookup confirmed, those of `resolved from sources` and the ones found by guessing or as CNAME targets. The second tier. |
| `the domain itself` | The domain given, when a source returned it. It is not printed. |
| `did not resolve` | Names DNS says do not exist: guesses and history names that did not resolve, and with `-live` every other name that did not. A guess that only a wildcard answered is one of them. |
| `collected` | With `-live`: `from sources` less the domain itself and the guesses that did not resolve. |
| `resolved from sources` | With `-live`: names from sources that resolved to an address and were printed. |
| `CNAME only` | With `-live`: printed names whose CNAME chain ends without an address. They are in `results` and not taken away from it. The takeover candidates among them are in `takeover`. |
| `found as CNAME targets`, `found by guessing` | Live names no source gave: another name's CNAME target in scope, and the names of `-w` and `-permute`. |
| `asked by guessing` | The names `-w` and `-permute` asked that no source gave. `found by guessing` is what is left of them after `did not resolve` and `left out by -m/-f`. |
| `guesses held back` | With `-guesses=false` and without `-live`: names only subdomain.center guessed, which no source asserted and nothing looked up. They are not printed. See [Guesses](#guesses). |
| `unverified` | Printed names no source asserted and no DNS lookup checked, without `-live`: names only the name history held, which no source gave this run, and the names only subdomain.center guessed. |
| `not checked` | With `-live`: guessed or history names the resolvers failed on, or the run ended before it checked, left out. The note names the cause (the resolvers, or the time limit) and, with `-db`, the commands that check and list them. `azhaq resume` checks them, and a resume that checks every one ends with exit 0. |
| `no answer` | With `-live`: names every resolver failed on, left out. A note says which resolver and why. The run ends with exit 3. |
| `not asked` | With `-live`: names the run stopped before DNS answered them (the answered ones are kept). `azhaq resume` asks them. |
| `left out by -m/-f` | Names a `-m`, `-f`, `-match-regex` or `-filter-regex` removed. |
| `listed under another domain` | A name under two of the domains given, printed once. |
| `cut by -max-names` | Names past `-max-names` (default 200,000), left out. The run ends with exit 3. |
| `guesses held back by -max-names` | With a `-max-names` you gave: the `-w` words and `-permute` variations past it, which were not asked. They are no row and not in `asked by guessing`. The run ends with exit 4, and a note names the cap. |

- `subs` lists subdomains, as subfinder does, so it does not print the domain itself. `run`'s map has it as the target it is.
- `dnsx -a -cname` lists a name whose CNAME leads nowhere, and so does `subs -live`: the row says `cname_only` and the summary counts it as `CNAME only`. A tool that wants addresses only filters on an empty `a`.

The number of results is `from sources`, less some counts and plus others:

- Less: `the domain itself`, `did not resolve`, `guesses held back` (with `-guesses=false`), `not checked`, `no answer`, `not asked`, `left out by -m/-f`, `listed under another domain` and `cut by -max-names`.
- Plus: `found as CNAME targets` and `asked by guessing` (the guesses that did not resolve are in `did not resolve`).

The run prints the sum as a note:

```
count: 2638 from the sources − 2093 did not resolve − 1 not checked + 10 found as CNAME targets = 554 printed
```

With `-w`, the guesses are in it: `count: 0 from the sources + 14 asked by guessing − 2 did not resolve = 12 printed`.

### Guesses
subdomain.center answers a random sample of about 500 names per call, nearly all of them made up. A name only it gave is a guess: no source asserted it.

- Without `-live` nothing is looked up, so such a name is printed as a candidate with `"unverified": true` in `-json`: no source asserted it and nothing confirmed it, and it is among the `raw candidates` like every other name. `-guesses=false` holds them back instead: they are not printed, counted as `guesses held back`, and a note says how many. A name another source gave, or one the name history holds, is not a guess.
- An explicit `-guesses` cannot go with `-live`, which looks them up and prints the ones that resolve; the ones that do not are counted in `did not resolve`.
- Without `-live` subdomain.center is asked once, as subfinder asks it. `-guess-samples N` asks it up to N times, until the names seen are most of its estimated pool.
- With `-live` every guess of a sample is looked up at `-dns-rate`, as `subfinder | dnsx` looks up every name it is given: your rate is the bound on the cost. A guess costs one query, an A, as a brute-force word does: an NXDOMAIN is taken at its word with no second resolver and no AAAA, and a name that answers with no address (an empty non-terminal) costs an A and an AAAA. A name a source gave costs a second resolver's opinion too when you give two resolvers. A zone is probed for a wildcard only when a guess in it resolves, once, with one query when it answers NXDOMAIN.
- The first sample is always checked in full, at any rate: it is what `subfinder | dnsx` checks. A further sample is taken while the last had a new name that resolves, or while the names seen are under 95% of the pool that the samples' repeats estimate (Schnabel's estimate, which needs one repeat: so the second sample is always taken), up to 12, and only if it fits the 20 s left of the budget for further samples. The budget starts when the first sample has been checked, and a sample is expected to cost what the last one did, so at a polite `-dns-rate` the first sample can be all there is time for.
- `-guess-samples N` goes further: up to N samples while each finds a new name that resolves or the pool is not yet covered, with no time budget, and N may be above 12. `-guess-samples 1` takes the first only. Without `-live` nothing resolves, so the samples go on only while the pool is not yet covered.
- The source's row says why it stopped in `sampling_stopped` (`sampling_bounded` is `true` for a bound), with `sample_ceiling`. A note names a stop that was a bound, says how many samples were left untaken and names the flag: `subdomain.center was asked for 1 sample of its guesses … and not again: another sample would not fit the 20 s budget …; up to 11 more samples left untaken; -guess-samples N takes up to N …`. The name history keeps the names that resolved for the next run.
- Names that could not be checked (the resolvers failed, or the run ended first) are counted as `not checked` and left out; `azhaq resume` checks them.

### Per-source status
The workspace keeps a status for each source, shown by `azhaq show` and held in the `sources` payload of an `azhaq-subdomains` observation:

| Field | Meaning |
| --- | --- |
| `count` | Names the source gave. |
| `seconds` | Time the source took. |
| `calls` | Calls made to it. |
| `requests` | Requests sent, retries included. |
| `error` | The failure, in the server's words. |
| `skipped` | Why it did not run. |
| `partial` | What the source says about its own answer. Cert Spotter without a key reads the first page only. |
| `rate_limited` | Set with `retried_429`, `waited_seconds`, `retry_after_seconds` and `gave_up_429` when the source answered 429. |
| `rounds` | For subdomain.center, per call: names given, how many were new, looked up, and resolved with no other source having them, and the seconds. |
| `kept`, `dropped_unresolved`, `unverified`, `checked_seconds` | From `-live` runs, for the sources whose names are checked. |
| `sampling_stopped` | For subdomain.center: why it stopped asking for more samples. `sampling_bounded` is `true` when the reason was a bound (the most samples, the budget for further samples, or its time), not that nothing more was to be had; `sample_ceiling` is the most samples it could take. |
| `"default": false` | The source ran only because of `-all-sources`. |

A source that answered 429 is asked again after its `Retry-After`, up to three times and 30 s each. One that asks for longer, or keeps refusing, is not waited for.

### Name history
Passive sources answer differently each run. subdomain.center, for one, returns a random sample of its names on each call. So `subs` keeps what it found.

- Azhaq keeps the names of a domain that a source gave, and the names of the history itself that resolved, in `names/DOMAIN.json`. A name that only `-w` or `-permute` guessed, and a CNAME target, is not stored: those can be asked again, and the history is the memory of what passive sources answered. The directory is `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`.
- Each name has its first and last time seen (`first_seen`, `last_seen`) and the sources that gave it (`sources`).
- At most 200,000 names are kept per domain. The ones unseen the longest go first.
- The next run asks this file as a source called `history`.
- With `-live`, a stored name counts only if it resolves now, and not to a wildcard. Stale names drop out, and a name a source missed this time comes back.
- Without `-live` no DNS lookup is made. A stored name that no source gave this run is listed with `"unverified": true`, and its `source` is `history`. The names are stored only once a source gave them or DNS confirmed them, so they are not guesses.
- A stored name that a source gave again is not flagged: its `source` is that source, and `history` comes last in `sources`. Every name a source gave and a run kept is stored, so flagging them all would flag nearly every name after the first run.
- A run that read names from the file or wrote to it says so in its summary, in `subs` and in `run`: `name history /home/me/.local/share/azhaq/names/example.com.json: 303 names read, 2 written; …`. It gives the path, the names the file gave the run (before any check) and the names the run wrote (a name no lookup checked is not written). For more than three domains one note counts them all.
- `-no-history` neither reads nor writes the file, and the summary says nothing of it. A file that cannot be written is a note: `name history not saved: …`.
- A resolver check (`-live`) that was stopped leaves its names unchecked and out of the list. The summary says how many, why, and, with `-db`, the commands that check them (`azhaq resume`) and list them (`azhaq query -db FILE -type Hostname -role unresolved`: `unresolved` is a name no lookup has asked, and its `proof` says `not checked:` and why). Without `-db` there is nothing to resume, and the note says to run again with `-db FILE`, or without `-live` to list them unverified.

### Tiers
A name is in one of three tiers, and the tiers are never mixed:

| Tier | Row's `tier` | What it says | Count |
| --- | --- | --- | --- |
| Raw candidate | `candidate` | A source (or the name history) gave the name. No lookup has confirmed it. `sources` says who gave it. | `raw candidates` |
| DNS-confirmed | `dns` | A DNS lookup resolved it (an address, or a CNAME chain), with wildcard answers left out. | `DNS-confirmed` |
| HTTP-confirmed | `http` | With `-http`: it also answered a request, of any status, on the ports `-web-ports` names (443 then 80 by default). | `HTTP-confirmed` |

- Without `-live` every printed row is a `candidate`, and the summary says `DNS-confirmed not asked (-live)`: nothing is confirmed, whatever the sources think of it.
- `-http` implies `-live`, sends one `GET /` to each live name (these are requests to the names, which is why it is a flag), and marks the rows that got an answer `http`; a live name that gave none stays `dns`. `-http-proxy URL` sends these requests through a proxy (`run`'s `-proxy`). The summary says `HTTP-confirmed not asked (-http)` without it.
- With `-live` the rows are the DNS-confirmed tier. The raw candidates that did not resolve are not printed: they are in `raw candidates` and `did not resolve`, so the two counts show how many names the sources gave and how many of them exist in DNS. `raw candidates` less `did not resolve` is `resolved from sources`, which `DNS-confirmed` includes along with the names found by guessing and as CNAME targets.
- A `tiers:` note states the counts: `tiers: 526 raw candidates (what the sources gave; a row's sources say who); 6 DNS-confirmed (resolved); HTTP-confirmed not asked (-http): a candidate is never counted as confirmed`.
- The reference tool prints its raw candidates as results, and `subs` prints them too, labelled; plan from the tier you need. A subdomain.center guess is a raw candidate with `"unverified": true`.

### Coverage estimate
`subs` ends with a note for each tier, such as:

```
coverage (raw candidates): what the independent sources know, not every name that exists. Their pool holds about 1609 names and this run has 1400 of them. Apart from the pool, the other 47 of the 1447 names in this tier came from the name history, from guesses checked in DNS or as CNAME targets
```

- The estimate is made for each tier and labelled with it (`coverage (raw candidates)`, `coverage (DNS-confirmed)`): a tier's note counts only the names that reached it, so a confirmed tier's pool is the confirmed names the independent sources know. It is a Chao1 estimate over how many independent sources gave each name: S + f1²/(2·f2). Here f1 is the number of names given by one source, and f2 the number given by two. With f2 = 0 it is S + f1(f1−1)/2.
- Independent means every source except the ones that pad their answer (subdomain.center) and `history`. A name only those gave is in the output but not in the count.
- It needs two independent sources that gave names.
- The raw candidate tier counts every name the sources gave. The DNS-confirmed tier counts the live ones printed.
- It estimates what the sources know, not every name that exists, and the note says so first. It prints no percentage: 1400 of 1609 is a share of what the sources hold, not of the subdomains the domain has.
- With `-live` the names of the DNS-confirmed tier that the pool does not hold (the name history, guesses DNS confirmed, CNAME targets) are counted apart from it, and the two add up to the names printed.
- The `azhaq-subdomains` payload has `"coverage": {"observed", "estimated", "share"}` (`share` is observed over estimated: a share of the sources' pool).
- The row of a sampled source (subdomain.center) in `sources` has `"population_estimate"`, a Schnabel estimate of how many names one call draws from. It is there when its rounds repeated names.

### Flags that follow subfinder
- [Migrating](../MIGRATING.md#subfinder-azhaq-subs) maps subfinder's flags to azhaq's, including the rates, `-max-results`, `-max-time`, `-max-body` and `-proxy`.
- `-m`, `-f`, `-match-regex` and `-filter-regex` filter the names.
- `-ls` lists the sources with their key requirement. With `-json` it prints one object for each.
- `-recursive` runs only the sources that handle subdomains of subdomains.
- `-max-names` is a different limit here than in `run`: names kept for each domain, 200,000 by default. In `run` it is the hostnames resolved, 200,000 by default. A value you give also caps the names `-w` and `-permute` ask, together, first the words and then the variations: the guesses past it are not asked, so `asked by guessing` is at most the cap, the run exits 4, `stopped` names `-max-names`, and a note says how many guesses it held back. Without it, a guess list has no cap: the cap's default is for the names looked up, never for a wordlist.
- A SOCKS5 `-proxy` carries crt.sh's database connection too. An HTTP proxy cannot, so crt.sh is then asked in the JSON API only, and a note says so.
- A source that needs a key and has none is not run. Its status says `skipped: needs a key`, and `-ls` marks it with `*`.
- `-stats` prints each source's requests, names and errors. `-version` prints the version.
- A source's key may also come from `$SOURCE_API_KEY`, or `$VAR` in the provider file.
- `-sources` with a name that is no source says so. `azhaq subs -ls` lists the real ones.

### `-live` and its time
- subdomain.center answers a random 500 names per call, most of them made up.
- Without a key it is asked again while its last round gave a name that resolves and no other source had, or while the names seen are not yet most of its pool: see [Guesses](#guesses).
- The next round is asked while the last round's new names are looked up, so a round costs the longer of the two. When a round adds no live name, the call already made ahead is dropped, and the source's `calls` counts it. No name is looked up twice.
- `-max-time` bounds the whole run, this source's rounds and the lookups of its guesses too: when it passes, the names gathered are kept, the ones whose lookup was cut are counted as `not checked`, and its row says the run's time limit cut it short. `-source-timeout` bounds each of its calls and, with them, half the time it spends asking; the lookups of its guesses are paced by `-dns-rate`, not by `-source-timeout`.
- `-max-time` is the whole run's wall-clock bound, as `-timeout` is, and the shorter of the two applies: the sources, subdomain.center's rounds, and the DNS checks of `-live`, `-w` and `-permute` all end with it. The run exits 4, `stopped` names `-max-time`, a note counts the names not asked in DNS, and `azhaq resume` asks them. subfinder's `-max-time` bounds only the enumeration.
- How many samples are taken is in [Guesses](#guesses).
- A lookup waits 3 s for an answer, as dnsx does, and is asked again on another resolver when it times out. A name that a source gave is asked up to 3 times. A generated name (a guess of subdomain.center, `-w`, `-permute`, a name only the history held) is asked up to 2 times, as dnsx's `-retry` default: made-up names mostly do not exist, and each attempt of a name no resolver answers is a paced query, so a third is 50% more time on a zone whose servers are silent. `azhaq dns -retry N` sets the attempts for every name, generated ones too. Resolvers that fail take turns: each is asked in its turn, so `-dns-rate` is the pace of each, not of one. Without `-dns-rate` a late attempt is also hedged: another is sent beside it and the first answer wins. With `-dns-rate` nothing is hedged, because a hedge spends a slot of your rate on every answer that is merely slow: a zone that answers in 1.2 s costs one query a guess.
- A name that no resolver answered in its attempts is asked again in a second pass at a quarter of the concurrency. When none of a batch of 16 names or more was answered, the resolvers are down, not busy, and there is no second pass. The second pass asks 16 of those names first, spread over the list and once each, and ends there when none of them is answered: the zone's servers are not answering, the rest would fail alike at the cost of every attempt again, and they keep the first failure (`no answer`, or `not checked` for a guess). When one is answered, every name still failed is asked in full. On a stand-in zone whose servers left 65% of 200 names unanswered, with `-dns-rate 10` and two resolvers, `subs -live` took 25 s and `subfinder | dnsx -rl 10` 26 s, for the same names found (130 unanswered, 70 nonexistent).
- crt.sh's database is asked for a quarter of `-source-timeout` and then left, whether or not the driver gives up: a connection that hangs holds the source for the quarter, not for the whole timeout, and the JSON API gets the rest.
- A name is live when DNS has a record for it: an address, directly or through its CNAME chain, or a CNAME whose chain ends without one (marked `cname_only`).
- Answers too big for 512 bytes, such as a long CNAME chain, arrive with EDNS0, or over TCP when a server truncates them.
- Without `-live` nothing is looked up. The guesses are listed with `"unverified": true`, and the summary counts them.
- With `-live`, a guess that could not be checked, near `-timeout` or `-max-time` or with the DNS lookups failing, is left out and counted as `not checked`. The source's status says `N of its names not checked`, and `azhaq resume` checks them.

On tesla.com, `subs -live -dns-rate 10` with two resolvers took 161 s and listed 555 live names. `subfinder | dnsx -a -cname -rl 10` on the same resolvers took 211 s and listed 513. At the default pace it took 25 to 29 s against 56 to 63 s.

## Flags

<!-- flags:begin subs -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-d` | string, repeatable |  | domain (repeatable; a comma list, a URL or a name with a trailing dot is cleaned, as subfinder does) |
| `-dL` | string |  | file of domains (- for stdin) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-live` | bool |  | only names that resolve (wildcard answers left out, tier "dns"); without it nothing is looked up and every name the sources gave is printed as a candidate (-json: "tier": "candidate"), the ones no source asserted (subdomain.center's guesses, the name history's) marked "unverified": true |
| `-http` | bool |  | also ask each live name's web service one request (GET /, as azhaq probe does) and mark the names that answered "tier": "http"; sends requests to the names, so it is off by default; implies -live (-web-ports names the ports) |
| `-guesses` | bool | `true` | print the names only subdomain.center guessed, which no source asserted and no lookup checked, as candidates marked "unverified": true; -guesses=false holds them back and counts them; not with -live, which looks them up |
| `-guess-samples` | int |  | take up to N samples of subdomain.center's guesses while each has a new name that resolves (with -live) or the names seen are not yet most of its pool, with no time budget (default: the first sample, which is what subfinder \| dnsx checks, then with -live more for 20s at most, up to 12; without -live one) |
| `-w` | string |  | also resolve WORD.domain for each word in this file, like puredns bruteforce (active DNS; the names found are live) |
| `-permute` | bool |  | also resolve variations of the names found (api → api-dev, api2, dev.api), like alterx \| dnsx (active DNS) |
| `-all-sources` | bool |  | also run slower subdomain sources outside the default set |
| `-sources` | string |  | subdomain sources to run, comma-separated (default: the default set; none: no source, and no archive, RDAP, search engine or RIPEstat lookup either: only the resolvers and the targets are asked) |
| `-m` | string, repeatable |  | only names matching these (comma list or file; * matches anything), as subfinder -m |
| `-providers` | string |  | API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml) |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-source-rate` | float |  | requests per second to each subdomain source, as subfinder -rl (0: each source's own pace); a source's lower own pace stays |
| `-source-rates` | string |  | pace single subdomain sources, as subfinder -rls: name=N/unit, comma-separated, unit s, m or h (hackertarget=10/m,crtsh=1/s) |
| `-source-timeout` | duration | `30s` | give each subdomain source this long, 30s as subfinder does; a slower one (crt.sh) is abandoned, listed as failed, and the names the others gave are kept; -source-timeout 60s or more waits for crt.sh on a large domain (not -timeout, the run's bound) |
| `-extra-wait` | duration | `5s` | how long the sources azhaq adds to subfinder's default set (commoncrawl, hudsonrock, rapiddns, sitedossier, thc, waybackarchive) may go on after every source of that set has answered; one still running then is cut, listed as failed, and its names so far are kept; 0 waits for them as long as -source-timeout; a source named with -sources is not cut |
| `-max-time` | duration |  | how long the run may take: subs stops after this long, in any phase (the sources, subdomain.center's guesses, the DNS checks of -live, -w and -permute), exits 4 and leaves the rest for azhaq resume; run and plan only wait this long for the sources of a domain, then go on with what they gave (0: -source-timeout and a short grace bound the wait; -timeout bounds a run), as subfinder -max-time |
| `-max-body` | int |  | largest response body read from a subdomain source, in bytes (default 33554432), as subfinder -rsr |
| `-max-results` | int |  | most names one paging subdomain source gives (0: no cap), as subfinder -mr |
| `-max-names` | int |  | most names kept per domain, and looked up with -live (default 200000); a value you give also caps the names -w and -permute ask, together: the guesses past it are not asked, the run exits 4 and says how many |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-t` | int |  | work items in flight (default 16) |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |

**Network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked |
| `-proxy` | string |  | send every subdomain source request through this proxy URL, as subfinder -http-proxy (else HTTP_PROXY and HTTPS_PROXY) |
| `-web-ports` | string |  | ports to probe on each hostname or address of the list, comma-separated (default: 443, falling back to 80; a target given with no port and nothing there is a note, not a failure) |
| `-http-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY, except for loopback targets, which stay direct) |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-o` | string |  | also write results to this file |
| `-oI` | bool |  | text output: host,ip,source, with -live (subfinder -oI); -json rows get an ip field |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-fail-on-errors` | bool |  | the same as -strict-exit |
| `-ls` | bool |  | list the sources and exit: name, then * if a key is required and ~ if one improves the answer; with -json one object each (name, default, recursive, keyRequirement) |
| `-stats` | bool |  | after the run, one note per source: requests, names, errors and seconds, as subfinder -stats |
| `-no-history` | bool |  | do not read or write the name history (names earlier runs found, kept under $AZHAQ_DATA_DIR, else ~/.local/share/azhaq; with -live each is checked by DNS in the run) |
| `-strict-exit` | bool |  | exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures |

<details>
<summary>Flags familiar from subfinder, other names and flags accepted with no effect (11)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-cs` | bool |  | text output: host,[source,source] (subfinder -cs) | subfinder's name |
| `-exclude-sources` | string |  | subdomain sources never to run, comma-separated | subfinder's name |
| `-f` | string, repeatable |  | leave out names matching these (comma list or file), as subfinder -f | subfinder's name |
| `-filter-regex` | string, repeatable |  | leave out names matching this regular expression | subfinder's name |
| `-match-regex` | string, repeatable |  | only names matching this regular expression | subfinder's name |
| `-oD` | string |  | write one file per domain into this directory (NAME.txt, NAME.json with -json), as well as stdout | subfinder's name |
| `-recursive` | bool |  | only sources that look for subdomains of subdomains, as subfinder -recursive (see -ls) | subfinder's name |
| `-version` | bool |  | print the version and exit | subfinder's name |
| `-nW` | bool |  | same as -live (subfinder's name) | other name |
| `-oJ` | bool |  | same as -json (subfinder's name) | other name |
| `-ei` | bool |  | accepted for subfinder's sake: an IP address given as a domain is always left out with a note | accepted, no effect |

</details>
<!-- flags:end -->
