# azhaq dns

Resolves names for any record type and leaves out wildcard answers. Replaces dnsx (see [Migrating](../MIGRATING.md#dnsx-azhaq-dns)).

## Synopsis

```
azhaq dns -d NAME | -l FILE | stdin  [-a -aaaa -cname -ns -txt -srv -ptr -mx -soa -caa -any -axfr -all] [-resp] [-json] [-w WORDS] [-r RESOLVERS]
```

## Examples

```
# the A records of every subdomain found, as JSON
azhaq subs -d example.com | azhaq dns -a -json

# MX and TXT records of a list, every record printed, two resolvers
azhaq dns -l names.txt -mx -txt -resp -r 1.1.1.1,tcp:9.9.9.9

# reverse lookups of a range
azhaq dns -l 192.0.2.0/24 -ptr -resp

# guess names under a domain from a wordlist, 50 names a second, 100 at once
azhaq dns -d example.com -w words.txt -rl 50 -t 100

# ask the name servers of a domain for its whole zone
azhaq dns -d example.com -axfr -allow example.com
```

## What it does

1. Takes names from `-d`, `-l` or stdin.
2. Asks resolvers for the record types you choose. A is the default.
3. Leaves out a name that only resolves through a wildcard zone.
4. Prints the names that have a record of the types asked.

`dns` neither reads nor writes the name history `subs` keeps under `azhaq-data/` (or the directory you name) (see [Name history](subs.md#name-history)): it resolves the names it is given and stores nothing outside `-db`.

`dns` sends DNS queries and nothing else. `-axfr` connects to the name servers of the name, `-trace` asks the root servers, and `-asn` asks Team Cymru's DNS service through your resolvers.

## Output

Plain output is one name per line: the names that have a record of the types asked. With `-json` you get one object per name that has a record of the types asked, with the fields below. A field with no value is left out. `-db FILE` keeps the names that have records in a workspace.

What the text forms print:

| Flag | Each line is |
| --- | --- |
| `-resp` | `NAME [TYPE] [VALUE]`, one per record |
| `-resp-only` | the values, each exactly as the resolver sent it: a TXT value or a target name keeps its capitals, as in `-json` |
| `-rcode` | `NAME [NXDOMAIN]`, with the code of the answer |
| `-cdn`, `-asn` | the name, then ` [cdn-name]` or ` [AS number, name, country]` |
| `-ot '{{host}} {{a}}'` | a template over the `-json` fields; `{{ip}}` is `a` and `aaaa` together |

The `-json` fields are dnsx's, in its order:

| Field | Meaning |
| --- | --- |
| `host` | The name asked. |
| `ttl` | The TTL of the first record that has one. |
| `resolver` | The resolvers that answered. |
| `a`, `aaaa` | The addresses. |
| `cname` | The targets, with no final dot. |
| `mx`, `ptr` | The record values. |
| `soa` | `name`, `ns`, `mailbox`, `serial`, `refresh`, `retry`, `expire`, `minttl`. |
| `ns` | The name servers. |
| `txt` | The strings of a record, joined. |
| `srv` | The targets. |
| `caa` | The values. |
| `all` | Every record as text. `-omit-raw` drops it. |
| `raw` | The raw answer, with `-raw`. |
| `has_internal_ips`, `internal_ips` | An answer in a private, loopback, link-local, documentation or multicast range. |
| `status_code` | The code of the name asked: `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, … A name that is a CNAME exists, so it is `NOERROR` even when its target does not. |
| `status_code_raw` | The code as a number. Left out for 0. |
| `cname_status` | Not a dnsx field: the code of a CNAME's target when it is not `NOERROR`, such as `NXDOMAIN` for a dangling CNAME. Whichever types were asked: see [A CNAME's target](#a-cnames-target). |
| `takeover` | Not a dnsx field: a name whose CNAME points at what is gone. It says what was observed and has `status`: `candidate` until the service itself shows the name is free. See [Takeover candidates](../CONCEPTS.md#takeover-candidates). |
| `trace`, `axfr` | `{host, chain: [rows]}`, with `-trace` and `-axfr`. |
| `timestamp` | The time of the query. |
| `hosts_file` | With `-hf`. |
| `cdn`, `cdn-name`, `cdn-type` | With `-cdn`. `cdn` is true for a CDN. |
| `asn` | With `-asn`: `as-number`, `as-name`, `as-country`, `as-range`. |
| `query-time` | The duration of the query. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). The summary counts:

| Count | Meaning |
| --- | --- |
| `asked` | Names asked. |
| `did not resolve` | Names with no record of the types asked. |
| `no answer` | Names no resolver answered. |
| `other codes` | Names answered, but not with a code `-rcode` lists. |
| `servfail from every resolver` | The name's own DNS is broken. This is not a failure. |
| `left out` | Inputs not asked about: see Details. |
| `not asked` | Names left when a run stops. |
| `wildcard answers left out` | Names that resolved only through a wildcard zone. |

The summary counts names: `12 names`. When a line is a record (`-resp`, `-resp-only`, a transfer), it counts both: `13 records of 12 names`. `-json` has one row for each name, so its `results` is the number of names.

`requests` is 0 for `dns`: its questions go to resolvers, not targets. `dns_queries` counts them (the retries and the wildcard probes too, so it is more than `asked`), and equals the ledger's `DNS queries` line count, with or without `-ledger`.

The summary also lists failures per kind of error, and takeover findings: a CNAME to a name that no longer exists. `takeover_candidates` and `takeover_verified` count them apart, and add up to the rows under `takeover`.

## Details

### Which names get a row
- Text and `-json` both give a row only to a name that has a record of the types asked. A is the type when no flag names one, as in dnsx. A name that does not exist, or has no such record, such as a TXT-only name when A is asked, gets no row and is counted as `did not resolve`. So `asked` minus `did not resolve` is the number of rows.
- A name no resolver answered gets no row in either form. It is counted as `no answer`.
- With a type flag (`-mx`, `-txt`, …), the types are those flags'.
- With `-rcode`, only the names whose answer has that code get a row, with its `status_code`. That is how to list the names that do not exist. A name whose CNAME points at what is gone is not one of them: its own code is `NOERROR`, and the target's `NXDOMAIN` is its `cname_status`.
- With `-all`, `-any` or `-axfr`, `-json` gives a row to every name a resolver answered, including one with no record at all.
- With `-response-type-filter` and no type flag, `-json` gives a row to every answered name that has none of the records filtered, as dnsx does: `-rtf a` keeps the names that have only AAAA, TXT, MX or SRV, that have no record (NODATA), that do not exist, and the CNAME-only ones, and leaves out the names with an A. In text, a kept name prints the records it has, so one with none prints nothing. With a type flag too (`-a -txt -rtf a`), a name needs a record of a type a flag asked.
- A name whose CNAME points at what is gone also gets its `-json` row, with `takeover`, whichever types are asked, unless `-no-takeover` is given (see [A CNAME's target](#a-cnames-target)): it is a finding, and it is not counted as `did not resolve`.

### A CNAME's target
- A name with a CNAME gets its target checked, whichever types were asked. A type whose answer follows the chain (`-a`, `-aaaa`, `-txt`, `-mx`, …) already says where the chain ends. `-cname` alone does not: a question for CNAME gets the record and stops, so the name is asked for A once more, and only the end of the chain is kept from that answer (`cname_status`, and `takeover` when the target is gone). That is one more query for each name that has a CNAME, in `dns_queries` and the ledger like the others.
- `-no-takeover` leaves that question out. Then `-cname` alone gives no `cname_status` and no `takeover`.

### Types
- `-all` asks A, AAAA, CNAME, MX, NS, SOA, TXT, SRV and CAA of a name: not PTR (`-ptr`) and not ANY (`-any`). AXFR is asked with `-axfr` only, because it connects to the name servers.
- An address gets PTR only.

### Zone transfer
- `-axfr` asks the zone's name servers on port 53 first, then each `-r` resolver at its own port, over TCP, as dnsx does. Text and `-json` ask the same servers.
- With `-allow`, `-scope` or `-deny` given, a name server is asked only at an address the scope allows: its name being in the scope does not vouch for where it points. A name server whose address is outside is not contacted. The summary names it, and adding its address to `-allow` allows the transfer. Without any scope flag, the name given is the scope, as before.
- `azhaq plan -axfr` lists these connections before anything is sent.
- `-json` gives the name's row with `axfr`: its `chain` holds one entry for each server that transferred the zone. An `axfr` with no `chain` says the transfer was tried and no server gave it.
- A note names each server that did not transfer the zone.
- When no server transferred it, the summary lists `-axfr: no server transferred the zone` under `failed` and the exit code is 3: the technique was asked for and gave nothing.

### Wildcards
- A name that only resolves through a wildcard zone is left out of `a`, `aaaa` and `cname`.
- `-no-wildcard` keeps it.

### Words and inputs left out
- With `-d DOMAIN -w WORDS` it resolves `WORD.DOMAIN` for each word, as `dnsx -d -w` does.
- `-dns-rate N` holds back the queries of `-d` with `-w` too: see [Time and pace](#time-and-pace).
- `left out` counts inputs that were not asked about:
  - an address or range without `-ptr`
  - a word that makes no name
  - a name outside the scope

### Time and pace
- `-timeout` is how long one DNS answer is waited for, 3 s by default, as in dnsx. In `run` and the other commands `-timeout` is the time of the whole run.
- `-maxtime SECONDS` bounds the run. It exits 4, and the summary says which `-start N` to go on from.
- `-retry N` is the attempts per question on other resolvers. The default is 3, where dnsx's is 2, and 2 for the names `-w` generates (made-up names mostly do not exist, and an unanswered one costs every attempt as a paced query); `-retry N` given sets it for every name. A name no resolver answers is counted as `no answer`, listed under `failed`, and the exit code is 3. A name no resolver answered is asked again in a second pass at a quarter of the concurrency. When none of a batch of 16 names or more was answered, the resolvers are down, not busy, and there is no second pass. The second pass asks 16 of them first, spread over the list and once each, and ends there when none is answered, because the rest would fail alike.
- `-rl N` is names a second over all resolvers, as in dnsx. `-t N` is names in flight, 100 by default.
- `-dns-rate N` is queries a second to each resolver. A second's worth may go out at once after a pause, so the total is N times the number of resolvers: six by default. A name asked for several types sends one query for each.
- With one `-r` resolver, or with `-rl`, the total is the rate you gave. For a polite run give `-rl 5` and `-t 5`.
- In one test run, `-rl` of dnsx 1.x did not slow the queries of `-d` with `-w` (20 names at `-rl 1` took 0.46 s). `-dns-rate` paces them: 20 names at 1 a second took 19 s. See [Migrating](../MIGRATING.md#dnsx-azhaq-dns).

## Flags

<!-- flags:begin dns -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-d` | string, repeatable |  | name to resolve, or with -w the domain to guess under (repeatable; a file, a comma list or - for stdin; FUZZ in it takes the words) |
| `-l` | string, repeatable |  | names: a file, a comma list or - for stdin; a CIDR range or an AS number (AS13335) is expanded to addresses |
| `-w` | string, repeatable |  | words to guess: a file, a comma list or -; with -d DOMAIN resolves WORD.DOMAIN for each (wildcard answers left out) |
| `-start` | int |  | skip this many names at the start of the input, in order after de-duplication |

**Record types**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-a` | bool |  | ask A records and print the names that have one (the default) |
| `-aaaa` | bool |  | ask AAAA records and print the names that have one |
| `-cname` | bool |  | ask CNAME records and print the names that have one |
| `-ns` | bool |  | ask NS records and print the names that have one |
| `-txt` | bool |  | ask TXT records and print the names that have one |
| `-srv` | bool |  | ask SRV records and print the names that have one |
| `-ptr` | bool |  | ask PTR records and print the names that have one |
| `-mx` | bool |  | ask MX records and print the names that have one |
| `-soa` | bool |  | ask SOA records and print the names that have one |
| `-caa` | bool |  | ask CAA records and print the names that have one |
| `-any` | bool |  | ask ANY records and print the names that have one |
| `-axfr` | bool |  | ask each name server of the name, and the -resolvers you gave, for the whole zone over TCP (active; a name server is asked at an address the scope allows: -allow, -scope) |
| `-all` | bool |  | ask A, AAAA, CNAME, SOA, TXT, SRV, MX, NS and CAA (not ANY, not AXFR) and print the records (-resp); an address gets only PTR |
| `-e` | string, repeatable |  | types not to ask with -all, comma-separated |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-no-wildcard` | bool |  | print names even when they only resolve because their zone has a wildcard |
| `-no-takeover` | bool |  | do not check CNAMEs for a takeover: no question is asked about the domain of a CNAME target, in scope or not |

**Answer format and filters**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-resp` | bool |  | print each record as: NAME [TYPE] [VALUE] |
| `-resp-only` | bool |  | print the values of the records only |
| `-rcode` | string |  | print NAME [RCODE] for names whose answer has one of these codes, comma-separated (noerror, nxdomain, servfail, refused, or a number); a name with no records is shown |
| `-response-type-filter` | string |  | print names with no record of these types, comma-separated (a, cname, ...); with -json and no type flag, a name that does not exist or has only other records has its row too |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; HOST:PORT allows that host on that port only; with any -allow, nothing else is requested |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rl` | int |  | names asked per second, over all resolvers; each name's types are asked together (0: no limit); see also -dns-rate |
| `-t` | int | `100` | names resolved at once |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-retry` | int |  | attempts per question on other resolvers (default 3, 2 for the names -w generates; 1 asks once) |
| `-timeout` | duration | `3s` | wait this long for each DNS answer (not the run's time, as in azhaq run: see -maxtime) |
| `-maxtime` | float |  | stop the run after this many seconds (0: no limit); the summary says where to go on |

**Network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked |
| `-proxy` | string |  | send DNS through this socks5 proxy (socks5://host:port), over TCP |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the names that have records in this database for query, show and export (default: workspace.db in the run's folder under ~/.azhaq/runs; with AZHAQ_HOME=none nothing is kept) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-o` | string |  | also write results to this file |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-v` | bool |  | print each name that got no records, with its status, on stderr |
| `-strict-exit` | bool |  | exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures |

<details>
<summary>Flags familiar from dnsx, other names and flags accepted with no effect (34)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-asn` | bool |  | add the autonomous system of each address (as-number, as-name, as-country, as-range), asked of Team Cymru's DNS service | dnsx's name |
| `-cdn` | bool |  | name the CDN, WAF or cloud in front of each name (cdn, cdn-name, cdn-type) | dnsx's name |
| `-health-check` | bool |  | ask each resolver a known name, print how it answered and how long it took, and exit | dnsx's name |
| `-hostsfile` | bool |  | answer from the system hosts file before asking resolvers | dnsx's name |
| `-omit-raw` | bool |  | leave the records as text (all) out of -json | dnsx's name |
| `-output-template` | string |  | print each name as this template; {{host}}, {{a}}, {{ip}} and the other -json fields, lists joined by commas | dnsx's name |
| `-raw` | bool |  | print the raw DNS answers, as dig does | dnsx's name |
| `-stats` | bool |  | print progress on stderr every 5 seconds | dnsx's name |
| `-stream` | bool |  | names come from stdin as they are written and are not de-duplicated | dnsx's name |
| `-trace` | bool |  | follow the delegations from the root servers to the answer (the roots are asked, so use it on names you may ask) | dnsx's name |
| `-trace-max-recursion` | int | `32` | most steps of -trace | dnsx's name |
| `-wildcard-domain` | string |  | also probe this zone for a wildcard (a zone the registrable domain does not reach, such as corp.internal) | dnsx's name |
| `-aw` | bool |  | same as -auto-wildcard | other name |
| `-debug` | bool |  | same as -raw | other name |
| `-disable-update-check` | bool |  | same as -duc | other name |
| `-hc` | bool |  | same as -health-check | other name |
| `-hf` | bool |  | same as -hostsfile | other name |
| `-j` | bool |  | same as -json | other name |
| `-or` | bool |  | same as -omit-raw | other name |
| `-ot` | string |  | same as -output-template | other name |
| `-r` | string |  | same as -resolvers | other name |
| `-rate-limit` | int |  | same as -rl | other name |
| `-rc` | string |  | same as -rcode | other name |
| `-re` | bool |  | same as -resp | other name |
| `-recon` | bool |  | same as -all | other name |
| `-ro` | bool |  | same as -resp-only | other name |
| `-rtf` | string |  | same as -response-type-filter | other name |
| `-threads` | int | `100` | same as -t | other name |
| `-wd` | string |  | same as -wildcard-domain | other name |
| `-wt` | int |  | same as -wildcard-threshold | other name |
| `-auto-wildcard` | bool |  | accepted: wildcard answers are always left out, unless -no-wildcard | accepted, no effect |
| `-duc` | bool |  | accepted: azhaq checks for no updates | accepted, no effect |
| `-nc` | bool |  | accepted: output has no colour | accepted, no effect |
| `-wildcard-threshold` | int |  | accepted and not needed: each parent zone is probed for a wildcard | accepted, no effect |

</details>
<!-- flags:end -->
