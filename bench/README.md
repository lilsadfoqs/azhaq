# Benchmark

`go run ./bench` measures Azhaq against the tools it is meant to replace, on the same targets, and prints the numbers including the ones where Azhaq loses.

```
go run ./bench                          # everything, both profiles
go run ./bench -profile polite          # only the polite profile (default or both too)
go run ./bench -only fuzz,dns,services  # these sections alone
go run ./bench -domains=false           # leave out the passive domain lookups
go run ./bench -crapi                   # also OWASP crAPI (about 2 GB of images)
go run ./bench -refbin DIR -nmap SCRIPT # reference tools built elsewhere; nmap unpacked without sudo
go run ./bench -readme                  # rewrite the README's benchmark table from the newest record
go run ./bench -list-units              # the units these flags select: default:apps, polite:dirs, claims:5, once:dropin ...
go run ./bench -units default:apps,once:docs  # only these units of the selection
go run ./bench -merge -expect LIST a.json b.json  # join records of units run apart into one; a unit of LIST no record holds fails a check
```

Run it from the repository root. It needs Docker (Juice Shop and VAmPI from `bench/compose.yaml`, the services lab from `bench/services.yaml` when the services section runs), network access, a C compiler (jsluice uses cgo), Python 3 (arjun), Chrome (screenshots, `-browser`, `-login`; the bench runs on machines that give it no sandbox, so every azhaq command it runs with Chrome passes `-chrome-no-sandbox`) and linux/amd64 (the reference tools are pinned to their linux/amd64 release archives, or taken from `-refbin`). It exits non-zero if a check fails, and writes a JSON record to `bench/history/`. The bench never stops containers: `-down` takes down only its own two (`azhaq-bench`).

## The lab images

`bench/images.env` is the one list of the lab apps' images (Juice Shop, VAmPI, DVGA, DVNA and DVWA), each pinned by tag and digest. `bench/compose.yaml` and `.github/ci/labs.sh` name the same images (a test, `TestLabImagesPinnedFromOneList`, fails when either differs from the list; the README's quick start must name the same Juice Shop build, which `bench/pin_test.go` checks), and labs.sh starts the five apps on 3001, 5002, 5013, 5020 and 5030 for the hunters and the trials. A user who starts the labs the documented way is on the build a row of the README's table was measured on. The truth files in `bench/truth` are per build (`juice-shop-v20.3.0-*`); a pin moves together with them. The services lab (`bench/services.yaml`) keeps its tags, and the table's service rows read what each daemon says, not a version.

`.github/ci/labs.sh` starts these, all on 127.0.0.1:

| Lab | Port | Notes |
| --- | --- | --- |
| Juice Shop, VAmPI, DVGA, DVNA, DVWA | 3001, 5002, 5013, 5020, 5030 | the pinned images; VAmPI's and DVWA's databases are set up and a login is checked (`.github/ci/lab_ready.py`) |
| Deploy lab | 5040 | `bench/truth/deploy`: an app whose API routes change when it is deployed, so `watch` can be tried against a deploy. `$HOME/lab/deploy v2` deploys the new version, `$HOME/lab/deploy v1` puts the first back; it starts on v1. What `watch` must report after the deploy is `bench/truth/deploy/expected.md`, and the `once:deploy` unit checks it: v1, v1 again (`no change`), then v2 |
| Services lab | 10021 to 21211 | `bench/services.yaml`, fifteen daemons |
| DNS lab | 5354 | `bench/labdns`, the zone azqlab.lan |

To reproduce a row, start the labs from that list and run the row's unit (`go run ./bench -list-units` names them: the row "Paths, 4750 words, Juice Shop and VAmPI" is `default:dirs`):

```
.github/ci/labs.sh                       # or: docker compose -f bench/compose.yaml up -d (Juice Shop and VAmPI)
go run ./bench -units default:dirs       # one row; -profile polite -units polite:dirs for the polite one
```

## The review checklist, as commands

`go run ./bench -checklist` runs what a release review spends its first hours on, with nobody in the loop, and fails on any broken check. It runs `claims:1`, `7`, `8`, `9` and `10` (the summary, the ledger and what a proxy or a listener saw agree, for a map, a port scan, the MCP server, a request budget and the kill file), `once:lab` (the DNS lab), `once:deploy` (`watch` against a deploy) and `once:checklist`: azhaq against a stand-in site on 127.0.0.1 that logs every request by method and holds a trap for each unsafe thing, with a second listener on 127.0.0.2 outside the scope. The `checklist` workflow runs it on every push to `next`, for a tag `checklist-NAME` (`.github/ci/run.sh checklist NAME`) or `gate-NAME`, and in under 20 minutes; the release workflow refuses a tag whose commit has no passing run, so run it on the commit to tag first.

| Checked | How |
| --- | --- |
| Exit codes: 0 complete, 2 usage, 3 the job failed, 4 limit | a plain map, a dead target, one target that answers and one that does not (0, and 3 with `-strict-exit`), an unknown flag, `-max-requests 4`, `-cookie` whose session ends |
| The summary's requests = the ledger's lines = what arrived | every run above, and the claims cases (the site, or a counting proxy in front of Juice Shop) |
| Every row inside the scope | a link, a script, a form and `-dirs`/`-graphql` toward 127.0.0.2: none arrives; a target outside `-allow` is refused (exit 2) |
| GET-only mapping by default | the page, its script and its API description name POST, PUT and DELETE routes and a GraphQL endpoint: only GET, HEAD and OPTIONS arrive |
| Writes only with their flags | `-submit-forms`, `-graphql`, `-params-writes`, `roles -replay-writes put`: that method arrives and no other; without the flag none |
| `-deny-path` | `/logout` and `/admin/purge` are asked (with `-send-state-changing`) without the rule and never with it, and the summary lists what was skipped |
| A found state-changing GET is held back | a default run never asks a found `/logout` or `/admin/purge`, and the summary lists them as held back with the flag that sends them |
| A lost session never goes on as an anonymous run | `-cookie`, a `/logout` link (sent with `-send-state-changing`) ends it: exit 3, the summary says so, no request without the session follows |
| The MCP lock | no `-allow` or `-scope`: exit 2; a call for a URL outside `-allow` sends nothing; `-unlocked` refuses port scans; the budget holds over calls (`claims:8`) |
| The request budget and the kill switch | `claims:9`, `claims:10`: the cap, the 0.6 s limit after the file, resume |
| Ledger | `ledger -verify` accepts a run's ledger and refuses an edited one with exit 3 |
| Web and API, hunt, diff, exports, ingest | the map holds the crawl, the script's routes, the API description and the GraphQL schema; `dirs` finds the five real paths and none of four that do not exist; `params` finds the parameter the page reads and not two it ignores; `hunt`, `diff`, `export -format openapi` and `ingest` give what is known |
| Subdomains, DNS, takeover candidates, UDP | `once:lab` |
| Monitoring with a deploy | `once:deploy`: v1, v1 again says `no change`, v2 reports `expected.md` |

Not covered: passive subdomain collection and the coverage estimate (they need the public sources), service detection across the services lab (one banner is checked), probing at scale, screenshots (`claims:3`, `11` need Chrome and are not in this run), archived URLs, the proxy-history matrix (HAR import), report generation and notifications. The list is `checklistCover` in `bench/checklist.go`; a test keeps it in step with the capabilities of `.github/ci/trial/GATE.md`'s checklist, so a capability added there must be listed there as covered or not.

## Units, and the CI run

A unit is one comparison section in one profile (`default:apps`; for `domains` one domain, `default:domains/hackerone.com`, each with its own no-silent-zeros check), one claims case (`claims:5`) or a section that runs once (`once:dropin`). No unit reads another's results, so any set of units gives the same checks as a full run, and `-merge` puts the records of several jobs in the order of one run (each record lists what every unit wrote in `units`). The bench logs `<profile>: <section> took Ns` for every unit.

The `bench` workflow asks `-list-units` for the units of the tag's flags, packs them into at most 18 jobs (repository variable `BENCH_MAXPARTS`) by the times in `.github/ci/bench-times.json` (a unit missing from it counts 60 s), and joins the records with `-merge -expect`: a unit no record holds is a failed check. Refresh the times from a run's log:

```
git show origin/ci-results:bench/TAG/bench.log > bench.log
.github/ci/bench_times.py bench.log --base .github/ci/bench-times.json > new.json && mv new.json .github/ci/bench-times.json
```

The jobs fetch the reference tools and the `.deb` files of nmap (artifact `bench-tools-HASH-GOVERSION`, the hash of `bench/tools.go`) from the newest earlier run that uploaded them (`.github/ci/latest-artifact.sh`; Actions caches would not do, as a tag run reads only its own ref's), and the merge job uploads the new ones. A miss only costs the install.

**The reference tools run in the same job as azhaq, every time.** azhaq runs live, so a reference answer measured on another runner hours earlier (other network, other resolver load) is no fair opponent: it showed as `azhaq 136, reference 349` on a day azhaq's resolvers were slow, with the reference's counts and time copied from the run before. `-reuse-ref` in the tag message (a word the workflow takes out of the flags; the bench does not know it) fetches the day's reference results of an earlier run (`bench-ref-DAY`) for a quick iteration where the comparison is not the point; the record then holds times measured elsewhere. `-fresh` runs the reference tools again even inside the job, and uploads nothing.

## Two profiles

Every comparison section runs azhaq and its reference tool with the same inputs and settings, once per profile; a check and a measured run carry the profile's name.

| | default | polite |
| --- | --- | --- |
| HTTP | the default flags of both tools | azhaq `-rate 5`; the reference at 5 (`-rl 5` httpx, katana and ffuf; arjun `--rate-limit 5`, which caps requests per second where its `-d` is a delay per thread; gowitness has no rate option and runs with its defaults, since with `-t 1` it shoots the first page and times out on the rest; notify `-rl 5`; gau one thread) |
| DNS | azhaq and dnsx defaults, the same two resolvers | azhaq `-dns-rate 10`; dnsx `-rl 10`, the same two resolvers |
| ports | the defaults, `-scan-type c` for naabu | azhaq `-rate 100`; naabu `-rate 100`; nmap `--max-rate 100` |
| path and fuzz lists | all 4,750 words of SecLists `common.txt` | about 250 words (`-polite-words`): every Nth word and twenty paths the apps serve. At 5 requests per second the whole list is 16 minutes a tool and app, which does not fit a run under 90 minutes |
| what else is smaller | everything | screenshots of four targets, parameters on three pages, domains `hackerone.com` and `vulnweb.com` (`-polite-domains`), DNS brute force with 300 words, no katana `-headless`, roles or scale |

Public test sites (ginandjuice.shop, testphp.vulnweb.com, demo.testfire.net) are always asked at 5 requests per second, in both profiles.

## The bar

Each comparison row is two checks.

- **Results**: azhaq's results are at least the reference's, counting only results that something other than azhaq confirms: a server's own log, a second resolver, `ss -ltn`, the app's own routes or planted parameters, a GET to the host itself. Not 95%.
- **Time**: azhaq's time is at most 1.05 times the reference's: the median of three runs when the first took under 20 s, one run above; for `dirs` and `fuzz` the two tools' runs alternate (azhaq, ffuf, azhaq, ffuf, …), so a target that slows down or speeds up as the bench goes on costs both the same. A run of azhaq that failed (a flag or a command a stream has not delivered) is no time to compare, and fails the check.
- **Memory**: azhaq is copied once after it is built (`freshCopy`): a binary the linker has just written shows up to 16 MB more resident than the same bytes unpacked from an archive, as a release and the reference tools are (30 MB against 14 MB for the same `azhaq dirs` of 11 words), and a number that depends on how a file got to disk is not a measure. What a small `dirs` sweep holds is the process itself: about 14 MB at start-up (the executable's pages and 4.4 MB of heap, 2.5 MB of it package initialisation), and the sweep, its calibration, the workspace and the ledger add less than the 0.5 MB the runs differ by. The peak resident size of each run is taken the same way (the median of the runs a time uses; for rows over several apps or pages, the largest). Every row keeps `azhaq_rss_mb` and `reference_rss_mb` in the record, the check's detail says "memory ×N of the reference" beside "time ×N", and the README's table and the report give the peak beside the time. It is shown and recorded, not a bar, except for the small jobs below.
- **Small jobs**: `dirs` on six words (against ffuf `-ac`, on the first app) and a scan of ports 1-1000 of 127.0.0.1 (against `nmap -sT`, connecting only, and against `nmap -sT -sV`, naming services) are the jobs where start-up and exit are most of the time. Their rows (`small` in the `dirs` and `ports` rows, default profile only: the polite pace is no start-up cost) hold azhaq to at most 1.25 times the reference's time and 2 times its peak memory, as well as to its results; a peak that was not measured fails the check.

Every check names the exact commands, so a reviewer can run them again. The record still has the old numbers (shares of the reference's results, ratios of times).

## Reference tools

Downloaded to `bench/.work/bin` and verified against pinned SHA-256 sums (`bench/tools.go`).

| Tool | Version | Used for |
| --- | --- | --- |
| katana | 1.8.0 | crawling with JavaScript parsing and its jsluice parser (`-d 3 -jc -jsl`), and with Chrome (`-headless -system-chrome -no-sandbox`) |
| subfinder | 2.17.0 | passive subdomains, default sources, no API keys |
| dnsx | 1.3.1 | deciding which names are live, for both tools; brute force with the same words and resolvers; reverse DNS (`-ptr`) |
| alterx | 0.1.0 | permutations of the live names, resolved by dnsx |
| gau | 2.2.4 | historical URLs (`--providers wayback,otx,urlscan`) |
| ffuf | 2.3.0 | the same wordlist as Azhaq's path sweep, with auto-calibration (`-ac`), at the same rate |
| httpx | 1.12.0 | probing: `-fr -td -cdn -favicon -title -sc`, the same User-Agent and concurrency as Azhaq |
| naabu | 2.6.1 | TCP connect scan (`-s c`), top 1,000 ports |
| jsluice | commit `0ddfab1` (2024-01-10) | URLs in the scripts katana found, and secrets in the planted script; built from source with `go install` |
| arjun | 2.2.7 | query parameters (GPL-3.0; installed with pip in a virtual environment and run as a separate program) |
| gowitness | 3.2.2 | screenshots (GPL-3.0; run as a separate program) |
| nmap | 7.94 | `-sV` service and version detection on the services lab (NPSL; run as a separate program; extracted from the Ubuntu .debs with `dpkg -x`, no sudo; `-nmap` names a script that runs it) |
| notify | 1.0.7 | notifications to a local stub (built with `go install` by the bench, like jsluice; MIT) |

Wordlists come from SecLists (MIT) at a pinned commit and are checked against their SHA-256 sums: `subdomains-top1million-5000.txt` for DNS brute force, `common.txt` for paths, `burp-parameter-names.txt` for parameters.

## What is measured

- **routes**: distinct paths on the app's origin a tool reported, static assets excluded.
- **known**: routes from an independent list that a tool found. For Juice Shop the list is the 77 routes its server defines (`app.get/post/…` in the container's `build/server.js`) whose static parts its frontend bundle writes, as they are or as a prefix constant plus a suffix (`bench/truth/juice_routes.py`, `bench/truth/juice-shop-v20.3.0-routes.txt`); until v0.6 it was the 45 `/api` and `/rest` strings a search of the bundle found, which left out every route built in a template literal. For VAmPI and crAPI it is the paths of the app's own OpenAPI document. A templated path (`/users/v1/{username}`) counts when a tool found a concrete instance of it or the same template, whatever its parameters are called; its static part alone (`/users/v1`) no longer counts. For ginandjuice.shop it is three routes that appear only in page scripts or script-driven forms.
- **shell**: reported URLs whose response is the page the app returns for any path (the SPA index on Juice Shop). For Azhaq these are URLs marked `visited`; katana does not claim to have visited what it lists, so its number is how much of its output is that page.
- **live**: names that dnsx resolves (A, AAAA or CNAME), out of the union of both tools' names. Each tool is credited with the live names it found.
- **katana ∪ jsluice**: known routes that either tool found, katana crawling and jsluice reading the scripts katana listed.
- **bundle grep**: known routes among the quoted strings that start with a path (`"/rest/user/login"`) in the same scripts: what reading the bundles by hand gives, without methods, bodies or the routes built from parts.
- **probe agreement**: for hosts both Azhaq and httpx answered, the final status, the title (whitespace collapsed) and the technology list (names and versions) must all match.
- **historical URLs**: distinct URLs on the domain or its subdomains, normalized the way Azhaq stores them, static assets left out; the share of gau's list that Azhaq's `-urls` file also holds (kept in the record). Azhaq drops scanner junk on purpose, so the bench runs it once more with `-raw` and counts as junk what Azhaq's own junk test drops, with its reason.
- **time** and **RSS**: wall time and peak resident memory of each run. Azhaq's app runs include its default domain fan-out (subdomain sources, archives, RDAP), which waits on third-party services, and technology fingerprints (about 30 MB; `-no-tech` leaves them out).

## Checks

The command fails when one of these does not hold. Rows marked "both" are measured in both profiles, each with the two checks of the bar.

- Apps (both): `crawl` against katana `-d 3 -jc -jsl` on Juice Shop, VAmPI and ginandjuice.shop, scored on the app's own routes. Default profile: Juice Shop at least 90% of its 77 known routes, VAmPI every path of its OpenAPI document, crAPI at least 30 of its 40; on every app at least as many known routes as katana ∪ jsluice, and no catch-all page reported as visited. ginandjuice.shop: the page scripts are read and the routes only they contain are found; product and blog pages fold into one template row each.
- Drop-in (`dropin`): `crawl -json` finds every Juice Shop route its pages and scripts name, which is the 77 known routes less the eight in `bench/truth/juice-shop-v20.3.0-full-map-only.txt` (the id form of five REST collections, `/rest/basket`, `/rest/basket/{id}/order` and `/ftp`: the truth holds them because their static parts are written in `main.js`, but a crawler is never sent to them; `run` reaches some). The record keeps how many of the eight `crawl` found.
- With a browser: `-browser` finds at least the known routes katana `-headless` finds, on Juice Shop and crAPI.
- Diffs: two identical Juice Shop runs produce an empty diff; a diff between two different targets is labelled; `azhaq watch` reports no change on an unchanged app.
- Roles: on Juice Shop, anonymous against a registered user (with its token, and signed in on the login page with Chrome), `/api/Users` and `/rest/user/authentication-details` go from 401 to 200; on the multi-tenant app, anonymous, member and owner match the known access table, and no signed-in role requests the sign-out link.
- Paths (both): hits of `dirs` against `ffuf -ac`, confirmed as not the app's catch-all answer; no more false positives.
- Fuzz (both): `fuzz` against ffuf on Juice Shop and VAmPI, calibrated (`-ac`) and, by default, with `-fs`; the hits confirmed as not the catch-all answer; the JSON report equals ffuf's after `duration` is dropped.
- Parameters (both): the parameters a planted server reads (and none it does not) against arjun; ginandjuice.shop, two pages and 1,000 names at 5 requests per second, in at most 1.05 times arjun's time.
- Ports (both): open ports of scanme.nmap.org (once), of 127.0.0.1 confirmed by `ss -ltn` taken before and after, and of 127.0.0.0/28 against listeners the bench opened, against naabu `-scan-type c`.
- Services (both): the lab's fifteen daemons, each named by what it says (the lab's own list in `bench/services.yaml`), against `nmap -sV`; at least 90% named.
- Screenshots (both): image files that decode and are not one colour, against gowitness, on the five local apps and three pages the bench serves; and at most 1.25 times its requests to the pages, counted by a proxy in front of each page that both tools are pointed at (a forward proxy given to Chrome would be bypassed by loopback pages).
- Probing (both): the hosts that answer (the local apps, the services lab's web ports and 100 local servers), confirmed by a GET to the host; status, title and technologies agree on at least 95% of shared hosts; three public test sites at 5 requests per second; and every input is a row, a failure or a skip.
- Domains (both): `subs -live` against `subfinder | dnsx`, on live names a third resolver confirms, in the time of the two together; every confirmed name only the reference finds is in azhaq's list or its source is named as failed; no empty subdomain or archive result without an error or `degraded` flag.
- URLs (both): `urls` against gau on vulnweb.com, and every URL gau lists is in azhaq's list or was dropped as junk with a reason (nothing is lost silently); azhaq's list and its junk together are at least gau's. The row reads `azhaq N listed, J dropped as junk (reasons), gau M, missing K`. After a change, rerun `-only urls`.
- DNS (both): record types (A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, SOA) and `-ptr` against dnsx on a zone the bench serves, counted at the server (answers right, queries received, queries in the busiest second); brute force on the DNS lab with the same words and resolver; in the wildcard zone, the three real names and nothing else.
- DNS lab, no docker (`lab`): `ports -pu` finds the lab's UDP port, `subs -w -live` gives the names the lab answers, a wildcard subzone gives only its real name, the dangling CNAMEs are named takeover candidates.
- Notify (both): `azhaq notify` against notify, with the same input and provider config, against a stub whose log is the evidence; the same requests; no webhook token in any output when the webhook cannot be reached.
- Networks: an AS's announced prefixes match its registered routes; reverse DNS finds at least 95% of what dnsx `-ptr` finds.
- Scope: no request leaves the program's scope, also with Chrome (`-browser`, `-login`, `shots`, `crawl -browser`).
- Claims: summary, ledger and an independent count agree on every path a request takes, including `azhaq_ports` after the MCP budget is spent.
- Scale: on Juice Shop behind a counting proxy, a run capped at 100 requests per process and resumed until done, a run killed with SIGKILL and resumed, and a run shared with two workers each map the same URLs as one uninterrupted run, and no process sends more than its budget.
- OpenAPI: the export of Juice Shop, VAmPI, DVGA, ginandjuice.shop and a fixture with `/blog` and `/blog/` is a valid OpenAPI 3 document by the bench's own checker (`bench/openapi.go`: structure, unique operation ids, path parameters declared, references resolve).
- Docs: no public doc says an active option needs `-allow` or a scope, or that requests are "GETs only" without HEAD, or in a plan or an MCP description; the README's "Latest run (date, vX)" names the newest release in the changelog and is not older than the tag.
- Go tests (`go test ./bench`): rows that were one assertion each (`bench/smoke_test.go`).

## Older results

The numbers below are from v0.6.2 to v0.9.0, taken before the two profiles and the 1.05 bar; the README's table is written from the newest record.

2026-10-27, v0.6.2, Go 1.27.1, one machine: `go run ./bench -crapi` (record `bench/history/2026-10-27T045837-db9f6fa-dirty.json`, taken before the commit). The probe comparison compares a redirect out of the host's site by its own status: httpx `-fr` reports the third party's page as the host's, Azhaq records the redirect. 44 of 45 checks pass; the one failure is the port comparison, which has nothing to compare with: this machine's security software removes the naabu binary. Ports and archives are compared on GitHub's network, by the benchmark workflow (`bench.yml`).

### Applications

Juice Shop, VAmPI and ginandjuice.shop from 2026-10-29 (v0.8.1, `go run ./bench -domains=false -brute=false -ports=false -probe=false -network=false`), katana with `-jsl`.


| App | Azhaq routes | known | shell | time | RSS | katana routes | known | shell | time | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Juice Shop | 110 | 70/77 | 0 | 5.4 s | 99 MB | 5 | 1/77 | 3 | 14.1 s | 1404 MB |
| VAmPI | 14 | 12/12 | 0 | 0.6 s | 75 MB | 1 | 1/12 | 0 | 11.1 s | 36 MB |
| ginandjuice.shop | 16 | 3/3 | 0 | 15.5 s | 99 MB | 14 | 2/3 | 0 | 18.5 s | 813 MB |
| crAPI (2026-10-27, katana without `-jsl`) | 85 | 32/40 | 0 | 4.5 s | 102 MB | 4 | 0/40 | 1 | 13.0 s | 59 MB |

| Known routes | Azhaq | katana `-jsl` | jsluice | katana ∪ jsluice | bundle grep |
| --- | --- | --- | --- | --- | --- |
| Juice Shop | 70/77 | 1/77 | 0/77 | 1/77 | 37/77 |
| VAmPI | 12/12 | 1/12 | 0/12 | 1/12 | 0/12 |
| ginandjuice.shop | 3/3 | 2/3 | 1/3 | 2/3 | 1/3 |
| crAPI (2026-10-27) | 32/40 | 0/40 | 0/40 | 0/40 | – |

| With a browser | routes | known | shell | time |
| --- | --- | --- | --- | --- |
| Juice Shop, Azhaq `-browser` | 176 | 70/77 | 0 | 12.7 s |
| Juice Shop, katana `-headless` | 30 | 6/77 | 4 | 6.9 s |
| crAPI, Azhaq `-browser` | 86 | 32/40 | 0 | 17.9 s |
| crAPI, katana `-headless` | 5 | 0/40 | 1 | 44.2 s |

Juice Shop's routes come from the calls its Angular bundle makes (`this.http.post(\`${host}/rest/2fa/verify\`, …)`); the seven Azhaq misses are parameter routes of `/api/*` resources the server defines and the frontend never asks for by id, and two middleware mounts. crAPI's frontend joins every API path from constants (`"identity/" + API.LOGIN`); the other 8 of its 40 (admin and management endpoints) appear nowhere in the frontend. Memory is the process alone, without Chrome for the browser rows. ginandjuice.shop's time includes the domain fan-out, which waits for the slowest subdomain source.

### Sessions and roles

| | endpoints listed | expected | time |
| --- | --- | --- | --- |
| Juice Shop, anonymous → user, with the user's token | 35 | `/api/Users`, `/rest/user/authentication-details` 401 → 200 | 11.7 s |
| Juice Shop, anonymous → user, signed in with `-role-login` | 37 | both, 401 → 200 | 14.9 s |
| multi-tenant app, anonymous → member → owner, `-role-login` | | 6/6 rows of the access table; no signed-in role requested the sign-out link | 7.3 s |

`azhaq roles` asks every endpoint any role reached with every other role and fills path parameters from identifiers in the answers, each role's own objects first, so the table is a full matrix. Outside the bench, on Juice Shop it reports another user's basket (`/rest/basket/14`, alice's, read by bob and admin), `/api/Addresss/3` read by admin only, and `/rest/memories` handing anyone users' password hashes; on VAmPI, a book's secret read by the other user and `/users/v1/_debug` handing anyone every password.

### Discovery

| | Azhaq | Reference | shared | Azhaq time | reference time |
| --- | --- | --- | --- | --- | --- |
| paths, 4,750 words on 3 apps (ffuf `-ac`) | 35 hits | 36 | 35 | 53.7 s | 59.3 s |
| false positives (hits that answer like a missing path) | 4 | 4 | | | |
| parameters, 5 pages, 6,453 names (arjun) | 5 | 2 | 2 | 120.1 s | 29.5 s |
| screenshots, 4 front pages (gowitness) | 4 | 3 | | 36 s | 34 s |
| secrets in the planted script (jsluice) | 12 | 4 | 4 | | |

Azhaq's parameter search is slower than arjun's: it confirms each name it finds on its own, and it sends at most 20 requests a second per host.

### Scope, watch and scale

- Scope: no request reached the host outside the program's scope (links, scripts, a redirect, a form and `robots.txt` pointed at it, with path, parameter, port and GraphQL modules on); 5 in-scope URLs mapped.
- Watch: three runs of an unchanged app, no change reported. Two identical Juice Shop runs diff empty.
- Juice Shop behind a counting proxy, 184 URLs in one run of 5.4 s:

| | URLs as one run | detail |
| --- | --- | --- |
| `-max-requests 100`, then `azhaq resume` until done | yes | 3 processes; Juice Shop received at most 100 requests from one, 211 in all against 205 for one run |
| killed with SIGKILL after 1.8 s, then `azhaq resume` | yes | |
| `-serve` with two `azhaq worker` processes | yes | the workers ran 239 tasks; 6.8 s |

### Domains

| Domain | live | Azhaq live | names | subdomains at | whole run | subfinder live | names | time | Azhaq URLs | gau URLs | gau's in Azhaq |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hackerone.com | 14 | 14 | 607 | 10 s | 19 s | 12 | 529 | 27 s | 2,981 | 1,621 | 1,620 |
| tesla.com | 526 | 516 | 1,855 | 9 s | 19 s | 490 | 1,806 | 19 s | 3,981 | 653 | 651 |
| vulnweb.com | 7 | 7 | 532 | 17 s | 25 s | 6 | 517 | 11 s | 141 | 65 | 62 |

Azhaq's default sources: 8 per domain, all of which answered (crt.sh is read from its `/json` endpoint; the sources that were dead or refusing every request are out of the default set). Both tools lost the Wayback Machine and Common Crawl, which refuse this address; Azhaq says so in every summary.

| Networks | Azhaq | Reference | shared |
| --- | --- | --- | --- |
| AS394161, announced prefixes (RIPEstat) against registered routes (RADb) | 102 | 39 | 31 |
| 45.33.32.128/25, addresses with a reverse name (dnsx `-ptr`) | 36 | 36 | 36 |

| Probing, 551 live hosts | answered | status, title and tech agree | favicon agrees | CDN agrees | time |
| --- | --- | --- | --- | --- | --- |
| Azhaq | 406 | 396/396 | 43/50 | 48/52 | 100.5 s |
| httpx | 396 | | | | 141.7 s |

Both sent the same User-Agent (a current browser's) with 16 requests in flight. Azhaq connects to the addresses its resolver found, IPv6 first where the machine has a route, and keeps the first hop of a redirect whose target fails.

| Active DNS on vulnweb.com | Azhaq | dnsx | shared | Azhaq time | dnsx time |
| --- | --- | --- | --- | --- | --- |
| brute force, 5,000 words | 3 | 3 | 3 | 37.0 s | 72.3 s |
| permutations of live names | 0 | 0 (alterx) | 0 | | |
| wildcard zone, 50 words, 3 real | 3 found, 0 fake | 50 (no filtering) | | | |

vulnweb.com has few names, so the permutation row says little; dnsx's `-wd` filter needs the zone to be named, and without it every guess in the wildcard zone comes back.
