# Parity replay

A cheap, unattended check of one question: run as its docs tell a user to run
it, how many of an estate's planted vulnerabilities does azhaq identify, and
how soon? It is a leading indicator. It does not replace the review
(`trial.yml`, `gate-a`), which is a 90-minute engagement judged by a person's
standard; the replay measures only what the documented default flow finds, and
how soon.

## What it measures

For each sample, `parity.yml` builds one fresh estate (the same `build.py`,
`up.py`, resolver and `vm.max_map_count` steps as `gate-a`) and runs
`replay.sh` on it: the commands of the README's "One workflow" and
`docs/START.md`, for a domain plus an address range with a given resolver.

| Command | Why |
| --- | --- |
| `azhaq plan FLAGS` | the docs plan first; it sends nothing |
| `azhaq run -domain D -cidr NET -allow D -allow NET -resolvers DNS -ports default -verify -max-time Ns -db FILE` | the seeds are the domain and the range; `-allow` is the fence `START.md` puts on every run; the resolver is the one the client gave; `-ports default` is `run.md`'s named default set (a run with no `-ports` scans none); `-verify` is the read-only service checks of `run.md`; `-max-time` is the cap |
| `azhaq hunt -db FILE -json -limit 1000` | "where to look first", the step after `run` in the README |
| `azhaq export -db FILE -format jsonl` and `-format findings` | the whole workspace, and the findings records |

No flag is chosen for the estate, and nothing reads the key or the catalog. No
`-rate` or `-max-requests`: the docs' examples set those for a program's scope,
and the default is unpaced. `-advisories` is left out because its advisory
records are ones the user downloads (`START.md`, job 3) and azhaq ships none.

`to_leads.py` turns the workspace into what `range/grade.py` reads, with
`grade.py` unchanged: `leads.jsonl`, `surface-1.txt` and `phases.log`. A lead
is a row azhaq presents as an identification or a finding: a service with a
product and version, a web service's root page with a technology or `Server`
header, a takeover candidate, a `-verify` result or an advisory lead, a stack
trace, and the rows `hunt` ranks for a finding-like signal (exposed file,
listing, source map, secret, API description, GraphQL, admin, debug, config and
env paths). A map row that only proves a URL exists is not a lead. Each lead's
time is a time azhaq stored (an observation's `observed_at`, else the entity's
`first_seen`); nothing is polled. The phase starts when `replay.sh` starts and
ends when `run` ends or the cap stops it.

`summary.py` reduces each sample to counts: key vulnerabilities identified at 5,
15 and 30 minutes and at the end (count and share of the key), seconds to the
first match, precision (matched leads over all leads), surface recall (hosts,
ports), and leads and matches by lead kind and by category. A lead that is real
but not in the key counts against precision, as `grade.py` lists it for a person
to judge; read precision as a trend, not a verdict. `summary.py agg` gives the
mean and the minimum across the samples.

## Fresh seeds, aggregates only

The four pool estates (`range/pool.json`) have known baselines, so tuning
azhaq to them would measure the tuning. Each parity sample is an estate no one
has seen: its seed is `HMAC-SHA256("TAG:SAMPLE")` keyed by `CODEX_AUTH_KEY`
(the repository's seed secret, used only as that key), and `seed.sh` fails when it equals the estate of any
pool entry. The estate's name, products and answers never reach the public log
or this repository: the key, azhaq's raw output, the leads and the full grade
are age-encrypted to the maintainer, and the summary carries no product, CVE,
host, port or path (`summary.py` refuses to write one that would). Look at the
aggregate, fix a class of miss rather than one estate's, and push a new tag for new estates.

## Run it

```
.github/ci/run.sh parity NAME count=3 minutes=30     # tag parity-NAME; both words optional
.github/ci/parity/fetch.sh NAME /tmp/parity-NAME     # decrypts, prints the aggregate table
```

`count` is 1 to 4 estates (default 3, two at a time) and `minutes` the cap on
each replay (default 30). `fetch.sh` prints only the table; for each sample the
answer key, azhaq's raw output, the leads and `graded/grade.md` stay in
`DIR/sK` for you. It needs `~/.config/azhaq/age.key` (or `AZHAQ_AGE_KEY`).

## Read it

- `identified at N min` and `at the end`: how much of the key azhaq names, and
  when. The pool's baselines (`trial/README.md`) were measured on other
  estates: a rough guide, not a paired test.
- `seconds to the first match`: the minimum is the best case; the mean is typical.
- `precision` and `leads by kind`: where azhaq's presentation is noisy.
- `surface`: hosts and ports azhaq listed against the key.
- A mean over three estates moves with the draw. Judge a change by a few
  runs, and by the by-kind and by-category counts, not by one number.

Tests: `python3 -m unittest discover -s .github/ci/parity`.
