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

`ident.py` asks a narrower question of the same workspace: of the key's
services azhaq found, how many did it name, product and version? A product is
named when a stored row states it (a port's service product, a web answer's
technology, a check's or an advisory's product); a product that is only in a
page title or a `Server` header is counted apart, as shown but not stated. The
version is counted where the key's version is one (not `latest`). It uses the
drift grader's rule for matching a product name, prints counts, shares and the
key's categories only, and writes the misses (what the rows said, per service)
to `graded/ident-misses.jsonl`, inside the encrypted sample. It reads only the
export, so it runs in seconds over any kept workspace:

```
python3 -I .github/ci/parity/ident.py sample DIR/sK/key.json DIR/sK/export.jsonl --out ident.json --misses misses.jsonl
python3 -I .github/ci/parity/ident.py agg DIR/s*/ident.json
```

The other side of that number is `stack.sh`. After the replay, it asks the
usual tools to name the same services azhaq found: `nmap -sV` on each
address's open ports, `httpx -td` (title and `Server` header too) and nuclei's
`tech` and `panel` templates on each web root. The tools are the control's
pinned versions. `stack_rows.py` turns their output into the rows `ident.py`
reads, and `ident.py` grades both sides with the same rule, so the comparison
is of naming, not of finding.

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
.github/ci/run.sh parity NAME count=3 minutes=30     # tag parity-NAME; the words are optional (pairs=1: see Run pairs)
.github/ci/parity/fetch.sh NAME /tmp/parity-NAME     # decrypts, prints the aggregate table
```

`count` is 1 to 4 estates (default 3, two at a time) and `minutes` the cap on
each replay (default 30). `estates=NAME` builds the estates of the earlier tag
`parity-NAME` instead of fresh ones, to compare two builds on the same estates. `fetch.sh` prints only the table; for each sample the
answer key, azhaq's raw output, the leads and `graded/grade.md` stay in
`DIR/sK` for you. It needs `~/.config/azhaq/age.key` (or `AZHAQ_AGE_KEY`).

## Run pairs

`pairs=1` in the tag's message keeps two runs of each sample's lab network, to
test the readers of stored rows on rows a real run wrote (#491). It is off by
default: without it nothing below happens and the timing of a run is the same.

```
.github/ci/run.sh parity NAME count=2 minutes=30 pairs=1
```

With it, each sample does this after its normal replay (and before `stack.sh`):

1. `pair.sh` runs `azhaq watch -db WORKSPACE -json -- RUN OPTIONS` into the
   workspace `replay.sh` made, with `replay.sh`'s options and the same cap. That
   is one watch cycle: the run options plus `-db` and `-quiet`, then the
   comparison of the last two runs, against the lab network as it stands.
2. It exports each of the workspace's two runs with
   `azhaq export -format jsonl -run ID` (the workspace's own export holds every
   run, so the two are told apart by the run ids of `azhaq query -runs`).
3. The sample's `pair/` folder holds `export-run1.jsonl`, `export-run2.jsonl`,
   `watch.json` (what watch reported), `watch.err` (the second run's report),
   `pair.json` (exit codes and counts) and the exports' error files; it goes
   in `sample.tgz.age` with the rest. When the archive passes 40 MB the sample's
   `export.jsonl` goes first (the pair holds the first run's export again), then
   the pair.

The job log gets counts only: the exit code of watch, the rows of each run and the
number of change lines. `pairs=1` takes `minutes=` of at most 60 (a pair runs twice
in the job's 180 minutes). A failed second run is a warning; the sample is
graded and published as before.

`fetch.sh NAME DIR` decrypts and unpacks the samples as before, so each pair is
in `DIR/sK/pair/`, which is the layout the replay tests read. It counts the
pairs and prints the command:

```
AZHAQ_REPLAY_DIR=DIR go test ./cmd/azhaq ./internal/portscan ./internal/httprow \
  -run 'TestReplay(ed|Recorded|ANewPort|RunPairs)'
```

The tests skip when the variable is unset. With it set:

| Test | What it checks |
| --- | --- |
| `TestReplayedRowsFitRow` (`portscan`, `httprow`) | every ports and http row of every `export.jsonl` decodes strictly |
| `TestReplayRecordedWorkspaces` | each `export.jsonl` stored as two runs, the second with its rows reversed: watch reports no change |
| `TestReplayANewPortIsNamedAtItsAddress` | a port closed in the first run is named at its address, with no other port line |
| `TestReplayRunPairsOfAnUnchangedTarget` | each `pair/` stored as two runs of one workspace: watch and diff report no new or gone port, service, name or URL, and no changed page or product |

The pair test does not filter. When two runs of an unchanged network differ in
a row (a session id, a time, a scan that the cap left partial), the test fails
and lists, for watch, the change lines, and for diff, each added or removed
entity and each kind of row that is new, with the fields of the first example that
differ from the first run's row about the same entity. Judge each: a false
change is a bug of the reader; a difference of the runs themselves is a field
for the volatile list or a reason to fix the run. The rows are loaded into a
scratch workspace by `replayRows` and `replayRun`: map entities and
observations are kept, edges are not (watch and diff read none). The cap can
leave the two runs at different depths of a scan, so a pair of capped runs
may differ for that reason alone.

`go test ./cmd/azhaq -run TestReplayPairFixture` makes a pair of its own on a
local server (two runs, one of them watch's, and the export of each) and runs
the same check, for a change to the reader or to `pair.sh`'s steps; it needs
no folder. `python3 -m unittest discover -s .github/ci/parity` tests `pair.sh`
and the workflow's parts against a stand-in `azhaq`.

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
