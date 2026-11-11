# Workflow trials

`trial.yml` runs five kinds. The first line of the tag's message picks one;
`.github/ci/run.sh trial NAME KIND` writes it.

| Kind | What happens | Brief |
| --- | --- | --- |
| `gate` | The current trial: one persona, one build, two parts - part A (`gate-a`), an engagement on one Vulhub estate drawn from the fixed pool, graded against the estate's baseline; part B (`gate-b`), the switch checklist head-to-head on the local labs. `samples=N` (N from 1 to 4) runs both parts N times, part A on N different pool estates, two sessions at a time (`max-parallel: 2` on each part, because the jobs share one Codex sign-in). The release review runs `samples=4`. | `GATE.md` |
| `baseline` | Part A's engagement again, usual tools only, azhaq off, on one pool estate: measures that estate's baseline once. `samples=N` measures N pool estates, two at a time (parts `a1`..`aN`). | `GATE.md` (usual tools) |
| `switch` (default) | Older, kept working: a blind review of the latest release against five training apps, one build, one job. | `BRIEF.md` |
| `research` | Older, kept working: a researcher does two phases of an engagement on two fresh estates. Phase 1, estate 1: usual tools only, azhaq not run. Phase 2, estate 2: azhaq used as the main tool; every fallback to another tool is logged with its reason. | `RESEARCH.md` |
| `hunter` | Older, kept working: the same estates as two bounty sessions, in the opposite order: azhaq first, the usual stack second with azhaq off. | `HUNTER.md` |

```
.github/ci/run.sh trial 20 gate                  # tag trial-20, kind gate, one estate
.github/ci/run.sh trial 21 gate seed=gate-alpha samples=4   # four estates, four samples
.github/ci/run.sh trial b-alpha baseline seed=gate-alpha    # the pool estate's baseline
.github/ci/run.sh trial b-all baseline samples=4            # all four pool estates, two at a time
.github/ci/run.sh trial dry1 gate dryrun         # build, estate, isolation and briefs, no agent
.github/ci/fetch.sh trial 21 /tmp/t21      # DIR/a1..a4, DIR/b1..b4 (DIR/a, DIR/b on samples=1)
python3 .github/ci/range/grade.py /tmp/t21/a1/key.json /tmp/t21/a1 --baseline /tmp/b-alpha
python3 .github/ci/range/merge_gate.py /tmp/t21 --samples 4  # per-item medians, every sample's scorecard

.github/ci/run.sh trial 11 research              # the older kinds still work
.github/ci/run.sh trial 12 hunter seed=lilac     # a fixed draw
.github/ci/fetch.sh trial 11 /tmp/t11
python3 .github/ci/range/grade.py /tmp/t11/key.json /tmp/t11
```

`research`, `hunter` and `switch` draw a secret estate (a keyed hash of the
tag) unless `seed=` fixes it, so the public catalog and the public tag name do
not give the estate away. `gate` and `baseline` instead draw from the fixed
pool (below); their `seed=` must name a pool entry.

## The gate's pool and the four baselines

`range/pool.json` is a committed list of seeds (four to start). `gate-a` and
`baseline` build one estate (`build.py SEED --count 1`) from a pool entry,
chosen by `range/pool_pick.py`: the tag's `seed=WORD` when it names a pool
entry, else round robin by the run number, so repeated gate runs cycle
through the whole pool. `samples=N` draws the next entries too: the pool entry
right after the first one for sample 2, and so on, so the samples are different
estates while N is at most the pool's size (`pool_pick.py --sample K`, K from 1
to 4; with the pool at four entries, `samples=4` draws all of them, and a larger
N is refused, by the `kind` job before anything is built).

The pool's names are public, the estates are not: a name goes through the
same keyed hash as research's draw (the secret is CODEX_AUTH_KEY) before
build.py, so reading the repository does not tell which applications an
estate holds. Changing that secret changes every estate, and the baselines
are measured again. Because the pool is fixed, each estate's usual-tools
result can be measured once and kept: push `trial-baseline-X baseline seed=POOL-ENTRY` for
each of the four entries (`.github/ci/range/pool.json`), fetch each
(`fetch.sh trial baseline-X /tmp/baseline-X`; or `samples=4` on one tag runs
all four, `fetch.sh` brings back `a1`..`a4`, each one a folder like the one below), and keep `/tmp/baseline-X`
(its `REPORT.md`, `leads.jsonl`, `surface-1.txt`, `phases.log`, `key.json`
and a `grade.py` run against its own `key.json`) beside the pool so a later
gate run's `grade.py --baseline` has something to compare against. A pool
entry's baseline only needs redoing when `catalog.json` or the entry's
Vulhub pin changes enough to change what that estate is.

## Part A and part B, one build

`gate`'s `build` job compiles azhaq from the tagged commit (any branch, or
`next`; no release needed) and uploads it as an artifact. `gate-a` and
`gate-b` each download it before isolating the agent and removing the
source, so neither review installs it: part A keeps that time for the
engagement, and part B's "install and first run" score reads the first
commands run against `./bin/azhaq`, not an install. The install script
itself is checked separately, against a `goreleaser --snapshot` build, by a
job in `ci.yml` (`azhaq version` after `scripts/install.sh -f DIST_DIR`).

`gate-a`'s brief is `GATE.md`'s part A section (single phase, about 90
minutes, `leads.jsonl` and `surface-1.txt` as the older `RESEARCH.md` and
`HUNTER.md` ask); `gate-b`'s is part B (the switch checklist, `BRIEF.md`'s
wording, minus the install checklist item). `range/render_brief.py gate-a`
and `gate-b` render them; `baseline` renders part A with the usual-tools
wording instead of azhaq's.

`fetch.sh trial NAME DIR` brings every part back: `DIR/a`, `DIR/b` (or
`DIR/a1`..`DIR/a4` and `DIR/b1`..`DIR/b4` on `samples=N`), each decrypted and
unpacked. `merge_gate.py DIR` reads both parts' `REPORT.md` scorecards (a
Markdown table, as `GATE.md` asks for), matches each row to its anchor line,
computes one overall (the lowest score; the gate needs every one at 9 or
more), and, when `DIR/a/grade.json` holds a `--baseline` comparison, adds it.
With several samples it first prints "Per-item medians" (each item's scores,
median and spread, and the lowest median), then the grade beside its baseline
with a row per sample, then every sample's scorecard. The verdict does not use
the medians: every sample must show a pass for the gate to pass, and a missing
sample (a gap, one part only, or fewer than `--samples N`) is not a pass.
While a run goes, only two sessions run at a time, so `watch.sh` needs
`WATCH_EXPECT="a1 a2 a3 a4 b1 b2 b3 b4"` to wait for the queued parts.

## The estates

Built from Vulhub (MIT), pinned to the commit in `.github/ci/range/catalog.json`.
`build.py` draws one or two disjoint estates (`--count`) of ten environments
each with the same category mix and a memory budget for all of them
together. Each has a random `.test` domain, a /24 of loopback, one address per
host, product-named and neutral host names (some under a `dev.` or `stg.`
subzone, sometimes with a wildcard), a few services on non-default ports, three
names served only by an nginx reverse proxy by Host, two dangling CNAMEs and
PTR records for some hosts. The zone's two name servers (`ns1`, `ns2`) have
addresses inside the /24 that no host uses. One `bench/labdns` resolver per
estate serves its zone (`-zone`): at 127.0.0.1:5301 (and :5302 for a second
estate), as given to the reviewer, and on port 53 (UDP and TCP) of its name
servers, so a zone transfer asked of the zone's own name servers stays inside
the company's range (the binary has `cap_net_bind_service`; the fence allows
those addresses on port 53). The company's name servers always refuse a
transfer; a planted Vulhub BIND that allows one serves its own zone on its own
host. `up.py` starts everything and records which probes answered in the key;
the grader leaves out what was not up.

In `research` and `hunter`, azhaq's latest release is installed into the
reviewer's workspace (`./bin/azhaq`) before the review, with
`scripts/install.sh --require-signature`; installing it is not part of the
timed work in these two kinds (it is in `switch`, where it is a scored item).
`gate` installs nothing (above): the build job's artifact is already there.

Placeholders filled at run time: `__VERSION__` (the release or, for `gate`
and `baseline`, the tag under test), `__DOMAIN1__`, `__NET1__`, `__DNS1__`
(and `__DOMAIN2__`, `__NET2__`, `__DNS2__` for a second estate),
`__PHASE1_TOOLS__`, `__PHASE2_TOOLS__` (`research`, `hunter`),
`__ENGAGEMENT_TOOLS__` (`gate`, `baseline`) (`range/render_brief.py`; it
fails if any is left).

## Isolation

The `work` job (research, hunter), the `codex` job (switch), `gate-a`,
`gate-b` and `baseline` do these before the agent starts, and
`range/isolate.sh` fails the job when any check does not hold. The switch
review gets the same: its labs are made ready first (`lab_ready.py`: VAmPI's
database created, DVWA's set up, each checked with a login), nmap is
installed, and a copy of each app's source is put in its folder
(`./lab-source`) because it cannot `docker cp` any more.

| Step | How it is verified |
| --- | --- |
| nmap and the other tools that need root are installed first | the job installs them; the agent has no sudo afterwards |
| `/proc` is mounted with `hidepid=2` | no process of another user is listed in /proc, and a canary process of user `nobody` is not visible |
| the docker socket becomes `root:root 0600`, the user leaves the docker group | `docker ps` fails, the socket cannot be opened, nothing listens on 2375/2376 |
| the user's sudo rights are removed (sudoers files, groups) | `sudo -n true` fails, `su root` without a password fails |
| the answer key is encrypted to the maintainer's age key; the plaintext, the build folder and the Vulhub checkout are deleted | the agent's folder starts empty and the key leaves only as `key.json.age` |

Containers, the proxy and the resolvers run as root or as `nobody`, so
`hidepid` hides them from `ps`. What is not hidden: the kernel's table of
listening sockets (`ss`, `/proc/net/tcp`) and the network interfaces. The
grader lists every command in the agent's log that touches docker, processes,
sockets, interfaces, privilege or the outside (`gh`, `git push`), for a person
to judge. Job logs are public: build, start and isolate print counts only.

## Heartbeat

The review of any trial kind writes no log until it ends. A loop
(`heartbeat.sh`) publishes counts every 10 minutes to
`trial/trial-NAME/heartbeat.txt` on ci-results (or `trial/trial-NAME/PART/heartbeat.txt`
for a gate or baseline part: `a`, `b`, or `a1`..`a4`/`b1`..`b4` on `samples=N`);
`.github/ci/beat.sh trial NAME [PART]` prints it: UTC time, minutes since the
stream began, whether `codex` runs, the stream's lines and the seconds since
its last line, the commands completed, `phases.log`, load and free disk. No
command, no stream text, no estate data. It runs as root from `/root` with the
token in a root-only file, started before `isolate.sh`, which checks that the
file is unreadable and the process unlisted; the review's files are read as
the agent's user and `phases.log` is cut to its `phase N start|end TIME` lines
(the switch and gate-b reviews have no `phases.log`, so that part is empty).
The stream of every kind is `stream.ts.jsonl`, one epoch second in front of
each line.

`.github/ci/watch.sh RUN...` polls one or more trial tags until every one is
done (its result is already on ci-results) or looks stuck (a heartbeat shows
no new stream line for a while and codex is not running), then prints one
line per run and exits; it never hangs (every network call is time bounded,
and it gives up after a deadline, default 6h).

## What comes back

`REPORT.md`, `leads.jsonl`, `phases.log`, `surface-*.txt`, `notes/`, the last
300 lines of the stream, the whole stream (`stream.ts.jsonl.gz`, up to 40 MB),
and `key.json`. Every stream line starts with the epoch second it arrived, so
the grader measures the time to a finding from the command that wrote the lead.

`grade.py KEY DIR` prints a Markdown table and writes `DIR/grade.json`: per
phase the share of hosts, ports and services in `surface-N.txt`, the
vulnerabilities identified (a lead's host or address, port and CVE or product
match a key entry), the leads that match nothing (listed, not counted as wrong),
the seconds to the first match and to each, and the commands run. `--baseline
GRADE.json` (or a directory holding one) adds a phase-by-phase comparison
against another run graded with the same key, for a fair before/after.

## The catalog

`range/catalog_gen.py VULHUB_DIR` writes `catalog.json` from a Vulhub checkout
(needs PyYAML). Push `range-smoke-NAME` (`run.sh range-smoke NAME`) to start the
environments on four runners and record readiness, seconds to answer, memory
and image size; then
`python3 .github/ci/range/smoke_apply.py DIR/smoke-*.json` keeps only the entries that passed.

Tests: `python3 -m unittest discover -s .github/ci/range` (set `VULHUB` to also
render every override with `docker compose config`).

## Scores

From the trials of v0.13.0 on, the briefs give the reviewer anchors for each
score (10: hand the job over; 9: at least as good as the usual tools on all
that was measured, nothing that stops relying on it; 7 to 8; 5 to 6; 3 to 4;
1 to 2), and each score names what kept it from the next one. Scores before
that had no anchors: compare across that line with care. The gate passes when
every merged score is 9 or more and no safety cap applies; the review before
tagging a release runs `samples=4` and all four samples must pass.

## The score history

Every review part writes a second, small record beside its archive: the
numbers of its scorecard (`range/scores.py extract`), encrypted to the same
key as the archive, as `trial/NAME[/PART]/scores.json.age` on ci-results (gate
parts, baseline and switch; not in the repository or an issue). `fetch.sh`
decrypts it to `scores.json` next to `REPORT.md`. `history.sh [N]` fetches only
those records of the last N reviews (not their archives) and prints each item
across them, one cell per review, with the spread between the samples of a
review (`7/9 (spread 2)`) and the range of the reviews' means. Two samples of one
build have differed by two points on the same item: a change inside that
spread is no trend. A review from before the records has none: fetch it and
`python3 .github/ci/range/scores.py history DIR` reads its `REPORT.md`.

```
.github/ci/history.sh 10
```

## Before tagging a release

The release workflow refuses a tag whose commit has no passing `checklist`
run. That workflow runs the review's capability checklist as commands
(`go run ./bench -checklist`: exit codes, counts that must agree, scope,
GET-only mapping, writes only with their flags, `-deny-path`, a lost session,
the MCP lock, the budget, the kill switch; `bench/README.md` lists what it
covers and what it does not) on every push to `next`, so a merged commit
usually has one. For the commit to tag, if it has none:

```
.github/ci/run.sh checklist v0-14-0       # a tag checklist-v0-14-0, under 20 minutes
```

then the `gate` trial with `samples=4`, then the tag.
