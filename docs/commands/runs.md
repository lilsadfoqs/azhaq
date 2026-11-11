# azhaq runs

List the kept runs, newest first: what each was pointed at, how it ended, what it sent and what it found. Remove old ones.

## Synopsis

```
azhaq runs [-json] [-limit N] [-home DIR]
azhaq runs -rm ID ... | -older 30d
```

## Examples

```
# the kept runs, newest first
azhaq runs

# the last five, as JSON
azhaq runs -json -limit 5

# remove the runs older than a month
azhaq runs -older 30d
```

## What it does

Each command that sends to targets or makes a workspace keeps its run in one folder:

```
./.azhaq/runs/20261108-183603-run-testphp.vulnweb.com/
  run.json                    what was asked, when, how it ended, the summary
  workspace.db                the graph (query, show, export, ui read it)
  workspace.db.ledger.jsonl   every request it sent
  roles/                      roles: one database per role
```

These commands are kept: `quickstart` (and `azhaq TARGET`), `run`, `resume`, `roles`, `watch`, `ingest`, `subs`, `dns`, `probe`, `crawl`, `urls`, `ports`, `dirs`, `fuzz`, `params`, `asn` and `shots`. The commands that read a workspace or serve are not kept.

- The home is `$AZHAQ_HOME`, else `.azhaq` in the current directory, so each folder keeps its own runs.
- `runs`, `ui`, and `query`, `show`, `export` and `diff` without `-db` read the folder you are in. `-home DIR` reads another folder's.
- `AZHAQ_HOME=~/.azhaq` gives back one home for the whole machine.
- `AZHAQ_HOME=none` turns keeping off: each command then works as it did before, in the current directory or a temporary folder.
- When the current directory cannot be written and no `-db` or `-dir` was given, the run fails before it sends anything and the message names `-db DIR/x.db` and `AZHAQ_HOME`. It does not keep the run somewhere else.
- In a folder with no runs, `runs` says no runs are kept there and names `-home DIR` and `AZHAQ_HOME`; `ui` says the same and exits 1.
- A workspace given with `-db`, a folder given with `-dir` and the files of `-o` stay where they are named. `run.json` records their paths.
- A folder is mode 0700 and `run.json` is mode 0600. A session or cookie given on the command line is masked in `run.json`.
- A command refused for its flags (exit 2) leaves no folder.
- A command ending in a terminal says where it was kept, on its last stderr line.

`runs` reads `run.json` of each folder. A folder with no `run.json` is left alone, by the list and by `-rm`.

## Output

One row per run, newest first:

| Column | What it is |
| --- | --- |
| `ID` | The folder's name: the time, the command and the target. |
| `WHEN` | When it started, local time. |
| `STATUS` | `ok`, `exit N`, `running`, or `did not finish` (the process ended before it could record how). |
| `TIME` | How long it ran. |
| `REQUESTS` | The requests to targets, from the run's own summary. |
| `GOT` | The summary's counts, the largest first. |

With `-json`, each line is a run's `run.json`. With `-rm` or `-older`, each folder removed is named on stderr.

## Flags

<!-- flags:begin runs -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-json` | bool |  | one JSON object per run: its run.json |
| `-home` | string |  | the run home to read (default $AZHAQ_HOME, else .azhaq in the current directory) |
| `-limit` | int |  | list at most this many runs (0: all) |
| `-rm` | string, repeatable |  | remove this run's folder (repeatable): its workspace and files go with it |
| `-older` | string |  | remove the runs that started more than this long ago (30d, 12h) |
<!-- flags:end -->
