# azhaq ui

See the kept runs in a browser: what each asked, did and got, and its graph on a canvas.

## Synopsis

```
azhaq ui [-listen 127.0.0.1:7190] [-home DIR]
```

## Examples

```
# serve the runs of ~/.azhaq, then browse to http://127.0.0.1:7190/
azhaq ui

# on any free port
azhaq ui -listen 127.0.0.1:0

# the JSON API from a script
curl -s http://127.0.0.1:7190/api/runs
```

## What it does

`ui` serves the runs that [`azhaq runs`](runs.md) lists to a browser on this machine. It reads the run home, each run's workspace and its ledger. It sends nothing to any target.

- The page is embedded in the binary and works offline: no CDN and no external font.
- The page's `Content-Security-Policy` lets the browser load only its own script and style, and talk only to the ui's own address.
- `-listen` takes a loopback address only, and the server answers only requests that name a loopback host.

## The page

On the left are the runs, newest first. A run shows three sentences:

| Line | Where it comes from |
| --- | --- |
| Asked | The command line from `run.json`, with secrets masked. |
| Did | The ledger lines written while the run ran: requests to targets and to how many hosts, queries to third-party sources, DNS queries, the time and the exit code with its meaning. With no ledger, the summary's own counts. |
| Got | The entities of the run's workspace by type, how many were new, the findings and leads, and the map hints. |

**Details** lists the folder, the workspace, the files written, the requests by purpose and by host, and the summary's failures, notes and next commands.

Below is the run's graph on a canvas, in columns: organisations and prefixes, domains, hosts, addresses, ports, then routes and services.

- A host's routes fold into one node when it has more than 8 (more than 2 when the run holds over 60 routes). A click opens the node.
- Routes that answered 401, 403, 404 or 410 fold into one muted node per host. So do the names that led to no address in the run.
- A red node holds a finding (proved, version-only or conditional) or a lead above severity info.
- A yellow dot is a map hint: a place to look, not a finding.
- A blue outline is an entity first seen while this run ran, shown when the workspace holds older runs too.
- A dashed outline is an entity seen through third-party sources only.

Drag to move, scroll to zoom, hover to light a node's links. A click on a node opens its observations: what saw it, from where, and what it recorded, with cookies, tokens and authorization values masked. A route also gets a `curl` line to check it by hand. The search box lights the matching nodes and opens the folds that hold them.

Every number on the page is a count of the run's summary, workspace or ledger. A number the run did not record is said to be not recorded.

## The JSON API

| Endpoint | What it returns |
| --- | --- |
| `GET /api/runs` | `home` and `runs`: `id`, `command`, `target`, `started`, `status`, `exit`, `time`, `requests`, `got` |
| `GET /api/runs/ID` | `record` (the run's `run.json`), `status`, `time`, `dir`, `exit_meaning`, and `ledger` (`lines`, `by_class`, `by_kind`, `by_purpose`, `hosts`, `sources`) |
| `GET /api/runs/ID/graph` | `nodes` (`id`, `type`, `key`, `new`, `passive`, `status`, `lead`, `hint`, `obs`) and `edges` (`from`, `to`, `type`) |
| `GET /api/runs/ID/node/NODE` | `entity`, its `observations` with secrets masked, and `curl` for a route |

## Summary and exit codes

| Exit | When |
| --- | --- |
| 0 | Stopped with Ctrl-C. The ui is a server: a signal is its normal end. |
| 2 | `-listen` is not a loopback address, or keeping is off (`AZHAQ_HOME=none`) and no `-home` was given. |

## Flags

<!-- flags:begin ui -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-listen` | string | `127.0.0.1:7190` | the loopback address to serve on (127.0.0.1:0 takes any free port); another address is refused |
| `-home` | string |  | the run home to show (default $AZHAQ_HOME, else ~/.azhaq) |
<!-- flags:end -->
