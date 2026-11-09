# azhaq diff

Compare two runs: the entities added and removed, what was there in both and changed, and the new observations.

## Synopsis

```
azhaq diff -a OLD.db -b NEW.db | -db WORKSPACE.db [-run ID]  [-json] [-quiet]
```

## Examples

```
# Compare the last two runs of a workspace
azhaq diff -db acme.db

# Compare two database files
azhaq diff -a old.db -b new.db

# Print added, removed and not_seen_again rows and a summary as JSON lines
azhaq diff -db acme.db -json
```

## What it does

1. Takes two runs: the last two recorded in a workspace (`-db`; `-run ID` takes the run its `run_id` names and the run before it), or `-a` (old) and `-b` (new, default the last run).
2. Lists the entities that were added and removed, what changed, and the new observations. `-quiet` prints entities, changes and counts only.
3. Compares a web page's answer by its status and title.
4. Compares a JSON listing's answer by its status, its title and how many items it holds (`json_items`). `watch` reports it as `/users/v1: [200] 5 items → [200] 6 items`.

A workspace with only one run says so: a diff needs two.

## Output

The text report lists the entities added and removed and the new observations.

`-json` (or `-jsonl`, the same flag) prints one JSON object per line, the `summary` last:

| Row | Meaning |
| --- | --- |
| `added` | An entity in the newer run and not in the older. |
| `changed` | Something that was there in both runs and differs. See Details. |
| `removed` | Something that answered in the older run and is gone from the newer. See Details. |
| `not_seen_again` | Something the older run only heard of and never checked. See Details. |
| `summary` | The totals, `changed` among them. It names the `failed_sources` of the newer run. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### What counts as removed

- `removed` is what answered in the older run: a name that resolved, a page with a status, a host with open ports.
- It is gone from the newer run.

### What counts as not seen again

- `not_seen_again` is what the older run only heard of: from a subdomain source, an archive or a link. The run never checked it.
- Sources answer differently from day to day, and they fail. Its absence says little.

### What counts as changed

`changed` is what `watch` lists under `~`, counted the same way, so `diff` and `watch` agree on the same two runs. Each `changed` row has a `what`:

- `route`: an API route a script calls whose methods or whose query and body names changed (`change` says `methods` or `fields`). A route that is new or gone is an entity added or removed, not a change.
- `page`: a page that answered in both runs with another status or title, or a JSON listing with another item count.
- `ports`: a host whose open ports differ between two runs that both scanned it.

### What is not compared

- Bodies are not compared byte for byte. Timestamps and tokens would make every run a change.
- A catch-all row's control is compared by its answer (status, type, title). The path it was asked for, the directory that path was in (a page's control is the site root's or its own directory's, whichever was asked first), and the size an echoing page gives it, are not compared.

## Flags

<!-- flags:begin diff -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | workspace: compare the last two runs recorded in this database |
| `-a` | string |  | old sqlite |
| `-b` | string |  | new sqlite (default: last run) |
| `-json` | bool |  | JSON lines instead of a text report, the summary last |
| `-quiet` | bool |  | entities and counts only (skip observation lines) |
| `-run` | string |  | with -db: the run to compare with the run before it, by the run_id of its summary (default: the last) |

<details>
<summary>Other names (1)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-jsonl` | bool |  | same as -json | other name |

</details>
<!-- flags:end -->
