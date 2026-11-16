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

### Which URLs are the same

Each URL is asked as it was written, and stored so. `diff` compares two runs by an identity of it, and one URL stands for each identity (the first by its spelling):

- The order of the query names is not part of it: `latest.php?sort=name&filter_rst=1` and `latest.php?filter_rst=1&sort=name` are one URL. A name written twice keeps the order of its values. The two spellings are still two requests when a page links both ([run](run.md#where-the-requests-go) asks each as written).
- A value that is a token by its shape is not part of it: hex of 16 characters or more, or 16 characters or more of the base64 alphabets that mix digits, lower and upper case. `index.php?sid=f34f757d65d157eb` and `?sid=d243c53758192467` are one.
- A number that changes between the two runs is not part of it, where a URL is new and another gone in the same place with the same query names and every value that differs is a number (`login.seam?conversationId=2` and `?conversationId=7`). They are counted as one URL, not as added and removed: the text report says how many (`= N URLs are in both runs with another number in their query`) and the summary has `paired_urls`. That name is then left out of the URLs the rows name (a redirect's `Location`, a link), in this comparison. Any other value, and a number with no partner (a page that is new), is a difference.
- The servlet session path parameter (`;jsessionid=`) and a fragment are not part of it.

`watch` is coarser on purpose: it ignores every query value and folds identifiers in the path ([which URLs are the same](watch.md#which-urls-are-the-same)). `diff` lists each URL, so it keeps the values that are not tokens or measured numbers.

### What is not compared

- Bodies are not compared byte for byte. Timestamps and tokens would make every run a change.
- A catch-all row's control is compared by its answer (status, type, title). The path it was asked for, the directory that path was in (a page's control is the site root's or its own directory's, whichever was asked first), and the size an echoing page gives it, are not compared.
- What records when or how a row was asked, not what the target answered, is left out, by the type of row:
  - Every row: `asked_at`, `observed_at` and a proof's `observed_at`, and an answer's `ms`, `response_headers`, body bytes and sizes (`body_excerpt`, `body_length`, `body_hash`, `length`, `words`, `lines`), `head` and the other fields of one request's bytes.
  - A web answer (`azhaq-http`): `cookies`, the ones the answer set (a server hands its session cookie to the first request that has none). A request that failed: the text of a timeout without the part Go adds for where it ran out (`(Client.Timeout ...)`).
  - A web link or redirect: every URL in the row is compared by its identity above.
  - A form (`azhaq-crawl`): a field name that is a token, as Joomla's anti-forgery field is, is one name `{}`. A secret a script holds (`azhaq-js`) whose value is such a field name on a page of the same run is that token, and its `value`, `context` and `entropy` are left out. A secret no form names is compared.
  - A port scan row (`azhaq-ports`): a checkpoint (`checkpoint: true`) is the scan's progress when it was kept, the ports done so far, and is skipped; the scan's own row follows it and is compared.
  - A verify read of DNS (`azhaq-verify`): the bytes of the request and the answer (`proof.request_bytes`, `proof.excerpt`, `proof.reproduce`, and `evidence` when it is bytes) start with a random message id, and are left out. The `label`, `product`, `version`, and a text `evidence` such as `rcode REFUSED` are compared.
  - The path checks' record (`azhaq-paths` `sweep`): how many checks were `sent`, `answered` from an earlier request or `described`, and `product_checks.sent`. The crawl runs at the same time, so a check it had asked first is answered from its cache in one run and sent in the other. `planned` and `product_checks.listed` are compared.
  - An advisory row (`azhaq-advisories`): `origin`, the name of the address the confirming read was sent to; an address with several names is scanned under each in no fixed order. `names`, `host` and `port` are compared.

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
