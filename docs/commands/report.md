# azhaq report

Write each finding `azhaq roles` listed up as a report to submit: title, steps with curl, evidence, impact.

Each report is ready to paste into HackerOne or Bugcrowd, or into a red team's client report. `report` reads the evidence the roles run kept in `DIR/roles.db` and sends nothing.

## Synopsis

```
azhaq report -dir DIR [-url URL [-method M] [-owner NAME]] [-format md|json] [-o FILE|DIR] [-redact]
azhaq report -findings -db WORKSPACE.db [-format jsonl|md] [-o FILE]
```

## Examples

```
# one Markdown report per finding, in azhaq-roles-20261028-101500/reports
azhaq report -dir azhaq-roles-20261028-101500

# one row's report on standard output, with hosts and identifiers masked
azhaq report -dir azhaq-roles-20261028-101500 -url https://app/rest/basket/6 -redact

# the findings records of a run's workspace, one JSON object per record
azhaq report -findings -db app.db -format jsonl
```

## What it does

1. Opens `DIR/roles.db`, the evidence store of an `azhaq roles` run. `-dir` is that run's `-dir`.
2. Picks the rows to write up. Without `-url`, a row gets a report when its verdict is one of these seven:
   - `reads another role's object`
   - `writes another role's object`
   - `writes another role's object: accepted; the change cannot be read back to confirm`
   - `anyone writes another role's object`
   - `creates in another role's collection`
   - `create accepted: nothing shows it crosses roles`
   - `anyone reads sensitive fields`
3. Orders the reports by confidence: `proved`, `likely`, `guess`, then rows that carry none.
4. Writes one Markdown report per row. Every piece of a report comes from the evidence; what the evidence does not hold is named in the report.

With `-url URL`, `report` writes that row's report to standard output (a report for each owner when several owners' requests share the URL and method: see below). A write or create row also needs `-method M`. A row whose verdict is not one of the seven is refused, with exit 1, and a `-url` that matches no row is exit 1 too.

When no row qualifies, `report` prints a note on stderr, writes nothing and exits 0.

### Findings records (`-findings`)

With `-findings -db WORKSPACE.db`, `report` writes the findings records of a run's workspace instead of roles reports, and sends nothing. One record is written per qualifying stored row: the `verify` results a `-verify` run stored, and the advisory leads a `-advisories` run stored (labelled as `-verify` labels them), restricted to rows whose label supports a record. A `not affected` lead is no record, and a verify row covers its own lead, so no lead is recorded twice. Each record carries the kind, the severity, the host, port and URL, the product and version where confirmed, the advisory id and URL where matched, the precondition where one is open, the exact request where one was sent, an excerpt of the evidence, the command that produced it, and the collector of the stored row it is read from — every field traceable to that row.

The labels are kept distinct, never merged: `proved` records come first, then `version-only`, then `conditional`. Rows that prove nothing — a map row whose coverage is `hint` and that the map lists — are written as leads, after the findings, under their own type in JSONL and their own heading in Markdown. In JSONL (`-format jsonl`, the same as `json`) each finding is one `{"type":"finding", …}` line and each lead one `{"type":"lead", …}` line; in Markdown (`-format md`) the records are grouped under `## Proved (n)`, `## Version-only (n)`, `## Conditional (n)` and `## Leads — unproved hints`. The counts in those headings are the numbers of records under them, read from the stored rows. A workspace with no qualifying rows writes an explicit empty record set — `{"type":"findings","findings":0,"leads":0}` in JSONL, a sentence saying no qualifying rows in Markdown — and exits 0. The same records are in `azhaq export -format findings` and `-format findings-md`. The labels and the fence behind them are in [Read-only verification](../CONCEPTS.md#read-only-verification--verify).

A hint the map's default view folds is not a lead: an image, font or media file no request asked for (`beyond-depth`), a string only scripts name that nothing requested (`unrequested`), or a route only scripts name whose GET answered 404 or 410 (`not-found`), as in [Folded rows](run.md#folded-rows). The report counts them by class, one line each: `{"type":"folded","class":…,"count":N,"line":…}` in JSONL, a `## Folded hints (N)` section in Markdown, and `N hints folded (class N, …)` after the counts on stderr.

Leads plus the folded counts are the URL rows of `azhaq query -type URL -coverage hint`, a templated row counting for its `count` URLs. A workspace whose hints all fold writes the explicit line with `"folded":N` first, then the fold lines.

## Output

`report` writes files. Without `-url` the reports go to `DIR/reports`, one file each, and stdout lists them. `-o` picks another place. With `-url`, one report goes to standard output instead.

```
$ azhaq report -dir azhaq-roles-20261028-101500
azhaq report: 3 reports in azhaq-roles-20261028-101500/reports
  …/01-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: bob reads alice's book via GET /books/v1/{book_title}
  …/02-proved-get-books-v1-book-title.md  [proved] Broken object level authorization: alice reads bob's book via GET /books/v1/{book_title}
  …/03-unrated-get-users-v1-debug.md  [unrated] Excessive data exposure: anyone reads password via GET /users/v1/_debug
```

### The parts of a report

1. **Title.** It names the bug class. A read is broken object level authorization, and a write adds "(write)", or "(write accepted, not read back)" when the change could not be read back. A create is "Missing authorization on create" only when something shows it: the anonymous role was let to create, or the object it made belongs to the role whose request was replayed. Any other create another role sent is "Create accepted: bob's POST to /books/v1 was accepted", which says what was observed and names no vulnerability. Sensitive fields anyone reads are excessive data exposure.
2. **Summary.** Two sentences.
3. **Severity.** A level labelled a guess, with the reason. Sensitive fields and a write raise it. A create starts low (an accepted create stays a guess at low), and a create rises to medium when a request that carries no credential was let to create.
4. **Steps.** Numbered, with the curl commands from the evidence. The sessions are shell variables: `$ALICE_TOKEN`, `$BOB_TOKEN`.
5. **Evidence.** For the owner's answer, the reader's and the control: status, length and the relevant JSON fields. The control is what a made-up identifier returned.
6. **Reason.** The row's `owner_by`, quoted as why the object is the owner's.
7. **Impact and remediation.** Written by class.
8. **Notes.** Confidence, both ways, and "found by azhaq roles, run DATE".
9. **Missing from the evidence store.** What the evidence does not hold; see Details.

### `-format json`

`-format json` gives the same content as structured fields, one object per report.

| Field | Meaning |
| --- | --- |
| `title` | The report title. |
| `class` | `bola_read`, `bola_write`, `unchecked_create`, `create_accepted` or `excessive_data_exposure`. |
| `method`, `url`, `route` | The row the report is about. |
| `verdict` | The row's roles verdict. |
| `confidence` | `proved`, `likely` or `guess`; `unrated` when roles gave none. |
| `summary` | The two-sentence summary. |
| `severity_guess` | `level` and `reason`. |
| `variables` | The shell variables the curl steps use. |
| `steps` | Each step: `n`, `text`, `curl`, `expect`. |
| `evidence` | One entry per answer; the keys are listed below. |
| `owner_reason` | The row's `owner_by`. |
| `impact`, `remediation` | The text for the class. |
| `notes` | `confidence`, `both_ways`, `found_by`, `run`. |
| `missing` | What the evidence store does not hold. |

Each `evidence` entry has `role`, `kind`, `request`, `status`, `length`, `content_type`, `body_kept` and `fields`. `kind` is `owner`, `reader`, `other` or `control`.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Where the reports go

- Default: `DIR/reports`, one Markdown file per report.
- `-o PATH` is a directory when it ends in a slash, already exists as a directory, or when several reports go to it: one file per report. Without a slash, `-o out` and `-o out/` act the same for several reports. If `PATH` is an existing file and several reports go to it, `report` refuses and says so.
- `-o PATH` for exactly one report, when `PATH` is not a directory: that report is written to the file `PATH`.
- With `-url`, the default is standard output; `-o` sends the report to a file or directory instead.

### What a report never claims

A report never says what the evidence does not hold. It says so under "Missing from the evidence store" when:

- the row has no control;
- a body was not kept;
- the row has no `owner_by`;
- the evidence file comes from an older azhaq, so it has no run date.

A write's before-and-after reads of the owner's object are not kept, and the report says so. A create that was not read back says so too, and a create's report gives no confidence (`unrated`).

`roles.db` keeps one row per method, URL and owner. When two roles both created in the same collection (`POST /books/v1` in each HAR), each owner's row is kept and each gets a report. With `-url`, both are written (to standard output only when one row matches; else to `DIR/reports` or `-o`); `-owner NAME` picks one. A `roles.db` an older azhaq wrote keeps one row per method and URL, and is read as it is.

### Redaction

`-redact` is for a report that leaves the engagement.

- The host becomes `<host>`.
- The identifier in the route and the values of identifier fields in the kept bodies become `<id-1>`, `<id-2>` and so on. Identifier fields are `id`, `*Id`, `username`, `owner`, `email` and similar.
- Any token is removed.
- Role names stay: they are the tester's own labels.

Read a redacted report once before sharing it. An identifier that no kept body names in an identifier field is not masked.

## Flags

<!-- flags:begin report -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-findings` | bool |  | write the findings records of a workspace instead of roles reports: one record per stored row whose label supports it (a -verify run's results and a -advisories run's leads), proved first, version-only and conditional kept distinct, unproved hints listed as leads; a workspace with no qualifying rows writes an explicit empty record set and exits 0 |
| `-db` | string |  | with -findings: the workspace database the records are read from |
| `-dir` | string |  | the -dir of the roles run (it holds roles.db) |
| `-url` | string |  | write up this one row (its URL as roles lists it); every cross-role finding by default |
| `-method` | string |  | the method of a write row (-replay-writes); a read's row by default |
| `-owner` | string |  | with -url: only the row of this owner, when several owners' requests share the URL and method (two roles creating in one collection); a report for each owner by default |
| `-format` | string | `md` | md or json |
| `-o` | string |  | FILE or DIR for the reports: a directory (it exists, ends in a slash, or several reports go to it) gets a file per report, any other path is the file of a single report; without -url, DIR/reports; with -url, standard output |
| `-redact` | bool |  | also mask hosts and identifiers (a report to share outside the engagement) |
<!-- flags:end -->
