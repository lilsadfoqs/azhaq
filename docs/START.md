# Start here

## Before you start

Four jobs, in the order you meet them: a first map, a comparison of two sessions, a check of one service, and the hand-over. Each gives the commands, what to look at, the exit codes to expect and one page to read next. Only test what you are allowed to test. `app.example.com` stands for your target, and `$TA` and `$TB` for the tokens of two of its accounts. `azhaq docs start` prints this page.

Exit codes, for every job: `0` the command finished and nothing failed; `2` the command line was wrong and nothing was sent; `3` something failed or the results are short, and the summary says what; `4` a limit or the kill file stopped it with work left, and `azhaq resume -db FILE` continues it.

## 1. Make a first map

```
azhaq plan -url https://app.example.com/ -allow app.example.com
azhaq run -url https://app.example.com/ -allow app.example.com -max-requests 2000 -rate 5 -db app.db
azhaq query -db app.db -role api,auth
```

`plan` sends nothing: it prints what the run would send and the estimate. `run` writes the rows on stdout and the summary on stderr. Look at the summary's first line, `azhaq run: N map rows … · N requests … · db app.db`, and the `note: ledger:` line under it, which counts what was sent. `query` lists the API routes and the ones that need a session. Expect `0`, or `4` when the 2000 requests ran out.

Next: [Map a single-page app and get its API into Burp](RECIPES.md#map-a-single-page-app-and-get-its-api-into-burp).

## 2. Compare two sessions

```
azhaq roles -dir roles1 -role anon -role "alice=Authorization: Bearer $TA" -role "bob=Authorization: Bearer $TB" -- -url https://app.example.com/ -allow app.example.com
azhaq roles show -dir roles1 https://app.example.com/api/me
```

`roles` maps the target once per role, asks each endpoint with every other role's session, and prints a row for each endpoint whose answer depends on the session: `status:size` per role, then the verdict in brackets. A `-` is a role that was never asked. Read the summary line `azhaq roles: N endpoints listed`. `roles show` prints one row's answers side by side, with a curl line per role; give it a URL from the table (`/api/me` stands for one of yours). Expect `0`, or `3` when a role's session died, which a note names.

Next: [Find IDOR and BOLA with two accounts](RECIPES.md#find-idor-and-bola-with-two-accounts).

## 3. Verify a service

```
azhaq run -url https://app.example.com/ -ports top-100 -allow app.example.com -db app.db
azhaq run -url https://app.example.com/ -ports top-100 -advisories-confirm -advisory-source osv.json -allow app.example.com -db app.db
```

azhaq carries an advisory index, built from public records and dated (`azhaq version` names its date). The first command matches each product and version the run confirmed against it, with no flag, and sends nothing more. The second adds the one read-only request each lead names, and matches the records in `osv.json` (OSV advisory records of your own) as well as the index. Look at the `advisory:` lines after the rows, one for each service, with the count of its advisories by label and its top advisory's id, and the `note: advisories:` line that counts them. A lead is never a proven finding. Expect `0`.

Next: [Known-issue matching](CONCEPTS.md#known-issue-matching--advisories), which says what the index holds and how to refresh it.

## 4. Hand over findings

```
azhaq report -dir roles1
azhaq export -db app.db -format html > app.html
azhaq ledger -csv app.db.ledger.jsonl > sent.csv
azhaq ledger -verify app.db.ledger.jsonl
```

`report` writes one Markdown report per finding of the `roles` run into `roles1/reports`; when no row qualifies it says so, writes nothing and exits `0`. `export` writes the map as one HTML page, and `sent.csv` has one row for every request, connection and query the run sent. `ledger -verify` prints `the chain is intact and sealed` for a ledger that was not altered. Expect `0`.

Next: [Deconfliction and audit](RECIPES.md#deconfliction-and-audit).
