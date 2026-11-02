# azhaq resume

Continue a run that was interrupted or stopped by a limit.

## Synopsis

```
azhaq resume -db FILE [run flags to add, such as -cookie or -max-requests]
```

## Examples

```
# Continue a run, with more requests allowed
azhaq resume -db app.db -max-requests 2000
```

## What it does

1. Opens the workspace given with `-db`, which is required.
2. Finds the run that has work left. If every run finished, it says so and exits 1. When no task is left but failed targets are retryable (in the newest run, else in an earlier one, which it names), it says `no task left in DB, but N failed targets are retryable` and names `-retry-failed`, still exiting 1.
3. Reads the run's flags back from the database. Flags given here are added and win. A flag the stopped command spells differently from `run` is read by the command's own name: for a `ports` run, `-rate`, `-min-rate`, `-workers`, `-c`, `-connect-timeout` and `-retries` replace the pace it was stopped at; for `dirs`, `-rate` and `-t`; for `params`, `-rate`. `-max-items`, `-max-names` and `-max-requests` hold for each run: a resume may start as many more tasks as it is given, so a resume at the same cap goes on. A larger `-depth` asks the URLs and names the stopped run found past its own.
4. Continues the targets the run started with. A `-list` given here replaces them.
   What this resume leaves out applies to the tasks the run kept: `-skip` (which adds to the collectors the run skipped), `-passive`, and an active technique whose flag is not given do not run theirs. Those tasks end here and a note in the summary counts them.
5. Continues a stopped `fuzz` run with its own command, a stopped port scan with the ports it has not asked (a scan keeps the ports it has finished about every second as it goes, so after a kill too the resume asks the ports after them; a port that timed out is not among them, and is asked again), a stopped range scan with the addresses of its blocks it had not finished (the stopped block's row keeps them, those that answered nothing included, so no address is asked twice), and a stopped `dirs` sweep with its words. A word whose answer the run stored is answered from the database: it takes no `-rate` slot and no request budget, so a resume at `-rate 20` replays 200 stored words at once and only the words not yet asked are paced.
6. After a run that was killed (SIGKILL, a crash: its ledger has no seal at the end), reads the ledger lines after the last seal. Reads that had no stored answer are asked again, and so are the connects of a port scan that came after the last ports it had kept; the summary says how many (`N connects made before the run was killed had no stored answer ... and were asked again`). Writes are never sent again: each is held back, listed under `skipped`, and the summary says so. See [Workspaces, runs and resuming](../CONCEPTS.md#workspaces-runs-and-resuming).
7. Prints a line on stderr: `azhaq: resuming run ID of DB, N tasks known and not done`. `-json` leaves it out.

## Output

As the command that started the run. A run that `ports` started prints the open ports it finds, as `ports` does, and one that `dirs` started prints the paths it finds, as `dirs` does (the summary's `command` is `ports` or `dirs`, `results` the rows this run printed). Rows an earlier run printed are not printed again, so the rows of the runs add up to one run's. A run that `probe`, `crawl`, `params`, `shots`, `urls`, `subs` or any other command started names that command in the summary's `command` and prints the rows of the map, as `run` does, not that command's own rows; a note says so, and `azhaq query -db FILE` lists what the run found. A run started with `run` prints as `run`. `-json` prints objects. `-quiet` prints only the summary.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Retrying failed targets

A request that failed is a finished task, so a plain `resume` does not ask it again. `azhaq resume -db FILE -retry-failed` does:

- It reads the newest run of the workspace, and says which run on stderr and in the summary's note. `-retry-run ID` (the `run_id` of an earlier run's summary, or the start of it) asks the failed targets of that run instead: a later command on the workspace is the newest run, and its own failures, or none, are what a plain `-retry-failed` finds. When the newest run has nothing retryable and an earlier run has, the error names it: `run ID has 1 retryable failed target: azhaq resume -db FILE -retry-failed -retry-run ID`. The run asked again is the one continued, whichever run is the newest.
- It asks again the failed targets the summary marks `retryable`: a timeout, a closed connection, an answer cut short, a 429 or a 5xx. Each target's task runs again with the failure it recorded dropped, and a stored 429 or 5xx answer is not read back. Targets that failed in a way a retry cannot fix are not asked, and stay in `failed` as they were. It exits 1 with `nothing to retry` when none is retryable.
- It goes with the tasks a limit left: both run in one resume. The summary's `notes` says `-retry-failed: N failed targets of run ID asked again, M still fail`, and what still fails is in `failed` again, with exit 3. A limit that stops the resume first leaves the rest as tasks, which the next `resume` continues.
- The retried requests count against `-max-requests` and are in the ledger like any other.
- It applies to the run's own tasks. A `ports` or `dirs` sweep continues its unfinished addresses and words with a plain `resume`.

### Which flags come back

- The run's flags are stored without its secrets: `-cookie`, `-login-pass`, `-worker-token`, the password (the whole `user:password@`) of a proxy URL (`-proxy`, `-source-proxy`, `-chrome-proxy`, `-urls-proxy`, `-port-proxy`), and a `-header` whose name holds `auth`, `cookie`, `token`, `key`, `session`, `secret`, `csrf` or `xsrf`. Give them again after `-db`; `-login-pass` and `-worker-token` are also read from `$AZHAQ_LOGIN_PASS` and `$AZHAQ_WORKER_TOKEN`. The answers a run keeps for its resume (`probe`'s too) hold the requests without those headers and without their body.
- A `fuzz` workspace keeps its command the same way: `-b` and `-cookie`, a `-H` of that kind and a proxy URL's credentials are left out (`-x`, `-proxy`, `-replay-proxy`), files (`-w`, `-request`, `-preflight`, `-ledger`, `-o` and the others) are stored by their full path, and the database is the one given to `resume`. Give the secrets again after `-db` (`fuzz` reads none from the environment). A resume that was not given what the run had says so in a note. What a resume is given for itself (`-quiet`, `-max-requests`) is not kept for the next one.
- `resume` takes run's flags, and gives them to a stopped `fuzz` as it spells them: `-quiet` prints no matches and no progress, only the summary, and run's `-timeout` (the run's bound, a duration) is `fuzz`'s `-maxtime`.
- Files and directories are stored as full paths, so `resume` works from another directory.
- A `-list` file is also copied into the workspace. If the file is gone or changed, the run continues the copy, and a note says so.
- `-all-gets` and `-get-words` are dropped from a run an older azhaq stored, with a note: every GET found in scope is requested now.

## Flags

<!-- flags:begin resume -->
`resume` takes the flags of [`run`](run.md#flags): the run's flags are read back from the database; flags given here are added and win.
<!-- flags:end -->
