# Contributing

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
type(scope): what changed, in 72 characters or fewer

Why, and what it did before. Wrap at 100 characters.
```

- **type**: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `bench`, `ci`, `build`, `chore` or `revert`.
- **scope** (optional): the command (`fuzz`, `roles`, `mcp`) or the package (`portscan`, `webextract`). Omit it when a change spans the tool.
- **subject**: lower case, no period, says what the tool now does.
- **body**: for anything that is not obvious from the subject: the behaviour before, the reason, the evidence. The CHANGELOG line is written separately, under `## Unreleased`.
- A breaking change to output or flags gets `!` after the type or scope and a `BREAKING CHANGE:` paragraph.

Examples:

```
fix(fuzz): hold host headers to the scope

-H 'Host: secret.lab' with -deny secret.lab sent both requests. Every
command that sends headers now refuses a host outside the scope before
anything goes out.
```

```
perf(ports): identify open ports while the scan goes on
docs(output): split the command fields into one page per command
ci: run commitlint on every push
```

The check runs twice: as a `commit-msg` hook, and on CI for every pushed commit. Enable the hook once per clone:

```
git config core.hooksPath .githooks
```

It needs commitlint, installed once: `npm i -g @commitlint/cli@19.8.1`. Merge, `fixup!` and `squash!` commits are not checked.

## Code

- `gofmt`, `go vet ./...` and `go test -race ./...` pass on CI for every push.
- Nothing outside `internal/egress` builds an `http.Client`, a `net.Dialer`, a `dns.Client` or a Chrome allocator, or calls `net.Dial`, `http.Get` and the like: ask egress for the client, so scope, budget, pace, proxy, kill file and ledger apply. The `lint` job and `go test ./internal/egress` check it; [Architecture: Egress](docs/ARCHITECTURE.md#egress) says how to add one.
- A fix comes with a test that fails before it.
- A test that runs a command through `cli`, `runContract` or `captureBoth` is held to the invariants in `cmd/azhaq/invariants_test.go`: a summary that lists a failure does not exit 0, the summary's requests are the ledger's lines to targets, no row or ledger line names a host and port outside `-allow` or `-scope`, and with `-resolvers` no DNS line goes to the system's resolver.
- Comments are short and say why, not what. An exported name's comment starts with the name.
- Flags and output fields are documented in `docs/`; tests in `cmd/azhaq` check the docs against the flags.

## Docs

Every command has a page, `docs/commands/NAME.md`. The table of its flags sits between `<!-- flags:begin NAME -->` and `<!-- flags:end -->` and is made from the binary, so it is never edited by hand. After a flag is added, changed or removed, rewrite the tables and commit them:

```
go generate ./docs      # or: go run ./cmd/azhaq docs -flags-into docs/commands
azhaq docs -flags NAME  # prints one table, to look at it
```

A test in `cmd/azhaq` fails when a table differs from what the binary makes, when a command has no page, and when a link in the docs leads to a heading that is not there.

### Claims

What a page says about azhaq's behaviour is a claim, and a claim has a proof: a test, or a row of the bench. `docs/claims.tsv` ties each claim to its proof: an id that starts with the page (`readme.kill-switch`, `plan.cap`), a piece of the claim's own text, and the proof (`test:DIR:TestName`, `bench:TEXT of a check`, `file:PATH`, or `note:WHY` for a line that is advice or a pointer and holds no behaviour). A line that reads as a claim is one outside Synopsis, Examples and Flags that says never, always, every, only, nothing, exactly, at most, at least, without, any, all, cannot, not or an exit code.

```
go run ./scripts/claims
```

It fails when a claim has no proof, when the text of a claim is gone from its page (it was reworded: prove the new wording and update the row), and when a proof is gone from the code. The pages named by `@cover` in `docs/claims.tsv` are held to the whole rule: every line that reads as a claim has a row. The other pages are listed with how many such lines they hold, and join `@cover` once each has its rows. A new claim in a covered page needs its row in the same commit.
