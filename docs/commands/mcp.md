# azhaq mcp

Serve azhaq to MCP clients over stdio, with the scope and the request budget fixed at start.

## Synopsis

```
azhaq mcp [-scope FILE|PLATFORM -program P] [-allow D] [-deny D] [-deny-path RE] [-resolvers LIST] [-sources LIST|none] [-history] [-allow-writes] [-skip LIST] [-no-takeover] [-chrome-no-sandbox] [-max-requests N] [-rate N] [-dir DIR]
```

## Examples

```
# Hold every tool to a HackerOne program, with a budget and a pace
azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5

# Resolve through a given resolver and ask no third party (no source, archive, RDAP or search engine)
azhaq mcp -allow example.com -resolvers 10.0.0.2 -sources none

# Add the server to Claude Code, limited to one domain
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000
```

## What it does

1. Starts a Model Context Protocol server that talks JSON-RPC on stdin and stdout.
2. Holds every tool to the scope given by `-scope`, `-allow`, `-deny` and `-deny-path`. All tool calls together share the `-max-requests` budget and the `-rate` pace.
3. Holds every tool to the resolvers and sources given by `-resolvers`, `-sources`, `-skip` and `-no-takeover`, as `run` takes them. A call cannot set or change them. `-sources` defaults to none: the server asks no third party at all, and reads or writes no name history either, unless it was started with `-sources` naming sources to ask or with `-history`. `azhaq_subdomains`, which is itself a third-party lookup, is refused unless the server was started with `-sources` naming some. `-chrome-no-sandbox` is held too: Chrome, which a tool uses with `browser` or `login`, does not start without its sandbox, and the tool answers with an error naming the flag, unless the server was started with it. `azhaq_scope` and `azhaq_status` show them as `run_options`, and `azhaq_resume` keeps them.
4. Holds the tools that send writes to a flag of the server's: `azhaq_params` with a body method, `azhaq_roles_writes` and `graphql` on `azhaq_map` and `azhaq_plan` (an introspection POST) are refused before anything is sent unless the server was started with `-allow-writes`. The sign-in POST of `login` is not one of them. A target a call names whose own path, query or API operation declares a state change is held back and listed as skipped, as a GET found on the way is, unless the server was started with `-send-state-changing`.
5. Writes the workspaces the tools make into `-dir`.

The tools and their arguments are listed in [MCP.md](../MCP.md).

## Output

JSON-RPC (Model Context Protocol) on stdin and stdout, in the order the protocol's lifecycle gives:

- A client sends `initialize` first and waits for its answer, then sends `notifications/initialized`.
- Before `initialize` the server answers `ping` and refuses every other request with an error (`the server is not initialized`).
- A second `initialize` on the same connection is refused (`already initialized`).
- Everything but a tool call is answered as soon as it is read, so requests sent back to back get their answers in the order they were sent. A tool call runs while the next lines are read: its answer comes when it ends, so two tool calls sent back to back may answer in either order (match each answer to its call by `id`), and a `notifications/cancelled` stops it.
- The scope, the budget and the pace hold for every call, however the requests are ordered.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). The server runs until its input closes or a signal comes. A signal ends it with exit 0, after the commands in flight stop.

## Flags

<!-- flags:begin mcp -->
**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-scope` | string |  | a program's scope every tool is held to: a file, or hackerone, bugcrowd, intigriti, yeswehack with -program |
| `-program` | string |  | the program to take from -scope |
| `-allow` | string, repeatable |  | a domain or host the tools may touch; HOST:PORT allows that host on that port only (repeatable); with -scope, added to it |
| `-deny` | string, repeatable |  | a domain or host the tools must not touch |
| `-deny-path` | string, repeatable |  | a regular expression on a URL's path and query: a URL it matches is never requested by any tool |
| `-send-state-changing` | bool |  | let the tools send the GETs whose own path, query or API operation declares a state change (create, delete, reset, logout, action=stop, ...), a target a call names included: without it they are held back and listed as skipped; fixed at start, no tool argument sets it |
| `-unlocked` | bool |  | serve without a scope: any target a tool is given may be touched (port scans stay refused) |
| `-allow-writes` | bool |  | let tools send writes: azhaq_params with a body method (POST, JSON or XML), azhaq_roles_writes and graphql (the introspection POST of azhaq_map and azhaq_plan); without it those calls are refused before anything is sent; the sign-in POST of login is not one of them; fixed at start |

**What a map asks**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-resolvers` | string |  | DNS resolvers every tool uses (a comma list or a file, as run -resolvers): fixed at start, no tool argument sets them |
| `-sources` | string |  | subdomain sources every tool may ask, comma-separated (default none: no third party at all — no source, archive, RDAP or search engine — only the resolvers and the targets are asked; name the sources at start to ask them); fixed at start |
| `-history` | bool |  | read and write the name history (names earlier runs found): without it no tool reads or writes it; fixed at start |
| `-skip` | string |  | collectors no tool runs, comma-separated (azhaq plan lists them): fixed at start |
| `-no-takeover` | bool |  | no tool checks CNAMEs for a takeover: fixed at start |
| `-chrome-no-sandbox` | bool |  | let Chrome run without its sandbox where the system gives it none (the tools that load pages in Chrome, such as azhaq_map with browser, and sign in with it): fixed at start. The pages are the targets' and untrusted: use a throwaway environment. By default Chrome does not start then |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | requests per second to targets in every tool call (0: no pace) |
| `-max-requests` | int |  | requests to targets all tool calls together may send (0: no cap) |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-dir` | string | `azhaq-mcp` | directory for the workspaces the tools write |
<!-- flags:end -->
