# azhaq mcp

Serve azhaq to MCP clients over stdio, with the scope and the request budget fixed at start.

## Synopsis

```
azhaq mcp [-scope FILE|PLATFORM -program P] [-allow D] [-deny D] [-deny-path RE] [-resolvers LIST] [-sources LIST|none] [-skip LIST] [-no-takeover] [-max-requests N] [-rate N] [-dir DIR]
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
3. Holds every tool to the resolvers and sources given by `-resolvers`, `-sources`, `-skip` and `-no-takeover`, as `run` takes them. A call cannot set or change them. `azhaq_scope` and `azhaq_status` show them as `run_options`, and `azhaq_resume` keeps them. With `-sources none`, `azhaq_plan` lists no collector that asks a third party and `azhaq_subdomains` is refused.
4. Writes the workspaces the tools make into `-dir`.

The tools and their arguments are listed in [MCP.md](../MCP.md).

## Output

JSON-RPC (Model Context Protocol) on stdin and stdout, in the order the protocol's lifecycle gives:

- A client sends `initialize` first and waits for its answer, then sends `notifications/initialized`.
- Before `initialize` the server answers `ping` and refuses every other request with an error (`the server is not initialized`).
- A second `initialize` on the same connection is refused (`already initialized`).
- Everything but a tool call is answered as soon as it is read, so requests sent back to back get their answers in the order they were sent. A tool call runs while the next lines are read: its answer comes when it ends, and a `notifications/cancelled` stops it.
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
| `-unlocked` | bool |  | serve without a scope: any target a tool is given may be touched (port scans stay refused) |

**What a map asks**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-resolvers` | string |  | DNS resolvers every tool uses (a comma list or a file, as run -resolvers): fixed at start, no tool argument sets them |
| `-sources` | string |  | subdomain sources every tool may ask, comma-separated; none: no third party at all (no source, archive, RDAP or search engine), only the resolvers and the targets are asked; fixed at start |
| `-skip` | string |  | collectors no tool runs, comma-separated (azhaq plan lists them): fixed at start |
| `-no-takeover` | bool |  | no tool checks CNAMEs for a takeover: fixed at start |

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
