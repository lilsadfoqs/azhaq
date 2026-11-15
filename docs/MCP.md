# Azhaq over MCP

`azhaq mcp` serves Azhaq to any client of the Model Context Protocol (Claude Code, Claude Desktop, Cursor, and others) over stdin and stdout. Each tool runs Azhaq itself and returns the same summary and rows the command line prints with `-json`. What a tool call does is what a command does.

## What is fixed when the server starts

The **scope**, the **request budget**, the **pace**, the **resolvers and sources** and the **proxy** are fixed at start. No tool argument can widen or change them:

- Targets outside the scope are skipped and listed in the summary.
- Paths a `-deny-path` rule matches are never requested by any tool, and are listed as skipped. azhaq's one name rule is the decided exception: `azhaq_map` asks every GET it finds in scope except one whose own path, query or API operation declares a state change (`/logout`, `?action=stop`, an API description's `GET /createdb`), which is held back and listed as skipped unless the server was started with `-send-state-changing`. `azhaq_dirs` holds back the words of any list the same way, the client's `words` included. `azhaq_roles` holds back the GETs of each role's map the same way, and the server's `-send-state-changing` sends them there too. A target a call names is held back the same way, because the client named it, not the person who started the server: only the server's `-send-state-changing` sends it. Besides that, the `-deny-path` rules set when the server starts are the only thing that keeps a URL out. A client cannot add one per call. A client cannot lift the exception either.
- A header that names a host (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`), in `headers` or a role's `header`, is held to the scope as on the command line: one inside it is sent, one outside it is refused before anything is sent, with the scope's reason.
- A subdomain lookup for a domain outside the scope is refused, because the passive sources would learn what the assistant asks about.
- Once the budget is spent, every tool that sends requests refuses.
- Chrome is not run without its sandbox: where the system gives it none, a tool that needs Chrome (`browser`, `login`, `azhaq_roles` with a login) answers with an error that names `-chrome-no-sandbox`, before any request. Start the server with that flag to allow it, in a throwaway environment.
- `-resolvers`, `-sources`, `-skip` and `-no-takeover` are held for every call that takes them, as `run` takes them. The server is locked down by default: it asks no third party at all (sources `none`: no subdomain source, archive, RDAP or search engine) and reads or writes no name history, unless the server was started with `-sources` naming the sources to ask or with `-history`. A `-resolvers` file is read at start and held as the list it holds: a file edited or removed later changes what a call asks no more. Without `-resolvers` a map asks the default public resolvers. `azhaq_subdomains`, which is itself a third-party lookup, is refused unless the server was started with `-sources` naming some. `azhaq_scope` and `azhaq_status` show them as `run_options`.
- Writes are held the same way: `azhaq_params` with a body method, `azhaq_roles_writes` and `graphql` on `azhaq_map` or `azhaq_plan` (the introspection POST) send requests that may change data, and they are refused before anything is sent unless the server was started with `-allow-writes`. `azhaq_params` by GET and the read tools need no such flag. The one POST a call may send without `-allow-writes` is the sign-in `login` names: the page's own sign-in form, submitted with the user and password the call gives.

See [Concepts](CONCEPTS.md) for scope, budget and pace.

```
azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5
azhaq mcp -allow example.com -deny admin.example.com -max-requests 5000
```

Every flag is described on the [`azhaq mcp` page](commands/mcp.md#flags): `-scope` with `-program`, `-allow`, `-deny`, `-deny-path`, `-resolvers`, `-proxy`, `-chrome-proxy`, `-sources`, `-history`, `-allow-writes`, `-send-state-changing`, `-skip`, `-no-takeover`, `-chrome-no-sandbox`, `-max-requests`, `-rate`, `-dir` (default `azhaq-mcp`) and `-unlocked`.

To see what the tools send in a proxy, start the server with `-proxy` (`http://`, `https://` or `socks5://`, as `run -proxy` takes it). It is fixed at start like `-resolvers`: no tool argument sets it, every tool that sends requests to targets gets it, loopback targets included (the `HTTP_PROXY` and `HTTPS_PROXY` variables never carry those: Go's rule), and `azhaq_status` and `azhaq_scope` show it, without a password. `-chrome-proxy` sets another proxy for Chrome's own connections, as `run -chrome-proxy` does; without it Chrome follows `-proxy`. An http proxy carries HTTP only: `azhaq_ports` and `azhaq_dns` are refused before anything is sent while the server's `-proxy` is not a `socks5://` one, because sent anyway they would go around it. With a socks5 proxy they go through it. DNS that a map sends goes to the `-resolvers`, not through the proxy. See [Proxies](CONCEPTS.md#proxies).

Without `-allow` or `-scope` the server does not start (exit 2), unless `-unlocked` says so. Then any target a tool is given may be touched, and port scans are refused.

An `-allow HOST:PORT` holds the tools to that port of the host: every command a tool runs gets the same `-allow`, so a target on another port of the host is skipped and listed, and a port scan asks that port only.

## Adding it to a client

Claude Code:

```
claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000 -rate 5
```

Any client that takes a JSON configuration:

```json
{"mcpServers": {"azhaq": {"command": "azhaq", "args": ["mcp", "-scope", "hackerone", "-program", "security", "-max-requests", "20000"]}}}
```

## Tools

| Tool | What it does |
| --- | --- |
| `azhaq_scope` | The scope, run options (resolvers, proxy, sources), budget and pace fixed at start, and how much of the budget is used (by the calls that ended). |
| `azhaq_status` | A compact status of the server and each workspace, with the calls running now (`in_flight`). Sends nothing and starts no command. |
| `azhaq_plan` | What a map would take, leave out and send, without sending anything. |
| `azhaq_map` | Maps a URL, a domain or a list into a workspace. Returns the summary and the highlights. |
| `azhaq_resume` | Continues the stopped run of a workspace, where it stopped. |
| `azhaq_subdomains` | Subdomains from passive sources, with the sources of each name. `live` keeps names that resolve. |
| `azhaq_probe` | Web services of targets, like httpx. |
| `azhaq_ports` | Open TCP ports and what serves them, and UDP ports with `udp_ports` (locked servers only). |
| `azhaq_dirs` | Paths on web services from a wordlist, like ffuf. |
| `azhaq_params` | Parameters pages read, from a wordlist, like arjun (GET, or a body method with `-allow-writes` at start). |
| `azhaq_dns_brute` | Subdomains by resolving guessed names, through the server's resolvers. |
| `azhaq_query` | Rows of a workspace's map, filtered, with chosen fields. |
| `azhaq_show` | Everything about one URL, host or name, with the evidence. |
| `azhaq_roles` | The access matrix of several sessions. |
| `azhaq_roles_writes` | The roles comparison, with the writes replayed across sessions (only with `-allow-writes` at start; `dry_writes` lists them and sends none). |
| `azhaq_export` | A workspace in a standard format, written to a file and returned a page at a time. |
| `azhaq_diff` | What the last run into a workspace added and lost. |
| `azhaq_workspaces` | The workspaces written so far. |

### Tool details

**`azhaq_status`**

- Reports the scope (locked, allow and deny rules), the run options held (`run_options`: resolvers, proxy, sources, skipped collectors, takeover check), the request budget (limit, used, left) and the pace. `used` counts the requests of the calls that ended: a call still running adds its own when it ends.
- Lists the calls running now in `in_flight`: `count`, and for each call its `command`, its `seconds` so far and the `max_requests` it was handed, which is the most it can still add to `used` (`reserved` is their sum). A call waiting for its turn is not listed: it has been handed nothing. `in_flight` and `used` are read together, so a call is in one or the other, never both.
- Names the server's ledger (`ledger`), the file of the calls that name no workspace. The file exists once such a call has run.
- Lists every workspace this server's directory holds, each with its state: `complete`, `stopped by a limit` or `failed`.
- `stopped by a limit` comes with `tasks_left`, the `requests` the run has sent and the `azhaq_resume` call that continues it. `complete` means the database holds no task left to do.
- The state is read from the workspace's database, so it is the same for a map this session ran, one it ran before a restart, and one made elsewhere, and a query of the workspace does not change it.
- `failed` is for a workspace whose last map, resume or roles call in this session failed outright; a call that succeeds clears it.
- Sends nothing and starts no command.

**`azhaq_plan`**

- Built by the same code path that builds `azhaq_map`'s call (the same targets and flags, the same lock, pace, budget and held options), so the plan is what the call would send; it sends nothing itself.
- `state_changing` names, per target, the GET requests among the targets whose own path or query declares a state change — a whole word of the documented set (create, createdb, delete, remove, reset, populate, logout, signout, clear, wipe, drop, truncate, purge, destroy, erase, seed, and run, execute, exec, start, stop, restart, kill, shutdown, reboot, install, setup, upload, import, init, initialize, reinit, restore, revert, rollback, sync, trigger, start_over: the list in [State-changing requests](commands/run.md#state-changing-requests)) in the URL's path, or a verb in the value of a query parameter that names an action (`?action=halt`), or a query value that is itself a path (`?s=/user/logout`) — each with the `-deny-path` rule that would keep it out. A target whose own path or query declares one is listed as held back (status `held back`, with the flag that sends it), not as a target that is sent, unless the server was started with `-send-state-changing`. What a crawl would only find by reading an API description (VAmPI's `GET /createdb`, whose description says it creates and populates its database) is not known to a plan; a run names those in its summary's `state_changing` as it finds them.

**`azhaq_map`**

- Returns the summary and the highlights: auth-gated routes, forbidden routes and API routes.
- Asks every GET it finds in scope, a GET operation of an API description and a GET form included, except one whose own path, query or API operation declares a state change: a link, a script's route, an API operation or a GET form's action like that is held back and listed as skipped, and the summary's `state_changing` gives its status, `held back`, with the flag that sends it; only a server started with `-send-state-changing` sends it. A target you named is held back the same way. A GET can change data or end a session; besides that exception only the server's `-deny-path` rules keep a URL out.
- `browser` loads pages in Chrome too.
- `graphql` asks each GraphQL endpoint for its schema. That is an introspection POST, and it is counted. Where introspection is off, the schema is recovered from validation errors, with POSTs too. A server started without `-allow-writes` refuses the call before anything is sent, here and in `azhaq_plan`.
- `login` signs in with Chrome: the one POST a call may send without `-allow-writes`, the page's sign-in.

**`azhaq_resume`**

- Continues a workspace that the budget, `timeout_seconds` or a cancellation stopped, where it stopped.
- Uses the server's scope, pace, run options and what is left of its budget. Returns what `azhaq_map` returns.
- A workspace keeps no session: give `headers` or `login` again.
- A run started with a scope wider than the server's is not resumed.

**`azhaq_probe`**

- Returns each answer as the target gave it. A redirect is not followed, and `final_url` is not set.
- A target with no answer is a row with `failed: true`.

**`azhaq_ports`**

- With `udp_ports`, UDP ports are asked too: a reply is open, an ICMP unreachable closed, neither `open|filtered`. Without it only TCP ports are scanned.
- Rows carry `product` and `version` where the port names one.
- A port that waits is asked up to 25 more connects, each counted.
- Each connect counts against the budget and follows the pace.

**`azhaq_dirs`**

- A GET for each word of the wordlist (built-in common list, or the call's `words`, at most 5000) under each target, calibrated as `azhaq dirs` is. Extensions add a word each.
- A word that declares a state change by its own path or query (logout, reset, delete, `?action=stop` and the like) is held back and listed as skipped, whether it is a word of the built-in list or of the `words` the call gives, unless the server was started with `-send-state-changing`, which sends every word, as ffuf does.
- A target outside the scope, and a word list the schema bounds out, are refused before anything is sent. The server's `-deny-path` rules keep their paths out, as for a map.

**`azhaq_params`**

- GET sends the names in the query and no body. `method` POST, JSON or XML sends them in a body, which may change data: refused unless the server was started with `-allow-writes`.
- `words` (at most 5000) or a built-in `wordlist` (small, medium, large); the two do not go together.

**`azhaq_dns_brute`**

- Resolves `WORD.domain` for each of the call's `words` (required, at most 5000) through the server's resolvers; wildcard answers are left out. Nothing is sent to the targets.
- A domain outside the scope is refused before any query, and the call is refused when the server's budget is spent.

**`azhaq_query`**

- Filters by type, role, coverage, status, method, host, text and newness.
- The default fields are key, type, role, coverage, status, title, methods, params and count. Choose others with the fields argument.

**`azhaq_show`**

- Fields over 2 KB are left out when the answer would pass 24 KB. The export has them.

**`azhaq_roles`**

Each role is an object, in one of three forms:

- `{"name":"anon"}`
- `{"name":"user","header":["Authorization: Bearer …"]}`, where `header` is always a list
- `{"name":"alice","user":"alice@example.com","password":"…"}`, which signs in with Chrome at `login_url`

`ids` names a role's own objects (`alice:book_title=aliceBook`), so another role reading them is reported.

For example, `azhaq_roles {"url":"http://127.0.0.1:5002/","roles":[{"name":"anon"},{"name":"user","header":["Authorization: Bearer …"]}]}` compares an anonymous session with a token's.

**`azhaq_export`**

Formats: OpenAPI, GraphQL introspection JSON or SDL, Burp scope, nuclei targets, URL or host lists, HTML and GraphML. The file is written on the server's machine and returned a page at a time: see [Exports in pages](#exports-in-pages).

## What the tools do not start

These are left out on purpose. Run them from the command line, where the person running them sees the flags.

- A client-chosen request body or method beyond what a tool declares: `fuzz`, Chrome's page writes (`-browser-writes`) and form submissions. The writes a tool does send are the ones its own description names — `azhaq_params` with a body method, `azhaq_roles_writes` and `graphql` — and only when the server was started with `-allow-writes`.
- Permutations of found names (`-permute`): `azhaq_dns_brute` guesses the call's words only, so the names it asks are the ones the call listed.

## Results

- A result is one text block of compact JSON. It is not repeated as `structuredContent`.
- A result carries at most `limit` rows: 100 by default, never more than 1000. It says when there are more.
- This keeps one call from filling a client's context: ask `azhaq_query` the next question instead.
- A summary names its next steps as tool calls, not shell commands. A run a limit stopped says `"resume":"azhaq_resume {\"workspace\":\"juice\"} continues it"`, and its `next` entries are `azhaq_query` and `azhaq_export` calls.

## Exports in pages

`azhaq_export` returns an export a page of about 16 KB at a time. Every page is a document of its own, cut between units and never inside one. What a unit is depends on the format:

| Format | A page holds some of its |
| --- | --- |
| OpenAPI | paths: whole path items, with the components they refer to |
| GraphQL introspection or SDL | definitions, keyed or headed by endpoint, as the export is |
| Burp options file | scope entries |
| HTML report, GraphML graph | rows, nodes and edges |
| other formats | whole lines |

- `offset` counts those units, not bytes.
- A unit larger than 16 KB is a page alone.
- An export that fits is returned whole, as written.

The result says how many units there are, which ones the page holds and the offset of the next page:

```
wrote …/juice.openapi.json on the server's machine (52363 bytes, openapi: 82 paths); this page holds paths 0 to 45 of 82 (/.well-known/csaf/provider-metadata.json to /rest/continue-code/apply/{id}). For the rest call azhaq_export again with offset 46, …
```

So `azhaq_export {"workspace":"juice","format":"openapi","offset":46}` gets the next page.

## Workspaces, ledger and kill switch

Workspaces and exports are files in the server's `-dir`, on the machine the server runs on.

- `azhaq_export` writes `juice.openapi.json`, `juice.html` and so on next to `juice.db`. It returns the content too, so a client on another machine gets it from the result.
- A list of targets given to a tool is written there while the command runs. It is kept only while the run it started can be resumed.

Each workspace has two more files, described in [Concepts](CONCEPTS.md):

- The ledger, `juice.db.ledger.jsonl`, has one line for each request, connection or query the tools sent for that workspace, to targets, third-party sources and resolvers. Each line holds the hash of the one before. `azhaq ledger -verify FILE` checks it, and `-csv` prints it for a client.
- `juice.db.stop` is the workspace's kill switch. While it exists, a call that uses the workspace sends nothing more and ends stopped (`the kill switch: kill file … exists`). `azhaq_resume` continues once the file is removed.

The calls that name no workspace have a ledger of the server's: `azhaq_probe`, `azhaq_ports`, `azhaq_subdomains`, `azhaq_dirs`, `azhaq_params` and `azhaq_dns_brute` without a `workspace`.

- It is one file, `server.ledger.jsonl`, in `-dir`, and `azhaq_status` gives its path as `ledger`. It has the same lines as a workspace's, for each request, connection or query those calls sent, and each call appends to it and seals it when it ends.
- `azhaq ledger -verify DIR/server.ledger.jsonl` checks its chain and its seal like a workspace's.
- The summaries' `requests`, which count against the server's budget, add up to the lines to targets of this file and of the workspaces' ledgers together.
- Its calls run one at a time, so the chain has one writer.

No tool argument turns any of them off.

## Arguments, progress and cancelling

A call's arguments are checked against the tool's `inputSchema`, the one `tools/list` publishes. These are refused with a JSON-RPC error (`-32602`), not dropped or guessed:

- an argument the schema does not name;
- a value of the wrong type, such as a string where a list goes or a role that is not an object;
- a value outside its list or under its minimum;
- a missing field.

The check applies at any depth. The error names the argument, what it takes and what was given:

```
invalid params: unknown argument "limt" for azhaq_query; it takes …
invalid params: argument roles[0] of azhaq_roles must be an object …, not the string "anon"
```

One string where a list of strings goes is taken as a list of one: `{"role":"auth"}` is `{"role":["auth"]}`.

- Calls send progress notifications when the client gives a `progressToken`: the first after a second, then every 5 seconds.
- A call the client cancels (`notifications/cancelled`) stops its command, which keeps what it found, and gets no response. `azhaq_resume` continues it.
