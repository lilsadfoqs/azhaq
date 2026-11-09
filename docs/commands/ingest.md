# azhaq ingest

Add other tools' results to a database: subfinder, dnsx, httpx, katana, naabu, nuclei, gau, ffuf, arjun, gowitness, asnmap and nmap output, or connector facts.

## Synopsis

```
azhaq ingest FILE… | -in FILE | - [-db FILE]
```

## Examples

```
# Add the output of two tools to one database
azhaq ingest httpx.jsonl katana.jsonl -db example.db

# Read from a pipe
subfinder -d example.com -json | azhaq ingest - -db example.db

# Ingest, then hand the web services to the next tool
httpx -l hosts.txt -json | azhaq ingest -in - -db example.db && azhaq export -db example.db -format targets
```

## What it does

1. Reads each file you give, or standard input for `-`.
2. Turns the lines into facts and adds them to the database `-db`. Without `-db` it uses the file `$AZHAQ_DB` names, else makes `workspace.db` in its [run folder](runs.md) (with `AZHAQ_HOME=none`, a new `azhaq-TIME-PID.db` in the current directory).
3. Prints its summary.

Files are arguments (`azhaq ingest a.jsonl b.jsonl`). `-` is stdin, and `-in FILE` still works. The formats it reads are listed under `-in` in Flags. How an httpx, katana or ffuf answer is recorded is in the [connector protocol](../CONNECTOR.md#loading-other-tools-output-with-azhaq-ingest).

## Output

`ingest` prints no rows, only its summary. What it added is in the database: look at the map with `azhaq query` or `azhaq export`.

| Summary field | Meaning |
| --- | --- |
| `results` | The facts read, of every file given. |
| `counts` | The lines read, per format. |
| `notes` | The first 5 lines it could not read and skipped, when there were any. |
| `next` | Commands to look at the result: `azhaq query`, and `azhaq dns` for names taken in without addresses. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Ports from naabu

Each open port a naabu line names is a `Port` row (`address:port/tcp`, or `/udp`; names that point to one address are one row, with the names on it), as `ports` makes them, so `query -type Port`, the summary counts and the MCP tools list it. The lines naabu repeats fold into one row. naabu says nothing of the service, so the row has none until `ports` or `probe` asks. `export -format targets` lists web services that answered: run `probe` on the ports to have them.

### Tools azhaq asks nothing for

arjun, gowitness, asnmap and nmap ran outside azhaq: what they say is taken in as their word. No row of theirs is `visited` (a URL azhaq did not request is a `hint`), and every row says the tool, in its `via=` and, for a URL, in `evidence_from`.

| Tool | File | What a row holds |
| --- | --- | --- |
| arjun | the JSON file of `arjun -oJ` | A URL row with the parameter names arjun found. A `GET` page's are its `params`; a `POST`, `JSON` or `XML` page's are the body fields of a POST (the media type follows the method). `evidence_from` says `arjun`, and the evidence is `given`. |
| gowitness | JSON lines (`gowitness scan --write-jsonl`) | A URL row (`hint`) with the status, title, final URL and technologies gowitness saw on the row's proof, and the screenshot's file name in the observation. A page gowitness could not load has the reason. The evidence is `browser`. |
| asnmap | `asnmap -json` lines, or `azhaq asn -json` lines | An `ASN` row with its holder and the count of prefixes, and a `Prefix` row for each prefix. |
| nmap | the XML of `nmap -oX` | A `Port` row for each port nmap found `open` (TCP) or `open` and `open\|filtered` (UDP): the service nmap named, the product and version it read, the extra info and whether it found TLS. What each NSE script printed is on the row as `script:ID="…"`, as nmap said it, cut to 200 characters (the whole output is in `export -format jsonl`). The host's addresses and names are rows too. A host that is down, and a port that is closed or filtered, give no row. |

An nmap script's output, a service name or a version is nmap's reading, kept as evidence and listed as nothing else: no finding is made from it, and nmap's guess of a service from its port number is not told apart from a probed one. Run `nmap -sV` for products and versions.

The summary counts what each format gave: the pages (arjun), lines (gowitness, asnmap) or ports (nmap) read.

### Where the facts go

- Into an existing workspace, they go to its newest run, so `query`, `show` and `export` see them with what that run found.
- A new file gets a run of its own.
- A line that cannot be read is skipped and named in a note, never a failure: the exit code stays 0.

## Flags

<!-- flags:begin ingest -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-in` | string |  | a file of results (- for stdin): subfinder, dnsx, httpx, katana, naabu, nuclei, gau, gowitness or asnmap JSON lines, an ffuf JSON report or -json lines, an arjun JSON file, an nmap XML file (-oX), azhaq export, connector facts, or lines of URLs, hostnames and addresses; files may also be given as arguments, several at once |
| `-db` | string |  | the database to add to (default: a new file) |
| `-json` | bool |  | the summary as JSON |
<!-- flags:end -->
