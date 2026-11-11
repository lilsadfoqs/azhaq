# orvel

orvel is a front end over a set of well-known recon tools. Each subcommand runs
one of them, passes your arguments through unchanged, and exits with that
tool's own exit code. **The tools' own documentation applies** to everything
orvel runs: `orvel SUBCOMMAND -h` shows the tool's own help.

orvel makes no claims of its own. It has no scope enforcement, no request
ledger, no safety features and no output format of its own: it sends what the
tools send, and prints what they print. Use it only on targets you are
authorized to test.

## The tools behind each subcommand

| Subcommand | Tool | Version |
| --- | --- | --- |
| `subs` | subfinder | 2.17.0 |
| `resolve` | dnsx | 1.3.1 |
| `probe` | httpx | 1.12.0 |
| `crawl` | katana | 1.8.0 |
| `fuzz` | ffuf | 2.3.0 |
| `params` | arjun | 2.2.7 |
| `urls` | gau | 2.2.4 |
| `ports` | naabu | 2.6.1 |
| `scan` | nmap | the Ubuntu package (apt) of the machine; `orvel version` prints it |
| `vulns` | nuclei | 3.11.1 (templates are fetched by nuclei itself, as it normally does) |
| `shots` | gowitness | 3.2.2 |

The tools sit in the same folder as `orvel` (`./bin`), and `orvel version`
prints this table as installed. `orvel help` lists the subcommands.

```
orvel subs -d example.com -silent          # subfinder -d example.com -silent
orvel scan -sV -p 80,443 192.0.2.10        # nmap -sV -p 80,443 192.0.2.10
orvel version | orvel help
```

## `orvel run TARGET...`

A simple default pipeline, nothing more than the commands below. TARGET is a
domain, an address or a range. The output goes to the folder `orvel-run-DATE`
(or the folder in `ORVEL_OUT`), each tool's output as JSON lines, and the
script prints where.

1. `subfinder -dL domains.txt -silent -oJ -o subfinder.jsonl` (domains only)
2. `dnsx -l hosts.txt -silent -json -a -resp -o dnsx.jsonl` (the domains and
   the names subfinder found)
3. `naabu -list resolved.txt -top-ports 100 -silent -json -o naabu.jsonl`
   (the names dnsx resolved, and any address or range given)
4. `httpx -l hostports.txt -silent -json -o httpx.jsonl` (`host:port` from naabu)
5. `katana -list urls.txt -silent -jsonl -o katana.jsonl` (the URLs httpx found)

A tool that exits non-zero stops the run, with its exit code. A stage that
finds nothing stops it with exit 0 and says so on stderr.

## Installing

`install-stack.sh DIR` (in the repository's `.github/ci/control/`) puts orvel,
this README as `orvel-README.md` and the pinned tools above in DIR: release
binaries checked against their sha256, arjun in a virtualenv behind a wrapper,
nmap from apt. The pins are the ones the repository's `bench` uses for the same
tools; nuclei's is its own.
