# azhaq ports

Finds the open TCP ports of hosts with a connect scan, so it needs no root. It names each service by what the port answers, on any port, and gives products and versions. Ranges, CIDR blocks and AS numbers have no size cap. `-udp` also asks the common UDP ports. Replaces naabu (see [Migrating](../MIGRATING.md#naabu-azhaq-ports)).

## Synopsis

```
azhaq ports -host HOST[,HOST…] | -l FILE | stdin | TARGET…  [-p LIST | -tp 100|1000|full | -pf FILE] [-ep LIST] [-udp | -pu LIST] [-rate N] [-T0..5] [-connect-timeout MS] [-retries N] [-c N] [-sn | -wn] [-sweep] [-ec] [-csv | -json] [-oX F] [-oG F] [-oA BASE]
```

## Examples

```
# the 1,000 likeliest ports of one host, as JSON
azhaq ports -host scanme.nmap.org -p top-1000 -json

# three ports of a /16, 2,000 connects a second, only the addresses that are up
azhaq ports 10.0.0.0/16 -p 22,80,443 -rate 2000 -wn

# UDP ports 1 to 1024 of one host, no TCP
azhaq ports -host 127.0.0.1 -p none -pu 1-1024 -json

# hosts from a file, slower timing, two ports left out, all output formats
azhaq ports -l hosts.txt -tp 1000 -ep 25,3306 -T2 -oA scan

# which addresses of a range are up
azhaq ports 192.0.2.0/24 -sn

# every address the scope holds, not only the one named
azhaq ports -allow 192.0.2.0/24 -sweep -p 22,80,443
```

## What it does

1. Takes targets: names, addresses, `host:port`, URLs, CIDR ranges or AS numbers. See [Targets](#targets).
2. Connects to each port in a random order, the likeliest first, paced by `-rate`. `-p` chooses the ports.
3. Asks the ports that neither accepted nor refused a connect once more, when few did not answer.
4. Names the service of each open port from what it says or answers, with its product and version.
5. With `-udp`, also sends each UDP port one harmless datagram.
6. Prints one line for each open port.

A port that says nothing is asked the request of its own protocol, an HTTP `HEAD /` and a TLS handshake. Then it gets one harmless request of each other protocol. That is at most 25 connects after the first. Nothing logs in, sends a credential or changes anything. Raw printing ports (9100–9107) are never asked anything. A CDN or WAF address is scanned in full, as naabu does; `-ec` limits it to ports 80, 443, 8080 and 8443.

## Output

Plain output is `host:port` for each open port, and `host:port/udp` for an open UDP port. `-json` prints one object per open port, and `-csv` the same fields as columns. [More on formats](#more-on-formats) has the nmap files and the options that choose fields.

| Flag | Output |
| --- | --- |
| (none) | `host:port`; a UDP port is `host:port/udp` |
| `-json`, `-j` | one object per open port |
| `-csv` | a header line, then the same fields as columns |
| `-oX FILE`, `-oG FILE` | nmap XML and nmap greppable output |
| `-oA BASE` | `BASE.json`, `BASE.xml`, `BASE.gnmap` |
| `-sn` | the addresses that are up, one per line; with `-json`, `{"host","ip","up":true,"timestamp"}` |

The fields of a `-json` row, which are naabu's plus azhaq's:

| Field | Meaning |
| --- | --- |
| `host` | The host scanned. |
| `ip` | Its address. |
| `port` | The port number. |
| `protocol` | `tcp`, or `udp`. |
| `tls` | `true` on a TLS port. |
| `cdn` | `true` on a CDN or WAF address. |
| `cdn-name` | The CDN or WAF. |
| `timestamp` | UTC, RFC 3339. |
| `ports`, `silent`, `asked`, `refused` | On the one row of an address's silent UDP ports (no `port`): the ports, how many, how many UDP ports were asked, how many the address refused. See [UDP rows and lines](#udp-rows-and-lines). |
| `service` | The service the port answered as. A name ending in `?` is only the registered name of the port, taken from its number: nothing answered as that service, so it is not an identification. With `-detect none` no row has a `service`: nothing is named from the port number. |
| `product`, `version` | What the service states: see [Products and versions](#products-and-versions-of-tcp-ports). |
| `extrainfo` | What the answer says beside the product and its version, as it was sent: the rest of a `Server` header (`Python/3.11.15`, `(Ubuntu)`), or an SSH line's comment and protocol (`Ubuntu-2ubuntu2.13; protocol 2.0`). nmap calls it `extrainfo` too, and `-oX` and `-oG` carry it. |
| `title` | The `<title>` of a web page that names no product. |
| `banner` | What the port said. A binary answer, to the first read or to the `HEAD`, is `(binary)` and its first bytes in hex. |
| `tls_version`, `cipher` | What the handshake of a TLS port negotiated: `tls10` to `tls13`, and the suite's name (`TLS_AES_128_GCM_SHA256`, `TLS_RSA_WITH_AES_128_GCM_SHA256`). |
| `subject_cn`, `subject_an` | The certificate's subject names of a TLS port, as httpx calls them. |
| `state` | UDP only: `open`, or `open\|filtered`. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes). Any failure exits 3 here: addresses and ranges have no answer to tell from a failure (see [Exit 3](../OUTPUT.md#exit-3)). The summary of `ports` says:

| Summary | Says |
| --- | --- |
| `addresses`, in `counts` | The addresses asked, wholly or in part when a limit stopped the run. |
| notes | How many addresses were not up (`-wn`), were outside the scope, or had ports that neither accepted nor refused a connect. |
| `the scope (-allow, -scope) holds N addresses and the targets name M of them` | The targets cover part of a range `-allow` or `-scope` allows (less what `-deny` holds); `-sweep` scans the rest. |
| AS prefixes | The prefixes RIPEstat lists for an AS number. |
| `IPv6 addresses of 1 name not scanned: no IPv6 route from this machine` | A name's IPv6 addresses were not scanned, because this machine cannot reach them. |
| CDN or WAF | With `-ec`, the addresses that were asked only ports 80, 443, 8080 and 8443. |
| the host `-pts` stopped on | The host that `-pts` stopped asking: it answers every port. |
| `-proxy` or `-source-ip` | The scan asked the banner only. |
| `-proxy HOST:PORT failed: …` | A proxy that cannot be reached: a failure, exit 3. |
| `-wn` or `-sn` | How many hosts were called down. |
| `open ports whose protocol was not probed, …` | The open ports that `-unnamed` stopped asking. |
| `ports that neither accepted nor refused a connect, asked twice: scanme.nmap.org (45.33.32.156) port 80; …` | Ports where an open port may hide. |
| UDP lines | What `open\|filtered` means, and the closed ports: see [UDP](#udp-ports-and-their-states). |
| `next`: `next pass, not run: N services found with a read-only check; -verify sends …` | A run that named a service with a [check](run.md#read-only-verification) and was not given `-verify` says so: the same `ports` line with `-verify`, what each check sends (no credential) and what it costs, one connect a service (measured: a run with `-verify` sends one request more for each service it checks). No line when no service found has a check. It is a line: nothing is run, and the command asks the ports again. |
| `next`: `next pass, not run: N ports of the default set (…) were not asked on A addresses: C connects` | A scan of a list that leaves out ports of the default set (the top 100 and the usual ports of the services azhaq names and checks: `-p top-1000` leaves out Redis 6379, MongoDB 27017 and 38 more) names them before the full range: the same `ports` line with the list and `,default` (`-p top-1000,default`; `-p default` beside `-tp` and `-pf`). N counts the ports of the default set the scan did not ask and an `-ep` list does not hold out, and C is N times the addresses the scan asked. Nothing is suggested when the scan asked the whole default set. It is a line: nothing is run. |
| `next`: `next pass, not run: the other N of the 65535 TCP ports were not asked` | A scan of fewer than all 65535 ports names the rest of the range, the addresses it asked, the connects it would send (N for each address) and the open ports found in the range asked, with the command: the same `ports` line with `-p full`. A scan that stopped at a limit, `-sn`, and targets read from stdin suggest nothing. It is a line: nothing is run. |

## Details

### Targets
- A target is a name, an address, `host:port`, a URL, a CIDR range or an AS number. Give them comma-separated in `-host`, one per line in `-l` or on stdin, or as arguments.
- A CIDR range is IPv4, or IPv6 down to /104. A larger IPv6 range is refused, since no scan finishes it.
- `AS13335` stands for the prefixes RIPEstat lists, and the summary says so.
- `-allow` and `-scope` are a fence: `-host 10.0.0.5 -allow 10.0.0.0/24` scans 10.0.0.5, and a note says `the scope (-allow, -scope) holds 256 addresses and the targets name 1 of them: -sweep covers the other 255`. `-sweep` scans every IPv4 address and range `-allow` and `-scope` hold, as if each were a target, and needs no target named alongside it. For example `azhaq ports -allow 10.0.0.0/24 -sweep`. An address given as `host:port` is asked its own port and, with `-sweep`, the default ports as an address of a range. `-eh`, `-deny`, `-rate`, `-max-requests` and the kill file hold as for any target; the summary counts every address of the range. IPv6 ranges in the scope are left alone, with a note: name them as targets.
- A `host:port` is asked that port only. `-p`, `-tp` and `-pf` apply to every target, and a `host:port` keeps its own port beside them: `-host 10.0.0.5:8081 -p 80` asks 80 and 8081. Each entry stands for itself: `-host 10.0.0.5,10.0.0.5:8081` scans the default ports of 10.0.0.5 and port 8081, and the same goes for an address in a given range, or a name given both ways.
- A scan keeps what it has finished while it runs: about every second, the ports it has asked (all those before the first connect still on its way, the open ones named, a port that timed out left out). A range keeps the addresses of its block it has finished every two seconds. A scan killed with SIGKILL or a crash is continued by `azhaq resume -db FILE` with the ports after them, and the summary says how many connects of the killed run it made again. The checkpoints are rows of the workspace marked `checkpoint`: the newest of an address stands, and the row that ends the scan replaces them. A scan that ends within a second leaves none.
- A range is split into blocks of 256 addresses. The run takes them one at a time and records them. So a range has no size limit and is not expanded in memory, and `azhaq resume` continues it: a block a limit stopped keeps which of its addresses it finished, and the resume asks only the others.
- In the map (`show`, `query -type Prefix`), a range's row lists the open ports of every address that answered, as `open=[8001 8002 …]`, and `addresses_open=N` says how many addresses had any. Which address answered on which port is in the `Port` rows (`query -type Port`).
- A name costs the DNS queries of its A and AAAA records and no others.
- One row is made for each address. A name's first two IPv4 and first two IPv6 addresses are scanned, IPv6 where this machine can reach it. `-sa` scans every address, and `-iv 4` or `-iv 6` keeps one family.
- An address that shows nothing has no row.
- `-wn` scans only the addresses that accept or refuse a connect to 80 or 443. `-sn` lists them and scans nothing.
- For `-wn` and `-sn`, an address is up when a connect to 80 or 443 is accepted or refused, asked twice. A host that drops both is called down.

### Ports, order and pace
- With no `-p`, `-tp` or `-pf`, a scan asks the default set: 163 ports, the top 100 and 63 more, the usual ports of the services azhaq can name and check (Redis 6379, MongoDB 27017, memcached 11211, Kafka 9092 and the like). They are read from the protocols azhaq identifies, plain and TLS, and the ports it names a silent port by, so a service azhaq learns to name is scanned by default with no edit to a list. The top 100 alone leaves those out: `-p top-100` does not ask 6379, 27017, 11211 or 9092. `-p top-100` asks the top 100 alone, `-p default,8001` adds a port to the default set, and the plan counts all 163.
- `-p`, `-tp 100|1000|full` and `-pf FILE` add ports. `-ep LIST|FILE` takes ports out.
- `-p -` is every port, `-p u:53` is a UDP port, and `-p none` leaves the TCP ports out.
- The ports of a host are asked in a random order, the likeliest first: nmap's top 100, then its top 1000. `-order asc` asks them by number, and `-seed N` repeats an order.
- `-rate` paces the scan: it is a ceiling. The default is 1500 connects a second. This machine's loopback is not paced unless you give `-rate`, and then 20,000 ports at `-rate 500` take 40 seconds. nmap's `--min-rate 500` is a floor, which is `-min-rate 500` here: it only ever raises the pace, to the higher of the default 1500 (or `-rate`) and `-min-rate`. So `-min-rate 500` leaves the default pace alone, and a loopback scan of 20,000 ports with `-detect none` takes a fraction of a second, as nmap's does; `-min-rate 5000` asks 5,000 connects a second.
- With `-rate`, the scan runs on as many cores as that rate needs, one for each 15,000 connects a second, never more than the machine has: a scan on one core costs about the CPU nmap's does for the same rate. `-min-rate` keeps every core; `GOMAXPROCS` in the environment sets the number yourself.
- From `-rate 1000` up, the connects go out in batches of up to 32 (`rate / 500`), each batch waited on by one poll on one goroutine, not one goroutine and one poller entry for each connect. A port that accepted gets a goroutine of its own to be named. The benchmark takes a full-range scan of 127.0.0.1 at `-rate 10000` with the workspace and the ledger on against `nmap -sT --max-rate 10000`, and holds its CPU and its time to 1.25 times nmap's, with the open ports of nmap's all found. Below `-rate 1000`, and through a proxy, each connect is its own dial.
- `-T0` to `-T5` set the rate, the connect timeout and the retries as nmap's templates do. An explicit flag wins.
- `-c` is how many connects are in flight.
- `-timeout` is how long the whole run may take, such as `90s`. `ports -timeout 500` is refused, with a pointer to `-connect-timeout`.
- `-connect-timeout` is the wait for one connect. A bare number is milliseconds.

### How an open port is named
A service that speaks first (`ssh`, `ftp`, `smtp`, `telnet`, `irc`, …) is named from what it says. A port that waits is asked what it serves, by what it answers and not by its port number. The steps, in this order:

1. The request of the protocol whose usual port it is.
2. An HTTP `HEAD / HTTP/1.0` on the open connection. An HTTP answer is `http`, and its banner is the `Server` header or the status line. A `405` or `501` is asked `GET /` for the page's title and product.
3. For an answer that is not HTTP text, a TLS handshake on a second connection, counted like a connect. The service is `tls`, or `https` when HTTP answers inside it. A greeting inside it, as an IMAPS or SMTPS server sends, is read first and names the service, with `tls` true.
4. One harmless request of each other protocol, each on a connection of its own, a few at a time. The first in the list that answers is the port's, with the product and version it states.
5. A port still unnamed after all that, whose silence to the `HEAD` was complete, is asked one `GET / HTTP/1.0`, nmap's GetRequest. A handler that answers `GET` and waits for its own protocol after any other first bytes (the Jenkins agent port) says `HTTP/1.0 200` and its text page. An HTTP answer is `http`, with the product its head or page names (`Jenkins-Version: 2.462` is Jenkins 2.462). Nothing else names the port. It is skipped for an address whose ports were no longer run down the list (see `-unnamed`).

- A `HEAD` that stays unanswered for half a second is waited on while the handshake and the list are asked beside it. A port that answers neither is done when the `HEAD`'s wait ends, not after a wait for each protocol.
- Every connect, whatever its purpose, counts against `-max-requests`, takes a token of the pace and is in the ledger.
- Every probe written to a connection (the `HEAD /`, a protocol's request, the `GET /` of step 5) is a `probe` line of its own in the ledger, after the line of its connection: its `proto` and, for HTTP, its `method` and its `target` with the path. It is not counted again as a request or a connection: the summary's `requests` counts the connection's line, and the ledger note says how many probes went on them. See [what a line means](../OUTPUT.md#what-a-line-means).
- An open port costs at most 25 connects after the first, the `GET /` of step 5, the bodies read for a product and a fallback TLS handshake included: they all come out of the 25. The second connect of a greeter that said nothing (below) is one more, so 26 in all; `plan` counts that as the allowance of each open port in its ceiling. A port named by a late protocol may cost a few more than asking the protocols one by one would. Several are asked at once.
- A port that accepts a connection and closes it without a word is `tcpwrapped`.
- Raw printing ports (9100–9107) are never asked anything.
- A service on a port that usually speaks first (22, 21, 25, 3306, …) gets a second wait for its greeting before it is asked anything. A greeting that arrives in reply to the `HEAD` is read as one.
- When no greeting came at all, the port gets one more connect after the scan, and that one waits six seconds for it (twice the connect and banner wait), as nmap's first probe does. sshd drops greetings when many connects arrive at once, and a server that looks the client up before it greets is late by the lookup. On a port with no service of its own that stayed silent to every request, the list included, the connect of the last `GET /` listens the same six seconds first, so a greeting that came late names it too; that costs no connect beyond the 25.
- A second name on the same address has its web and TLS ports asked again under its own name.
- After six open ports of one address that no request could name, the remaining silent ports of that address are not asked the whole list. `-unnamed N` changes the six, `run -port-unnamed N` does the same in `run`, and `-1` means no limit. A workspace row says how many in `unprobed`, and the summary names them.

### Ports that stay silent
- A port that neither accepts nor refuses a connect, by a timeout or an ICMP unreachable, is asked once more after the others. That happens when such ports are at most 64 or a tenth of the scan.
- A loaded or lossy host drops a connect now and then. A firewall that drops nearly everything would only double the scan, so it is not asked again.
- `-retries N` asks them N more times, and `-retries 0` never.
- When a connect timed out, the pass first waits one connect timeout, at most 3 s. A listener whose accept queue is full makes Linux drop the SYN, and the port is open once its service has drained the queue.
- Each ask counts against `-max-requests` and is in the ledger.
- A port still silent is in the row's `filtered_ports` and in the summary.
- In `run` and `query`, the `ports` row of a scanned address counts these silent ports in `filtered`. It lists them in `filtered_ports` when there are no more than 64.

### Limits, and what the scan does not do silently
- A CDN or WAF address is scanned in full, as naabu does. The row has `cdn` and a `note`. `-ec` (`-exclude-cdn`) asks it only ports 80, 443, 8080 and 8443, which is naabu's two ports plus 8080 and 8443, because its other ports are the provider's other customers'. The summary then names the addresses. `-cdn-full` is accepted and does nothing; it is the default.
- `-pts N` stops asking a host after N open ports, for a host that answers every port. The row has `"threshold":true` and the summary names the host. Ports already in flight are still asked, so a few more than N may be listed.
- `-detect` says what is asked of an open port:
  - `none` connects and closes: one connect per port, as naabu without `-sV`. No row names a service, not even by its port number (no `service` field, and no name in the `-oX` and `-oG` files), as naabu prints only `host:port`; the other modes mark a name taken from the port number with `?`.
  - `banner` reads what the service says on that connection and sends nothing after it: a bare `220` greeting stays `ftp-or-smtp` with its banner, and an FTP greeting that names no product is not asked `SYST`. Only `all` sends `EHLO` or `SYST`.
  - `all` is the default. `-detect none` (`-port-detect none` in `run`) matches naabu's time and output. It also asks a silent port for HTTP and TLS, then one request of each protocol that waits to be asked. Each goes on a connection of its own, several at once while the scan has workers free.
- `-proxy host:port` (SOCKS5) and `-source-ip` make the TCP connects go through that proxy or from that address. The service probes beyond the first connection dial on their own, so with either the scan asks the banner only, and the summary says so. A proxy that cannot be reached, or that breaks the SOCKS exchange, is a failure the summary names (`-proxy HOST:PORT failed: …`, exit 3), and the scan stops: its ports are not called closed. A proxy that works and says the target refused leaves the port closed, as a refusal does. A `-source-ip` that is not an address of this machine is a usage error (exit 2) before anything is sent.
- UDP is not sent through a proxy. `-proxy` with `-udp` is refused.

### More on formats
- `-csv` writes a list joined with spaces. `-lof` lists the fields and stops.
- `-eof a,b` leaves fields out of `-json`, `-csv` and `-oA`'s JSON.
- `-json` rows have `timestamp` in UTC, RFC 3339, and `tls_version`, `cipher`, `subject_cn` and `subject_an` on a TLS port.
- `-oX FILE` and `-oG FILE` take `-` for stdout. Hosts are in address order and ports by number. `service` has no `?`, which marks a guess from the port number alone (`method="table"` in the XML).
- The XML and greppable layouts follow naabu's.

### UDP, products and versions

#### UDP ports
- `ports -udp` asks the 25 common UDP ports. `-pu top` asks the same: 53, 67, 69, 111, 123, 137, 161, 500, 514, 520, 623, 1194, 1434, 1900, 3478, 4500, 5060, 5351, 5353, 5683, 10001, 11211, 27015, 47808 and 51820.
- `-pu LIST` asks a list instead, such as `-pu 1-1024` or `-pu top,5354`. List names and numbers combine, in `-p` too.
- `-p none` leaves the TCP ports out. `-pu LIST` without `-p`, `-tp` or `-pf` does the same: only those UDP ports are asked, as `nmap -sU` does, so that a low `-rate` under `-timeout` is not spent on the default TCP ports first. `-udp` alone still asks TCP too. In `run` it is `-ports-udp SPEC`, with `top`, `full` or a list.
- What each UDP port is sent, in one rule: a port with a protocol of its own (the list above) is asked that request, and 161 a second one (SNMPv3 discovery); any other port is asked a DNS query, an SNMP get, memcached's version and an empty datagram, in that order. The scan stops asking a port at its first answer or ICMP port unreachable, so a silent port costs 2 datagrams on a known port and 4 on any other: a full range of N addresses is up to 4 x 65,535 x N datagrams. `-detect all` and `-detect banner` follow that rule.
- `-detect none` (`-port-detect none` in `run`) asks each UDP port one datagram: the request of its protocol on a port that has one, an empty datagram on any other. A silent port then costs 1 datagram, and the summary says the `open|filtered` ports were asked once. An empty datagram is answered by few services, so `none` finds fewer open ports than the default and is for sizing or for a full-range sweep that must stay small.
- No privileges are needed. Each port gets one datagram on a connected socket, and the kernel tells an ICMP port unreachable from silence.
- Every datagram counts against `-max-requests`, is paced by `-rate` and goes in the request ledger as kind `udp`.
- A CDN or WAF address is not asked.
- Nothing logs in, guesses a credential or changes state.

#### UDP ports and their states

| What came back | State |
| --- | --- |
| a datagram | `open`, with the service, product, version and banner the reply gives |
| an ICMP port unreachable | `closed` |
| nothing, every way asked | `open\|filtered`: a service that ignores the request, or a filter |

The request is the harmless one of the protocol the port usually carries:

- DNS: `. NS`.
- NTP: a client request.
- SNMP: a GET of `sysDescr.0`, community `public`. As the second ask of 161, an SNMPv3 engine id discovery: the vendor is read from the engine id.
- SSDP: M-SEARCH.
- mDNS: a service query.
- NetBIOS: a node status request.
- IKEv2: a header.
- STUN: a binding request.
- memcached: `version`.
- BACnet: Who-Is.
- CoAP: `GET /.well-known/core`.
- TFTP: a read of a file that does not exist. An ERROR packet proves TFTP. It is read on a socket that is not connected, since the server answers from a port of its own.
- The portmapper: DUMP, which lists the programs.
- SQL Server Browser: CLNT_UCAST_EX, which gives the version.
- SIP: OPTIONS.
- NAT-PMP: the public address request.
- Ubiquiti: its discovery request.
- ASF: a presence ping.

A sysDescr that names Linux, Cisco IOS, JUNOS or Windows gives `product` and `version`. A port with no known protocol is asked a DNS query first. Then come an SNMP get with community `public`, memcached's version and an empty datagram, until one answers. DNS, SNMP and memcached are what move to odd ports: 5354, 8053, 10161.

#### UDP rows and lines
- JSON rows have `"protocol":"udp"` and `"state"`. A port that answered has a row of its own, with `"port"`.
- The ports of an address that stayed silent (`open|filtered`) are one row, not one each: a range of silent ports is a screenful, and the least informative answer of the scan. The row has `"state":"open|filtered"`, `ports` (the silent ports as a list, `1-24,60`), `silent` (how many), `asked` (how many UDP ports were asked of the address) and `refused` (how many the address refused with an ICMP port unreachable, left out when none). It has no `port`. `-csv` writes the same four as columns when the scan asks UDP ports.
- Plain output prints that row as `host/udp open|filtered 24 of 25 ports: 1-24,60 (1 refused)`; `-silent` prints the same lines. A closed port answers with an ICMP error and a silent one does not, so `refused` against `silent` is what tells the two apart on one address.
- `-udp-rows` prints each silent port as a row of its own instead, `host:port/udp open|filtered` in plain output and a row with `port` in `-json` and `-csv`. It lists every silent port, past the 64 a row lists one by one. `-oX`, `-oG` and `-oA`'s XML and greppable files list each silent port as nmap does, with or without it.
- Each row is a result, counted in `results`, so the aggregate row is one. The summary's `open|filtered` counts ports: the sum of the `silent` of the rows printed, or one for each row of `-udp-rows`.
- A closed port is not a result, because nmap lists closed ports only on request.
- When any row is `open|filtered`, the summary counts `open` and `open|filtered` apart, so a silent port is never read as an open one.

In a workspace, the `ports` row has these UDP fields:

| Field | Meaning |
| --- | --- |
| `udp_open`, `udp_open_filtered` | The ports in each state. |
| `udp_closed` | How many ports the host refused. |
| `udp_closed_ports` | The first 16 of them. |
| `udp_scanned` | How many UDP ports were scanned. |
| `udp_limited` | Silent ports that may be closed: see below. |
| `udp_services` | For each listed port: port, state, service, product, version, banner. |
| `udp_one_request` | `true` when `-detect none` asked each port one datagram. |
| `partial`, `udp_refused`, `udp_asked`, `udp_unfinished`, `udp_unasked` | On the row of a scan a limit stopped: the ports refused, how many requests each undecided port was asked (`udp_asked` maps a request count to its ports), and how many ports are undecided or not asked at all. `azhaq resume` reads them. |
| `udp_unlisted` | How many `open\|filtered` ports the row does not list one by one. |
| `udp_silent_only` | `true` on the row of an address of a range that answered nothing on UDP: it holds only `udp_open_filtered` and `udp_scanned`. |
| `udp_silent_ports`, `udp_silent_addresses` | On a range row, the silent ports and addresses that answered nothing on UDP. |

#### What the summary says about UDP
- A scan that a limit, `-timeout` or a signal stopped says how far it got: `127.0.0.1:5354/udp: 3 of 4 payloads asked before the run stopped; no answer yet, so open|filtered is not final`. Ports not asked at all are counted.
- A stopped scan prints and stores what it has, as a stopped TCP scan does: the ports that answered, the ports refused (counted in `udp_closed`), and the silent ports asked so far as `open|filtered`. Those silent ports are not final: a later request may still be answered. They are results of the stopped run, and `results` counts them.
- `azhaq resume` goes on from there, port by port. It does not ask again a port that answered or was refused, and a silent port is asked the requests it was not, so a resume under the same cap makes progress and the scan finishes. The resumed run prints the final state of the ports the stop left undecided.
- UDP scans of the addresses of a range run on as many addresses at once as the rate can keep busy (the rate times the timeout over 100 datagrams in flight each: 23 at the default `-rate 1500`), not on all 64 at once. With a cap or a stop, the first addresses are finished and the others hold their progress, and a resume continues from it.
- It says what the state means: `1 UDP port open|filtered: no reply and no ICMP port unreachable after every request its protocol has (a silent service or a firewall); …`.
- It names the closed ports, so that a scan that found nothing says what it saw: `1 UDP port closed (ICMP port unreachable): 127.0.0.1:9`. Up to three are shown as `address:port`, then `and N more`. In a range, the addresses that refused ports and showed nothing else are counted.
- An address asked on its own, or a name, has one row for its silent ports. The workspace row's `udp_services` lists them up to 64, and its `udp_open_filtered` keeps every one.
- In a range, an address that answered nothing at all on UDP, because it is down or drops it, has no row in the output: 254 of them would be a screenful. The range row counts its `udp_silent_ports` and `udp_silent_addresses`, the summary says how many addresses and how many ports were asked of each, and `-udp-rows` lists them. The workspace keeps them in a row of the address that has `udp_silent_only` and the silent ports in `udp_open_filtered`; `azhaq show` and `azhaq query` do not take that row for an open port.
- An address that refused or answered some port, or has an open one, has the one row for its silent ports.

#### Why a UDP port reads open|filtered
- A port is `closed` only on an ICMP unreachable for that port.
- On a loopback or LAN address, `open|filtered` usually means a service that does not answer a request it does not understand. A closed port there answers with an ICMP error and is reported `closed`.
- Across a firewall that drops ICMP, closed ports also read `open|filtered`.
- A host that refuses with ICMP but rate-limits it, as Linux does at about one a second, leaves closed ports silent too. When some ports were refused and at most 80 silent ones remain, those are asked again one at a time at that pace. Each reply can then arrive. This is slower, and happens on a non-loopback address only.
- When more than 80 remain, they stay `open|filtered`, `udp_limited` counts them and the summary says some may be closed.

#### Products and versions of TCP ports
Each open TCP port gets `product` and `version` next to `service`, from what it says first or answers:

| Source | Example | Product, version |
| --- | --- | --- |
| SSH greeting | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`, `SSH-2.0-Cisco-1.25`, `SSH-2.0-ROSSSH`, a Bitvise `FlowSsh: Bitvise SSH Server (WinSSHD) 8.49` | OpenSSH, 9.6p1 (the distribution's part is in `extrainfo`); Cisco SSH 1.25; MikroTik RouterOS sshd; Bitvise WinSSHD 8.49 |
| FTP, SMTP, POP3, IMAP greeting | `220 (vsFTPd 3.0.5)`, `220 Serv-U FTP Server v15.1`, `ESMTP Exim 4.96`, `ESMTP MDaemon 21.5.1`, `Dovecot`, `Microsoft Exchange Server 2016 POP3 server version 15.01.2308.008` | vsftpd 3.0.5, Serv-U ftpd 15.1, Exim 4.96, MDaemon smtpd 21.5.1, Dovecot, Microsoft Exchange pop3d 15.01.2308.008 |
| FTP greeting naming no product: `SYST` before login (`-detect all` only) | vsftpd 2.0.8 and later refuses it with `530 Please login with USER and PASS.` | vsftpd, no version (the greeting states none) |
| MySQL, MariaDB handshake | server version in the first packet | MySQL 8.0.35, MariaDB 10.11.6 |
| HTTP `Server` | `Werkzeug/2.2.3 Python/3.11`, `Apache/2.4.25 (Debian)`, `CUPS/2.4` | Werkzeug 2.2.3, Apache httpd 2.4.25, CUPS 2.4 |
| HTTP `X-Powered-By`, when `Server` names none | `Express` | Express |
| `GET /` body, when the head names no product | `Ollama is running`; Elasticsearch or OpenSearch JSON `version.number` | Ollama; Elasticsearch 8.11.1 |
| Redis: `INFO server` | `redis_version:7.4.12` (a server that wants a password says `-NOAUTH`: Redis, no version) | Redis 7.4.12 |
| PostgreSQL: a startup message of a protocol version that does not exist | the error names the versions the server supports | PostgreSQL, a range of majors from them (`14 - 17`) |
| MongoDB: `isMaster`, then `buildInfo` | `version` | MongoDB 7.0.45 |
| MQTT: a CONNECT without credentials, a subscribe to `$SYS/broker/version` | CONNACK, the broker's version message | Mosquitto 2.0.22 (the CONNACK alone: `mqtt`) |
| AMQP: the protocol header | Connection.Start's server properties | RabbitMQ 3.13.7 |
| memcached: `version` | `VERSION 1.6.45` | memcached 1.6.45 |
| LDAP: an anonymous root DSE search | `vendorName`, `vendorVersion`, `namingContexts`, the object classes | OpenLDAP; the vendor and version where the server states them; Active Directory's functional level |
| SMB: a NEGOTIATE, no session | dialect, signing, server start time (zero on Samba) | `smb` with the dialect; Samba smbd |
| DNS over TCP: a length-prefixed query, then `version.bind` CHAOS TXT | an answer; the version string | `dns`; BIND, dnsmasq or Unbound with the version where the server answers |
| Kafka: ApiVersions | the response | `kafka` |
| ZooKeeper: `srvr` | `Zookeeper version: 3.9.2` | Apache ZooKeeper 3.9.2 |
| SQL Server: a TDS prelogin | the VERSION token | Microsoft SQL Server 2019 15.0.2000 |
| Oracle TNS: a connect with a ping | VSNNUM in the answer | Oracle TNS Listener 19.0.0.0.0 |
| Cassandra: an OPTIONS frame | SUPPORTED | `cassandra` |
| Kerberos: an AS-REQ for a principal that does not exist | KRB-ERROR with the realm | `kerberos` |
| RDP: an X.224 connection request | the selected protocol | `rdp` |
| X11: a connection setup with no authorization | the vendor and release of an open server | `x11` |
| Java RMI: the stream header `JRMI`, version 2, StreamProtocol (7 bytes), asked first on 1090, 1098, 1099, 1129, 1199, 2199, 5999, 7800, 8686, 8999, 9999, 10098, 10099, 10990, 11099, 31099, 47001 and 47002, and last in the list on any port | a ProtocolAck (`0x4e`), then the host and port the registry sees the asker as | `java-rmi`, product Java RMI; `extrainfo` is `client seen as HOST:PORT` |
| Elasticsearch transport: the keep-alive ping (`ES` and a length of -1), 6 bytes, asked first on 9300 to 9303 | the same six bytes | `elasticsearch-transport`, product Elasticsearch |
| SOCKS5, STOMP, XMPP, RTSP, SIP, JDWP, AFP, Minecraft, gopher, finger | the method reply, the CONNECTED frame, the stream header, the status line and `Server` header, the handshake, and so on | the service; a product where the answer states one |
| Nping echo server: it opens with a binary handshake (version 1, type 1, its length) | the first 24 bytes or more | `nping-echo`, product Nping echo |
| Greetings: VNC, Telnet, IRC, NNTP, ManageSieve, ICY | `RFB 003.008`, an option negotiation, `NOTICE AUTH`, `200 …`, `"IMPLEMENTATION" "…"`, `ICY 200 OK` | `vnc` with the protocol version; the service; INN, Icecast and Dovecot Pigeonhole where named |
| A web page's title, when the head names no product (and for a `HEAD` that was refused) | `<title>Mailpit</title>` and its stylesheet's version | Mailpit 1.20.7 |
| `GET /version` of a Go server that answers `/` with a 404 | etcd, Kubernetes or Docker JSON | etcd, Kubernetes, Docker Engine with the version |

- `service` is unchanged.
- `product` and `version` are the first token of the `Server` header (`Werkzeug/2.2.3`); the rest of the header is `extrainfo`, and the header as sent stays the `banner`. A version is only ever one the answer states.
- A web page that names no product gets its `<title>` in `title`, and its `<meta name="generator">` as the product.
- The `GET /` for a body is one more connection on a web port. It is made when the `HEAD` answer gave no product and is a 200 or 401 of type JSON or text. It is also made when the `HEAD` was refused (403, 404, 405, 501). It counts, is paced and is recorded like a connect, and it comes out of the port's 25 connects.
- Every request above, but the `SYST` and `EHLO` that `-detect all` sends to a greeting that names no product, is sent only to a port that said nothing and is not one of the raw printing ports (9100–9107). None logs in, sends a credential or changes anything.
- Elasticsearch's transport ping is answered by a node of 7.x or later. An older node ignores it, and a silent 9300 then reads `elasticsearch-transport?`: a guess by port, marked with the question mark like every guess. The ping carries no version, so a confirmed port has none.
- A binary answer is read by the protocols' readers, and by none that does not recognise it. So a port with no recognised protocol keeps its banner and stays `service` empty.

### Known-issue matching

With `-advisories -advisory-source FILE`, each open port's product and version (what the service itself stated) is matched against the advisory records of that source, and each match is printed after the port rows: one lead line each, or one `{"type":"advisory", …}` object with `-json`. They are counted apart in the summary (`advisory leads` in `counts`, and the label counts in a note), never as open ports. Matching sends nothing: it reads only what the scan already holds. `-advisories-confirm` adds, for each affected or conditional lead, the one benign read the advisory names (a `GET` of its documented version or info path, or of `/`), labelled `observed`, `inferred` or `claimed` with what was read; it goes through the scope, the budget and the ledger like any request. A lead is never a proven finding. See [Known-issue matching](../CONCEPTS.md#known-issue-matching--advisories).

```
azhaq ports -host 192.0.2.10 -p top-100 -advisories -advisory-source osv.json -json
```

### Read-only verification

With `-verify`, each service the scan named that has a check (a version need not be known first) gets one more read from the fixed list of checks, each sent with no credential, exactly as a client with no credentials reads what the service already gives anyone: `INFO server` to Redis, an `isMaster` hello to MongoDB, `version` to memcached, `srvr` to ZooKeeper, and the first request of the protocol for Kafka, SQL Server, LDAP, SMB and the others in [the table of checks](run.md#read-only-verification). A service the scan names with no check has its reason in [the services with no check](../CONCEPTS.md#services-with-no-check). Each answer is labelled `proved` (it answered with no credential), `version-only` (it asked for authentication, so only the identification stands) or `conditional` (a precondition the read did not show, which the result names), printed after the port rows with the exact request sent and an excerpt of the answer, counted in the summary as `verify results`, and stored as one `verify` observation per result. With `-advisories`, advisory leads are labelled the same way from their confirmation reads. Every read goes through the scope, the kill file, `-max-requests` and the pace, and is a ledger line of the collector `azhaq-verify`: the `tcp` line of its connection and a `probe` line of the read. Never a payload, a write, a credential or a request that tries to trigger a flaw. The checks, the labels and the boundary are in [Read-only verification](../CONCEPTS.md#read-only-verification--verify).

```
azhaq ports -host 192.0.2.10 -p top-1000 -verify -json
```

## Flags

<!-- flags:begin ports -->
**Targets and input**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-host` | string, repeatable |  | hosts, addresses, CIDR ranges, AS numbers or host:port, comma-separated and repeatable |
| `-l` | string |  | file of targets (- for stdin) |
| `-p` | string | `default` | ports: default (the top 100 and the usual ports of the services azhaq names and checks), top-100, top-1000, full, - (all), none, or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888; u:53 is a UDP port |
| `-tp` | string |  | the most common TCP ports: 100, 1000 or full (added to -p) |
| `-ep` | string |  | ports not to scan: a list or a file |
| `-no-stdin` | bool |  | do not read targets from stdin when none is given |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |

**What to ask**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-udp` | bool |  | also ask the common UDP ports (25: dns, ntp, snmp, ssdp, mdns, ...) |
| `-pu` | string |  | UDP ports to ask: top, full or a list of ports, ranges and these names, such as 53,123,1-1024 or top,5354 (implies -udp; without -p, -tp or -pf no TCP port is asked) |
| `-detect` | string | `all` | what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection, several at once while the scan has workers free: at most 25 connects after the first), banner (what it says on the one connection; nothing is sent, so a bare 220 stays ftp-or-smtp) or none (connect and close, as naabu without -sV). UDP ports: all and banner ask every request a port's protocol has (4 datagrams to a silent port); none asks one |
| `-order` | string | `random` | the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc |
| `-unnamed` | int |  | after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6, a guard against hosts that accept every connect; -1: no limit) |
| `-exclude-cdn` | bool |  | ask a CDN or WAF address only ports 80, 443, 8080 and 8443 (naabu's two ports plus 8080 and 8443; the default is the full list) |
| `-seed` | int |  | make the random port order repeat (default: a new one each run) |
| `-sn` | bool |  | list the addresses that are up (a connect to 80 or 443 is accepted or refused) and scan nothing |
| `-wn` | bool |  | scan only the addresses that are up (by -sn's test); the default scans every address |
| `-advisories` | bool |  | match the products and versions this run already confirmed against the advisory records of -advisory-source, as labelled leads (affected, not affected or conditional, each with its advisory id and URL): a pure lookup over what the run already holds, nothing more is sent to a target |
| `-advisories-confirm` | bool |  | with -advisories: for each affected or conditional lead, also make the one benign read the advisory names (a GET of its documented version or info path, or of / to read the version it states): no payload, no login, no state change, never a request that could trigger the issue; each read is in the ledger and counts against -max-requests, and each lead is labelled observed, inferred or claimed (with -advisories; reads only within the run's scope: the targets given, -allow or -scope) |
| `-advisory-source` | string |  | the advisory records to match against, OSV JSON (a record, a list, {"vulns": [...]}, or JSON lines): a file the user downloaded (works offline), or an http(s) URL asked once as a third-party source; azhaq vendors no snapshot and fetches none it was not given |
| `-verify` | bool |  | with the services this run confirmed: make each enumerated safe read-only verification (one fixed request a client with no credentials sends, listed by plan: Redis INFO server, MongoDB isMaster, memcached version, ZooKeeper srvr and so on; with -advisories, each advisory lead is labelled from its confirmation read) and label the results proved, version-only or conditional, each with the exact request sent and an excerpt of the answer; every read goes through the scope, -deny-path (for the advisory GET), -max-requests, the pace, the kill file and the ledger; no payload, no credential, no write and no request that tries to trigger an issue |

**Scope and safety**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; HOST:PORT allows that host on that port only; with any -allow, nothing else is requested |
| `-sweep` | bool |  | scan the whole scope: every IPv4 address -allow and -scope hold, not only the targets given (without it a note says how much of a range the targets leave); -eh, -deny, -rate, -max-requests and the kill file hold as for any target |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-kill-file` | string |  | stop all sending when this file exists, so that no request starts after it, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-ledger` | string |  | write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |

**Pace and limits**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-rate` | float |  | port connection attempts per second, a ceiling (0: 1500, as naabu's connect scan, and 127.0.0.1 unpaced) |
| `-min-rate` | float |  | connects per second at least, as nmap's --min-rate: raises the pace to this when the pace (-rate, or the default 1500) is lower, and never lowers it |
| `-workers` | int |  | connects in flight at once, over all hosts (default: as many as the rate allows, up to 20000) |
| `-connect-timeout` | string |  | wait this long for one port to accept or refuse a connect: 1500, 1500ms or 2s (default 1.5s; -timeout is the run's limit) |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-retries` | int | `-1` | more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |

**Network**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-proxy` | string |  | connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent |
| `-resolvers` | string |  | DNS resolvers: a list such as 1.1.1.1,8.8.8.8:53 or a file, one a line (default: public resolvers); named ones answer every name, and the system resolver is never asked |

**Output**

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: workspace.db in the run's folder under ~/.azhaq/runs; with AZHAQ_HOME=none a temporary one) |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-o` | string |  | also write results to this file |
| `-oA` | string |  | write JSON lines, XML and greppable output to BASE.json, BASE.xml and BASE.gnmap |
| `-oX` | string |  | write nmap XML to this file (- for stdout) |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-udp-rows` | bool |  | list each UDP port that stayed silent (open\|filtered) as a row of its own; by default an address has one row for them, with their count, how many ports were asked and how many were refused (the nmap files and the workspace list them one by one either way) |
| `-v` | bool |  | print a line for every finished task, not only failures |

<details>
<summary>Flags familiar from naabu, other names and flags accepted with no effect (23)</summary>

| Flag | Type | Default | Meaning | Kind |
| --- | --- | --- | --- | --- |
| `-T` | int | `-1` | timing template, 0 (paranoid) to 5 (insane); sets -rate, -connect-timeout and -retries where they are not given; 3 is the default | naabu's name |
| `-cp` | string |  | send this to each open TCP port before reading what it says (\r and \n are CR and LF) | naabu's name |
| `-csv` | bool |  | CSV output, a header line first | naabu's name |
| `-ef` | string |  | file of hosts, addresses and ranges not to scan | naabu's name |
| `-eh` | string |  | hosts, addresses or ranges not to scan, comma-separated (same as -deny) | naabu's name |
| `-eof` | string |  | leave these fields out of -json, -csv and -oA's JSON, comma-separated | naabu's name |
| `-iv` | string |  | the address families of a name to scan: 4 or 6 (default both) | naabu's name |
| `-lof` | bool |  | list the fields of -json and -csv, and stop | naabu's name |
| `-oG` | string |  | write nmap greppable output to this file (- for stdout) | naabu's name |
| `-pf` | string |  | file of ports, one spec a line (added to -p) | naabu's name |
| `-proxy-auth` | string |  | user:password for -proxy | naabu's name |
| `-pts` | int |  | stop asking a host after this many open ports: it answers every port (default: no limit) | naabu's name |
| `-sa` | bool |  | scan every address of a name, not the first two of each family | naabu's name |
| `-source-ip` | string |  | connect from this local address, one of this machine's (any other is refused) | naabu's name |
| `-c` | int |  | same as -workers | other name |
| `-ec` | bool |  | same as -exclude-cdn | other name |
| `-j` | bool |  | same as -json | other name |
| `-max-retries` | int | `-1` | same as -retries | other name |
| `-r` | string |  | same as -resolvers | other name |
| `-Pn` | bool |  | accepted: addresses are scanned without asking whether they are up, which is the default | accepted, no effect |
| `-cdn` | bool |  | accepted: a CDN address is marked in the output, always | accepted, no effect |
| `-cdn-full` | bool |  | accepted: CDN and WAF addresses are scanned in full by default | accepted, no effect |
| `-nc` | bool |  | accepted: no colours are printed | accepted, no effect |

</details>
<!-- flags:end -->
