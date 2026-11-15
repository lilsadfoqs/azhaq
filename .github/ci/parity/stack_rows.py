#!/usr/bin/env python3
"""stack_rows.py targets EXPORT.jsonl OUT_DIR
stack_rows.py rows OUT_DIR > rows.jsonl

The usual tools' side of ident.py, on the services azhaq found, so both are
asked to name the same services.

`targets` reads azhaq's workspace export and writes OUT_DIR/ports.txt (one
"ADDRESS PORT,PORT,..." line per address with open TCP ports) and
OUT_DIR/urls.txt (the root URL of every web service azhaq answered, at a name
or an address). stack.sh hands them to nmap -sV, httpx -td and nuclei's
technology and panel templates.

`rows` turns what those tools wrote in OUT_DIR (nmap-*.xml, httpx.jsonl,
nuclei.jsonl) into rows ident.py reads: a port's product and version from
nmap; a web answer's technologies, title and Server header from httpx; a
template's name and what it extracted from nuclei.
"""
import argparse
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urlsplit


def read_jsonl(path):
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return
    with f:
        for line in f:
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if isinstance(o, dict):
                yield o


def targets(export, out):
    ports, urls = defaultdict(set), set()
    for o in read_jsonl(export):
        if o.get("kind") != "observation":
            continue
        ob = o.get("observation") or {}
        p = ob.get("payload") or {}
        if not isinstance(p, dict):
            continue
        if ob.get("collector") == "azhaq-ports" and p.get("ip") and not p.get("range"):
            for x in p.get("open") or []:
                if isinstance(x, int) or str(x).isdigit():
                    ports[p["ip"]].add(int(x))
        elif ob.get("collector") == "azhaq-http" and p.get("status"):
            u = urlsplit(p.get("url") or "")
            if u.scheme in ("http", "https") and u.hostname:
                urls.add("%s://%s/" % (u.scheme, u.netloc))
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "ports.txt"), "w") as f:
        for ip in sorted(ports):
            f.write("%s %s\n" % (ip, ",".join(str(x) for x in sorted(ports[ip]))))
    with open(os.path.join(out, "urls.txt"), "w") as f:
        f.write("".join(u + "\n" for u in sorted(urls)))
    return len(ports), len(urls)


def row(collector, payload):
    return {"kind": "observation", "observation": {"collector": collector, "kind": "stack", "payload": payload}}


def nmap_rows(path):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return
    for h in root.iter("host"):
        ip = next((a.get("addr") for a in h.iter("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not ip:
            continue
        svcs, open_ = [], []
        for p in h.iter("port"):
            st = p.find("state")
            if p.get("protocol") != "tcp" or st is None or st.get("state") != "open":
                continue
            port = int(p.get("portid"))
            open_.append(port)
            s = p.find("service")
            if s is not None:
                svcs.append({"port": port, "service": s.get("name") or "",
                             "product": " ".join(x for x in (s.get("product"), s.get("extrainfo")) if x),
                             "version": s.get("version") or ""})
        yield row("azhaq-ports", {"ip": ip, "host": "", "open": open_, "services": svcs})


def httpx_rows(path):
    for o in read_jsonl(path):
        url = o.get("url") or ""
        ip = o.get("host_ip") or (o.get("a") or [None])[0] or o.get("host")
        yield row("azhaq-http", {"url": url, "ip": ip, "status": o.get("status_code"), "tech": o.get("tech") or [],
                                 "title": o.get("title") or "", "server": o.get("webserver") or ""})


def nuclei_rows(path):
    for o in read_jsonl(path):
        at = o.get("matched-at") or o.get("host") or ""
        if "://" not in at:
            continue
        info = o.get("info") or {}
        # A template that names many products (tech-detect, fingerprinthub) says which one in its matcher's name.
        parts = [info.get("name") or o.get("template-id") or "", o.get("matcher-name") or ""]
        name = " ".join(parts + [str(x) for x in o.get("extracted-results") or []])
        yield row("azhaq-http", {"url": at, "ip": o.get("ip"), "status": 200, "tech": [name.strip()]})


def rows(out):
    for p in sorted(glob.glob(os.path.join(out, "nmap-*.xml"))):
        yield from nmap_rows(p)
    yield from httpx_rows(os.path.join(out, "httpx.jsonl"))
    yield from nuclei_rows(os.path.join(out, "nuclei.jsonl"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("targets")
    a.add_argument("export")
    a.add_argument("out")
    b = sub.add_parser("rows")
    b.add_argument("out")
    args = ap.parse_args(argv)
    if args.cmd == "targets":
        n, u = targets(args.export, args.out)
        print("stack targets: %d addresses, %d web roots" % (n, u))
        return 0
    for r in rows(args.out):
        sys.stdout.write(json.dumps(r) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
