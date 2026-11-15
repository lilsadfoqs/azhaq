#!/usr/bin/env python3
"""ident.py sample KEY.json EXPORT.jsonl [--misses FILE] [--out FILE]
ident.py agg SUMMARY.json... [--json]

How often azhaq names the product, and the version, of a service it finds.
`sample` reads one replay's workspace export (`azhaq export -format jsonl`)
beside its key. For each service of the key that was up, it asks:

  found    a stored row is about one of its ports: at its name, or at its
           address unless it is a virtual host (its address is the proxy's)
  product  one of those rows states the product: a port's service product, a
           web answer's technology or detection-template product, a check's or
           an advisory's product (the
           drift grader's rule, where the maker's name and the words for a
           part of the product are not required)
  version  one of them states the version as well (counted only where the
           key's version is a version, not "latest")
  title    the product is only in a page title or a Server header, which
           azhaq shows but does not state as the product

`agg` adds the samples up. Both print counts, shares and the key's categories
only: no product, host, address or port of the key, so CI logs can show
them. `--misses FILE` writes each found service whose product or version was
not stated, with what the rows said; it holds the key's details and stays
off logs (encrypted in CI, like the key).
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with -I: the sibling, explicitly
import summary as sm  # noqa: E402

# The drift grader's rule for naming a product (exp/drift/grade.py), so both rulers agree.
GENERIC = {"apache", "server", "console", "database", "spring", "framework", "web", "application", "with", "from", "remote",
           "service", "services", "panel", "admin", "project", "platform", "management", "manager", "registry", "app"}


# Who makes a product is not its name: "Nexus 3.21" names Sonatype Nexus
# Repository, "Jetty 9.4" names Eclipse Jetty. Nor are the words that say which
# part of it answers (a broker, a name server, a UI). Neither is required.
NOT_THE_NAME = {"sonatype", "eclipse", "gnu", "oracle", "ibm", "microsoft", "jetbrains", "atlassian", "vmware", "alibaba",
                "tencent", "adobe", "google", "hashicorp", "repository", "broker", "name", "ui", "edition", "community"}


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def product_words(product):
    head = re.split(r"\s+(?:behind|with|via|on)\s+|\(", product or "")[0]
    return norm(head), [w for w in norm(head).split() if len(w) >= 2 and w not in GENERIC and w not in NOT_THE_NAME]


def names_product(text, product):
    head, words = product_words(product)
    t = " " + norm(text) + " "
    if head and (" " + head + " ") in t:
        return True
    return bool(words) and all((" " + w + " ") in t for w in words)


def names_version(text, version):
    return bool(version) and bool(re.search(r"(?<![\d.])" + re.escape(str(version).lower()) + r"(?!\d)", (text or "").lower()))


def low(s):
    return str(s or "").strip().lower().rstrip(".")


def statements(rows):
    """(host, port) and (address, port) to the texts that state a product, and the texts that only show one."""
    said, shown = defaultdict(list), defaultdict(list)

    def add(names, port, text, title=False):
        for n in names:
            if n and port:
                (shown if title else said)[(low(n), int(port))].append(text)

    for o in rows:
        ob = o.get("observation") or {}
        p = ob.get("payload") or {}
        if not isinstance(p, dict):
            continue
        c = ob.get("collector")
        if c == "azhaq-ports":
            for s in p.get("services") or []:
                if isinstance(s, dict) and s.get("port"):
                    text = " ".join(str(s.get(k) or "") for k in ("product", "version")).strip()
                    add((p.get("host"), p.get("ip")), s["port"], text)
                    # Seen open, even with nothing stated: found.
                    add((p.get("host"), p.get("ip")), s["port"], "")
            for port in p.get("open") or []:
                add((p.get("host"), p.get("ip")), port, "")
        elif c == "azhaq-http" or c == "azhaq-paths" and ob.get("kind") == "detected":
            u = urlsplit(p.get("url") or "")
            if not u.hostname:
                continue
            port = u.port or (443 if u.scheme == "https" else 80)
            tech = " ".join(str(t).replace(":", " ") for t in p.get("tech") or [])
            # What a detection template named on the answer (internal/detect).
            tech += " " + " ".join("%s %s" % (d.get("product", ""), d.get("version", "")) for d in p.get("detected") or [] if isinstance(d, dict))
            add((u.hostname, p.get("ip")), port, tech.strip())
            if c == "azhaq-paths":
                continue
            loose = " ".join(str(x) for x in (p.get("title"), p.get("server")) if x)
            if loose:
                add((u.hostname, p.get("ip")), port, loose, title=True)
        elif c in ("azhaq-verify", "azhaq-advisories"):
            port = p.get("port")
            if not port and ":" in str(p.get("target") or ""):
                port = str(p["target"]).rsplit(":", 1)[1]
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            text = " ".join(str(p.get(k) or "") for k in ("product", "version", "version_seen")).strip()
            add((p.get("host"), p.get("address"), p.get("ip")), port, text)
    return said, shown


def services(key):
    for est in key["estates"]:
        for h in est["hosts"]:
            if h.get("kind", "service") == "service" and h.get("up", True) and h.get("product"):
                yield h


def sample(key, rows):
    said, shown = statements(rows)
    out = {"services": 0, "found": 0, "product": 0, "versioned": 0, "version": 0, "title_only": 0, "by_category": {}}
    misses = []
    for h in services(key):
        names = [h.get("host")] + ([] if h.get("vhost") else [h.get("address")])
        ports = [int(p["port"]) for p in h.get("ports", []) if p.get("transport", "tcp") == "tcp"]
        texts = [t for n in names if n for port in ports for t in said.get((low(n), port), [])]
        loose = [t for n in names if n for port in ports for t in shown.get((low(n), port), [])]
        found = bool(texts) or bool(loose)
        prod = any(names_product(t, h["product"]) for t in texts)
        versioned = found and bool(re.match(r"\d", str(h.get("version") or "")))
        ver = versioned and prod and any(names_product(t, h["product"]) and names_version(t, h["version"]) for t in texts)
        title = not prod and any(names_product(t, h["product"]) for t in loose)
        cat = out["by_category"].setdefault(h.get("category") or "other", {"services": 0, "found": 0, "product": 0, "versioned": 0, "version": 0})
        for d in (out, cat):
            d["services"] += 1
            d["found"] += found
            d["product"] += prod
            d["versioned"] += versioned
            d["version"] += ver
        out["title_only"] += title
        if found and not (ver or prod and not versioned):
            misses.append({"host": h.get("host"), "address": h.get("address"), "ports": ports, "product": h["product"],
                           "version": h.get("version"), "category": h.get("category"), "product_named": prod,
                           "said": sorted({t for t in texts if t}), "shown": sorted(set(loose))[:5]})
    return out, misses


def shares(d):
    f = d["found"]
    return {"found": sm.frac(f, d["services"]), "product": sm.frac(d["product"], f), "version": sm.frac(d["version"], d["versioned"])}


def agg(samples):
    tot = {"samples": len(samples), "services": 0, "found": 0, "product": 0, "versioned": 0, "version": 0, "title_only": 0, "by_category": {}}
    for s in samples:
        for k in ("services", "found", "product", "versioned", "version", "title_only"):
            tot[k] += s[k]
        for c, v in s["by_category"].items():
            t = tot["by_category"].setdefault(c, {"services": 0, "found": 0, "product": 0, "versioned": 0, "version": 0})
            for k in t:
                t[k] += v[k]
    tot["shares"] = shares(tot)
    return tot


def table(t):
    lines = ["samples %d: services %d, found %d (%s); of the found, product stated %d (%s), version %d of %d (%s); "
             "product only in a title or Server header %d" % (
                 t["samples"], t["services"], t["found"], t["shares"]["found"], t["product"], t["shares"]["product"],
                 t["version"], t["versioned"], t["shares"]["version"], t["title_only"]),
             "", "%-22s %8s %6s %8s %8s" % ("category", "services", "found", "product", "version")]
    for c, v in sorted(t["by_category"].items(), key=lambda kv: -kv[1]["found"]):
        lines.append("%-22s %8d %6d %8d %4d/%-3d" % (c, v["services"], v["found"], v["product"], v["version"], v["versioned"]))
    return "\n".join(lines)


def read_rows(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if isinstance(o, dict) and o.get("kind") == "observation":
                yield o


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("sample")
    a.add_argument("key")
    a.add_argument("export")
    a.add_argument("--misses")
    a.add_argument("--out")
    b = sub.add_parser("agg")
    b.add_argument("summaries", nargs="+")
    b.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "sample":
        with open(args.key) as f:
            key = json.load(f)
        res, misses = sample(key, read_rows(args.export))
        sm.check_clean(res, key)
        text = json.dumps(res, indent=1, sort_keys=True)
        if args.out:
            with open(args.out, "w") as f:
                f.write(text + "\n")
        else:
            print(text)
        if args.misses:
            with open(args.misses, "w") as f:
                for m in misses:
                    f.write(json.dumps(m) + "\n")
        return 0
    loaded = []
    for p in args.summaries:
        with open(p) as f:
            loaded.append(json.load(f))
    t = agg(loaded)
    print(json.dumps(t, indent=1, sort_keys=True) if args.json else table(t))
    return 0


if __name__ == "__main__":
    sys.exit(main())
