#!/usr/bin/env python3
"""to_leads.py --export EXPORT.jsonl --out DIR [--hunt HUNT.jsonl] [--start TS] [--end TS]:
turns what azhaq wrote into the files grade.py reads (.github/ci/trial/GATE.md,
"Findings, as you find them"): DIR/leads.jsonl, DIR/surface-1.txt and
DIR/phases.log (phase 1 only: the replay is one estate).

EXPORT.jsonl is `azhaq export -format jsonl` of the run's workspace and HUNT.jsonl
is `azhaq hunt -json -limit 1000` of it. Every lead's time is a time azhaq
stored: an observation's observed_at, else the entity's first_seen; nothing is
polled or invented. A row becomes a lead when azhaq presents it as an
identification or a finding:
  ports      a service with a product (and version): vulnerable-software
  web        a web service's root page with a technology or Server header
  takeover   a CNAME or page azhaq flags as a takeover candidate
  verify     a -verify result (unauthenticated read or handshake) and an
             advisory lead (CVE, product, version)
  stack      an answer that held a stack trace
  hunt       the rows hunt ranks for a finding-like signal (exposed file,
             listing, source map, secret, API description, GraphQL, admin
             path, debug path, config or env file)
Map rows that only prove a URL exists, and hunt's route heuristics, are not leads.
"""
import argparse
import datetime
import ipaddress
import json
import os
import re
import sys
from urllib.parse import urlparse

# hunt signal -> (lead kind, weight): the heaviest signal of a row names its kind.
HUNT_KINDS = {
    "exposed-file": ("exposed-file", 55),
    "listing": ("exposed-file", 55),
    "sourcemap": ("exposed-file", 45),
    "secret": ("secret", 40),
    "api-description": ("info-leak", 35),
    "graphql": ("exposed-panel", 40),
    "path-admin": ("exposed-panel", 30),
    "path-debug": ("misconfig", 30),
    "path-config": ("exposed-file", 30),
    "path-env": ("exposed-file", 30),
}
VERIFY_KINDS = {"unauthenticated-read": "unauthenticated-access", "unauthenticated-handshake": "unauthenticated-access",
                "advisory-precondition": "vulnerable-software"}
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def epoch(s):
    d = datetime.datetime.fromisoformat(str(s).strip().replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.timestamp()


def stamp(t):
    return datetime.datetime.fromtimestamp(int(t), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def split_url(u):
    """(host, port) of a URL; the port is the scheme's own when none is named."""
    p = urlparse(u or "")
    try:
        port = p.port
    except ValueError:
        port = None
    return (p.hostname or "").lower(), port or {"http": 80, "https": 443}.get(p.scheme)


def is_root(u):
    return urlparse(u or "").path in ("", "/")


def load(path):
    """(entities by id, observations as dicts with a numeric time, the latest time)."""
    ents, obs, last = {}, [], 0.0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if not isinstance(d, dict):
                continue
            if d.get("kind") == "entity" and isinstance(d.get("entity"), dict):
                e = d["entity"]
                try:
                    e["_t"] = epoch(e["first_seen"])
                except (KeyError, ValueError):
                    continue
                ents[e["id"]] = e
                last = max(last, e["_t"])
            elif d.get("kind") == "observation" and isinstance(d.get("observation"), dict):
                o = d["observation"]
                try:
                    o["_t"] = epoch(o["observed_at"])
                except (KeyError, ValueError):
                    continue
                if isinstance(o.get("payload"), dict):
                    obs.append(o)
                    last = max(last, o["_t"])
    return ents, obs, last


def product_text(product, version):
    return " ".join(x for x in (product, version) if x).strip()


def tech_text(tech):
    return [t.replace(":", " ", 1) for t in tech if isinstance(t, str) and t]


def lead(t, kind, severity, host, port, title, product="", cve="", evidence="", how="", url=""):
    d = {"phase": 1, "time": stamp(t), "kind": kind, "severity": severity, "host": host}
    if port:
        d["port"] = port
    if url:
        d["url"] = url
    d.update({"product": product, "cve": cve, "title": title, "evidence": evidence, "how": how})
    d["_t"] = t
    return d


def port_leads(obs):
    """One lead per (address, port) azhaq named a product for; the first record wins."""
    best = {}
    for o in obs:
        p = o["payload"]
        if o.get("collector") != "azhaq-ports" or not isinstance(p.get("services"), list):
            continue
        ip = p.get("ip") or p.get("host") or ""
        for s in p["services"]:
            if not isinstance(s, dict) or not s.get("product") or not s.get("port"):
                continue
            k = (ip, s["port"])
            if k in best and best[k]["_t"] <= o["_t"]:
                continue
            prod = product_text(s["product"], s.get("version", ""))
            best[k] = lead(o["_t"], "vulnerable-software", "info", ip, s["port"], "%s on %s:%s" % (prod, ip, s["port"]),
                           product=prod, evidence="service=%s banner=%s" % (s.get("service", ""), s.get("banner", "")[:120]),
                           how="azhaq run -ports default")
    return list(best.values())


def web_leads(obs):
    """One lead per web origin's root page with a technology or Server header.
    The same answer under several names of one address is one lead, named by the
    first DNS name, else the address."""
    groups = {}
    for o in obs:
        p = o["payload"]
        if o.get("collector") != "azhaq-http" or o.get("kind") != "application":
            continue
        url = p.get("url") or o.get("source") or ""
        if not is_root(url) or not is_root(p.get("final_url") or url):
            continue
        tech, server = tech_text(p.get("tech") or []), (p.get("server") or "").strip()
        if not tech and not server:
            continue
        host, port = split_url(url)
        if not host or not port:
            continue
        sig = (p.get("ip") or host, port, server, tuple(tech), p.get("title") or "")
        g = groups.setdefault(sig, {"t": o["_t"], "hosts": [], "tech": tech, "server": server, "title": p.get("title") or "", "url": url})
        if o["_t"] < g["t"]:
            g["t"] = o["_t"]
        g["hosts"].append((o["_t"], host))
    out = []
    for (ip, port, server, _, title), g in groups.items():
        names = sorted(h for h in g["hosts"] if not is_ip(h[1]))
        host = names[0][1] if names else sorted(g["hosts"])[0][1]
        prod = "; ".join(([server] if server else []) + g["tech"])
        out.append(lead(g["t"], "vulnerable-software", "info", host, port, ("%s: %s" % (title, prod) if title else prod),
                        product=prod, evidence="title=%s server=%s tech=%s" % (title, server, ", ".join(g["tech"])),
                        how="azhaq run (web stage)", url=g["url"]))
    return out


def takeover_leads(obs):
    out, seen = [], set()
    for o in obs:
        p = o["payload"]
        f = p.get("takeover")
        if not isinstance(f, dict):
            continue
        host = (p.get("fqdn") or split_url(p.get("url") or o.get("source") or "")[0]).lower()
        if not host or host in seen:
            continue
        seen.add(host)
        sev = "medium" if f.get("status") == "verified" else "low"
        out.append(lead(o["_t"], "takeover", sev, host, None,
                        "takeover %s: %s CNAME %s (%s)" % (f.get("status", "candidate"), host, f.get("target", ""), f.get("service", "")),
                        product=f.get("service", ""), evidence="%s; target %s" % (f.get("evidence", ""), f.get("target", "")),
                        how="azhaq run (names stage)"))
    return out


def cve_of(*texts):
    for t in texts:
        m = CVE.search(t or "")
        if m:
            return m.group(0).upper()
    return ""


def verify_leads(obs):
    """-verify results, and -advisories leads a verify result does not cover."""
    out, covered = [], set()
    for o in obs:
        p = o["payload"]
        if o.get("collector") != "azhaq-verify" or o.get("kind") != "verify":
            continue
        host = p.get("host") or split_url(p.get("url") or "")[0]
        if not host:
            continue
        covered.add((p.get("advisory_id", ""), p.get("target", "")))
        prod = product_text(p.get("product", ""), p.get("version", ""))
        label = p.get("label", "")
        out.append(lead(o["_t"], VERIFY_KINDS.get(p.get("kind"), "other"), p.get("severity") or "info", host, p.get("port"),
                        "%s %s%s" % (label, p.get("kind", ""), (": " + prod) if prod else ""), product=prod,
                        cve=cve_of(p.get("advisory_id"), p.get("evidence")),
                        evidence="%s; %s" % (label, (p.get("evidence") or "")[:200]), how="azhaq run -verify", url=p.get("url", "")))
    for o in obs:
        p = o["payload"]
        if o.get("collector") != "azhaq-advisories" or o.get("kind") != "advisory" or p.get("label") == "not affected":
            continue
        if (p.get("advisory_id", ""), p.get("target", "")) in covered or not p.get("host"):
            continue
        prod = product_text(p.get("product", ""), p.get("version_seen", ""))
        out.append(lead(o["_t"], "vulnerable-software", "info", p["host"], p.get("port"),
                        "%s: %s %s" % (p.get("label", ""), prod, p.get("advisory_id", "")), product=prod,
                        cve=cve_of(p.get("advisory_id")), evidence=(p.get("read") or p.get("summary") or "")[:200],
                        how="azhaq run -advisories"))
    return out


def stack_leads(obs):
    out, seen = [], set()
    for o in obs:
        p = o["payload"]
        st = p.get("stack_trace")
        if o.get("collector") != "azhaq-http" or not isinstance(st, dict):
            continue
        url = p.get("url") or o.get("source") or ""
        if url in seen:
            continue
        seen.add(url)
        host, port = split_url(url)
        out.append(lead(o["_t"], "info-leak", "low", host, port, "stack trace in the answer of %s" % urlparse(url).path,
                        evidence="%s %s" % (st.get("runtime", ""), st.get("exception", "")), how="azhaq run (web stage)", url=url))
    return out


def url_times(ents, obs):
    """URL -> when azhaq first got an answer for it, else when it first saw it."""
    t = {}
    for o in obs:
        if o.get("collector") == "azhaq-http" and o.get("kind") == "application":
            u = o["payload"].get("url") or o.get("source") or ""
            t[u] = min(t.get(u, o["_t"]), o["_t"])
    for e in ents.values():
        if e.get("type") in ("URL", "Hostname"):
            t.setdefault(e.get("key", ""), e["_t"])
    return t


def hunt_leads(path, times, fallback):
    out = []
    if not path or not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if not isinstance(d, dict) or not isinstance(d.get("reasons"), list):
                continue
            hit = [(HUNT_KINDS[r["signal"]], r) for r in d["reasons"] if isinstance(r, dict) and r.get("signal") in HUNT_KINDS]
            if not hit:
                continue
            (kind, _), r = max(hit, key=lambda x: x[0][1])
            key = d.get("key", "")
            host, port = split_url(key) if "://" in key else (key.lower(), None)
            if not host:
                continue
            score = d.get("score", 0)
            sev = "high" if score >= 70 else "medium" if score >= 40 else "low"
            out.append(lead(times.get(key, fallback), kind, sev, host, port, "%s: %s" % (r["signal"], r.get("detail", ""))[:140],
                            evidence="; ".join("%s: %s" % (x.get("signal"), x.get("detail")) for x in d["reasons"] if isinstance(x, dict))[:300],
                            how="azhaq hunt", url=key if "://" in key else ""))
    return out


def names_by_ip(obs):
    m = {}
    for o in obs:
        p = o["payload"]
        if o.get("collector") == "azhaq-dns" and p.get("fqdn") and isinstance(p.get("ips"), list):
            for ip in p["ips"]:
                m.setdefault(ip, set()).add(p["fqdn"].lower())
        elif o.get("collector") == "azhaq-http" and p.get("ip"):
            h, _ = split_url(p.get("url") or "")
            if h and not is_ip(h):
                m.setdefault(p["ip"], set()).add(h)
    return m


def surface(obs, ents=None):
    """Hosts, open ports and services as azhaq lists them: one line per address
    and port, and one per name that points at the address."""
    names = names_by_ip(obs)
    lines, seen = [], set()

    def add(s):
        if s not in seen:
            seen.add(s)
            lines.append(s)
    for ip, ns in sorted(names.items()):
        for n in sorted(ns):
            add("%s %s" % (n, ip))
    # Every open port azhaq kept, service named or not: a port the second pass found
    # has its entity before any service detection says what it is.
    for e in sorted((ents or {}).values(), key=lambda e: e.get("key") or ""):
        if e.get("type") != "Port":
            continue
        addr, _, rest = (e.get("key") or "").rpartition(":")
        port, _, proto = rest.partition("/")
        if addr and port.isdigit():
            for h in [addr] + sorted(names.get(addr, ())):
                add("%s:%s/%s" % (h, port, proto or "tcp"))
    for o in obs:
        p = o["payload"]
        if o.get("collector") != "azhaq-ports" or not isinstance(p.get("services"), list):
            continue
        ip = p.get("ip") or p.get("host") or ""
        for s in p["services"]:
            if not isinstance(s, dict) or not s.get("port"):
                continue
            what = " ".join(x for x in (s.get("service", ""), s.get("product", ""), s.get("version", "")) if x)
            for h in [ip] + sorted(names.get(ip, ())):
                add("%s:%s/tcp %s" % (h, s["port"], what))
    for o in obs:
        p = o["payload"]
        if o.get("collector") == "azhaq-http" and o.get("kind") == "application":
            url = p.get("url") or ""
            if is_root(url) and p.get("status"):
                h, port = split_url(url)
                add("%s:%s %s web %s" % (h, port, urlparse(url).scheme, (p.get("title") or "")[:60]))
    return lines


def write(args, ents, obs, last):
    first = min([o["_t"] for o in obs] + [e["_t"] for e in ents.values()] or [0])
    start = epoch(args.start) if args.start else first
    end = epoch(args.end) if args.end else last
    leads = port_leads(obs) + web_leads(obs) + takeover_leads(obs) + verify_leads(obs) + stack_leads(obs)
    leads += hunt_leads(args.hunt, url_times(ents, obs), end)
    for d in leads:
        d["_t"] = max(d["_t"], start)  # a clock a second off must not give a negative time
        d["time"] = stamp(d["_t"])
    leads.sort(key=lambda d: (d["_t"], d["host"], d.get("port") or 0, d["kind"]))
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "leads.jsonl"), "w", encoding="utf-8") as f:
        for d in leads:
            f.write(json.dumps({k: v for k, v in d.items() if k != "_t"}) + "\n")
    with open(os.path.join(args.out, "surface-1.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(surface(obs, ents)) + "\n")
    with open(os.path.join(args.out, "phases.log"), "w", encoding="utf-8") as f:
        f.write("phase 1 start %s\nphase 1 end %s\n" % (stamp(start), stamp(max(end, start))))
    return len(leads)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", required=True, help="azhaq export -format jsonl of the run's workspace")
    ap.add_argument("--hunt", help="azhaq hunt -json -limit 1000 of it")
    ap.add_argument("--out", required=True)
    ap.add_argument("--start", help="when the replay started (ISO 8601); default the first row azhaq stored")
    ap.add_argument("--end", help="when it ended; default the last row")
    a = ap.parse_args(argv)
    ents, obs, last = load(a.export)
    n = write(a, ents, obs, last)
    print("to_leads.py: %d leads" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
